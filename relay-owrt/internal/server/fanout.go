package server

import (
	"sort"
	"strings"
	"time"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

// verifyEnvelope is the fixed pipeline: rate limit → clock skew → Ed25519
// signature → content id. Nothing reaches the store before all four pass.
func (s *Server) verifyEnvelope(env *wire.Envelope, limiter *rateLimiter) bool {
	now := time.Now().UTC()
	if !limiter.allow(env.SenderPubKey, now) {
		s.counts.rejected.Add(1)
		return false
	}
	if !env.WithinSkew(now.UnixMilli()) {
		s.counts.rejected.Add(1)
		return false
	}
	if !env.Verify() {
		s.counts.rejected.Add(1)
		return false
	}
	if !env.HasValidID() {
		s.counts.rejected.Add(1)
		return false
	}
	return true
}

func (s *Server) acceptEnvelope(env *wire.Envelope, source string, hops int) bool {
	if !s.verifyEnvelope(env, s.rate) {
		return false
	}
	inserted := s.store.Insert(env, source, hops)
	if inserted {
		s.counts.received.Add(1)
	} else {
		s.counts.duplicate.Add(1)
	}
	return inserted
}

// fanOut delivers a stored envelope to subscribers and to federated peers.
func (s *Server) fanOut(env *wire.Envelope, hops int, except *client) {
	for _, c := range s.clients() {
		if c == except || c.isClosed() || c.isUpstream() {
			continue
		}
		if c.isFederated() {
			if hops >= limits.HostGossipMaxHops {
				continue
			}
			c.send(&wire.Envelopes{
				Envelopes: []*wire.Envelope{env},
				Done:      false,
				Hops:      hops + 1,
			})
			s.counts.relayed.Add(1)
			continue
		}
		if c.isSubscribed(env.RecipientPubKey) {
			c.send(&wire.Envelopes{
				Envelopes: []*wire.Envelope{env},
				Done:      false,
				Hops:      hops,
			})
			s.counts.relayed.Add(1)
		}
	}
}

// fanOutLive forwards a never-stored slice only to currently connected
// subscribers. Federated relays are excluded: they would store it.
func (s *Server) fanOutLive(env *wire.Envelope, except *client) int {
	forwarded := 0
	for _, c := range s.clients() {
		if c == except || c.isClosed() || c.isFederated() ||
			c.isUpstream() {
			continue
		}
		if !c.isSubscribed(env.RecipientPubKey) {
			continue
		}
		c.send(&wire.Envelopes{
			Envelopes: []*wire.Envelope{env},
			Done:      false,
			Hops:      0,
		})
		s.counts.relayed.Add(1)
		forwarded++
	}
	return forwarded
}

// localSubscriptionKeys is the union of X25519 keys subscribed by devices on
// this LAN. The seed host is subscribed to this set so a NATed router can
// receive messages addressed to its devices.
func (s *Server) localSubscriptionKeys() []string {
	set := make(map[string]struct{})
	for _, c := range s.clients() {
		if c.isClosed() || c.isUpstream() || c.isFederated() {
			continue
		}
		keys, _ := c.subscriptionSnapshot()
		for _, k := range keys {
			set[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limits.MaxHostSubscriptionKeys {
		s.logf("upstream: %d LAN keys, bridging first %d",
			len(keys), limits.MaxHostSubscriptionKeys)
		keys = keys[:limits.MaxHostSubscriptionKeys]
	}
	return keys
}

func (s *Server) refreshUpstream(c *client) {
	if c.isClosed() || !c.isUpstream() {
		return
	}
	c.send(&wire.Subscribe{Since: 0, Keys: s.localSubscriptionKeys()})
}

// refreshAllUpstream pushes the current LAN key set to every seed host. The
// seed replaces its subscription set, so removals are propagated too.
func (s *Server) refreshAllUpstream() {
	keys := s.localSubscriptionKeys()
	for _, c := range s.clients() {
		if c.isClosed() || !c.isUpstream() {
			continue
		}
		c.send(&wire.Subscribe{Since: 0, Keys: keys})
	}
}

// forwardUpstream publishes a LAN-originated envelope to seed relays. Stored
// envelopes use PUBLISH; live slices use PUBLISH_LIVE and stay unstored.
func (s *Server) forwardUpstream(env *wire.Envelope, live bool) {
	for _, c := range s.clients() {
		if c.isClosed() || !c.isUpstream() {
			continue
		}
		if live {
			c.send(&wire.PublishLive{Envelope: env})
		} else {
			c.send(&wire.Publish{Envelope: env})
		}
	}
}

func (s *Server) entitledTo(c *client, env *wire.Envelope) bool {
	return c.isFederated() || c.isSubscribed(env.RecipientPubKey)
}

// sendBackfill answers SUBSCRIBE with bounded batches and a final done frame,
// exactly like HostServer._sendBackfill.
func (s *Server) sendBackfill(c *client, since int64) {
	keys, _ := c.subscriptionSnapshot()
	cursor := since
	for round := 0; round < limits.HostBackfillMaxRounds; round++ {
		batch := s.store.EnvelopesForRecipients(keys, cursor,
			limits.MaxGossipItems)
		if len(batch) == 0 {
			break
		}
		s.counts.backfill.Add(int64(len(batch)))
		c.send(&wire.Envelopes{Envelopes: batch, Done: false})
		cursor = batch[len(batch)-1].Timestamp + 1
		if len(batch) < limits.MaxGossipItems {
			break
		}
	}
	c.send(&wire.Envelopes{Envelopes: []*wire.Envelope{}, Done: true})
}

type presenceEntry struct {
	key string
	at  int64
}

// presenceKeys lists keys subscribed right now, newest first, capped at
// maxPresenceKeys so a busy LAN truncates the stalest devices first.
func (s *Server) presenceKeys() []string {
	entries := make([]presenceEntry, 0)
	seen := make(map[string]struct{})
	for _, c := range s.clients() {
		if c.isClosed() || c.isFederated() {
			continue
		}
		keys, at := c.subscriptionSnapshot()
		for _, k := range keys {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			entries = append(entries, presenceEntry{key: k, at: at[k]})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].at > entries[j].at
	})
	if len(entries) > limits.MaxPresenceKeys {
		entries = entries[:limits.MaxPresenceKeys]
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.key)
	}
	return out
}

func (s *Server) presenceMessage() *wire.Presence {
	return &wire.Presence{Online: s.presenceKeys(), At: nowMs()}
}

func (s *Server) sendPresenceTo(c *client) {
	if c.isFederated() {
		return
	}
	c.send(s.presenceMessage())
}

// schedulePresence coalesces churn into one feed 400 ms later.
func (s *Server) schedulePresence() {
	if s.isStopping() {
		return
	}
	s.presenceMu.Lock()
	defer s.presenceMu.Unlock()
	if s.presenceTimer != nil {
		s.presenceTimer.Stop()
	}
	s.presenceTimer = time.AfterFunc(400*time.Millisecond, s.broadcastPresence)
}

func (s *Server) broadcastPresence() {
	select {
	case <-s.done:
		return
	default:
	}
	msg := s.presenceMessage()
	fingerprint := strings.Join(msg.Online, ",")
	s.presenceMu.Lock()
	changed := fingerprint != s.lastPresence
	s.lastPresence = fingerprint
	s.presenceMu.Unlock()
	if !changed {
		return
	}
	for _, c := range s.clients() {
		if c.isClosed() || c.isFederated() ||
			!c.hasCap(limits.CapPresence) {
			continue
		}
		c.send(msg)
	}
}

// networkMembers is this relay plus operator seeds and learned members,
// addr-keyed and bounded like HostServer._networkMembers.
func (s *Server) networkMembers() []wire.HostEndpoint {
	members := make(map[string]wire.HostEndpoint)
	self := wire.HostEndpoint{Addr: s.announce, EdPubKey: s.id.PubHex()}
	members[self.Addr] = self
	for _, ep := range s.cfg.Seeds {
		if _, ok := members[ep.Addr]; !ok {
			members[ep.Addr] = ep
		}
	}
	for _, ep := range s.store.FederatedHosts() {
		if _, ok := members[ep.Addr]; !ok {
			members[ep.Addr] = ep
		}
	}
	out := make([]wire.HostEndpoint, 0, len(members))
	out = append(out, self)
	for addr, ep := range members {
		if addr == self.Addr {
			continue
		}
		out = append(out, ep)
		if len(out) >= limits.MaxFederatedHosts {
			break
		}
	}
	return out
}

// publicNetworkMembers is the PEER_LIST host list: every member except self.
func (s *Server) publicNetworkMembers() []wire.HostEndpoint {
	out := make([]wire.HostEndpoint, 0, limits.MaxTrackerHosts)
	for _, ep := range s.networkMembers() {
		if ep.Addr == s.announce {
			continue
		}
		out = append(out, ep)
		if len(out) >= limits.MaxTrackerHosts {
			break
		}
	}
	return out
}

func (s *Server) adoptNetworkMember(ep wire.HostEndpoint) {
	if ep.Addr == s.announce || ep.Addr == "" {
		return
	}
	if !wire.ValidRelayAddr(ep.Addr) {
		return
	}
	s.store.RememberFederatedHost(ep, nowMs())
	if !s.cfg.Federation {
		return
	}
	s.startPeerLink(ep)
}

// prune runs age retention, the relay window and the subscriber TTL. Router
// storage caps are enforced on insert (a cache drop, not a retention promise).
func (s *Server) prune() {
	now := nowMs()
	s.store.ForgetStalePeers(now - s.cfg.TrackerPeerTTLMs)
	s.store.ForgetExpiredSubscriptions(now, s.cfg.RetentionMs)
	remembered := s.store.RememberedSubscriptions(now, s.cfg.RetentionMs)
	age, err := s.store.PruneOlderThan(now-s.cfg.RetentionMs, s.id)
	if err != nil {
		s.logf("prune age: %v", err)
	}
	window, err := s.store.PruneRelayWindow(now, s.cfg.RelayWindowMs,
		remembered, s.id)
	if err != nil {
		s.logf("prune relay window: %v", err)
	}
	s.logf("prune: connections=%d links=%d peers=%d hosts=%d envelopes=%d "+
		"evicted=%d age=%d window=%d", s.activeConnections(),
		s.linkCount(), s.store.PeerCount(), len(s.store.FederatedHosts()),
		s.store.EnvelopeCount(), s.store.Evicted(), age.Count, window.Count)
}
