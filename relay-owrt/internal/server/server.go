// Package server implements the dtm_host WebSocket protocol for the
// OpenWrt router relay. It is wire-compatible with host/lib/host_server.dart:
// HELLO/WELCOME, SUBSCRIBE, PUBLISH/PUBLISHED, PUBLISH_LIVE,
// WANT/HAVE/GET/ENVELOPES, PRESENCE, PEER_LIST and the federation frames.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/slavabars/soty-relay/relay-owrt/internal/identity"
	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
	"github.com/slavabars/soty-relay/relay-owrt/internal/store"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

// Config is the router operator's knob set. Defaults mirror dtm_host; only
// MaxConnections and the store caps are lower because a router has less RAM.
type Config struct {
	Listen   string
	Port     int
	Announce string

	RetentionMs   int64
	RelayWindowMs int64

	MaxConnections int

	// Federation is off by default: a router relay serves its LAN and never
	// opens an outbound connection unless the operator opts in (T-120).
	Federation bool
	// AllowInboundFederation lets reachable clients act as federated relays.
	// A LAN router keeps this false: "federation" means the outbound upstream
	// bridge, never an inbound privileged role. Never enable it on a listener
	// reachable from the internet without pinned peers.
	AllowInboundFederation bool
	Seeds                  []wire.HostEndpoint

	TrackerPeerTTLMs int64

	PruneInterval          time.Duration
	FederationSyncInterval time.Duration

	RateLimitPerWindow     int
	LiveRateLimitPerWindow int
	RateWindowSeconds      int
	RateLimiterMaxKeys     int

	MaxStoredEnvelopes int
	MaxStoredBytes     int

	Version string
}

// DefaultConfig returns the stock router profile.
func DefaultConfig() Config {
	return Config{
		Listen:                 "0.0.0.0",
		Port:                   3100,
		RetentionMs:            limits.HostRetentionMs,
		RelayWindowMs:          limits.HostRelayWindowMs,
		MaxConnections:         128,
		TrackerPeerTTLMs:       limits.HostTrackerPeerTTLMs,
		PruneInterval:          6 * time.Hour,
		FederationSyncInterval: 10 * time.Minute,
		RateLimitPerWindow:     limits.HostRateLimitPerWindow,
		LiveRateLimitPerWindow: limits.HostRateLimitLivePerWindow,
		RateWindowSeconds:      limits.HostRateWindowSeconds,
		RateLimiterMaxKeys:     limits.MaxRateLimiterKeys,
		MaxStoredEnvelopes:     limits.MaxStoredEnvelopes,
		MaxStoredBytes:         limits.MaxStoredBytes,
		Version:                "0.1.0",
	}
}

func (c *Config) applyDefaults() {
	d := DefaultConfig()
	if c.Listen == "" {
		c.Listen = d.Listen
	}
	if c.RetentionMs <= 0 {
		c.RetentionMs = d.RetentionMs
	}
	if c.RelayWindowMs <= 0 {
		c.RelayWindowMs = d.RelayWindowMs
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = d.MaxConnections
	}
	if c.MaxConnections > limits.MaxHostConnections {
		c.MaxConnections = limits.MaxHostConnections
	}
	if c.TrackerPeerTTLMs <= 0 {
		c.TrackerPeerTTLMs = d.TrackerPeerTTLMs
	}
	if c.PruneInterval <= 0 {
		c.PruneInterval = d.PruneInterval
	}
	if c.FederationSyncInterval <= 0 {
		c.FederationSyncInterval = d.FederationSyncInterval
	}
	if c.RateLimitPerWindow <= 0 {
		c.RateLimitPerWindow = d.RateLimitPerWindow
	}
	if c.LiveRateLimitPerWindow <= 0 {
		c.LiveRateLimitPerWindow = d.LiveRateLimitPerWindow
	}
	if c.RateWindowSeconds <= 0 {
		c.RateWindowSeconds = d.RateWindowSeconds
	}
	if c.RateLimiterMaxKeys <= 0 {
		c.RateLimiterMaxKeys = d.RateLimiterMaxKeys
	}
	if c.MaxStoredEnvelopes <= 0 {
		c.MaxStoredEnvelopes = d.MaxStoredEnvelopes
	}
	if c.MaxStoredBytes <= 0 {
		c.MaxStoredBytes = d.MaxStoredBytes
	}
	if c.Version == "" {
		c.Version = d.Version
	}
}

type counters struct {
	connectionsTotal atomic.Int64
	received         atomic.Int64
	relayed          atomic.Int64
	rejected         atomic.Int64
	duplicate        atomic.Int64
	backfill         atomic.Int64
	live             atomic.Int64
}

// Server is one running relay.
type Server struct {
	cfg   Config
	store *store.Store
	id    *identity.Identity
	log   *log.Logger

	rate     *rateLimiter
	liveRate *rateLimiter

	upgrader websocket.Upgrader

	mu       sync.Mutex
	conns    map[*client]struct{}
	links    map[string]*peerLink
	stopping bool

	presenceMu    sync.Mutex
	presenceTimer *time.Timer
	lastPresence  string

	addrMu    sync.Mutex
	addrCache map[string]addrCheck

	counts counters

	startedAt time.Time
	boundPort int
	announce  string

	httpSrv   *http.Server
	listener  net.Listener
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New wires a server around an opened store and identity.
func New(cfg Config, st *store.Store, id *identity.Identity, logger *log.Logger) *Server {
	cfg.applyDefaults()
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cfg:   cfg,
		store: st,
		id:    id,
		log:   logger,
		rate: newRateLimiter(cfg.RateLimitPerWindow, cfg.RateWindowSeconds,
			cfg.RateLimiterMaxKeys),
		liveRate: newRateLimiter(cfg.LiveRateLimitPerWindow,
			cfg.RateWindowSeconds, cfg.RateLimiterMaxKeys),
		conns:     make(map[*client]struct{}),
		links:     make(map[string]*peerLink),
		done:      make(chan struct{}),
		addrCache: make(map[string]addrCheck),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
	}
	return s
}

// Start binds the listener and starts background loops.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.cfg.Listen,
		strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln
	s.boundPort = ln.Addr().(*net.TCPAddr).Port
	s.announce = s.effectiveAnnounce()
	s.startedAt = time.Now().UTC()

	s.httpSrv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(ln); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			s.logf("http server: %v", err)
		}
	}()
	s.wg.Add(1)
	go s.loop(s.cfg.PruneInterval, s.prune)
	if s.cfg.Federation {
		s.wg.Add(1)
		go s.loop(s.cfg.FederationSyncInterval, s.federationSync)
		s.mu.Lock()
		seeds := append([]wire.HostEndpoint(nil), s.cfg.Seeds...)
		members := s.store.FederatedHosts()
		s.mu.Unlock()
		for _, ep := range append(seeds, members...) {
			s.startPeerLink(ep)
		}
	} else {
		s.logf("federation off: LAN relay only, no outbound connections")
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.prune()
	}()
	s.logf("listening on %s (ws), identity %s", s.announce,
		s.id.PubHex())
	return nil
}

// Shutdown stops accepting sockets, closes every connection and flushes the
// store. Safe to call twice.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.stopping = true
		conns := make([]*client, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		links := make([]*peerLink, 0, len(s.links))
		for _, l := range s.links {
			links = append(links, l)
		}
		s.mu.Unlock()
		s.presenceMu.Lock()
		if s.presenceTimer != nil {
			s.presenceTimer.Stop()
		}
		s.presenceMu.Unlock()
		for _, c := range conns {
			c.close()
		}
		for _, l := range links {
			l.close()
		}
		if s.httpSrv != nil {
			err = s.httpSrv.Shutdown(ctx)
		}
	})
	s.wg.Wait()
	return err
}

// BoundPort is the actual port after Start (useful with Port 0 in tests).
func (s *Server) BoundPort() int { return s.boundPort }

// Announce is the relay's advertised ws:// URL.
func (s *Server) Announce() string { return s.announce }

func (s *Server) effectiveAnnounce() string {
	if s.cfg.Announce != "" {
		return s.cfg.Announce
	}
	host := s.cfg.Listen
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("ws://%s/ws", net.JoinHostPort(host,
		strconv.Itoa(s.boundPort)))
}

func (s *Server) loop(every time.Duration, fn func()) {
	defer s.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			fn()
		}
	}
}

func (s *Server) logf(format string, args ...any) {
	s.log.Printf("[relay] "+format, args...)
}

// ServeHTTP routes the operational endpoints and the WebSocket upgrade.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/status", "/status/":
		s.handleStatus(w, r)
	case "/directory", "/directory/":
		s.handleDirectory(w, r)
	case "/healthz", "/healthz/":
		writeJSON(w, map[string]any{"ok": true})
	case "/ws":
		s.handleWS(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.hasCapacity() {
		http.Error(w, "connection limit reached",
			http.StatusServiceUnavailable)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{
		srv:          s,
		ws:           ws,
		remote:       remoteHost(r.RemoteAddr),
		caps:         make(map[string]bool),
		subscribed:   make(map[string]struct{}),
		subscribedAt: make(map[string]int64),
		clientDone:   make(chan struct{}),
		challenge:    randomHex(32),
	}
	s.mu.Lock()
	if s.stopping || len(s.conns) >= s.cfg.MaxConnections {
		s.mu.Unlock()
		_ = ws.Close()
		return
	}
	s.conns[c] = struct{}{}
	s.counts.connectionsTotal.Add(1)
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.handleSocket(c)
	}()
}

func (s *Server) hasCapacity() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.stopping && len(s.conns) < s.cfg.MaxConnections
}

func (s *Server) removeClient(c *client) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	if link := c.peerLink(); link != nil {
		link.wsGone()
	}
	if !c.isUpstream() && !s.isStopping() {
		s.refreshAllUpstream()
	}
	s.schedulePresence()
}

func (s *Server) clients() []*client {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*client, 0, len(s.conns))
	for c := range s.conns {
		out = append(out, c)
	}
	return out
}

func (s *Server) activeConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for c := range s.conns {
		if !c.isClosed() {
			n++
		}
	}
	return n
}

func (s *Server) handleSocket(c *client) {
	defer c.close()
	c.ws.SetReadLimit(limits.MaxFrameBytes)
	_ = c.ws.SetReadDeadline(time.Now().Add(limits.HostIdleTimeout))
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(limits.HostIdleTimeout))
	})
	go c.pingLoop()
	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		if len(data) > limits.MaxFrameBytes {
			return
		}
		msg, err := wire.Parse(data)
		if err != nil {
			return
		}
		if err := s.dispatch(c, msg); err != nil {
			return
		}
	}
}

// dispatch is the server half of GossipMessage dispatch. Returning an error
// drops the connection (protocol violation), like FormatException in Dart.
func (s *Server) dispatch(c *client, msg wire.Message) error {
	switch m := msg.(type) {
	case *wire.Hello:
		c.setPeerID(m.MyPeerID)
		c.setCapabilities(m.Capabilities)
		federated := c.hasCap(limits.CapHost) &&
			s.mayFederate(c, m.MyPeerID, m.Announce)
		c.setFederated(federated)
		now := nowMs()
		if !federated && len(m.MyAddrs) > 0 {
			s.store.RememberPeer(m.MyPeerID, "", m.MyAddrs, now)
		}
		welcomeCaps := []string{limits.CapTracker, limits.CapNet, limits.CapLive}
		welcome := &wire.Welcome{
			ServerTime:       now,
			RetentionSeconds: s.cfg.RetentionMs / 1000,
			MaxEnvelopeSize:  limits.MaxFrameBytes,
			Identity:         s.id.PubHex(),
			Capabilities:     welcomeCaps,
			Challenge:        c.challenge,
		}
		if m.Nonce != "" {
			data := fmt.Sprintf("dtm-welcome-v1|%s|%d|%s|%s",
				m.Nonce, now, welcome.Identity, strings.Join(welcomeCaps, ","))
			welcome.Proof = s.id.Sign([]byte(data))
		}
		c.send(welcome)
		if federated && c.hasCap(limits.CapNet) && m.Announce != nil {
			s.adoptNetworkMember(wire.HostEndpoint{
				Addr:     *m.Announce,
				EdPubKey: m.MyPeerID,
			})
			c.send(&wire.Network{Hosts: s.networkMembers()})
		}
		if c.hasCap(limits.CapPresence) {
			s.sendPresenceTo(c)
		}
		return nil
	case *wire.Subscribe:
		now := nowMs()
		if !c.allowDiscovery(&c.subscribeWindow, &c.subscribeCount,
			limits.HostSubscribesPerWindow, now) {
			c.send(&wire.Envelopes{Envelopes: []*wire.Envelope{}, Done: true})
			return nil
		}
		since := scanWindowStart(m.Since, now)
		keys := m.Keys
		if len(keys) > limits.MaxHostSubscriptionKeys {
			keys = keys[:limits.MaxHostSubscriptionKeys]
		}
		for _, k := range keys {
			if !isHex32(k) {
				return errors.New("subscription key is not 32-byte hex")
			}
			s.store.RememberSubscription(k, now)
		}
		if peerID := c.peerID(); peerID != "" && len(keys) > 0 {
			s.store.RememberPeer(peerID, keys[0], nil, now)
		}
		c.setSubscriptions(keys, now)
		s.schedulePresence()
		s.sendBackfill(c, since)
		if !c.isUpstream() {
			s.refreshAllUpstream()
		}
		return nil
	case *wire.Publish:
		accepted := s.acceptEnvelope(m.Envelope, "publish", 0)
		if accepted {
			s.fanOut(m.Envelope, 0, c)
			if !c.isFederated() && !c.isUpstream() {
				s.forwardUpstream(m.Envelope, false)
			}
		}
		c.send(&wire.Published{ID: m.Envelope.ID, Accepted: accepted})
		return nil
	case *wire.PublishLive:
		verified := s.verifyEnvelope(m.Envelope, s.liveRate)
		forwarded := 0
		if verified {
			s.counts.live.Add(1)
			forwarded = s.fanOutLive(m.Envelope, c)
			if !c.isFederated() && !c.isUpstream() {
				s.forwardUpstream(m.Envelope, true)
			}
		}
		c.send(&wire.Published{
			ID:       m.Envelope.ID,
			Accepted: verified && forwarded > 0,
		})
		return nil
	case *wire.Want:
		now := nowMs()
		if !c.allowDiscovery(&c.wantWindow, &c.wantCount,
			limits.HostWantsPerWindow, now) {
			c.send(&wire.Have{IDs: []string{}})
			return nil
		}
		// HAVE is bounded by the same maxGossipItems the peer parser
		// enforces; a 4096-id answer would be rejected as a malformed frame.
		ids := s.store.IDsSince(scanWindowStart(m.Since, now),
			limits.MaxGossipItems)
		c.send(&wire.Have{IDs: ids})
		return nil
	case *wire.Have:
		if !c.isFederated() {
			return nil
		}
		missing := make([]string, 0, limits.MaxGossipItems)
		for _, id := range m.IDs {
			if len(missing) >= limits.MaxGossipItems {
				break
			}
			if !s.store.Has(id) {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			c.send(&wire.Get{IDs: missing})
		}
		return nil
	case *wire.Get:
		out := make([]*wire.Envelope, 0, limits.MaxGossipItems)
		for _, id := range m.IDs {
			if len(out) >= limits.MaxGossipItems {
				break
			}
			env := s.store.EnvelopeByID(id)
			if env == nil || !s.entitledTo(c, env) {
				continue
			}
			out = append(out, env)
		}
		c.send(&wire.Envelopes{Envelopes: out, Done: true})
		return nil
	case *wire.Envelopes:
		if !c.isFederated() {
			return nil
		}
		for _, env := range m.Envelopes {
			if s.acceptEnvelope(env, "federated", m.Hops) {
				s.fanOut(env, m.Hops, c)
			}
		}
		return nil
	case *wire.Welcome:
		c.addCapabilities(m.Capabilities)
		if link := c.peerLink(); link != nil && m.Identity != "" {
			link.setIdentity(m.Identity)
			pinned := link.endpoint.EdPubKey
			if pinned != "" && pinned != m.Identity {
				return fmt.Errorf("host identity mismatch: expected %s got %s",
					pinned, m.Identity)
			}
		}
		if c.isUpstream() {
			s.refreshUpstream(c)
			c.send(&wire.Want{Since: s.store.LatestTimestamp()})
		} else if c.isFederated() && c.hasCap(limits.CapNet) {
			c.send(&wire.Network{Hosts: s.networkMembers()})
		}
		return nil
	case *wire.PeerListRequest:
		now := nowMs()
		peers := s.store.SamplePeers(limits.MaxTrackerPeers, c.peerID(),
			now, s.cfg.TrackerPeerTTLMs)
		c.send(&wire.PeerList{
			Peers: peers,
			Hosts: s.publicNetworkMembers(),
		})
		return nil
	case *wire.Network:
		if !c.isFederated() || c.isUpstream() ||
			!c.hasCap(limits.CapNet) {
			return nil
		}
		for _, ep := range m.Hosts {
			s.adoptNetworkMember(ep)
		}
		return nil
	case *wire.PeerList, *wire.Published, *wire.Presence:
		return nil
	default:
		return nil
	}
}

// scanWindowStart matches HostServer.scanWindowStart.
func scanWindowStart(since, now int64) int64 {
	if since < 0 {
		return 0
	}
	if now-since > limits.GossipMaxScanWindowMs {
		return now - limits.GossipMaxScanWindowMs
	}
	return since
}

func nowMs() int64 { return time.Now().UTC().UnixMilli() }

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

func isHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') &&
			(c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// client is one accepted socket plus its protocol state.
type client struct {
	srv    *Server
	ws     *websocket.Conn
	remote string

	writeMu sync.Mutex

	stateMu         sync.Mutex
	peerIDValue     string
	identity        string
	challenge       string
	subscribeWindow int64
	subscribeCount  int
	wantWindow      int64
	wantCount       int
	federated       bool
	upstream        bool
	caps            map[string]bool
	subscribed      map[string]struct{}
	subscribedAt    map[string]int64
	closed          bool
	link            *peerLink
	clientDone      chan struct{}

	closeOnce sync.Once
}

func (c *client) allowDiscovery(window *int64, count *int,
	limit int, now int64) bool {
	w := now / (limits.HostRateWindowSeconds * 1000)
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if *window != w {
		*window = w
		*count = 0
	}
	if *count >= limit {
		return false
	}
	*count++
	return true
}

func (c *client) send(msg wire.Message) {
	data, err := wire.Encode(msg)
	if err != nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.isClosed() {
		return
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.ws.WriteMessage(websocket.TextMessage, data); err != nil {
		c.close()
	}
}

func (c *client) pingLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.srv.done:
			return
		case <-c.clientDone:
			return
		case <-ticker.C:
			if c.isClosed() {
				return
			}
			if err := c.ws.WriteControl(websocket.PingMessage, nil,
				time.Now().Add(10*time.Second)); err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *client) close() {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closed = true
		c.stateMu.Unlock()
		close(c.clientDone)
		_ = c.ws.Close()
		c.srv.removeClient(c)
	})
}

func (c *client) isClosed() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.closed
}

func (c *client) peerID() string {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.peerIDValue
}

func (c *client) setPeerID(id string) {
	c.stateMu.Lock()
	c.peerIDValue = id
	c.stateMu.Unlock()
}

func (c *client) setCapabilities(caps []string) {
	c.stateMu.Lock()
	for _, cap := range caps {
		c.caps[cap] = true
	}
	c.stateMu.Unlock()
}

func (c *client) addCapabilities(caps []string) {
	c.setCapabilities(caps)
}

func (c *client) hasCap(cap string) bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.caps[cap]
}

func (c *client) setFederated(v bool) {
	c.stateMu.Lock()
	c.federated = v
	c.stateMu.Unlock()
}

func (c *client) isFederated() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.federated
}

func (c *client) setUpstream(v bool) {
	c.stateMu.Lock()
	c.upstream = v
	c.stateMu.Unlock()
}

func (c *client) isUpstream() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.upstream
}

func (c *client) setSubscriptions(keys []string, now int64) {
	c.stateMu.Lock()
	c.subscribed = make(map[string]struct{}, len(keys))
	c.subscribedAt = make(map[string]int64, len(keys))
	for _, k := range keys {
		c.subscribed[k] = struct{}{}
		c.subscribedAt[k] = now
	}
	c.stateMu.Unlock()
}

func (c *client) subscriptionSnapshot() ([]string, map[string]int64) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	keys := make([]string, 0, len(c.subscribed))
	at := make(map[string]int64, len(c.subscribedAt))
	for k := range c.subscribed {
		keys = append(keys, k)
		at[k] = c.subscribedAt[k]
	}
	return keys, at
}

func (c *client) isSubscribed(key string) bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	_, ok := c.subscribed[key]
	return ok
}

func (c *client) peerLink() *peerLink {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.link
}

func (c *client) setPeerLink(link *peerLink) {
	c.stateMu.Lock()
	c.link = link
	c.stateMu.Unlock()
}
