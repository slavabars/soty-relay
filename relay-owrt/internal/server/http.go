package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
)

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(payload)
}

// handleStatus exposes aggregate counters only: never identity, client
// addresses or envelope metadata.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	now := nowMs()
	started := s.startedAt
	uptime := int64(0)
	if !started.IsZero() {
		uptime = now - started.UnixMilli()
		if uptime < 0 {
			uptime = 0
		}
	}
	payload := map[string]any{
		"ok":               true,
		"ts":               now,
		"startedAt":        started.UnixMilli(),
		"uptimeSeconds":    uptime / 1000,
		"connections":      s.activeConnections(),
		"connectionsTotal": s.counts.connectionsTotal.Load(),
		"federatedLinks":   s.linkCount(),
		"queue":            s.store.EnvelopeCount(),
		"envelopes":        s.store.EnvelopeCount(),
		"peers":            s.store.PeerCount(),
		"subscriptions":    s.store.SubscriptionCount(),
		"dbBytes":          s.store.DiskBytes(),
		"memoryBytes":      s.store.Bytes(),
		"evictedTotal":     s.store.Evicted(),
		"receivedTotal":    s.counts.received.Load(),
		"relayedTotal":     s.counts.relayed.Load(),
		"rejectedTotal":    s.counts.rejected.Load(),
		"duplicateTotal":   s.counts.duplicate.Load(),
		"backfillTotal":    s.counts.backfill.Load(),
		"liveTotal":        s.counts.live.Load(),
		"rssBytes":         rssBytes(),
		"load1":            load1(),
		"version":          s.cfg.Version,
	}
	writeJSON(w, payload)
}

// handleDirectory is the public relay table entry: this relay plus every
// federated member that is reachable from outside its LAN.
func (s *Server) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	self := map[string]string{
		"addr":    s.announce,
		"ed25519": s.id.PubHex(),
	}
	members := make([]map[string]string, 0)
	seen := map[string]struct{}{s.announce: {}}
	for _, ep := range s.publicNetworkMembers() {
		if ep.EdPubKey == "" || ep.EdPubKey == self["ed25519"] {
			continue
		}
		if _, ok := seen[ep.Addr]; ok {
			continue
		}
		seen[ep.Addr] = struct{}{}
		if !publiclyRoutable(ep.Addr) {
			continue
		}
		members = append(members, map[string]string{
			"addr":    ep.Addr,
			"ed25519": ep.EdPubKey,
		})
		if len(members) >= limits.MaxFederatedHosts {
			break
		}
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"ts":      nowMs(),
		"self":    self,
		"members": members,
	})
}

// publiclyRoutable mirrors HostServer._publiclyRoutable: loopback, link-local,
// multicast and private IPv4 ranges cannot be probed from the internet.
func publiclyRoutable(addr string) bool {
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || host == "::1" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return false
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return false
		case v4[0] == 192 && v4[1] == 168:
			return false
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
			return false
		case v4[0] == 0:
			return false
		}
	}
	return true
}

func rssBytes() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func load1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return v
}
