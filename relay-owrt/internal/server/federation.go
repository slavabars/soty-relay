package server

import (
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

type addrCheck struct {
	ips     []net.IP
	expires time.Time
}

// mayFederate implements the granted-never-claimed rule. With federation off
// (the router default) it always returns false, so a `dtm-host` capability in
// a HELLO is just a claim from an ordinary client.
func (s *Server) mayFederate(c *client, claimed string, announce *string) bool {
	if !s.cfg.Federation || claimed == "" {
		return false
	}
	if link := c.peerLink(); link != nil {
		pinned := link.endpoint.EdPubKey
		return pinned == "" || pinned == claimed
	}
	for _, ep := range s.networkMembers() {
		if ep.EdPubKey == claimed {
			return true
		}
	}
	if announce == nil || *announce == "" {
		return false
	}
	for _, ep := range s.store.FederatedHosts() {
		if ep.Addr == *announce && ep.EdPubKey == claimed {
			return true
		}
	}
	return s.announceMatchesRemote(*announce, c.remote)
}

// announceMatchesRemote checks that the announced host resolves to the
// socket's source address. DNS answers are cached for ten minutes.
func (s *Server) announceMatchesRemote(announce, remote string) bool {
	if remote == "" {
		return false
	}
	u, err := url.Parse(announce)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") ||
		u.Hostname() == "" || len(announce) > limits.MaxAddrLength {
		return false
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.String() == remote
	}
	s.addrMu.Lock()
	cached, ok := s.addrCache[host]
	s.addrMu.Unlock()
	if !ok || time.Now().After(cached.expires) {
		ips, err := net.LookupIP(host)
		if err != nil {
			ips = nil
		}
		cached = addrCheck{ips: ips, expires: time.Now().Add(10 * time.Minute)}
		s.addrMu.Lock()
		if len(s.addrCache) > limits.MaxFederatedHosts*4 {
			s.addrCache = make(map[string]addrCheck)
		}
		s.addrCache[host] = cached
		s.addrMu.Unlock()
	}
	for _, ip := range cached.ips {
		if ip.String() == remote {
			return true
		}
	}
	return false
}

type peerLink struct {
	srv      *Server
	endpoint wire.HostEndpoint

	mu       sync.Mutex
	identity string
	ws       *websocket.Conn
	closed   bool
	attempt  int
	done     chan struct{}
}

func newPeerLink(s *Server, ep wire.HostEndpoint) *peerLink {
	return &peerLink{srv: s, endpoint: ep, done: make(chan struct{})}
}

func (l *peerLink) setIdentity(id string) {
	l.mu.Lock()
	l.identity = id
	l.mu.Unlock()
}

func (l *peerLink) wsGone() {
	l.mu.Lock()
	l.ws = nil
	l.mu.Unlock()
}

func (l *peerLink) close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	ws := l.ws
	l.ws = nil
	close(l.done)
	l.mu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

func (l *peerLink) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// startPeerLink opens one outbound federation link. Idempotent by address and
// disabled when Federation is off.
func (s *Server) startPeerLink(ep wire.HostEndpoint) {
	if !s.cfg.Federation || !wire.ValidRelayAddr(ep.Addr) {
		return
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	if _, ok := s.links[ep.Addr]; ok {
		s.mu.Unlock()
		return
	}
	l := newPeerLink(s, ep)
	s.links[ep.Addr] = l
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		l.run()
	}()
}

func (l *peerLink) run() {
	for {
		if l.isClosed() || l.srv.isStopping() {
			return
		}
		l.connectOnce()
		if l.isClosed() || l.srv.isStopping() {
			return
		}
		l.mu.Lock()
		l.attempt++
		attempt := l.attempt
		l.mu.Unlock()
		delay := backoff(attempt)
		select {
		case <-time.After(delay):
		case <-l.done:
			return
		case <-l.srv.done:
			return
		}
	}
}

func (l *peerLink) connectOnce() {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, _, err := dialer.Dial(l.endpoint.Addr, nil)
	if err != nil {
		return
	}
	s := l.srv
	c := &client{
		srv:          s,
		ws:           ws,
		remote:       remoteFromConn(ws),
		caps:         make(map[string]bool),
		subscribed:   make(map[string]struct{}),
		subscribedAt: make(map[string]int64),
		clientDone:   make(chan struct{}),
	}
	c.setFederated(true)
	c.setUpstream(true)
	c.setPeerLink(l)
	l.mu.Lock()
	l.ws = ws
	l.mu.Unlock()
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		_ = ws.Close()
		return
	}
	s.conns[c] = struct{}{}
	s.counts.connectionsTotal.Add(1)
	s.mu.Unlock()
	announce := s.announce
	c.send(&wire.Hello{
		MyPeerID:     s.id.PubHex(),
		Capabilities: []string{limits.CapHost, limits.CapNet},
		Announce:     &announce,
	})
	s.handleSocket(c)
	l.mu.Lock()
	l.ws = nil
	if l.attempt > 0 {
		l.attempt = 0
	}
	l.mu.Unlock()
}

func (s *Server) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func (s *Server) linkCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

// federationSync nudges every established link: WANT from the newest stored
// timestamp plus the current network view.
func (s *Server) federationSync() {
	cursor := s.store.LatestTimestamp()
	network := s.networkMembers()
	for _, c := range s.clients() {
		if c.isClosed() || !c.isFederated() {
			continue
		}
		c.send(&wire.Want{Since: cursor})
		if !c.isUpstream() && c.hasCap(limits.CapNet) {
			c.send(&wire.Network{Hosts: network})
		}
	}
}

func backoff(attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	d := 2 * time.Second * time.Duration(1<<attempt)
	if d <= 0 {
		return time.Second
	}
	return d
}

func remoteFromConn(ws *websocket.Conn) string {
	if ws == nil || ws.RemoteAddr() == nil {
		return ""
	}
	return remoteHost(ws.RemoteAddr().String())
}
