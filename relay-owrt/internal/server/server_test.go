package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/slavabars/soty-relay/relay-owrt/internal/identity"
	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
	"github.com/slavabars/soty-relay/relay-owrt/internal/store"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

func startTestServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Listen = "127.0.0.1"
	cfg.Port = 0
	if mutate != nil {
		mutate(&cfg)
	}
	st, err := store.New(store.Options{
		MaxEnvelopes: cfg.MaxStoredEnvelopes,
		MaxBytes:     cfg.MaxStoredBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st, id, log.New(io.Discard, "", 0))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = st.Close()
	})
	return srv
}

func wsURL(s *Server) string {
	return fmt.Sprintf("ws://127.0.0.1:%d/ws", s.BoundPort())
}

type testClient struct {
	t      *testing.T
	ws     *websocket.Conn
	frames chan wire.Message
	errs   chan error
}

func dial(t *testing.T, s *Server) *testClient {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(s), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &testClient{
		t:      t,
		ws:     ws,
		frames: make(chan wire.Message, 64),
		errs:   make(chan error, 1),
	}
	go func() {
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				select {
				case c.errs <- err:
				default:
				}
				close(c.frames)
				return
			}
			msg, err := wire.Parse(data)
			if err != nil {
				select {
				case c.errs <- err:
				default:
				}
				close(c.frames)
				return
			}
			c.frames <- msg
		}
	}()
	t.Cleanup(func() { _ = ws.Close() })
	return c
}

func (c *testClient) send(msg wire.Message) {
	c.t.Helper()
	data, err := wire.Encode(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := c.ws.WriteMessage(websocket.TextMessage, data); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *testClient) sendRaw(data string) {
	c.t.Helper()
	if err := c.ws.WriteMessage(websocket.TextMessage, []byte(data)); err != nil {
		c.t.Fatalf("write raw: %v", err)
	}
}

func (c *testClient) next(timeout time.Duration) wire.Message {
	c.t.Helper()
	select {
	case msg, ok := <-c.frames:
		if !ok {
			c.t.Fatal("connection closed while waiting for a frame")
		}
		return msg
	case <-time.After(timeout):
		c.t.Fatal("timeout waiting for a frame")
		return nil
	}
}

func (c *testClient) waitFor(pred func(wire.Message) bool, timeout time.Duration) wire.Message {
	c.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg, ok := <-c.frames:
			if !ok {
				c.t.Fatal("connection closed while waiting for a match")
			}
			if pred(msg) {
				return msg
			}
		case <-deadline:
			c.t.Fatal("timeout waiting for a matching frame")
			return nil
		}
	}
}

func (c *testClient) expectNo(pred func(wire.Message) bool, d time.Duration) {
	c.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case msg, ok := <-c.frames:
			if !ok {
				return
			}
			if pred(msg) {
				c.t.Fatalf("unexpected frame: %#v", msg)
			}
		case <-deadline:
			return
		}
	}
}

func (c *testClient) expectClosed(timeout time.Duration) {
	c.t.Helper()
	select {
	case <-c.frames:
		// Drain until the reader closes the channel.
		for range c.frames {
		}
	case <-time.After(timeout):
		c.t.Fatal("connection stayed open")
	}
}

func mustKey(t *testing.T) string {
	t.Helper()
	return strings.Repeat("a", 64)
}

func signedEnvelope(t *testing.T, seedByte byte, recipient string, ts int64,
	text string) *wire.Envelope {
	t.Helper()
	seed := strings.Repeat(string([]byte{seedByte}), 32)
	rawSeed, err := hex.DecodeString(hex.EncodeToString([]byte(seed)))
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(rawSeed)
	sender := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	ciphertext := base64.StdEncoding.EncodeToString([]byte(text))
	sum := sha256.Sum256([]byte(sender + recipient + ciphertext +
		strconv.FormatInt(ts, 10)))
	env := &wire.Envelope{
		ID:              hex.EncodeToString(sum[:]),
		SenderPubKey:    sender,
		RecipientPubKey: recipient,
		Timestamp:       ts,
		Ciphertext:      ciphertext,
		EphemeralPubKey: strings.Repeat("b", 64),
		ChainLink:       "",
	}
	env.Signature = hex.EncodeToString(ed25519.Sign(priv, env.SignedData()))
	return env
}

func tamper(t *testing.T, env *wire.Envelope, mutate func(*wire.Envelope)) *wire.Envelope {
	t.Helper()
	clone := *env
	mutate(&clone)
	return &clone
}

func TestHelloWelcome(t *testing.T) {
	s := startTestServer(t, nil)
	c := dial(t, s)
	c.send(&wire.Hello{MyPeerID: "dev", Capabilities: []string{}})
	msg := c.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	w := msg.(*wire.Welcome)
	if w.Identity != s.id.PubHex() {
		t.Fatalf("identity=%s", w.Identity)
	}
	if w.RetentionSeconds != s.cfg.RetentionMs/1000 {
		t.Fatalf("retention=%d", w.RetentionSeconds)
	}
	if w.MaxEnvelopeSize != limits.MaxFrameBytes {
		t.Fatalf("max=%d", w.MaxEnvelopeSize)
	}
	for _, cap := range []string{limits.CapTracker, limits.CapNet, limits.CapLive} {
		found := false
		for _, got := range w.Capabilities {
			if got == cap {
				found = true
			}
		}
		if !found {
			t.Fatalf("capability %s missing: %v", cap, w.Capabilities)
		}
	}
}

func TestSubscribeBackfillEmpty(t *testing.T) {
	s := startTestServer(t, nil)
	c := dial(t, s)
	c.send(&wire.Hello{MyPeerID: "dev"})
	c.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	c.send(&wire.Subscribe{Since: 0, Keys: []string{mustKey(t)}})
	msg := c.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)
	if e := msg.(*wire.Envelopes); len(e.Envelopes) != 0 {
		t.Fatalf("backfill=%+v", e.Envelopes)
	}
}

func TestPublishBackfillAndDuplicate(t *testing.T) {
	s := startTestServer(t, nil)
	recipient := mustKey(t)
	publisher := dial(t, s)
	publisher.send(&wire.Hello{MyPeerID: "pub"})
	publisher.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)

	env := signedEnvelope(t, 1, recipient, nowMs(), "hello")
	publisher.send(&wire.Publish{Envelope: env})
	ack := publisher.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Published)
		return ok
	}, 2*time.Second).(*wire.Published)
	if !ack.Accepted || ack.ID != env.ID {
		t.Fatalf("ack=%+v", ack)
	}
	publisher.send(&wire.Publish{Envelope: env})
	dup := publisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == env.ID
	}, 2*time.Second).(*wire.Published)
	if dup.Accepted {
		t.Fatal("duplicate accepted")
	}

	subscriber := dial(t, s)
	subscriber.send(&wire.Hello{MyPeerID: "sub"})
	subscriber.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	subscriber.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	batch := subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, got := range e.Envelopes {
			if got.ID == env.ID {
				return true
			}
		}
		return false
	}, 2*time.Second).(*wire.Envelopes)
	if len(batch.Envelopes) != 1 {
		t.Fatalf("batch=%+v", batch.Envelopes)
	}
}

func TestHostileEnvelopesRejected(t *testing.T) {
	s := startTestServer(t, nil)
	recipient := mustKey(t)
	c := dial(t, s)
	c.send(&wire.Hello{MyPeerID: "evil"})
	c.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	base := signedEnvelope(t, 2, recipient, nowMs(), "x")

	cases := []*wire.Envelope{
		tamper(t, base, func(e *wire.Envelope) {
			e.Signature = "00" + e.Signature[2:]
		}),
		tamper(t, base, func(e *wire.Envelope) {
			e.ID = strings.Repeat("d", 64)
		}),
		signedEnvelope(t, 3, recipient, nowMs()+10*60*1000, "future"),
	}
	for _, env := range cases {
		c.send(&wire.Publish{Envelope: env})
		ack := c.waitFor(func(m wire.Message) bool {
			p, ok := m.(*wire.Published)
			return ok && p.ID == env.ID
		}, 2*time.Second).(*wire.Published)
		if ack.Accepted {
			t.Fatalf("hostile envelope accepted: %s", env.ID)
		}
	}
	if s.store.EnvelopeCount() != 0 {
		t.Fatalf("stored=%d", s.store.EnvelopeCount())
	}
}

func TestLiveFanoutAndNoStorage(t *testing.T) {
	s := startTestServer(t, nil)
	recipient := mustKey(t)
	subscriber := dial(t, s)
	subscriber.send(&wire.Hello{MyPeerID: "sub"})
	subscriber.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	subscriber.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)

	publisher := dial(t, s)
	publisher.send(&wire.Hello{MyPeerID: "pub"})
	publisher.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	env := signedEnvelope(t, 4, recipient, nowMs(), "slice")
	publisher.send(&wire.PublishLive{Envelope: env})
	ack := publisher.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Published)
		return ok
	}, 2*time.Second).(*wire.Published)
	if !ack.Accepted {
		t.Fatal("live slice with a subscriber not acknowledged")
	}
	got := subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, candidate := range e.Envelopes {
			if candidate.ID == env.ID {
				return true
			}
		}
		return false
	}, 2*time.Second).(*wire.Envelopes)
	if got.Hops != 0 {
		t.Fatalf("hops=%d", got.Hops)
	}
	if s.store.EnvelopeCount() != 0 {
		t.Fatal("live slice was stored")
	}

	// No subscriber: not acknowledged, so the sender keeps retrying.
	lonely := signedEnvelope(t, 5, strings.Repeat("f", 64), nowMs(), "nobody")
	publisher.send(&wire.PublishLive{Envelope: lonely})
	ack = publisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == lonely.ID
	}, 2*time.Second).(*wire.Published)
	if ack.Accepted {
		t.Fatal("live slice acknowledged with no subscriber")
	}
}

func TestGetEntitlement(t *testing.T) {
	s := startTestServer(t, nil)
	recipient := mustKey(t)
	env := signedEnvelope(t, 6, recipient, nowMs(), "secret")
	if !s.acceptEnvelope(env, "publish", 0) {
		t.Fatal("setup publish rejected")
	}

	stranger := dial(t, s)
	stranger.send(&wire.Hello{MyPeerID: "stranger"})
	stranger.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	stranger.send(&wire.Get{IDs: []string{env.ID}})
	answer := stranger.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Envelopes)
		return ok
	}, 2*time.Second).(*wire.Envelopes)
	if len(answer.Envelopes) != 0 {
		t.Fatal("stranger received an unsubscribed envelope")
	}

	subscriber := dial(t, s)
	subscriber.send(&wire.Hello{MyPeerID: "sub"})
	subscriber.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	subscriber.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, candidate := range e.Envelopes {
			if candidate.ID == env.ID {
				return true
			}
		}
		return false
	}, 2*time.Second)
}

func TestPresenceFeed(t *testing.T) {
	s := startTestServer(t, nil)
	keyA := strings.Repeat("a", 64)
	keyB := strings.Repeat("b", 64)

	first := dial(t, s)
	first.send(&wire.Hello{MyPeerID: "devA", Capabilities: []string{limits.CapPresence}})
	first.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	first.send(&wire.Subscribe{Since: 0, Keys: []string{keyA}})

	second := dial(t, s)
	second.send(&wire.Hello{MyPeerID: "devB", Capabilities: []string{limits.CapPresence}})
	second.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	feed := second.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Presence)
		return ok && contains(p.Online, keyA)
	}, 3*time.Second).(*wire.Presence)
	if contains(feed.Online, keyB) {
		t.Fatal("unsubscribed key listed")
	}

	second.send(&wire.Subscribe{Since: 0, Keys: []string{keyB}})
	updated := first.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Presence)
		return ok && contains(p.Online, keyB)
	}, 3*time.Second).(*wire.Presence)
	if !contains(updated.Online, keyA) {
		t.Fatalf("feed lost keyA: %v", updated.Online)
	}

	_ = first.ws.Close()
	after := second.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Presence)
		return ok && !contains(p.Online, keyA)
	}, 3*time.Second).(*wire.Presence)
	if !contains(after.Online, keyB) {
		t.Fatalf("feed=%v", after.Online)
	}
}

func TestPresenceOnlyForAskCapability(t *testing.T) {
	s := startTestServer(t, nil)
	silent := dial(t, s)
	silent.send(&wire.Hello{MyPeerID: "silent"})
	silent.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)

	watcher := dial(t, s)
	watcher.send(&wire.Hello{MyPeerID: "watch", Capabilities: []string{limits.CapPresence}})
	watcher.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	watcher.send(&wire.Subscribe{Since: 0, Keys: []string{mustKey(t)}})
	watcher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Presence)
		return ok && contains(p.Online, mustKey(t))
	}, 3*time.Second)
	silent.expectNo(func(m wire.Message) bool {
		_, ok := m.(*wire.Presence)
		return ok
	}, 700*time.Millisecond)
}

func TestTrackerPeerList(t *testing.T) {
	s := startTestServer(t, nil)
	recipient := mustKey(t)
	devA := dial(t, s)
	devA.send(&wire.Hello{
		MyPeerID: "devA",
		MyAddrs:  []string{"/ip4/192.168.1.20/tcp/4010"},
	})
	devA.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	devA.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	devA.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)

	devB := dial(t, s)
	devB.send(&wire.Hello{MyPeerID: "devB"})
	devB.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	devB.send(&wire.PeerListRequest{})
	list := devB.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.PeerList)
		return ok
	}, 2*time.Second).(*wire.PeerList)
	if len(list.Peers) != 1 {
		t.Fatalf("peers=%+v", list.Peers)
	}
	peer := list.Peers[0]
	if peer.PeerID != "devA" || peer.XPubKey != recipient ||
		len(peer.Addrs) != 1 || peer.Addrs[0] != "/ip4/192.168.1.20/tcp/4010" {
		t.Fatalf("peer=%+v", peer)
	}
}

func TestHostileFramesDropConnection(t *testing.T) {
	s := startTestServer(t, nil)

	garbage := dial(t, s)
	garbage.sendRaw("this is not json")
	garbage.expectClosed(2 * time.Second)

	unknown := dial(t, s)
	unknown.sendRaw(`{"type":"NOPE"}`)
	unknown.expectClosed(2 * time.Second)

	badKey := dial(t, s)
	badKey.send(&wire.Hello{MyPeerID: "bad"})
	badKey.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	badKey.send(&wire.Subscribe{Since: 0, Keys: []string{"zzz"}})
	badKey.expectClosed(2 * time.Second)

	oversized := dial(t, s)
	if err := oversized.ws.WriteMessage(websocket.TextMessage,
		make([]byte, limits.MaxFrameBytes+1)); err == nil {
		oversized.expectClosed(2 * time.Second)
	}

	manyKeys := dial(t, s)
	manyKeys.send(&wire.Hello{MyPeerID: "many"})
	manyKeys.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	keys := make([]string, limits.MaxHostSubscriptionKeys+1)
	for i := range keys {
		keys[i] = fmt.Sprintf("%064x", i)
	}
	manyKeys.send(&wire.Subscribe{Since: 0, Keys: keys})
	manyKeys.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)
}

func TestConnectionCap(t *testing.T) {
	s := startTestServer(t, func(c *Config) { c.MaxConnections = 2 })
	first := dial(t, s)
	second := dial(t, s)
	first.send(&wire.Hello{MyPeerID: "a"})
	second.send(&wire.Hello{MyPeerID: "b"})
	first.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	second.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)

	_, _, err := websocket.DefaultDialer.Dial(wsURL(s), nil)
	if err == nil {
		t.Fatal("third connection accepted")
	}
}

func TestStatusHealthAndDirectory(t *testing.T) {
	s := startTestServer(t, nil)
	base := fmt.Sprintf("http://127.0.0.1:%d", s.BoundPort())

	get := func(path string) (int, []byte) {
		res, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, body
	}

	code, body := get("/status")
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	var status map[string]any
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ok", "ts", "startedAt", "uptimeSeconds",
		"connections", "connectionsTotal", "federatedLinks", "queue",
		"envelopes", "peers", "subscriptions", "dbBytes",
		"receivedTotal", "relayedTotal", "rejectedTotal", "duplicateTotal",
		"backfillTotal", "liveTotal", "version"} {
		if _, ok := status[key]; !ok {
			t.Errorf("status missing %q", key)
		}
	}
	if strings.Contains(string(body), s.id.PubHex()) {
		t.Fatal("status leaked the identity")
	}
	if strings.Contains(string(body), "127.0.0.1") {
		t.Fatal("status leaked a client address")
	}

	if code, body := get("/healthz"); code != 200 ||
		!strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("healthz=%d %s", code, body)
	}
	if code, _ := get("/nope"); code != 404 {
		t.Fatalf("missing route=%d", code)
	}

	code, body = get("/directory")
	if code != 200 {
		t.Fatalf("directory=%d", code)
	}
	var dir map[string]any
	if err := json.Unmarshal(body, &dir); err != nil {
		t.Fatal(err)
	}
	self := dir["self"].(map[string]any)
	if self["ed25519"] != s.id.PubHex() {
		t.Fatalf("self=%v", self)
	}
	if !strings.HasPrefix(self["addr"].(string), "ws://127.0.0.1:") {
		t.Fatalf("self addr=%v", self["addr"])
	}
}

func TestFederationOffGrantsNothing(t *testing.T) {
	// A listener that would notice an outbound federation dial.
	outbound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := outbound.Accept()
		if err == nil {
			close(accepted)
			conn.Close()
		}
	}()
	seed := wire.HostEndpoint{
		Addr:     fmt.Sprintf("ws://127.0.0.1:%d/ws", outbound.Addr().(*net.TCPAddr).Port),
		EdPubKey: strings.Repeat("e", 64),
	}

	s := startTestServer(t, func(c *Config) {
		c.Federation = false
		c.Seeds = []wire.HostEndpoint{seed}
	})

	recipient := mustKey(t)
	publisher := dial(t, s)
	publisher.send(&wire.Hello{MyPeerID: "pub"})
	publisher.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)

	impostor := dial(t, s)
	impostor.send(&wire.Hello{
		MyPeerID:     strings.Repeat("e", 64),
		Capabilities: []string{limits.CapHost, limits.CapNet},
		Announce:     &seed.Addr,
	})
	impostor.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)

	env := signedEnvelope(t, 7, recipient, nowMs(), "leak")
	publisher.send(&wire.Publish{Envelope: env})
	publisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == env.ID
	}, 2*time.Second)

	impostor.expectNo(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, got := range e.Envelopes {
			if got.ID == env.ID {
				return true
			}
		}
		return false
	}, 500*time.Millisecond)

	impostor.send(&wire.Get{IDs: []string{env.ID}})
	answer := impostor.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Envelopes)
		return ok
	}, 2*time.Second).(*wire.Envelopes)
	if len(answer.Envelopes) != 0 {
		t.Fatal("impostor pulled an envelope")
	}

	impostor.send(&wire.Have{IDs: []string{"x"}})
	impostor.expectNo(func(m wire.Message) bool {
		_, ok := m.(*wire.Get)
		return ok
	}, 300*time.Millisecond)

	select {
	case <-accepted:
		t.Fatal("federation off still dialed the seed")
	case <-time.After(400 * time.Millisecond):
	}
}

func TestFederationLinksRelay(t *testing.T) {
	a := startTestServer(t, func(c *Config) {
		c.Federation = true
		c.AllowInboundFederation = true
	})
	b := startTestServer(t, func(c *Config) {
		c.Federation = true
		c.AllowInboundFederation = true
		c.Seeds = []wire.HostEndpoint{{Addr: a.Announce()}}
	})

	waitLinks := func(s *Server) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if s.linkCount() > 0 {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("federation link did not come up")
	}
	waitLinks(a)
	waitLinks(b)

	recipient := mustKey(t)
	subscriber := dial(t, b)
	subscriber.send(&wire.Hello{MyPeerID: "sub"})
	subscriber.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	subscriber.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 3*time.Second)

	publisher := dial(t, a)
	publisher.send(&wire.Hello{MyPeerID: "pub"})
	publisher.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	env := signedEnvelope(t, 8, recipient, nowMs(), "federated")
	publisher.send(&wire.Publish{Envelope: env})
	ack := publisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == env.ID
	}, 2*time.Second).(*wire.Published)
	if !ack.Accepted {
		t.Fatal("publish on A rejected")
	}
	subscriber.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, got := range e.Envelopes {
			if got.ID == env.ID {
				return true
			}
		}
		return false
	}, 4*time.Second)
}

func TestUpstreamBridge(t *testing.T) {
	seed := startTestServer(t, func(c *Config) {
		c.Federation = false
	})
	edge := startTestServer(t, func(c *Config) {
		c.Federation = true
		c.Seeds = []wire.HostEndpoint{{Addr: seed.Announce()}}
		// A router behind NAT: the internet host cannot dial this address and
		// must not grant the router a federated role. The bridge is a client.
		c.Announce = "ws://192.168.1.1:3100/ws"
	})

	waitUntil(t, func() bool { return edge.linkCount() > 0 },
		3*time.Second, "edge link")

	recipient := mustKey(t)
	local := dial(t, edge)
	local.send(&wire.Hello{MyPeerID: "lan-device"})
	local.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	local.send(&wire.Subscribe{Since: 0, Keys: []string{recipient}})
	local.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)

	waitUntil(t, func() bool { return seed.store.SubscriptionCount() >= 1 },
		3*time.Second, "seed subscription")

	var upstream *client
	for _, c := range edge.clients() {
		if c.isUpstream() {
			upstream = c
			break
		}
	}
	if upstream == nil {
		t.Fatal("edge has no upstream link")
	}
	waitUntil(t, func() bool { return upstream.isSubscribed(recipient) },
		3*time.Second, "upstream subscription snapshot")
	if !edge.entitledTo(upstream,
		signedEnvelope(t, 22, recipient, nowMs(), "subscribed")) {
		t.Fatal("upstream cannot read its subscribed key")
	}
	if edge.entitledTo(upstream,
		signedEnvelope(t, 23, strings.Repeat("e", 64), nowMs(), "other")) {
		t.Fatal("upstream can read an unsubscribed key")
	}

	publisher := dial(t, seed)
	publisher.send(&wire.Hello{MyPeerID: "internet-device"})
	publisher.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	inbound := signedEnvelope(t, 20, recipient, nowMs(), "from the internet")
	publisher.send(&wire.Publish{Envelope: inbound})
	ack := publisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == inbound.ID
	}, 2*time.Second).(*wire.Published)
	if !ack.Accepted {
		t.Fatal("seed rejected the external publish")
	}
	local.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, got := range e.Envelopes {
			if got.ID == inbound.ID {
				return true
			}
		}
		return false
	}, 3*time.Second)
	if edge.store.EnvelopeCount() != 1 {
		t.Fatalf("edge store=%d", edge.store.EnvelopeCount())
	}

	// LAN -> internet: the edge must publish to the seed, and the seed must
	// fan out to its own subscriber.
	externalKey := strings.Repeat("f", 64)
	external := dial(t, seed)
	external.send(&wire.Hello{MyPeerID: "internet-recipient"})
	external.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	external.send(&wire.Subscribe{Since: 0, Keys: []string{externalKey}})
	external.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		return ok && e.Done
	}, 2*time.Second)

	lanPublisher := dial(t, edge)
	lanPublisher.send(&wire.Hello{MyPeerID: "lan-publisher"})
	lanPublisher.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	outbound := signedEnvelope(t, 21, externalKey, nowMs(), "from the LAN")
	lanPublisher.send(&wire.Publish{Envelope: outbound})
	outAck := lanPublisher.waitFor(func(m wire.Message) bool {
		p, ok := m.(*wire.Published)
		return ok && p.ID == outbound.ID
	}, 2*time.Second).(*wire.Published)
	if !outAck.Accepted {
		t.Fatal("edge rejected the LAN publish")
	}
	external.waitFor(func(m wire.Message) bool {
		e, ok := m.(*wire.Envelopes)
		if !ok {
			return false
		}
		for _, got := range e.Envelopes {
			if got.ID == outbound.ID {
				return true
			}
		}
		return false
	}, 3*time.Second)
	if edge.store.EnvelopeCount() != 2 {
		t.Fatalf("edge store=%d", edge.store.EnvelopeCount())
	}
}

func waitUntil(t *testing.T, ok func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestInboundFederationClaimIsRejected(t *testing.T) {
	seedKey := strings.Repeat("a", 64)
	seedAddr := "ws://127.0.0.1:1/ws"

	run := func(t *testing.T, allow bool, announce string) {
		s := startTestServer(t, func(c *Config) {
			c.Federation = true
			c.AllowInboundFederation = allow
			c.Seeds = []wire.HostEndpoint{{Addr: seedAddr, EdPubKey: seedKey}}
		})
		recipient := mustKey(t)
		env := signedEnvelope(t, 30, recipient, nowMs(), "private")
		if !s.acceptEnvelope(env, "publish", 0) {
			t.Fatal("setup publish rejected")
		}
		c := dial(t, s)
		c.send(&wire.Hello{
			MyPeerID:     seedKey,
			Capabilities: []string{limits.CapHost, limits.CapNet},
			Announce:     &announce,
		})
		c.waitFor(func(m wire.Message) bool {
			_, ok := m.(*wire.Welcome)
			return ok
		}, 2*time.Second)
		c.send(&wire.Get{IDs: []string{env.ID}})
		answer := c.waitFor(func(m wire.Message) bool {
			_, ok := m.(*wire.Envelopes)
			return ok
		}, 2*time.Second).(*wire.Envelopes)
		if len(answer.Envelopes) != 0 {
			t.Fatalf("inbound client pulled %d envelopes", len(answer.Envelopes))
		}
	}

	t.Run("inbound federation off by default", func(t *testing.T) {
		run(t, false, seedAddr)
	})
	t.Run("known key alone is not an address proof", func(t *testing.T) {
		run(t, true, "ws://203.0.113.9:3100/ws")
	})
}

func TestWantAnswerStaysWithinGossipCap(t *testing.T) {
	s := startTestServer(t, nil)
	now := nowMs()
	for i := 0; i < limits.MaxGossipItems+20; i++ {
		env := &wire.Envelope{
			ID:              fmt.Sprintf("%064x", i),
			SenderPubKey:    strings.Repeat("a", 64),
			RecipientPubKey: strings.Repeat("b", 64),
			Timestamp:       now - 1000 + int64(i),
			Ciphertext:      "AA==",
			EphemeralPubKey: strings.Repeat("c", 64),
			Signature:       strings.Repeat("d", 128),
		}
		s.store.Insert(env, "publish", 0)
	}
	c := dial(t, s)
	c.send(&wire.Hello{MyPeerID: "want"})
	c.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Welcome)
		return ok
	}, 2*time.Second)
	c.send(&wire.Want{Since: 0})
	have := c.waitFor(func(m wire.Message) bool {
		_, ok := m.(*wire.Have)
		return ok
	}, 2*time.Second).(*wire.Have)
	if len(have.IDs) > limits.MaxGossipItems {
		t.Fatalf("HAVE has %d ids, cap %d", len(have.IDs),
			limits.MaxGossipItems)
	}
}

func TestRateLimit(t *testing.T) {
	s := startTestServer(t, func(c *Config) {
		c.RateLimitPerWindow = 2
		c.RateWindowSeconds = 60
	})
	recipient := mustKey(t)
	c := dial(t, s)
	c.send(&wire.Hello{MyPeerID: "flood"})
	c.waitFor(func(m wire.Message) bool { _, ok := m.(*wire.Welcome); return ok },
		2*time.Second)
	now := nowMs()
	for i := 0; i < 3; i++ {
		env := signedEnvelope(t, 9, recipient, now+int64(i), fmt.Sprintf("m%d", i))
		c.send(&wire.Publish{Envelope: env})
	}
	accepted := 0
	for i := 0; i < 3; i++ {
		ack := c.waitFor(func(m wire.Message) bool {
			_, ok := m.(*wire.Published)
			return ok
		}, 2*time.Second).(*wire.Published)
		if ack.Accepted {
			accepted++
		}
	}
	if accepted != 2 {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestScanWindowStart(t *testing.T) {
	const now = int64(1700000000000)
	if got := scanWindowStart(0, now); got != now-limits.GossipMaxScanWindowMs {
		t.Fatalf("since 0=%d", got)
	}
	if got := scanWindowStart(-5, now); got != 0 {
		t.Fatalf("negative=%d", got)
	}
	if got := scanWindowStart(now-1000, now); got != now-1000 {
		t.Fatalf("recent=%d", got)
	}
	if got := scanWindowStart(now-limits.GossipMaxScanWindowMs-1, now); got !=
		now-limits.GossipMaxScanWindowMs {
		t.Fatalf("old=%d", got)
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
