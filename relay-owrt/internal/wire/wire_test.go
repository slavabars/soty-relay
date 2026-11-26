package wire

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
)

// The vector in testdata/vector.json is produced by the app's own
// Envelope.computeId and Ed25519 signing (host/tool/gen_wire_vector.dart).
// If these tests fail after a wire change, the relay is no longer compatible
// with a real client; do not "fix" the fixture.
func loadVector(t *testing.T) (env *Envelope) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEnvelope(v.Envelope)
	if err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return parsed
}

func TestEnvelopeVectorMatchesDart(t *testing.T) {
	env := loadVector(t)
	if !env.Verify() {
		t.Fatal("Dart-signed envelope did not verify in Go")
	}
	if !env.HasValidID() {
		t.Fatal("Dart-computed id did not match the Go digest")
	}
	if !env.WithinSkew(env.Timestamp + 1) {
		t.Fatal("envelope rejected inside the skew window")
	}
	if env.WithinSkew(env.Timestamp - limits.MaxFutureSkewMs - 1) {
		t.Fatal("envelope accepted beyond the future skew")
	}
}

func TestEnvelopeTamperingIsRejected(t *testing.T) {
	base := loadVector(t)
	cases := []struct {
		name   string
		mutate func(*Envelope)
	}{
		{"signature", func(e *Envelope) {
			e.Signature = "00" + e.Signature[2:]
		}},
		{"id", func(e *Envelope) {
			e.ID = strings.Repeat("d", 64)
		}},
		{"timestamp", func(e *Envelope) {
			e.Timestamp++
		}},
		{"ciphertext", func(e *Envelope) {
			e.Ciphertext = e.Ciphertext + "AA=="
		}},
		{"chainLink", func(e *Envelope) {
			e.ChainLink = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := *base
			tc.mutate(&e)
			if e.Verify() && e.HasValidID() {
				t.Fatal("tampered envelope passed both checks")
			}
		})
	}
}

func TestParseEnvelopeStrictness(t *testing.T) {
	env := loadVector(t)
	good, _ := json.Marshal(env)
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	drop := func(key string) {
		delete(m, key)
	}
	corrupt := func(key string, value any) {
		m[key] = value
	}

	drop("id")
	if _, err := json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	if _, err := ParseEnvelope(raw); err == nil {
		t.Fatal("missing id accepted")
	}
	// Rebuild for the remaining cases.
	_ = json.Unmarshal(good, &m)
	corrupt("signature", "zz")
	raw, _ = json.Marshal(m)
	if _, err := ParseEnvelope(raw); err == nil {
		t.Fatal("non-hex signature accepted")
	}
	_ = json.Unmarshal(good, &m)
	corrupt("timestamp", "1700000000000")
	raw, _ = json.Marshal(m)
	if _, err := ParseEnvelope(raw); err == nil {
		t.Fatal("string timestamp accepted")
	}
	_ = json.Unmarshal(good, &m)
	corrupt("ciphertext", "")
	raw, _ = json.Marshal(m)
	if _, err := ParseEnvelope(raw); err == nil {
		t.Fatal("empty ciphertext accepted")
	}
}

func TestParseHello(t *testing.T) {
	msg, err := Parse([]byte(`{"type":"HELLO","myPeerId":"peer",` +
		`"capabilities":["dtm-presence"],"myAddrs":["/ip4/1.2.3.4/tcp/1"],` +
		`"announce":"ws://router.lan:3100/ws"}`))
	if err != nil {
		t.Fatal(err)
	}
	h, ok := msg.(*Hello)
	if !ok {
		t.Fatalf("got %T", msg)
	}
	if h.MyPeerID != "peer" || h.Announce == nil ||
		*h.Announce != "ws://router.lan:3100/ws" {
		t.Fatalf("unexpected hello: %+v", h)
	}

	for name, frame := range map[string]string{
		"missing peer":   `{"type":"HELLO"}`,
		"numeric peer":   `{"type":"HELLO","myPeerId":7}`,
		"bad addr":       `{"type":"HELLO","myPeerId":"p","myAddrs":["1.2.3.4"]}`,
		"empty addr":     `{"type":"HELLO","myPeerId":"p","myAddrs":[""]}`,
		"too many addrs": `{"type":"HELLO","myPeerId":"p","myAddrs":["/1","/2","/3","/4","/5","/6","/7","/8","/9"]}`,
		"bad announce":   `{"type":"HELLO","myPeerId":"p","announce":"http://x"}`,
		"long peer":      `{"type":"HELLO","myPeerId":"` + strings.Repeat("p", limits.MaxPeerIDLength+1) + `"}`,
	} {
		if _, err := Parse([]byte(frame)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseStrictFields(t *testing.T) {
	for name, frame := range map[string]string{
		"not object":     `[]`,
		"missing type":   `{"myPeerId":"p"}`,
		"unknown type":   `{"type":"NOPE"}`,
		"welcome int":    `{"type":"WELCOME","serverTime":"x","retentionSeconds":1,"maxEnvelopeSize":1}`,
		"subscribe keys": `{"type":"SUBSCRIBE","since":0,"keys":[1]}`,
		"subscribe list": `{"type":"SUBSCRIBE","since":0,"keys":"x"}`,
		"published bool": `{"type":"PUBLISHED","id":"x","accepted":"yes"}`,
		"presence at":    `{"type":"PRESENCE","online":[],"at":"now"}`,
		"envelopes done": `{"type":"ENVELOPES","envelopes":[],"done":1}`,
		"too many caps":  `{"type":"WELCOME","serverTime":1,"retentionSeconds":1,"maxEnvelopeSize":1,"capabilities":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}`,
	} {
		if _, err := Parse([]byte(frame)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// 17 capabilities is over maxCapabilities; 16 is fine.
	hello16 := `{"type":"HELLO","myPeerId":"p","capabilities":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"]}`
	if _, err := Parse([]byte(hello16)); err != nil {
		t.Fatalf("16 capabilities rejected: %v", err)
	}
}

func TestListCaps(t *testing.T) {
	tooManyKeys := make([]string, limits.MaxGossipItems+1)
	for i := range tooManyKeys {
		tooManyKeys[i] = "k"
	}
	raw, _ := json.Marshal(map[string]any{
		"type": "SUBSCRIBE", "since": 0, "keys": tooManyKeys,
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("257 keys accepted")
	}

	tooManyEnvelopes := make([]any, limits.MaxGossipItems+1)
	raw, _ = json.Marshal(map[string]any{
		"type": "ENVELOPES", "envelopes": tooManyEnvelopes,
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("257 envelopes accepted")
	}

	tooManyPeers := make([]any, limits.MaxTrackerPeers+1)
	raw, _ = json.Marshal(map[string]any{
		"type": "PEER_LIST", "peers": tooManyPeers,
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("65 peers accepted")
	}

	tooManyHosts := make([]any, limits.MaxFederatedHosts+1)
	raw, _ = json.Marshal(map[string]any{
		"type": "NETWORK", "hosts": tooManyHosts,
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("33 hosts accepted")
	}
}

func TestHopsAreClamped(t *testing.T) {
	for name, tc := range map[string]struct {
		json string
		want int
	}{
		"missing":  {`{"type":"ENVELOPES","envelopes":[]}`, 0},
		"string":   {`{"type":"ENVELOPES","envelopes":[],"hops":"x"}`, 0},
		"negative": {`{"type":"ENVELOPES","envelopes":[],"hops":-5}`, 0},
		"huge":     {`{"type":"ENVELOPES","envelopes":[],"hops":99}`, limits.HostGossipMaxHops},
		"two":      {`{"type":"ENVELOPES","envelopes":[],"hops":2}`, 2},
	} {
		msg, err := Parse([]byte(tc.json))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		envs := msg.(*Envelopes)
		if envs.Hops != tc.want {
			t.Errorf("%s: hops=%d want %d", name, envs.Hops, tc.want)
		}
	}
}

func TestPresenceKeysAreFiltered(t *testing.T) {
	msg, err := Parse([]byte(`{"type":"PRESENCE","at":1,"online":[` +
		`"` + strings.Repeat("a", 64) + `","bad","` +
		strings.Repeat("B", 64) + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	p := msg.(*Presence)
	if len(p.Online) != 2 {
		t.Fatalf("online=%v", p.Online)
	}
	tooMany := make([]string, limits.MaxPresenceKeys+1)
	raw, _ := json.Marshal(map[string]any{
		"type": "PRESENCE", "at": 1, "online": tooMany,
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("65 presence keys accepted")
	}
}

func TestPeerRefsDropCorruptEntries(t *testing.T) {
	valid := strings.Repeat("a", 64)
	frame := `{"type":"PEER_LIST","peers":[` +
		`{"xPubKey":"` + valid + `","peerId":"p1","addrs":["/ip4/1/tcp/1"]},` +
		`{"xPubKey":"nope","peerId":"p2"},` +
		`{"xPubKey":"` + valid + `","peerId":""},` +
		`{"xPubKey":"` + valid + `","peerId":"p4","addrs":["nope"]},` +
		`"not an object"` +
		`],"hosts":[{"addr":"ws://ok/ws","edPubKey":"` + valid + `"},` +
		`{"addr":"http://bad","edPubKey":""}]}`
	msg, err := Parse([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	pl := msg.(*PeerList)
	if len(pl.Peers) != 1 || pl.Peers[0].PeerID != "p1" {
		t.Fatalf("peers=%+v", pl.Peers)
	}
	if len(pl.Hosts) != 1 || pl.Hosts[0].Addr != "ws://ok/ws" {
		t.Fatalf("hosts=%+v", pl.Hosts)
	}
}

func TestValidRelayAddr(t *testing.T) {
	for _, ok := range []string{
		"ws://router:3100/ws", "wss://soty.su/soty-ws",
		"ws://192.168.1.1/ws", "ws://[::1]:3100/ws",
	} {
		if !ValidRelayAddr(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{
		"", "router:3100", "http://router/ws", "ws://", "ws:///ws",
		"ws://" + strings.Repeat("a", limits.MaxAddrLength),
	} {
		if ValidRelayAddr(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEncodeShape(t *testing.T) {
	raw, err := Encode(&Welcome{
		ServerTime: 1, RetentionSeconds: 2, MaxEnvelopeSize: 3,
		Identity: "id", Capabilities: []string{"dtm-tracker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var w map[string]any
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "serverTime", "retentionSeconds",
		"maxEnvelopeSize", "identity", "capabilities"} {
		if _, ok := w[key]; !ok {
			t.Errorf("WELCOME missing %q", key)
		}
	}

	raw, _ = Encode(&Envelopes{})
	want := `"envelopes":[]`
	if !strings.Contains(string(raw), want) {
		t.Errorf("empty envelopes encoded as %s", raw)
	}

	hello := &Hello{MyPeerID: "p", Capabilities: []string{}, MyAddrs: []string{}}
	raw, _ = Encode(hello)
	if strings.Contains(string(raw), "announce") {
		t.Errorf("nil announce must be omitted: %s", raw)
	}
	if !strings.Contains(string(raw), `"capabilities":[]`) {
		t.Errorf("empty capabilities must be []: %s", raw)
	}

	raw, _ = Encode(&PeerList{})
	if !strings.Contains(string(raw), `"peers":[]`) ||
		!strings.Contains(string(raw), `"hosts":[]`) {
		t.Errorf("empty peer list must use []: %s", raw)
	}
}

func TestFuzzParseNeverPanics(t *testing.T) {
	frames := [][]byte{
		[]byte(`null`), []byte(`{}`), []byte(`{"type":null}`),
		[]byte(`{"type":"HELLO","myPeerId":{}}`),
		[]byte(`{"type":"ENVELOPES","envelopes":[null]}`),
		[]byte(`{"type":"PUBLISH","envelope":[]}`),
		[]byte(`{"type":"PUBLISHED","id":null}`),
		[]byte(`{"type":"PEER_LIST","peers":[[]]}`),
		[]byte(strings.Repeat("{", 4096)),
	}
	for _, frame := range frames {
		_, _ = Parse(frame)
	}
}

func TestSkewBoundary(t *testing.T) {
	now := time.Now().UnixMilli()
	e := &Envelope{Timestamp: now + limits.MaxFutureSkewMs}
	if !e.WithinSkew(now) {
		t.Fatal("boundary rejected")
	}
	e.Timestamp++
	if e.WithinSkew(now) {
		t.Fatal("one ms past the boundary accepted")
	}
}
