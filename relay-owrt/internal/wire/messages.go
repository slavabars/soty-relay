package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
)

// Message is one parsed gossip frame. Parsing is strict: a missing or
// mistyped required field, an over-cap list or an unknown type is an error,
// and the relay drops the connection at the boundary. Extra fields are
// ignored, exactly as GossipMessage.fromJson does.
type Message interface{ messageType() string }

type Hello struct {
	MyPeerID     string
	Capabilities []string
	MyAddrs      []string
	Announce     *string
}

type Welcome struct {
	ServerTime       int64
	RetentionSeconds int64
	MaxEnvelopeSize  int64
	Identity         string
	Capabilities     []string
}

type Want struct{ Since int64 }
type Have struct{ IDs []string }
type Get struct{ IDs []string }

type Envelopes struct {
	Envelopes []*Envelope
	Done      bool
	Hops      int
}

type Publish struct{ Envelope *Envelope }
type PublishLive struct{ Envelope *Envelope }

type Published struct {
	ID       string
	Accepted bool
}

type Subscribe struct {
	Since int64
	Keys  []string
}

type PeerListRequest struct{}

type PeerRef struct {
	XPubKey  string   `json:"xPubKey"`
	PeerID   string   `json:"peerId"`
	Addrs    []string `json:"addrs"`
	LastSeen *int64   `json:"lastSeen,omitempty"`
}

type HostEndpoint struct {
	Addr     string
	EdPubKey string
}

type PeerList struct {
	Peers []PeerRef
	Hosts []HostEndpoint
}

type Network struct{ Hosts []HostEndpoint }

type Presence struct {
	Online []string
	At     int64
}

func (*Hello) messageType() string           { return "HELLO" }
func (*Welcome) messageType() string         { return "WELCOME" }
func (*Want) messageType() string            { return "WANT" }
func (*Have) messageType() string            { return "HAVE" }
func (*Get) messageType() string             { return "GET" }
func (*Envelopes) messageType() string       { return "ENVELOPES" }
func (*Publish) messageType() string         { return "PUBLISH" }
func (*PublishLive) messageType() string     { return "PUBLISH_LIVE" }
func (*Published) messageType() string       { return "PUBLISHED" }
func (*Subscribe) messageType() string       { return "SUBSCRIBE" }
func (*PeerListRequest) messageType() string { return "PEER_LIST_REQUEST" }
func (*PeerList) messageType() string        { return "PEER_LIST" }
func (*Network) messageType() string         { return "NETWORK" }
func (*Presence) messageType() string        { return "PRESENCE" }

// Parse decodes one frame. [data] must already be bounded by the caller.
func Parse(data []byte) (Message, error) {
	f, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	typ, err := f.str("type")
	if err != nil {
		return nil, err
	}
	switch typ {
	case "HELLO":
		peerID, err := f.str("myPeerId")
		if err != nil {
			return nil, err
		}
		if peerID == "" || len(peerID) > limits.MaxPeerIDLength {
			return nil, errors.New("HELLO myPeerId is out of bounds")
		}
		caps, err := f.strings("capabilities", limits.MaxCapabilities, nil)
		if err != nil {
			return nil, err
		}
		addrs, err := f.strings("myAddrs", limits.MaxPeerAddrsOnWire,
			func(s string) bool {
				return s != "" && len(s) <= limits.MaxAddrLength &&
					strings.HasPrefix(s, "/")
			})
		if err != nil {
			return nil, err
		}
		announce, _, err := f.optStr("announce")
		if err != nil {
			return nil, err
		}
		var announcePtr *string
		if announce != "" {
			if len(announce) > limits.MaxAddrLength ||
				(!strings.HasPrefix(announce, "ws://") &&
					!strings.HasPrefix(announce, "wss://")) {
				return nil, errors.New("HELLO announce is out of bounds")
			}
			announcePtr = &announce
		}
		return &Hello{
			MyPeerID:     peerID,
			Capabilities: caps,
			MyAddrs:      addrs,
			Announce:     announcePtr,
		}, nil
	case "WELCOME":
		serverTime, err := f.integer("serverTime")
		if err != nil {
			return nil, err
		}
		retention, err := f.integer("retentionSeconds")
		if err != nil {
			return nil, err
		}
		maxEnvelope, err := f.integer("maxEnvelopeSize")
		if err != nil {
			return nil, err
		}
		identity, _, err := f.optStr("identity")
		if err != nil {
			return nil, err
		}
		caps, err := f.strings("capabilities", limits.MaxCapabilities, nil)
		if err != nil {
			return nil, err
		}
		return &Welcome{
			ServerTime:       serverTime,
			RetentionSeconds: retention,
			MaxEnvelopeSize:  maxEnvelope,
			Identity:         identity,
			Capabilities:     caps,
		}, nil
	case "WANT":
		since, _, err := f.optInt("since")
		if err != nil {
			return nil, err
		}
		return &Want{Since: since}, nil
	case "HAVE":
		ids, err := f.strings("ids", limits.MaxGossipItems, nil)
		if err != nil {
			return nil, err
		}
		return &Have{IDs: ids}, nil
	case "GET":
		ids, err := f.strings("ids", limits.MaxGossipItems, nil)
		if err != nil {
			return nil, err
		}
		return &Get{IDs: ids}, nil
	case "ENVELOPES":
		raw, err := f.list("envelopes", limits.MaxGossipItems)
		if err != nil {
			return nil, err
		}
		envelopes := make([]*Envelope, 0, len(raw))
		for _, item := range raw {
			env, err := ParseEnvelope(item)
			if err != nil {
				return nil, err
			}
			envelopes = append(envelopes, env)
		}
		done, _, err := f.optBool("done")
		if err != nil {
			return nil, err
		}
		hops := int(f.optIntClamped("hops", 0, limits.HostGossipMaxHops))
		return &Envelopes{Envelopes: envelopes, Done: done, Hops: hops}, nil
	case "PUBLISH", "PUBLISH_LIVE":
		envelope, err := f.envelope("envelope")
		if err != nil {
			return nil, err
		}
		if typ == "PUBLISH" {
			return &Publish{Envelope: envelope}, nil
		}
		return &PublishLive{Envelope: envelope}, nil
	case "PUBLISHED":
		id, err := f.str("id")
		if err != nil {
			return nil, err
		}
		accepted, _, err := f.optBool("accepted")
		if err != nil {
			return nil, err
		}
		return &Published{ID: id, Accepted: accepted}, nil
	case "SUBSCRIBE":
		since, _, err := f.optInt("since")
		if err != nil {
			return nil, err
		}
		keys, err := f.strings("keys", limits.MaxGossipItems, nil)
		if err != nil {
			return nil, err
		}
		return &Subscribe{Since: since, Keys: keys}, nil
	case "PEER_LIST_REQUEST":
		return &PeerListRequest{}, nil
	case "PEER_LIST":
		peers, err := f.peerRefs("peers")
		if err != nil {
			return nil, err
		}
		hosts, err := f.hostEndpoints("hosts", limits.MaxTrackerHosts)
		if err != nil {
			return nil, err
		}
		return &PeerList{Peers: peers, Hosts: hosts}, nil
	case "NETWORK":
		hosts, err := f.hostEndpoints("hosts", limits.MaxFederatedHosts)
		if err != nil {
			return nil, err
		}
		return &Network{Hosts: hosts}, nil
	case "PRESENCE":
		online, err := f.presenceKeys("online")
		if err != nil {
			return nil, err
		}
		at, err := f.integer("at")
		if err != nil {
			return nil, err
		}
		return &Presence{Online: online, At: at}, nil
	default:
		return nil, fmt.Errorf("unknown gossip message: %q", typ)
	}
}

// Encode serializes one outbound frame. Empty lists are encoded as [] (never
// null) so the Dart parser, which requires a list when the key is present,
// accepts every answer.
func Encode(m Message) ([]byte, error) {
	switch v := m.(type) {
	case *Hello:
		out := map[string]any{
			"type":         "HELLO",
			"myPeerId":     v.MyPeerID,
			"capabilities": nonNil(v.Capabilities),
			"myAddrs":      nonNil(v.MyAddrs),
		}
		if v.Announce != nil {
			out["announce"] = *v.Announce
		}
		return json.Marshal(out)
	case *Welcome:
		return json.Marshal(map[string]any{
			"type":             "WELCOME",
			"serverTime":       v.ServerTime,
			"retentionSeconds": v.RetentionSeconds,
			"maxEnvelopeSize":  v.MaxEnvelopeSize,
			"identity":         v.Identity,
			"capabilities":     nonNil(v.Capabilities),
		})
	case *Want:
		return json.Marshal(map[string]any{"type": "WANT", "since": v.Since})
	case *Have:
		return json.Marshal(map[string]any{
			"type": "HAVE",
			"ids":  nonNil(v.IDs),
		})
	case *Get:
		return json.Marshal(map[string]any{
			"type": "GET",
			"ids":  nonNil(v.IDs),
		})
	case *Envelopes:
		list := make([]*Envelope, 0, len(v.Envelopes))
		list = append(list, v.Envelopes...)
		return json.Marshal(map[string]any{
			"type":      "ENVELOPES",
			"envelopes": list,
			"done":      v.Done,
			"hops":      v.Hops,
		})
	case *Publish:
		return json.Marshal(map[string]any{
			"type":     "PUBLISH",
			"envelope": v.Envelope,
		})
	case *PublishLive:
		return json.Marshal(map[string]any{
			"type":     "PUBLISH_LIVE",
			"envelope": v.Envelope,
		})
	case *Published:
		return json.Marshal(map[string]any{
			"type":     "PUBLISHED",
			"id":       v.ID,
			"accepted": v.Accepted,
		})
	case *Subscribe:
		return json.Marshal(map[string]any{
			"type":  "SUBSCRIBE",
			"since": v.Since,
			"keys":  nonNil(v.Keys),
		})
	case *PeerListRequest:
		return []byte(`{"type":"PEER_LIST_REQUEST"}`), nil
	case *PeerList:
		peers := make([]PeerRef, 0, len(v.Peers))
		for _, p := range v.Peers {
			p.Addrs = nonNil(p.Addrs)
			peers = append(peers, p)
		}
		hosts := make([]map[string]any, 0, len(v.Hosts))
		for _, h := range v.Hosts {
			hosts = append(hosts, hostJSON(h))
		}
		return json.Marshal(map[string]any{
			"type":  "PEER_LIST",
			"peers": peers,
			"hosts": hosts,
		})
	case *Network:
		hosts := make([]map[string]any, 0, len(v.Hosts))
		for _, h := range v.Hosts {
			hosts = append(hosts, hostJSON(h))
		}
		return json.Marshal(map[string]any{
			"type":  "NETWORK",
			"hosts": hosts,
		})
	case *Presence:
		return json.Marshal(map[string]any{
			"type":   "PRESENCE",
			"online": nonNil(v.Online),
			"at":     v.At,
		})
	default:
		return nil, fmt.Errorf("cannot encode %T", m)
	}
}

func hostJSON(h HostEndpoint) map[string]any {
	return map[string]any{"addr": h.Addr, "edPubKey": h.EdPubKey}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return make([]T, 0)
	}
	return s
}

// fields gives strict access to the top-level object. Every helper rejects a
// mistyped value; absent and JSON null mean "not set", as in the app parser.
type fields map[string]json.RawMessage

func decodeObject(data []byte) (fields, error) {
	var f fields
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errors.New("frame is not a JSON object")
	}
	return f, nil
}

func (f fields) str(key string) (string, error) {
	raw, ok := f[key]
	if !ok {
		return "", fmt.Errorf("field %q is missing", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("field %q is mistyped", key)
	}
	return s, nil
}

func (f fields) optStr(key string) (string, bool, error) {
	raw, ok := f[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fmt.Errorf("field %q is mistyped", key)
	}
	return s, true, nil
}

func (f fields) integer(key string) (int64, error) {
	raw, ok := f[key]
	if !ok {
		return 0, fmt.Errorf("field %q is missing", key)
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("field %q is mistyped", key)
	}
	return n, nil
}

func (f fields) optInt(key string) (int64, bool, error) {
	raw, ok := f[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return 0, false, nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fmt.Errorf("field %q is mistyped", key)
	}
	return n, true, nil
}

func (f fields) optIntClamped(key string, min, max int64) int64 {
	raw, ok := f[key]
	if !ok {
		return min
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return min
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func (f fields) optBool(key string) (bool, bool, error) {
	raw, ok := f[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return false, false, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, false, fmt.Errorf("field %q is mistyped", key)
	}
	return b, true, nil
}

func (f fields) list(key string, cap int) ([]json.RawMessage, error) {
	raw, ok := f[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("field %q is not a list", key)
	}
	if len(list) > cap {
		return nil, fmt.Errorf("field %q has too many items", key)
	}
	return list, nil
}

func (f fields) strings(key string, cap int, valid func(string) bool) ([]string, error) {
	list, err := f.list(key, cap)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		var s string
		if err := json.Unmarshal(item, &s); err != nil {
			return nil, fmt.Errorf("field %q item is not a string", key)
		}
		if valid != nil && !valid(s) {
			return nil, fmt.Errorf("field %q item is out of bounds", key)
		}
		out = append(out, s)
	}
	return out, nil
}

func (f fields) envelope(key string) (*Envelope, error) {
	raw, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("field %q is missing", key)
	}
	return ParseEnvelope(raw)
}

func (f fields) peerRefs(key string) ([]PeerRef, error) {
	list, err := f.list(key, limits.MaxTrackerPeers)
	if err != nil {
		return nil, err
	}
	out := make([]PeerRef, 0, len(list))
	for _, item := range list {
		ref, ok := parsePeerRef(item)
		if ok {
			out = append(out, ref)
		}
	}
	return out, nil
}

func parsePeerRef(raw json.RawMessage) (PeerRef, bool) {
	var f fields
	if err := json.Unmarshal(raw, &f); err != nil || f == nil {
		return PeerRef{}, false
	}
	xPubKey, err := f.str("xPubKey")
	if err != nil || !isHexOfLength(xPubKey, 32) {
		return PeerRef{}, false
	}
	peerID, err := f.str("peerId")
	if err != nil || peerID == "" || len(peerID) > limits.MaxPeerIDLength {
		return PeerRef{}, false
	}
	addrs, err := f.strings("addrs", limits.MaxPeerAddrsOnWire,
		func(s string) bool {
			return s != "" && len(s) <= limits.MaxAddrLength &&
				strings.HasPrefix(s, "/")
		})
	if err != nil {
		return PeerRef{}, false
	}
	lastSeen, has, err := f.optInt("lastSeen")
	if err != nil {
		return PeerRef{}, false
	}
	var lastSeenPtr *int64
	if has {
		if lastSeen < 0 || lastSeen > limits.MaxReasonableTimestamp {
			return PeerRef{}, false
		}
		lastSeenPtr = &lastSeen
	}
	return PeerRef{
		XPubKey:  xPubKey,
		PeerID:   peerID,
		Addrs:    addrs,
		LastSeen: lastSeenPtr,
	}, true
}

func (f fields) hostEndpoints(key string, cap int) ([]HostEndpoint, error) {
	list, err := f.list(key, cap)
	if err != nil {
		return nil, err
	}
	out := make([]HostEndpoint, 0, len(list))
	for _, item := range list {
		ep, ok := ParseHostEndpoint(item)
		if ok {
			out = append(out, ep)
		}
	}
	return out, nil
}

// ParseHostEndpoint validates one {addr, edPubKey} entry. Corrupt entries are
// dropped, never fatal: a messy tracker answer must not kill a connection.
func ParseHostEndpoint(raw json.RawMessage) (HostEndpoint, bool) {
	var f fields
	if err := json.Unmarshal(raw, &f); err != nil || f == nil {
		return HostEndpoint{}, false
	}
	addr, err := f.str("addr")
	if err != nil || !ValidRelayAddr(addr) {
		return HostEndpoint{}, false
	}
	pub, _, err := f.optStr("edPubKey")
	if err != nil {
		return HostEndpoint{}, false
	}
	if pub != "" && !isHexOfLength(pub, 32) {
		return HostEndpoint{}, false
	}
	return HostEndpoint{Addr: addr, EdPubKey: pub}, true
}

// ValidRelayAddr accepts a bounded ws:// or wss:// URL with a host. The
// hardened-build policy (refusing ws://) belongs to the client, not the relay:
// a LAN router relay is plain ws:// by design.
func ValidRelayAddr(addr string) bool {
	if addr == "" || len(addr) > limits.MaxAddrLength {
		return false
	}
	if !strings.HasPrefix(addr, "ws://") && !strings.HasPrefix(addr, "wss://") {
		return false
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(addr, "ws://"), "wss://")
	host := rest
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	return host != ""
}

func (f fields) presenceKeys(key string) ([]string, error) {
	list, err := f.list(key, limits.MaxPresenceKeys)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		var s string
		if err := json.Unmarshal(item, &s); err != nil {
			continue
		}
		if isHexOfLength(s, 32) {
			out = append(out, s)
		}
	}
	return out, nil
}
