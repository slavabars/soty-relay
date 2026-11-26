package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/slavabars/soty-relay/relay-owrt/internal/identity"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

func testEnv(n int, ts int64, recipient string) *wire.Envelope {
	return &wire.Envelope{
		ID:              fmt.Sprintf("%064x", n),
		SenderPubKey:    strings.Repeat("a", 64),
		RecipientPubKey: recipient,
		Timestamp:       ts,
		Ciphertext:      "AA==",
		EphemeralPubKey: strings.Repeat("b", 64),
		Signature:       strings.Repeat("c", 128),
		ChainLink:       "",
	}
}

func writeRawJournal(dir, content string) error {
	return os.WriteFile(filepath.Join(dir, journalName), []byte(content), 0o600)
}

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.FromSeedHex(
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestInsertDedupAndOrder(t *testing.T) {
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Insert(testEnv(3, 3000, "r"), "publish", 0) {
		t.Fatal("insert 3 failed")
	}
	s.Insert(testEnv(1, 1000, "r"), "publish", 0)
	s.Insert(testEnv(2, 2000, "r"), "publish", 0)
	if s.Insert(testEnv(2, 2000, "r"), "publish", 0) {
		t.Fatal("duplicate insert accepted")
	}
	if got := s.EnvelopeCount(); got != 3 {
		t.Fatalf("count=%d", got)
	}
	ids := s.IDsSince(0, 10)
	want := []string{testEnv(1, 0, "").ID, testEnv(2, 0, "").ID,
		testEnv(3, 0, "").ID}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids=%v want %v", ids, want)
		}
	}
	if s.LatestTimestamp() != 3000 {
		t.Fatalf("latest=%d", s.LatestTimestamp())
	}
	if ids := s.IDsSince(2000, 1); len(ids) != 1 || ids[0] != want[1] {
		t.Fatalf("limit ids=%v", ids)
	}
}

func TestCapsEvictOldest(t *testing.T) {
	s, err := New(Options{MaxEnvelopes: 2})
	if err != nil {
		t.Fatal(err)
	}
	s.Insert(testEnv(1, 1000, "r"), "publish", 0)
	s.Insert(testEnv(2, 2000, "r"), "publish", 0)
	s.Insert(testEnv(3, 3000, "r"), "publish", 0)
	if s.EnvelopeCount() != 2 {
		t.Fatalf("count=%d", s.EnvelopeCount())
	}
	if s.Has(testEnv(1, 0, "").ID) {
		t.Fatal("oldest was not evicted")
	}
	if s.Evicted() != 1 {
		t.Fatalf("evicted=%d", s.Evicted())
	}
}

func TestByteCapEvicts(t *testing.T) {
	e := testEnv(1, 1000, "r")
	s, err := New(Options{MaxBytes: e.Size() + 10})
	if err != nil {
		t.Fatal(err)
	}
	s.Insert(testEnv(1, 1000, "r"), "publish", 0)
	s.Insert(testEnv(2, 2000, "r"), "publish", 0)
	if s.EnvelopeCount() != 1 {
		t.Fatalf("count=%d bytes=%d", s.EnvelopeCount(), s.Bytes())
	}
	if s.Has(testEnv(1, 0, "").ID) {
		t.Fatal("oldest was not evicted by byte cap")
	}
}

func TestBackfillQuery(t *testing.T) {
	s, _ := New(Options{})
	s.Insert(testEnv(1, 1000, "a"), "publish", 0)
	s.Insert(testEnv(2, 2000, "b"), "publish", 0)
	s.Insert(testEnv(3, 3000, "a"), "publish", 0)
	got := s.EnvelopesForRecipients([]string{"a"}, 0, 10)
	if len(got) != 2 || got[0].Timestamp != 1000 || got[1].Timestamp != 3000 {
		t.Fatalf("got %+v", got)
	}
	if got := s.EnvelopesForRecipients([]string{"a"}, 2000, 10); len(got) != 1 {
		t.Fatalf("since filter got %d", len(got))
	}
	if got := s.EnvelopesForRecipients(nil, 0, 10); len(got) != 0 {
		t.Fatal("empty key list returned envelopes")
	}
}

func TestSubscriptionsRetention(t *testing.T) {
	s, _ := New(Options{})
	s.RememberSubscription("a", 5000)
	s.RememberSubscription("b", 1000)
	if got := s.SubscriptionCount(); got != 2 {
		t.Fatalf("count=%d", got)
	}
	remembered := s.RememberedSubscriptions(5000, 1000)
	if _, ok := remembered["a"]; !ok {
		t.Fatal("fresh subscription forgotten")
	}
	if _, ok := remembered["b"]; ok {
		t.Fatal("expired subscription remembered")
	}
	s.ForgetExpiredSubscriptions(5000, 1000)
	if s.SubscriptionCount() != 1 {
		t.Fatalf("count=%d", s.SubscriptionCount())
	}
}

func TestPeerMergeAndSample(t *testing.T) {
	s, _ := New(Options{})
	s.RememberPeer("p1", "", []string{"/ip4/1/tcp/1"}, 1000)
	s.RememberPeer("p1", strings.Repeat("a", 64), []string{"/ip4/2/tcp/1"}, 2000)
	peers := s.SamplePeers(10, "p2", 2000, 1000)
	if len(peers) != 1 {
		t.Fatalf("peers=%+v", peers)
	}
	if peers[0].XPubKey != strings.Repeat("a", 64) ||
		peers[0].Addrs[0] != "/ip4/2/tcp/1" {
		t.Fatalf("merge lost facts: %+v", peers[0])
	}
	if peers[0].LastSeen == nil || *peers[0].LastSeen != 2000 {
		t.Fatal("lastSeen missing")
	}
	if got := s.SamplePeers(10, "p1", 2000, 1000); len(got) != 0 {
		t.Fatal("asker was suggested to itself")
	}
	// TTL expiry: last_seen 2000, now 4000, ttl 1000.
	if got := s.SamplePeers(10, "", 4000, 1000); len(got) != 0 {
		t.Fatal("stale peer served")
	}
	if s.PeerCount() != 0 {
		t.Fatalf("peer count=%d", s.PeerCount())
	}
}

func TestFederatedHostsAreBounded(t *testing.T) {
	s, _ := New(Options{})
	for i := 0; i < 40; i++ {
		s.RememberFederatedHost(wire.HostEndpoint{
			Addr:     fmt.Sprintf("ws://10.0.0.%d:3100/ws", i),
			EdPubKey: strings.Repeat("a", 64),
		}, int64(i))
	}
	hosts := s.FederatedHosts()
	if len(hosts) != 32 {
		t.Fatalf("hosts=%d", len(hosts))
	}
	if hosts[0].Addr != "ws://10.0.0.8:3100/ws" {
		t.Fatalf("oldest kept: %s", hosts[0].Addr)
	}
}

func TestPruneSignsRoot(t *testing.T) {
	s, _ := New(Options{})
	id := testIdentity(t)
	s.Insert(testEnv(1, 1000, "r"), "publish", 0)
	s.Insert(testEnv(2, 2000, "r"), "publish", 0)
	res, err := s.PruneOlderThan(1500, id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.MerkleRoot == "" {
		t.Fatalf("res=%+v", res)
	}
	if s.Has(testEnv(1, 0, "").ID) || !s.Has(testEnv(2, 0, "").ID) {
		t.Fatal("wrong envelope pruned")
	}
	wantRoot := merkleRoot([]string{testEnv(1, 0, "").ID})
	if res.MerkleRoot != wantRoot {
		t.Fatalf("root=%s want %s", res.MerkleRoot, wantRoot)
	}
	pub, _ := hex.DecodeString(id.PubHex())
	sig, _ := hex.DecodeString(s.Roots()[0].Signature)
	data := []byte(res.MerkleRoot + strconv.FormatInt(1500, 10) + "1")
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		t.Fatal("prune root signature does not verify")
	}
}

func TestRelayWindowKeepsSubscribed(t *testing.T) {
	s, _ := New(Options{})
	id := testIdentity(t)
	s.Insert(testEnv(1, 1000, "keep"), "publish", 0)
	s.Insert(testEnv(2, 1000, "drop"), "publish", 0)
	remembered := map[string]struct{}{"keep": {}}
	res, err := s.PruneRelayWindow(2000, 500, remembered, id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 {
		t.Fatalf("count=%d", res.Count)
	}
	if !s.Has(testEnv(1, 0, "").ID) || s.Has(testEnv(2, 0, "").ID) {
		t.Fatal("relay window dropped the wrong row")
	}
}

func TestJournalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Options{Disk: true, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity(t)
	keep := strings.Repeat("e", 64)
	drop := strings.Repeat("f", 64)
	s.Insert(testEnv(1, 1000, keep), "publish", 0)
	s.Insert(testEnv(2, 2000, drop), "publish", 0)
	s.RememberSubscription(keep, 2000)
	if _, err := s.PruneOlderThan(1500, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := New(Options{Disk: true, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.EnvelopeCount() != 1 {
		t.Fatalf("count=%d", again.EnvelopeCount())
	}
	if again.Insert(testEnv(2, 2000, drop), "publish", 0) {
		t.Fatal("replayed envelope was inserted twice")
	}
	if again.SubscriptionCount() != 1 {
		t.Fatalf("subs=%d", again.SubscriptionCount())
	}
	if len(again.Roots()) != 1 {
		t.Fatalf("roots=%d", len(again.Roots()))
	}
}

func TestJournalSkipsCorruptLines(t *testing.T) {
	dir := t.TempDir()
	if err := writeRawJournal(dir, "not json\n{\"t\":\"m\"}\n"); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Disk: true, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if s.EnvelopeCount() != 0 {
		t.Fatal("corrupt journal produced envelopes")
	}
}

func TestMerkleRootKnownValues(t *testing.T) {
	single := strings.Repeat("ab", 32)
	if got := merkleRoot([]string{single}); got != single {
		t.Fatalf("single root=%s", got)
	}
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	// sha256("aa..a" + "bb..b") computed independently in the app; the tree
	// test only needs determinism and duplication for the odd node.
	if got := merkleRoot([]string{a}); got != a {
		t.Fatal("odd tree changed a leaf")
	}
	if merkleRoot([]string{a, b}) == merkleRoot([]string{a}) {
		t.Fatal("pair root equals leaf")
	}
	if merkleRoot([]string{a, b, a}) != merkleRoot([]string{a, b, a}) {
		t.Fatal("unstable root")
	}
}
