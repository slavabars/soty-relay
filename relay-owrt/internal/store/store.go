// Package store keeps the relay's opaque envelope backlog. Memory is the
// default because router flash wears out; an append-only journal on USB is
// opt-in. The store never decrypts and never logs ciphertext.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/slavabars/soty-relay/relay-owrt/internal/identity"
	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

// Entry is a stored envelope plus the relay bookkeeping dtm_host keeps in
// the messages table.
type Entry struct {
	Envelope *wire.Envelope
	Source   string
	Hops     int
}

// Peer is one tracker-known device.
type Peer struct {
	PeerID    string
	XPubKey   string
	Addrs     []string
	FirstSeen int64
	LastSeen  int64
}

// Root is one signed prune record, mirroring host.db pruned_roots.
type Root struct {
	CutoffTs   int64
	MerkleRoot string
	Count      int
	DevicePub  string
	Signature  string
}

// PruneResult reports what one prune removed.
type PruneResult struct {
	CutoffTs   int64
	Count      int
	MerkleRoot string
}

// Options configure a Store. Disk turns on the append-only journal in Dir.
type Options struct {
	Disk         bool
	Dir          string
	MaxEnvelopes int
	MaxBytes     int
}

type hostRecord struct {
	Endpoint  wire.HostEndpoint
	FirstSeen int64
}

// Store is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	byID map[string]*Entry
	all  []*Entry // sorted by (timestamp, id)
	subs map[string]int64
	peer map[string]*Peer
	host map[string]*hostRecord
	root []Root

	bytes     int
	evicted   int64
	maxEnv    int
	maxBytes  int
	journal   *journal
	journalOK bool
}

const maxRoots = 1000

// New opens an empty store, replaying [Options.Dir]/envelopes.ndjson when
// Disk is set. Corrupt journal lines are skipped; an unreadable file is an
// error (the operator must see it rather than silently lose the queue).
func New(opts Options) (*Store, error) {
	if opts.MaxEnvelopes <= 0 {
		opts.MaxEnvelopes = limits.MaxStoredEnvelopes
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = limits.MaxStoredBytes
	}
	s := &Store{
		byID:     make(map[string]*Entry),
		subs:     make(map[string]int64),
		peer:     make(map[string]*Peer),
		host:     make(map[string]*hostRecord),
		maxEnv:   opts.MaxEnvelopes,
		maxBytes: opts.MaxBytes,
	}
	if !opts.Disk {
		return s, nil
	}
	j, records, err := openJournal(opts.Dir)
	if err != nil {
		return nil, err
	}
	s.journal = j
	s.journalOK = true
	for _, rec := range records {
		s.applyRecordLocked(rec)
	}
	if len(s.root) > maxRoots {
		s.root = s.root[len(s.root)-maxRoots:]
	}
	s.enforceCapsLocked()
	s.enforceSubscriptionCapLocked()
	return s, nil
}

func (s *Store) applyRecordLocked(rec journalRecord) {
	switch rec.T {
	case recordEnvelope:
		env := rec.E
		if env == nil || env.Validate() != nil {
			return
		}
		if _, ok := s.byID[env.ID]; ok {
			return
		}
		s.insertLocked(env, rec.S, rec.H)
	case recordSubscription:
		if isHex32(rec.K) {
			s.subs[rec.K] = rec.TS
		}
	case recordRoot:
		s.root = append(s.root, Root{
			CutoffTs:   rec.C,
			MerkleRoot: rec.R,
			Count:      rec.N,
			DevicePub:  rec.Pub,
			Signature:  rec.Sig,
		})
	}
}

// Close flushes the journal and rewrites it from the live state so restart
// replays exactly what the relay held.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil {
		return nil
	}
	if err := s.rewriteJournalLocked(); err != nil {
		_ = s.journal.close()
		return err
	}
	return s.journal.close()
}

// Insert stores an envelope idempotently. A duplicate id returns false.
func (s *Store) Insert(env *wire.Envelope, source string, hops int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[env.ID]; ok {
		return false
	}
	s.insertLocked(env, source, hops)
	s.enforceCapsLocked()
	if s.journal != nil && s.journalOK {
		if err := s.journal.appendEnvelope(env, source, hops); err != nil {
			s.journalOK = false
		}
	}
	return true
}

func (s *Store) insertLocked(env *wire.Envelope, source string, hops int) {
	e := &Entry{Envelope: env, Source: source, Hops: hops}
	idx := sort.Search(len(s.all), func(i int) bool {
		a := s.all[i].Envelope
		if a.Timestamp != env.Timestamp {
			return a.Timestamp > env.Timestamp
		}
		return a.ID > env.ID
	})
	s.all = append(s.all, nil)
	copy(s.all[idx+1:], s.all[idx:])
	s.all[idx] = e
	s.byID[env.ID] = e
	s.bytes += env.Size()
}

// EnvelopeByID returns a copy of the stored envelope, or nil.
func (s *Store) EnvelopeByID(id string) *wire.Envelope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.byID[id]
	if e == nil {
		return nil
	}
	return e.Envelope
}

// Has reports whether the id is stored.
func (s *Store) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id] != nil
}

// IDsSince returns ids with timestamp >= since, oldest first, bounded.
func (s *Store) IDsSince(since int64, limit int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx := sort.Search(len(s.all), func(i int) bool {
		return s.all[i].Envelope.Timestamp >= since
	})
	out := make([]string, 0, min(limit, len(s.all)-idx))
	for _, e := range s.all[idx:] {
		if len(out) >= limit {
			break
		}
		out = append(out, e.Envelope.ID)
	}
	return out
}

// EnvelopesForRecipients returns envelopes for any of keys with
// timestamp >= since, oldest first, bounded.
func (s *Store) EnvelopesForRecipients(keys []string, since int64, limit int) []*wire.Envelope {
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx := sort.Search(len(s.all), func(i int) bool {
		return s.all[i].Envelope.Timestamp >= since
	})
	out := make([]*wire.Envelope, 0, min(limit, len(s.all)-idx))
	for _, e := range s.all[idx:] {
		if len(out) >= limit {
			break
		}
		if _, ok := set[e.Envelope.RecipientPubKey]; ok {
			out = append(out, e.Envelope)
		}
	}
	return out
}

// LatestTimestamp is 0 for an empty store.
func (s *Store) LatestTimestamp() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.all) == 0 {
		return 0
	}
	return s.all[len(s.all)-1].Envelope.Timestamp
}

// RememberSubscription upserts a recipient key and bounds the table.
func (s *Store) RememberSubscription(key string, nowMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[key] = nowMs
	s.enforceSubscriptionCapLocked()
	if s.journal != nil && s.journalOK {
		if err := s.journal.appendSubscription(key, nowMs); err != nil {
			s.journalOK = false
		}
	}
}

func (s *Store) enforceSubscriptionCapLocked() {
	for len(s.subs) > limits.MaxHostSubscriptionRows {
		oldestKey := ""
		oldest := int64(1<<63 - 1)
		for k, ts := range s.subs {
			if ts < oldest {
				oldest = ts
				oldestKey = k
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.subs, oldestKey)
	}
}

// RememberedSubscriptions returns keys seen within retentionMs.
func (s *Store) RememberedSubscriptions(nowMs, retentionMs int64) map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]struct{})
	for k, ts := range s.subs {
		if ts >= nowMs-retentionMs {
			out[k] = struct{}{}
		}
	}
	return out
}

// ForgetExpiredSubscriptions drops keys older than retentionMs.
func (s *Store) ForgetExpiredSubscriptions(nowMs, retentionMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ts := range s.subs {
		if ts < nowMs-retentionMs {
			delete(s.subs, k)
		}
	}
}

// RememberPeer merges tracker facts for peerID. New empty fields keep the
// previous value; firstSeen is preserved.
func (s *Store) RememberPeer(peerID, xPubKey string, addrs []string, nowMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.peer[peerID]
	if p == nil {
		p = &Peer{PeerID: peerID, FirstSeen: nowMs}
		s.peer[peerID] = p
	}
	if xPubKey != "" {
		p.XPubKey = xPubKey
	}
	if len(addrs) > 0 {
		p.Addrs = append([]string(nil), addrs...)
	}
	p.LastSeen = nowMs
	for len(s.peer) > limits.MaxKnownPeers {
		oldestID := ""
		oldest := int64(1<<63 - 1)
		for id, cand := range s.peer {
			if cand.FirstSeen < oldest {
				oldest = cand.FirstSeen
				oldestID = id
			}
		}
		if oldestID == "" {
			return
		}
		delete(s.peer, oldestID)
	}
}

// ForgetStalePeers drops peers not refreshed since cutoffMs.
func (s *Store) ForgetStalePeers(cutoffMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.peer {
		if p.LastSeen < cutoffMs {
			delete(s.peer, id)
		}
	}
}

// SamplePeers returns a random, TTL-bounded set for PEER_LIST.
func (s *Store) SamplePeers(limit int, excludePeerID string, nowMs, ttlMs int64) []wire.PeerRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.peer {
		if p.LastSeen < nowMs-ttlMs {
			delete(s.peer, id)
		}
	}
	candidates := make([]*Peer, 0, len(s.peer))
	for id, p := range s.peer {
		if id == excludePeerID {
			continue
		}
		candidates = append(candidates, p)
	}
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]wire.PeerRef, 0, len(candidates))
	for _, p := range candidates {
		lastSeen := p.LastSeen
		out = append(out, wire.PeerRef{
			XPubKey:  p.XPubKey,
			PeerID:   p.PeerID,
			Addrs:    append([]string(nil), p.Addrs...),
			LastSeen: &lastSeen,
		})
	}
	return out
}

// RememberFederatedHost upserts a network member, evicting the oldest beyond
// the cap (firstSeen order, like dtm_host).
func (s *Store) RememberFederatedHost(ep wire.HostEndpoint, nowMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := nowMs
	if prev, ok := s.host[ep.Addr]; ok {
		first = prev.FirstSeen
	}
	s.host[ep.Addr] = &hostRecord{Endpoint: ep, FirstSeen: first}
	for len(s.host) > limits.MaxFederatedHosts {
		oldestAddr := ""
		oldest := int64(1<<63 - 1)
		for addr, rec := range s.host {
			if rec.FirstSeen < oldest {
				oldest = rec.FirstSeen
				oldestAddr = addr
			}
		}
		if oldestAddr == "" {
			return
		}
		delete(s.host, oldestAddr)
	}
}

// FederatedHosts lists members oldest-first.
func (s *Store) FederatedHosts() []wire.HostEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := make([]*hostRecord, 0, len(s.host))
	for _, rec := range s.host {
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].FirstSeen < recs[j].FirstSeen
	})
	out := make([]wire.HostEndpoint, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.Endpoint)
	}
	return out
}

// PruneOlderThan removes envelopes older than cutoffMs and signs a root.
func (s *Store) PruneOlderThan(cutoffMs int64, id *identity.Identity) (PruneResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := sort.Search(len(s.all), func(i int) bool {
		return s.all[i].Envelope.Timestamp >= cutoffMs
	})
	ids := make([]string, 0, idx)
	for _, e := range s.all[:idx] {
		ids = append(ids, e.Envelope.ID)
	}
	return s.pruneLocked(ids, cutoffMs, id)
}

// PruneRelayWindow removes cache envelopes older than windowMs whose
// recipient is not a remembered subscription, and signs a root.
func (s *Store) PruneRelayWindow(nowMs, windowMs int64, remembered map[string]struct{}, id *identity.Identity) (PruneResult, error) {
	cutoff := nowMs - windowMs
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := sort.Search(len(s.all), func(i int) bool {
		return s.all[i].Envelope.Timestamp >= cutoff
	})
	ids := make([]string, 0, idx)
	for _, e := range s.all[:idx] {
		if _, keep := remembered[e.Envelope.RecipientPubKey]; keep {
			continue
		}
		ids = append(ids, e.Envelope.ID)
	}
	return s.pruneLocked(ids, cutoff, id)
}

func (s *Store) pruneLocked(ids []string, cutoff int64, id *identity.Identity) (PruneResult, error) {
	if len(ids) == 0 {
		return PruneResult{CutoffTs: cutoff}, nil
	}
	root := merkleRoot(ids)
	data := []byte(root + strconv.FormatInt(cutoff, 10) +
		strconv.Itoa(len(ids)))
	sig := id.Sign(data)
	s.root = append(s.root, Root{
		CutoffTs:   cutoff,
		MerkleRoot: root,
		Count:      len(ids),
		DevicePub:  id.PubHex(),
		Signature:  sig,
	})
	if len(s.root) > maxRoots {
		s.root = s.root[len(s.root)-maxRoots:]
	}
	drop := make(map[string]struct{}, len(ids))
	for _, eid := range ids {
		drop[eid] = struct{}{}
	}
	kept := s.all[:0]
	for _, e := range s.all {
		if _, gone := drop[e.Envelope.ID]; gone {
			delete(s.byID, e.Envelope.ID)
			s.bytes -= e.Envelope.Size()
			continue
		}
		kept = append(kept, e)
	}
	s.all = kept
	if err := s.rewriteJournalLocked(); err != nil {
		return PruneResult{}, err
	}
	return PruneResult{CutoffTs: cutoff, Count: len(ids), MerkleRoot: root}, nil
}

// enforceCapsLocked drops the oldest envelopes past the count/byte cap.
// This is a cache bound, not a signed retention promise.
func (s *Store) enforceCapsLocked() {
	for len(s.all) > 0 &&
		(len(s.all) > s.maxEnv || s.bytes > s.maxBytes) {
		e := s.all[0]
		s.all = s.all[1:]
		delete(s.byID, e.Envelope.ID)
		s.bytes -= e.Envelope.Size()
		s.evicted++
	}
}

// Compact rewrites the journal from live state.
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rewriteJournalLocked()
}

func (s *Store) rewriteJournalLocked() error {
	if s.journal == nil {
		return nil
	}
	recs := make([]journalRecord, 0, len(s.all)+len(s.subs)+len(s.root))
	for _, e := range s.all {
		recs = append(recs, journalRecord{
			T: recordEnvelope, E: e.Envelope, S: e.Source, H: e.Hops,
		})
	}
	for k, ts := range s.subs {
		recs = append(recs, journalRecord{T: recordSubscription, K: k, TS: ts})
	}
	for _, r := range s.root {
		recs = append(recs, journalRecord{
			T: recordRoot, C: r.CutoffTs, N: r.Count, R: r.MerkleRoot,
			Pub: r.DevicePub, Sig: r.Signature,
		})
	}
	if err := s.journal.rewrite(recs); err != nil {
		s.journalOK = false
		return err
	}
	s.journalOK = true
	return nil
}

// Counts for /status and the prune log.
func (s *Store) EnvelopeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.all)
}

func (s *Store) Bytes() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bytes
}

func (s *Store) Evicted() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evicted
}

func (s *Store) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peer)
}

func (s *Store) SubscriptionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

func (s *Store) DiskBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.journal == nil {
		return 0
	}
	return s.journal.size()
}

func (s *Store) Roots() []Root {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Root(nil), s.root...)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// merkleRoot is the same tree the app and dtm_host build: nodes are
// sha256(leftHex || rightHex), odd nodes duplicate themselves.
func merkleRoot(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	level := make([]string, len(ids))
	for i, id := range ids {
		level[i] = strings.ToLower(id)
	}
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			sum := sha256.Sum256([]byte(level[i] + right))
			next = append(next, hex.EncodeToString(sum[:]))
		}
		level = next
	}
	return level[0]
}

func isHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
