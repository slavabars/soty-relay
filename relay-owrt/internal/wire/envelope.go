package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/slavabars/soty-relay/relay-owrt/internal/limits"
)

// Envelope is the opaque, end-to-end encrypted wire unit. A relay verifies
// the signature and content id but can never decrypt [Ciphertext]. The JSON
// field names must match app-src/lib/models/envelope.dart exactly.
type Envelope struct {
	ID              string `json:"id"`
	SenderPubKey    string `json:"senderPubKey"`
	RecipientPubKey string `json:"recipientPubKey"`
	Timestamp       int64  `json:"timestamp"`
	Ciphertext      string `json:"ciphertext"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
	Signature       string `json:"signature"`
	ChainLink       string `json:"chainLink"`
}

var errEnvelopeField = errors.New("envelope field is missing or mistyped")

// ParseEnvelope parses one envelope object from raw JSON. Missing or
// mistyped fields and invalid key/signature encodings are rejected before
// any crypto work runs, mirroring Envelope.fromJson in the app.
func ParseEnvelope(raw json.RawMessage) (*Envelope, error) {
	var f struct {
		ID              *string `json:"id"`
		SenderPubKey    *string `json:"senderPubKey"`
		RecipientPubKey *string `json:"recipientPubKey"`
		Timestamp       *int64  `json:"timestamp"`
		Ciphertext      *string `json:"ciphertext"`
		EphemeralPubKey *string `json:"ephemeralPubKey"`
		Signature       *string `json:"signature"`
		ChainLink       *string `json:"chainLink"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&f); err != nil {
		return nil, errEnvelopeField
	}
	if f.ID == nil || f.SenderPubKey == nil || f.RecipientPubKey == nil ||
		f.Timestamp == nil || f.Ciphertext == nil || f.EphemeralPubKey == nil ||
		f.Signature == nil || f.ChainLink == nil {
		return nil, errEnvelopeField
	}
	e := &Envelope{
		ID:              *f.ID,
		SenderPubKey:    *f.SenderPubKey,
		RecipientPubKey: *f.RecipientPubKey,
		Timestamp:       *f.Timestamp,
		Ciphertext:      *f.Ciphertext,
		EphemeralPubKey: *f.EphemeralPubKey,
		Signature:       *f.Signature,
		ChainLink:       *f.ChainLink,
	}
	if !isHexOfLength(e.ID, 32) || !isHexOfLength(e.SenderPubKey, 32) ||
		!isHexOfLength(e.RecipientPubKey, 32) ||
		!isHexOfLength(e.EphemeralPubKey, 32) ||
		!isHexOfLength(e.Signature, 64) || e.Ciphertext == "" ||
		(e.ChainLink != "" && !isHexOfLength(e.ChainLink, 32)) {
		return nil, errors.New("envelope field format is invalid")
	}
	return e, nil
}

// SignedData is the exact byte string covered by [Signature]:
// id || timestamp(decimal) || ciphertext || chainLink.
func (e *Envelope) SignedData() []byte {
	return []byte(e.ID + strconv.FormatInt(e.Timestamp, 10) +
		e.Ciphertext + e.ChainLink)
}

// Verify checks the sender's Ed25519 signature over [SignedData].
func (e *Envelope) Verify() bool {
	pub, err := hex.DecodeString(e.SenderPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), e.SignedData(), sig)
}

// HasValidID recomputes the content address and compares it with [ID].
// The digest input is sender || recipient || ciphertext || timestamp || link,
// the same concatenation Envelope.computeId uses.
func (e *Envelope) HasValidID() bool {
	h := sha256.New()
	h.Write([]byte(e.SenderPubKey))
	h.Write([]byte(e.RecipientPubKey))
	h.Write([]byte(e.Ciphertext))
	h.Write([]byte(strconv.FormatInt(e.Timestamp, 10)))
	h.Write([]byte(e.ChainLink))
	return hex.EncodeToString(h.Sum(nil)) == e.ID
}

// WithinSkew rejects envelopes stamped too far into the future. Old
// timestamps are allowed (backfill), exactly as Envelope.withinSkew.
func (e *Envelope) WithinSkew(nowMs int64) bool {
	return e.Timestamp <= nowMs+limits.MaxFutureSkewMs
}

// Size is a conservative byte cost for the RAM cap: field bytes plus struct
// and map overhead. Only used for [Store] accounting, never on the wire.
func (e *Envelope) Size() int {
	const overhead = 96
	return overhead + len(e.ID) + len(e.SenderPubKey) + len(e.RecipientPubKey) +
		len(e.Ciphertext) + len(e.EphemeralPubKey) + len(e.Signature) +
		len(e.ChainLink)
}

// Validate checks protocol-independent invariants a stored envelope must
// keep when it is replayed from a journal.
func (e *Envelope) Validate() error {
	if !isHexOfLength(e.ID, 32) || !isHexOfLength(e.SenderPubKey, 32) ||
		!isHexOfLength(e.RecipientPubKey, 32) ||
		!isHexOfLength(e.EphemeralPubKey, 32) ||
		!isHexOfLength(e.Signature, 64) || e.Ciphertext == "" ||
		(e.ChainLink != "" && !isHexOfLength(e.ChainLink, 32)) {
		return fmt.Errorf("invalid envelope %q", firstN(e.ID, 8))
	}
	return nil
}

const maxFutureSkewMs int64 = 5 * 60 * 1000

func isHexOfLength(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
