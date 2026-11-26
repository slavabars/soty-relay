// Package identity owns the relay's Ed25519 key. The seed is the single
// secret this process keeps: clients pin the public key, and losing it means
// every pinned client reports IDENTITY CHANGED. It signs prune roots only;
// it never touches an envelope's payload.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const seedBytes = ed25519.SeedSize

// Identity is a loaded Ed25519 key pair plus its canonical hex forms.
type Identity struct {
	private ed25519.PrivateKey
	seedHex string
	pubHex  string
}

// FromSeedHex builds an identity from the 64-character seed written by
// dtm_host (`host_state.ed_seed`) or by [LoadOrCreate].
func FromSeedHex(seedHex string) (*Identity, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil || len(raw) != seedBytes {
		return nil, errors.New("identity seed must be 32 bytes of hex")
	}
	return newFromSeed(raw), nil
}

// Generate returns a fresh random identity. Tests use it instead of carrying a
// fixed seed in the published source.
func Generate() (*Identity, error) {
	seed := make([]byte, seedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return newFromSeed(seed), nil
}

func newFromSeed(raw []byte) *Identity {
	priv := ed25519.NewKeyFromSeed(raw)
	return &Identity{
		private: priv,
		seedHex: hex.EncodeToString(raw),
		pubHex:  hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}
}

// LoadOrCreate reads [path] or creates it with a fresh seed. The directory is
// created 0700 and the file 0600. An existing but malformed file is a hard
// error: silently regenerating it would break every client that pinned the
// relay.
func LoadOrCreate(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		id, err := FromSeedHex(string(data))
		if err != nil {
			return nil, fmt.Errorf("identity file %s: %w", path, err)
		}
		return id, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	id, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(id.seedHex+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write identity: %w", err)
	}
	return id, nil
}

// PubHex is the 32-byte public key as lowercase hex; it is the relay
// identity clients pin.
func (i *Identity) PubHex() string { return i.pubHex }

// Sign returns the hex Ed25519 signature over data.
func (i *Identity) Sign(data []byte) string {
	return hex.EncodeToString(ed25519.Sign(i.private, data))
}
