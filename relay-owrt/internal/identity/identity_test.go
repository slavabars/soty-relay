package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// The seed and public key come from the same vector the wire tests use, so a
// seed written by dtm_host resolves to the same pinned identity here.
const vectorSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const vectorPub = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"

func TestFromSeedHexMatchesDart(t *testing.T) {
	id, err := FromSeedHex(vectorSeed)
	if err != nil {
		t.Fatal(err)
	}
	if id.PubHex() != vectorPub {
		t.Fatalf("pub=%s want %s", id.PubHex(), vectorPub)
	}
	if len(id.Sign([]byte("x"))) != 128 {
		t.Fatal("signature is not 64-byte hex")
	}
}

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "identity")
	id, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.PubHex()) != 64 {
		t.Fatalf("pub=%q", id.PubHex())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	again, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.PubHex() != id.PubHex() {
		t.Fatal("identity changed across reload")
	}
}

func TestInvalidSeedIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, []byte("not-a-seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("malformed identity file accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "not-a-seed\n" {
		t.Fatal("malformed identity was rewritten")
	}
}
