package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromSeedHexRoundTrip(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := FromSeedHex(generated.seedHex)
	if err != nil {
		t.Fatal(err)
	}
	if id.PubHex() != generated.PubHex() {
		t.Fatalf("pub=%s want %s", id.PubHex(), generated.PubHex())
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
