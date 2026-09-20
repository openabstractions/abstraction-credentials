//go:build linux

package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

func TestFileBackend(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	backend, err := NewFileBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode: %v %v", st.Mode(), err)
	}
	key := "openabstractions/1000/hf/1-00"
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := backend.Put(key, []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	item := backend.(fileBackend).path(key)
	if st, err := os.Lstat(item); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("item mode: %v %v", st.Mode(), err)
	}
	if got, err := backend.Get(key); err != nil || string(got) != testSecret {
		t.Fatalf("read back: %v", err)
	}
	os.Chmod(item, 0o644)
	if _, err := backend.Get(key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("widened permissions: %v", err)
	}
	os.Remove(item)
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("planted"), 0o600)
	if err := os.Symlink(target, item); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Get(key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symbolic link followed: %v", err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatal(err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBackend("relative"); err == nil {
		t.Fatal("relative directory accepted")
	}

	h := open(t, Config{Backend: backend, StatePath: filepath.Join(t.TempDir(), "state.json")})
	if h.Limits().SecureStore != StoreFile {
		t.Fatal(h.Limits())
	}
	stored := h.Store(owner, "", registration("hf"))
	if r := h.Apply(context.Background(), use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Headers["Authorization"] != "Bearer "+testSecret {
		t.Fatalf("apply: %s", r.Outcome)
	}
	if r := h.Revoke(owner, stored.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatal(r)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("revoke left %d files", len(entries))
	}
}
