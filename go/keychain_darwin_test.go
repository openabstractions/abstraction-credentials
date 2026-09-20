//go:build darwin && cgo

package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// testKeys lists the keychain item keys under prefix.
func testKeys(t *testing.T, prefix string) []string {
	t.Helper()
	keys, err := keychainKeys(prefix)
	if err != nil {
		t.Fatalf("list keychain items: %v", err)
	}
	return keys
}

// testNamespace is a test-unique store namespace, the first segment of every
// item key. Cleanup deletes every item under it, whatever the test left behind.
func testNamespace(t *testing.T, backend Backend) (namespace, prefix string) {
	t.Helper()
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	namespace = "oa-test-" + hex.EncodeToString(nonce[:])
	prefix = namespace + "/"
	t.Cleanup(func() {
		for _, key := range testKeys(t, prefix) {
			if err := backend.Delete(key); err != nil {
				t.Errorf("cleanup %s: %v", key, err)
			}
		}
		if left := testKeys(t, prefix); len(left) != 0 {
			t.Errorf("cleanup left %d test items", len(left))
		}
	})
	return namespace, prefix
}

// TestKeychainWithoutEntitlementIsUnavailable runs where the test binary has no
// keychain access group entitlement, as every unsigned build: NewKeychain reads
// unavailable, and the store it would have used writes nothing and reads no
// secret.
func TestKeychainWithoutEntitlementIsUnavailable(t *testing.T) {
	_, err := NewKeychain()
	if err == nil {
		t.Skip("this binary is entitled; TestKeychain covers the store")
	}
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "OSStatus -34018") {
		t.Fatalf("NewKeychain: %v", err)
	}
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	key := "oa-test-" + hex.EncodeToString(nonce[:]) + "/account/hf/1-00"
	store := keychain{}
	t.Cleanup(func() { store.Delete(key) })
	if err := store.Put(key, []byte(testSecret)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("put without entitlement: %v", err)
	}
	if got, err := store.Get(key); err == nil || len(got) != 0 {
		t.Fatalf("get without entitlement returned %d bytes, %v", len(got), err)
	}
}

// TestKeychain writes, reads and deletes real generic passwords of the current
// user in a test-unique namespace and removes them all. It needs a binary
// signed with a keychain access group entitlement.
func TestKeychain(t *testing.T) {
	backend, err := NewKeychain()
	if errors.Is(err, ErrUnavailable) {
		t.Skipf("the data protection keychain needs an entitled binary: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	namespace, prefix := testNamespace(t, backend)
	key := prefix + "account/hf/1-00"
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent item: %v", err)
	}
	if err := backend.Put(key, []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	got, err := backend.Get(key)
	if err != nil || string(got) != testSecret {
		t.Fatalf("read back: %v", err)
	}
	if err := backend.Put(key, []byte("replaced")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got, err := backend.Get(key); err != nil || string(got) != "replaced" {
		t.Fatalf("read replaced: %v", err)
	}
	if err := backend.Put(key, make([]byte, keychainMaxSecret+1)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized secret: %v", err)
	}
	if keys := testKeys(t, prefix); len(keys) != 1 || keys[0] != key {
		t.Fatalf("listed keys: %v", keys)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatal(err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted item: %v", err)
	}

	subject := owner
	account := subject.Account
	h := open(t, Config{Backend: backend, Namespace: namespace})
	if l := h.Limits(); l.SecureStore != StoreMacOSKeychain || l.MaxSecretBytes != keychainMaxSecret {
		t.Fatalf("limits: %+v", l)
	}
	stored := h.Store(subject, "", registration("hf"))
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal(stored.Outcome)
	}
	if keys := testKeys(t, prefix); len(keys) != 1 || keys[0] != h.storeKey(account, "hf", stored.Revision) {
		t.Fatalf("stored keys: %v", keys)
	}
	page := h.List(account, "", 64)
	if page.Outcome != wire.PageOutcomePage || len(page.Records) != 1 || page.Records[0].Name != "hf" || page.Records[0].State != wire.StateActive {
		t.Fatalf("list: %+v", page)
	}
	u := use("hf", "huggingface.co")
	u.Subject = subject
	if r := h.Apply(context.Background(), u, permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Headers["Authorization"] != "Bearer "+testSecret {
		t.Fatalf("apply: %s", r.Outcome)
	}
	rotated := h.Rotate(subject, stored.Revision, wire.Rotation{Name: "hf", Secret: []byte("rotated")})
	if rotated.Outcome != wire.RotateOutcomeRotated {
		t.Fatal(rotated.Outcome)
	}
	if _, err := backend.Get(h.storeKey(account, "hf", stored.Revision)); !errors.Is(err, ErrNotFound) {
		t.Fatal("previous revision still in the keychain")
	}
	// An item deleted outside the holder reads lost.
	backend.Delete(h.storeKey(account, "hf", rotated.Revision))
	if r := h.Apply(context.Background(), u, permit("permitted")); r.Outcome != wire.ApplyOutcomeLost {
		t.Fatalf("loss: %s", r.Outcome)
	}
	again := h.Rotate(subject, rotated.Revision, wire.Rotation{Name: "hf", Secret: []byte("again")})
	if r := h.Revoke(subject, again.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatal(r.Outcome)
	}
	if left := testKeys(t, prefix); len(left) != 0 {
		t.Fatalf("revoke left items: %v", left)
	}
}
