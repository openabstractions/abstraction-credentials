//go:build windows

package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"unsafe"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"golang.org/x/sys/windows"
)

var procCredEnumerateW = advapi32.NewProc("CredEnumerateW")

// testTargets lists the generic credential target names under prefix.
func testTargets(t *testing.T, prefix string) []string {
	t.Helper()
	filter, err := windows.UTF16PtrFromString(prefix + "*")
	if err != nil {
		t.Fatal(err)
	}
	var count uint32
	var list **credentialW
	if r, _, e := procCredEnumerateW.Call(uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list))); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil
		}
		t.Fatalf("CredEnumerateW: %v", e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(list)))
	names := []string{}
	for _, cred := range unsafe.Slice(list, count) {
		names = append(names, windows.UTF16PtrToString(cred.TargetName))
	}
	return names
}

// testNamespace is a test-unique store namespace, the first segment of every
// target name. Cleanup deletes every generic credential under it, whatever the
// test left behind.
func testNamespace(t *testing.T, backend Backend) (namespace, prefix string) {
	t.Helper()
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	namespace = "oa-test-" + hex.EncodeToString(nonce[:])
	prefix = namespace + "/"
	t.Cleanup(func() {
		for _, target := range testTargets(t, prefix) {
			if err := backend.Delete(target); err != nil {
				t.Errorf("cleanup %s: %v", target, err)
			}
		}
		if left := testTargets(t, prefix); len(left) != 0 {
			t.Errorf("cleanup left %d test credentials", len(left))
		}
	})
	return namespace, prefix
}

// TestCredentialManager writes, reads and deletes real generic credentials of
// the current user in a test-unique target namespace and removes them all.
func TestCredentialManager(t *testing.T) {
	backend, err := NewCredentialManager()
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
	if err := backend.Put(key, make([]byte, credentialManagerMaxBlob+1)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized blob: %v", err)
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
	if l := h.Limits(); l.SecureStore != StoreWindowsCredentialManager || l.MaxSecretBytes != credentialManagerMaxBlob {
		t.Fatalf("limits: %+v", l)
	}
	stored := h.Store(subject, "", registration("hf"))
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal(stored.Outcome)
	}
	if targets := testTargets(t, prefix); len(targets) != 1 || targets[0] != h.storeKey(account, "hf", stored.Revision) {
		t.Fatalf("stored targets: %v", targets)
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
		t.Fatal("previous revision still in Credential Manager")
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
	if left := testTargets(t, prefix); len(left) != 0 {
		t.Fatalf("revoke left items: %v", left)
	}
}
