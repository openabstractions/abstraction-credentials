//go:build darwin && cgo

package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func loginKeychainTestKey(t *testing.T) string {
	t.Helper()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return "oa-test-login-" + hex.EncodeToString(nonce[:]) + "/dummy"
}

func TestLoginKeychainRejectsInvalidKeysBeforeNativeCall(t *testing.T) {
	b := &loginKeychain{}
	for _, key := range []string{"", "bad\x00key", "bad\nkey", "非ASCII", strings.Repeat("x", 257)} {
		if err := b.Put(key, []byte("dummy")); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if _, err := b.Get(key); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if err := b.Delete(key); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
}

func TestLoginKeychainRejectsInvalidPathsBeforeNativeCall(t *testing.T) {
	for _, path := range []string{"", "relative.keychain", "/bad\x00path", "/" + strings.Repeat("x", 4095), string([]byte{'/', 0xff})} {
		if _, err := NewLoginKeychainAt(path); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
}

func TestLoginKeychainNativeAvailability(t *testing.T) {
	if err := DisableLoginKeychainInteraction(); err != nil {
		t.Fatal(err)
	}
	b, err := NewLoginKeychain()
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		t.Logf("native user Keychain unavailable: %v", err)
		return
	}
	if b.Name() != StoreMacOSLoginKeychain || b.MaxSecretBytes() != MaxSecretBytes {
		t.Fatal("wrong native backend limits")
	}
	if _, err := b.Get(loginKeychainTestKey(t)); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing or locked native Keychain: %v", err)
	} else {
		t.Logf("native missing-item/availability result: %v", err)
	}
	path, err := DefaultLoginKeychainPath()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLoginKeychainAt(path)
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		t.Logf("bound native user Keychain unavailable: %v", err)
	} else if _, err := reopened.Get(loginKeychainTestKey(t)); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bound native store: %v", err)
	}
}

func TestLoginKeychainMissingBoundPathIsUnavailable(t *testing.T) {
	if err := DisableLoginKeychainInteraction(); err != nil {
		t.Fatal(err)
	}
	path := "/var/tmp/" + loginKeychainTestKey(t) + ".keychain-db"
	b, err := NewLoginKeychainAt(path)
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		return
	}
	if _, err := b.Get("dummy"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) {
		t.Fatalf("missing bound store became a missing item: %v", err)
	}
}

// Explicit opt-in runs real native writes under a dummy-only name. A configured
// but locked/unusable Keychain fails this qualification rather than skipping it.
func TestLoginKeychainNativeCRUD(t *testing.T) {
	if os.Getenv("OA_TEST_LOGIN_KEYCHAIN") != "1" {
		t.Skip("real dummy-only user Keychain CRUD requires OA_TEST_LOGIN_KEYCHAIN=1")
	}
	if err := DisableLoginKeychainInteraction(); err != nil {
		t.Fatal(err)
	}
	b, err := NewLoginKeychain()
	if err != nil {
		t.Fatal(err)
	}
	key := loginKeychainTestKey(t)
	created := false
	t.Cleanup(func() {
		if created {
			if err := b.Delete(key); err != nil {
				t.Errorf("owned dummy cleanup: %v", err)
			}
			if _, err := b.Get(key); !errors.Is(err, ErrNotFound) {
				t.Errorf("owned dummy absence: %v", err)
			}
		}
	})
	if _, err := b.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before create: %v", err)
	}
	if err := b.Put(key, []byte("native dummy one")); err != nil {
		t.Fatal(err)
	}
	created = true
	secret, err := b.Get(key)
	if err != nil || string(secret) != "native dummy one" {
		zero(secret)
		t.Fatalf("created dummy read verification failed: %v", err)
	}
	zero(secret)
	if err := b.Put(key, []byte("native dummy two")); err != nil {
		t.Fatal(err)
	}
	secret, err = b.Get(key)
	if err != nil || string(secret) != "native dummy two" {
		zero(secret)
		t.Fatalf("updated dummy read verification failed: %v", err)
	}
	zero(secret)
	if err := b.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := b.Delete(key); err != nil {
		t.Fatal("absent delete:", err)
	}
}
