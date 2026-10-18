//go:build windows

package credentials

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"golang.org/x/sys/windows"
)

func dpapiStore(t *testing.T) (Backend, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "items")
	backend, err := NewDPAPIFileBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	return backend, dir
}

func itemFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestDPAPIFileStore writes, reads and deletes sealed items: the file holds
// neither the key nor the secret, and an absent item reads ErrNotFound.
func TestDPAPIFileStore(t *testing.T) {
	backend, dir := dpapiStore(t)
	if backend.Name() != StoreWindowsDPAPIFile || backend.MaxSecretBytes() != MaxSecretBytes {
		t.Fatalf("store %s %d", backend.Name(), backend.MaxSecretBytes())
	}
	key := "openabstractions/S-1-5-21-1/hf/1-00"
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent item: %v", err)
	}
	if err := backend.Put(key, []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(key, bytes.Repeat([]byte("x"), MaxSecretBytes+1)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized secret: %v", err)
	}
	got, err := backend.Get(key)
	if err != nil || string(got) != testSecret {
		t.Fatalf("read back: %q %v", got, err)
	}
	files := itemFiles(t, dir)
	if len(files) != 1 || strings.Contains(files[0], "hf") {
		t.Fatalf("item files: %v", files)
	}
	raw, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil || bytes.Contains(raw, []byte(testSecret)) || bytes.Contains(raw, []byte("hf/1-00")) {
		t.Fatalf("item file holds the secret or the key (%v)", err)
	}
	if err := backend.Put(key, []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	if got, err := backend.Get(key); err != nil || string(got) != "replaced" || len(itemFiles(t, dir)) != 1 {
		t.Fatalf("replace: %q %v %v", got, err, itemFiles(t, dir))
	}
	if err := backend.Delete(key); err != nil {
		t.Fatal(err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) || len(itemFiles(t, dir)) != 0 {
		t.Fatalf("deleted item: %v %v", err, itemFiles(t, dir))
	}
}

// TestDPAPIFileStoreSealsToTheKey: an item file moved under another key's name
// or damaged does not unseal there and reads ErrNotFound.
func TestDPAPIFileStoreSealsToTheKey(t *testing.T) {
	backend, _ := dpapiStore(t)
	b := backend.(dpapiFile)
	if err := backend.Put("ns/a/one/1", []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(b.path("ns/a/one/1"), b.path("ns/a/two/1")); err != nil {
		t.Fatal(err)
	}
	if got, err := backend.Get("ns/a/two/1"); !errors.Is(err, ErrNotFound) || got != nil {
		t.Fatalf("moved item unsealed: %v", err)
	}
	if err := os.WriteFile(b.path("ns/a/three/1"), []byte("not a DPAPI blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Get("ns/a/three/1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("damaged item: %v", err)
	}
}

// stubUnseal replaces unseal for one test: the item's key fails with itemErr,
// and the canary fails too when canaryFails.
func stubUnseal(t *testing.T, itemErr error, canaryFails bool) *int {
	t.Helper()
	real := unseal
	canaries := new(int)
	unseal = func(sealed, entropy []byte) ([]byte, error) {
		if string(entropy) == "openabstractions/dpapi-canary" {
			*canaries++
			if canaryFails {
				return nil, nteBadKeyState
			}
			return real(sealed, entropy)
		}
		return nil, itemErr
	}
	t.Cleanup(func() { unseal = real })
	return canaries
}

// TestDPAPIUnsealFailuresSplitLostFromUnavailable (CRED-B2): a key-state or
// password failure reads lost only when a fresh canary seals and unseals now,
// and unavailable when the user's key is unreachable; a data failure reads
// lost without a canary.
func TestDPAPIUnsealFailuresSplitLostFromUnavailable(t *testing.T) {
	for _, c := range []struct {
		name        string
		err         error
		canaryFails bool
		want        error
		canaries    int
	}{
		{"key state, key works", nteBadKeyState, false, ErrNotFound, 1},
		{"key state, key unreachable", nteBadKeyState, true, ErrUnavailable, 1},
		{"password, key unreachable", windows.ERROR_INVALID_PASSWORD, true, ErrUnavailable, 1},
		{"damaged data", windows.ERROR_INVALID_DATA, true, ErrNotFound, 0},
		{"bad data", nteBadData, true, ErrNotFound, 0},
		{"other failure", windows.ERROR_NOT_ENOUGH_MEMORY, false, ErrUnavailable, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			backend, _ := dpapiStore(t)
			if err := backend.Put("ns/a/one/1", []byte(testSecret)); err != nil {
				t.Fatal(err)
			}
			canaries := stubUnseal(t, c.err, c.canaryFails)
			got, err := backend.Get("ns/a/one/1")
			if !errors.Is(err, c.want) || got != nil || *canaries != c.canaries {
				t.Fatalf("Get: %v (canaries %d), want %v (canaries %d)", err, *canaries, c.want, c.canaries)
			}
		})
	}
}

// TestDPAPIWrongEntropyIsADataFailure pins the code DPAPI returns for a blob
// sealed to other entropy, which unsealOutcome reads as lost without a canary.
func TestDPAPIWrongEntropyIsADataFailure(t *testing.T) {
	sealed, err := seal([]byte(testSecret), []byte("ns/a/one/1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unseal(sealed, []byte("ns/a/two/1")); !errors.Is(err, windows.ERROR_INVALID_DATA) {
		t.Fatalf("wrong entropy: %v", err)
	}
	if _, err := unseal([]byte("not a DPAPI blob"), nil); !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("no DPAPI header: %v", err)
	}
}

// TestDPAPIFileStoreRemovesStaleTemporaries: an open removes a crashed Put's
// temporary older than a minute and keeps a fresh one and every item.
func TestDPAPIFileStoreRemovesStaleTemporaries(t *testing.T) {
	backend, dir := dpapiStore(t)
	if err := backend.Put("ns/a/one/1", []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	stale, fresh := filepath.Join(dir, ".item-stale"), filepath.Join(dir, ".item-fresh")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleTemporaryAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDPAPIFileBackend(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temporary kept: %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatalf("fresh temporary removed: %v", err)
	}
	if got, err := backend.Get("ns/a/one/1"); err != nil || string(got) != testSecret {
		t.Fatalf("item after open: %v", err)
	}
}

// TestDPAPIFileStoreIsOwnerOnly: the item directory's DACL is protected and
// grants the current user alone; an item file inherits only that grant.
func dpapiOwnerOnlyDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, directory bool) error {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return errors.New("descriptor must have exactly one ACE")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	const fileFullControl = 0x1f01ff // FILE_ALL_ACCESS, rendered as FA in SDDL.
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != fileFullControl {
		return errors.New("descriptor must grant full control through one allow ACE")
	}
	if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user) {
		return errors.New("descriptor grants a different principal")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if directory {
		if control&windows.SE_DACL_PROTECTED == 0 || ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			return errors.New("directory grant must be protected, explicit and inheritable")
		}
	} else if control&windows.SE_DACL_PROTECTED != 0 || control&windows.SE_DACL_AUTO_INHERITED == 0 || ace.Header.AceFlags != windows.INHERITED_ACE {
		return errors.New("file grant must be inherited from the directory")
	}
	return nil
}

func TestDPAPIOwnerOnlyDescriptor(t *testing.T) {
	alias, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;LA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := alias.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	admin := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	full := admin.String()
	if !strings.HasSuffix(full, "-500") {
		t.Fatalf("LA did not resolve to RID500: %s", full)
	}
	for _, test := range []struct {
		name, sddl          string
		directory, accepted bool
	}{
		{"RID500 alias", "D:P(A;OICI;FA;;;LA)", true, true},
		{"RID500 full SID", "D:P(A;OICI;FA;;;" + full + ")", true, true},
		{"inherited file", "D:AI(A;ID;FA;;;" + full + ")", false, true},
		{"foreign trustee", "D:P(A;OICI;FA;;;SY)", true, false},
		{"extra grant", "D:P(A;OICI;FA;;;LA)(A;OICI;FR;;;WD)", true, false},
		{"deny ACE", "D:P(D;OICI;FA;;;LA)", true, false},
		{"wrong mask", "D:P(A;OICI;FR;;;LA)", true, false},
		{"unprotected directory", "D:(A;OICI;FA;;;LA)", true, false},
		{"directory missing propagation", "D:P(A;;FA;;;LA)", true, false},
		{"explicit file", "D:(A;;FA;;;LA)", false, false},
		{"protected file", "D:P(A;ID;FA;;;LA)", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := dpapiOwnerOnlyDescriptor(sd, admin, test.directory); (err == nil) != test.accepted {
				t.Fatalf("descriptor accepted=%v, want %v: %v (%s)", err == nil, test.accepted, err, sd.String())
			}
		})
	}
}

func TestDPAPIFileStoreIsOwnerOnly(t *testing.T) {
	backend, dir := dpapiStore(t)
	if err := backend.Put("ns/a/one/1", []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range []string{dir, backend.(dpapiFile).path("ns/a/one/1")} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if err := dpapiOwnerOnlyDescriptor(sd, user.User.Sid, i == 0); err != nil {
			t.Fatalf("%s: %v: %s", path, err, sd.String())
		}
	}
}

// TestDPAPIFileStoreUnderConcurrentCalls: eight goroutines write, read and
// delete their own items at once; nothing written is lost and nothing deleted
// returns.
func TestDPAPIFileStoreUnderConcurrentCalls(t *testing.T) {
	backend, dir := dpapiStore(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			wrong := churnStore(backend, "ns/g"+string(rune('0'+g))+"/", 30)
			mu.Lock()
			defer mu.Unlock()
			for _, w := range wrong {
				t.Error(w)
			}
		}(g)
	}
	wg.Wait()
	if files := itemFiles(t, dir); len(files) != 16 {
		t.Fatalf("%d item files, want the 16 kept items", len(files))
	}
}

// TestDPAPIFileStoreHolder runs the holder over the store: store, apply,
// rotate, loss and revoke, leaving no item file.
func TestDPAPIFileStoreHolder(t *testing.T) {
	backend, dir := dpapiStore(t)
	h := open(t, Config{Backend: backend})
	if l := h.Limits(); l.SecureStore != StoreWindowsDPAPIFile || l.MaxSecretBytes != MaxSecretBytes {
		t.Fatalf("limits: %+v", l)
	}
	stored := h.Store(owner, "", registration("hf"))
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal(stored.Outcome)
	}
	u := use("hf", "huggingface.co")
	u.Subject = owner
	if r := h.Apply(context.Background(), u, permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Headers["Authorization"] != "Bearer "+testSecret {
		t.Fatalf("apply: %s", r.Outcome)
	}
	rotated := h.Rotate(owner, stored.Revision, wire.Rotation{Name: "hf", Secret: []byte("rotated")})
	if rotated.Outcome != wire.RotateOutcomeRotated || len(itemFiles(t, dir)) != 1 {
		t.Fatalf("rotate: %s %v", rotated.Outcome, itemFiles(t, dir))
	}
	backend.Delete(h.storeKey(owner.Account, "hf", rotated.Revision))
	if r := h.Apply(context.Background(), u, permit("permitted")); r.Outcome != wire.ApplyOutcomeLost {
		t.Fatalf("loss: %s", r.Outcome)
	}
	again := h.Rotate(owner, rotated.Revision, wire.Rotation{Name: "hf", Secret: []byte("again")})
	if r := h.Revoke(owner, again.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatal(r.Outcome)
	}
	if files := itemFiles(t, dir); len(files) != 0 {
		t.Fatalf("revoke left item files: %v", files)
	}
}
