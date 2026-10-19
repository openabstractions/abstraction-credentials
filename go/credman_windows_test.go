//go:build windows

package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"golang.org/x/sys/windows"
)

// Exercise CRED-B3 with native stores and owned state. Each interrupted start
// keeps serving the marker's store, then the public startup entry completes
// migration. The unique namespace cleanup verifies every native item is gone.
func TestWindowsMigrationNativeExistingState(t *testing.T) {
	for _, stopAt := range []string{"", stepCopy, stepVerify, stepPending, stepMarker, stepDelete, stepFinished} {
		t.Run("interrupt="+stopAt, func(t *testing.T) {
			old, err := NewCredentialManager()
			if err != nil {
				t.Fatal(err)
			}
			namespace, prefix := testNamespace(t, old)
			dir := filepath.Join(t.TempDir(), "credentials")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			h := open(t, Config{Backend: old, Namespace: namespace, StatePath: filepath.Join(dir, "holder.json")})
			stored := h.Store(owner, "", registration("hf"))
			if stored.Outcome != wire.StoreOutcomeStored {
				t.Fatal(stored.Outcome)
			}
			key := h.storeKey(owner.Account, "hf", stored.Revision)
			var reports []error
			b, release := openWindowsStore(dir, namespace, windowsCredentialsConstructors{
				credentialManager: NewCredentialManager, dpapiFile: NewDPAPIFileBackend,
			}, func(step string) error {
				if step == stopAt {
					return errCrash
				}
				return nil
			}, func(err error) { reports = append(reports, err) })
			t.Cleanup(release)
			active := open(t, Config{Backend: b, Namespace: namespace, StatePath: filepath.Join(dir, "holder.json")})
			if got := active.Apply(context.Background(), use("hf", "huggingface.co"), permit("permitted")); got.Outcome != wire.ApplyOutcomeApplied || got.Headers["Authorization"] != "Bearer "+testSecret {
				t.Fatalf("interrupted apply: %s", got.Outcome)
			}
			if strings.TrimSpace(markerWord(t, dir)) != b.Name() {
				t.Fatal("served store differs from marker")
			}
			if stopAt == "" && len(reports) != 0 || stopAt != "" && len(reports) != 1 {
				t.Fatalf("reports: %d", len(reports))
			}
			release()
			b, release, err = OpenPlatformStore(dir, namespace, owner.Account, func(err error) { t.Error(err) })
			t.Cleanup(release)
			if err != nil || b.Name() != StoreWindowsDPAPIFile {
				t.Fatalf("restart: %v %v", b, err)
			}
			if got, err := b.Get(key); err != nil || string(got) != testSecret {
				t.Fatalf("native copied value: %v", err)
			}
			if left := testTargets(t, prefix); len(left) != 0 {
				t.Fatalf("old store keeps %d items", len(left))
			}
			for _, path := range []string{windowsMigrationAttempt(dir), windowsMigrationPending(dir)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("migration note remains: %v", err)
				}
			}
		})
	}
}

// Only the native read/free and the existing DPAPI canary hooks are scripted.
// No Credential Manager item or DPAPI material is read or written.
func TestCredentialManagerReadClassification(t *testing.T) {
	savedRead, savedFree, savedSeal, savedUnseal := credentialRead, credentialFree, seal, unseal
	t.Cleanup(func() { credentialRead, credentialFree, seal, unseal = savedRead, savedFree, savedSeal, savedUnseal })
	for _, tc := range []struct {
		name                   string
		readErr                error
		canaryFails            bool
		sealFails, canaryWrong bool
		blobSize               uint32
		nilCredential, nilBlob bool
		want                   error
		canaries               int
	}{
		{name: "absent", readErr: windows.ERROR_NOT_FOUND, want: ErrNotFound},
		{name: "no logon session", readErr: windows.ERROR_NO_SUCH_LOGON_SESSION, want: ErrUnavailable},
		{name: "key state readable", readErr: nteBadKeyState, want: ErrNotFound, canaries: 1},
		{name: "key state unreachable", readErr: nteBadKeyState, canaryFails: true, want: ErrUnavailable, canaries: 1},
		{name: "canary seal fails", readErr: nteBadKeyState, sealFails: true, want: ErrUnavailable, canaries: 1},
		{name: "canary differs", readErr: nteBadKeyState, canaryWrong: true, want: ErrUnavailable, canaries: 1},
		{name: "password readable", readErr: windows.ERROR_INVALID_PASSWORD, want: ErrNotFound, canaries: 1},
		{name: "password unreachable", readErr: windows.ERROR_INVALID_PASSWORD, canaryFails: true, want: ErrUnavailable, canaries: 1},
		{name: "uncertain data error", readErr: windows.ERROR_INVALID_DATA, want: ErrUnavailable},
		{name: "unknown failure", readErr: windows.ERROR_ACCESS_DENIED, want: ErrUnavailable},
		{name: "empty blob", want: ErrUnavailable},
		{name: "nil nonempty blob", blobSize: 3, nilBlob: true, want: ErrUnavailable},
		{name: "nil credential", nilCredential: true, want: ErrUnavailable},
		{name: "oversized blob", blobSize: credentialManagerMaxBlob + 1, want: ErrUnavailable},
		{name: "valid bytes", blobSize: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob := []byte{1, 0, 255}
			cred := &credentialW{CredentialBlobSize: tc.blobSize, CredentialBlob: &blob[0]}
			if tc.nilBlob {
				cred.CredentialBlob = nil
			}
			if tc.nilCredential {
				cred = nil
			}
			reads, frees, canaries := 0, 0, 0
			credentialRead = func(target *uint16, out **credentialW) error { reads++; *out = cred; return tc.readErr }
			credentialFree = func(got *credentialW) {
				frees++
				if got != cred {
					t.Fatal("freed another credential")
				}
			}
			seal = func(data, entropy []byte) ([]byte, error) {
				canaries++
				if tc.sealFails {
					return nil, nteBadKeyState
				}
				return []byte("inert sealed canary"), nil
			}
			unseal = func(data, entropy []byte) ([]byte, error) {
				if tc.canaryFails {
					return nil, nteBadKeyState
				}
				if tc.canaryWrong {
					return []byte("inert mismatch"), nil
				}
				return []byte("openabstractions dpapi canary"), nil
			}
			got, err := (credentialManager{}).Get("inert/native-result")
			if !errors.Is(err, tc.want) || (tc.want != nil && got != nil) || reads != 1 || canaries != tc.canaries {
				t.Fatalf("Get=%v, reads=%d canaries=%d; want %v/%d", err, reads, canaries, tc.want, tc.canaries)
			}
			if tc.want == ErrUnavailable && errors.Is(err, ErrNotFound) {
				t.Fatal("uncertain native result classified lost")
			}
			wantFree := 0
			if tc.readErr == nil && cred != nil {
				wantFree = 1
			}
			if frees != wantFree {
				t.Fatalf("frees=%d want %d", frees, wantFree)
			}
			if tc.want == nil && (len(got) != 3 || got[0] != 1 || got[1] != 0 || got[2] != 255 || blob[0] != 0 || blob[2] != 0) {
				t.Fatal("native bytes were not copied and cleared")
			}
		})
	}
}

type credentialResultBackend struct{ *memoryBackend }

func (b credentialResultBackend) Get(key string) ([]byte, error) {
	return (credentialManager{}).Get(key)
}

func TestCredentialManagerEmptyBlobKeepsHolderActive(t *testing.T) {
	savedRead, savedFree := credentialRead, credentialFree
	t.Cleanup(func() { credentialRead, credentialFree = savedRead, savedFree })
	store := credentialResultBackend{newMemory()}
	mode := "readable"
	credentialRead = func(target *uint16, out **credentialW) error {
		if mode == "absent" {
			return windows.ERROR_NOT_FOUND
		}
		if mode == "empty" {
			*out = &credentialW{}
			return nil
		}
		blob, err := store.memoryBackend.Get(windows.UTF16PtrToString(target))
		if err != nil {
			return windows.ERROR_NOT_FOUND
		}
		*out = &credentialW{CredentialBlobSize: uint32(len(blob)), CredentialBlob: &blob[0]}
		return nil
	}
	credentialFree = func(*credentialW) {}
	h := open(t, Config{Backend: store})
	h.Store(owner, "", registration("hf"))
	apply := func() wire.ApplyOutcome {
		return h.Apply(context.Background(), use("hf", "huggingface.co"), permit("permitted")).Outcome
	}
	mode = "empty"
	if got := apply(); got != wire.ApplyOutcomeUnavailable {
		t.Fatalf("empty blob: %s", got)
	}
	mode = "readable"
	if got := apply(); got != wire.ApplyOutcomeApplied {
		t.Fatalf("record not kept: %s", got)
	}
	mode = "absent"
	if got := apply(); got != wire.ApplyOutcomeLost {
		t.Fatalf("genuine absence: %s", got)
	}
}

// testTargets lists the generic credential target names under prefix.
func testTargets(t *testing.T, prefix string) []string {
	t.Helper()
	names, err := credentialManager{}.Targets(prefix)
	if err != nil {
		t.Fatal(err)
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

// concurrentPrefixEnv hands a worker process its namespace prefix and id.
const concurrentPrefixEnv = "OA_CREDMAN_CONCURRENT_PREFIX"

// churnStore writes two kept items under ns, then writes, reads, deletes and
// rereads one temporary item per round, checking the kept items each round.
// It returns every observation that contradicts the calls' results.
func churnStore(backend Backend, ns string, rounds int) []string {
	var wrong []string
	keeps := []string{ns + "keep0", ns + "keep1"}
	for _, k := range keeps {
		if err := backend.Put(k, []byte(k)); err != nil {
			wrong = append(wrong, fmt.Sprintf("put %s: %v", k, err))
		}
	}
	for r := 0; r < rounds; r++ {
		tmp := fmt.Sprintf("%stmp%d", ns, r)
		if err := backend.Put(tmp, []byte(tmp)); err != nil {
			wrong = append(wrong, fmt.Sprintf("put %s: %v", tmp, err))
		}
		if _, err := backend.Get(tmp); err != nil {
			wrong = append(wrong, fmt.Sprintf("%s unreadable after its write: %v", tmp, err))
		}
		if err := backend.Delete(tmp); err != nil {
			wrong = append(wrong, fmt.Sprintf("delete %s: %v", tmp, err))
		}
		if _, err := backend.Get(tmp); !errors.Is(err, ErrNotFound) {
			wrong = append(wrong, fmt.Sprintf("%s readable after its delete: %v", tmp, err))
		}
		for _, k := range keeps {
			if v, err := backend.Get(k); err != nil || string(v) != k {
				wrong = append(wrong, fmt.Sprintf("%s lost in round %d: %v", k, r, err))
			}
		}
	}
	return wrong
}

// TestCredentialManagerConcurrentWorker is one worker process of
// TestCredentialManagerAcrossProcesses; it skips unless that test started it.
func TestCredentialManagerConcurrentWorker(t *testing.T) {
	prefix := os.Getenv(concurrentPrefixEnv)
	if prefix == "" {
		t.Skip("started only by TestCredentialManagerAcrossProcesses")
	}
	if !strings.HasPrefix(prefix, "oa-test-") {
		t.Fatalf("worker prefix %q is outside the test namespace", prefix)
	}
	backend, err := NewCredentialManager()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			wrong := churnStore(backend, fmt.Sprintf("%sg%d/", prefix, g), concurrentRounds)
			mu.Lock()
			defer mu.Unlock()
			for _, w := range wrong {
				t.Error(w)
			}
		}(g)
	}
	wg.Wait()
}

const (
	concurrentProcesses = 4
	concurrentRounds    = 30
)

// TestCredentialManagerAcrossProcesses runs four processes of two goroutines
// each against the account's Credential Manager, every one writing, reading
// and deleting its own items. Unserialized, concurrent calls lose items that
// were written and bring back items that were deleted (TODO "Windows
// Credential Manager loses and restores OA items", 2026-10-07): the backend
// serializes every call it makes, in and across processes.
func TestCredentialManagerAcrossProcesses(t *testing.T) {
	if os.Getenv(concurrentPrefixEnv) != "" {
		t.Skip("worker process")
	}
	backend, err := NewCredentialManager()
	if err != nil {
		t.Fatal(err)
	}
	_, prefix := testNamespace(t, backend)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		out []byte
		err error
	}
	results := make([]result, concurrentProcesses)
	var wg sync.WaitGroup
	for p := 0; p < concurrentProcesses; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestCredentialManagerConcurrentWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%sp%d/", concurrentPrefixEnv, prefix, p))
			out, err := cmd.CombinedOutput()
			results[p] = result{out, err}
		}(p)
	}
	wg.Wait()
	for p, r := range results {
		if r.err != nil {
			t.Errorf("worker %d: %v\n%s", p, r.err, r.out)
		}
	}
	want := map[string]bool{}
	for p := 0; p < concurrentProcesses; p++ {
		for g := 0; g < 2; g++ {
			for k := 0; k < 2; k++ {
				want[fmt.Sprintf("%sp%d/g%d/keep%d", prefix, p, g, k)] = true
			}
		}
	}
	for _, target := range testTargets(t, prefix) {
		if !want[target] {
			t.Errorf("deleted item came back: %s", target)
		}
		delete(want, target)
	}
	for target := range want {
		t.Errorf("written item lost: %s", target)
	}
}

// TestCredentialManagerLockWaitIsOneDeadlinePerCall holds the session mutex
// and starts three Gets: each reads unavailable within one storeLockWait of
// its own start, rather than waiting its turn in the process queue first.
func TestCredentialManagerLockWaitIsOneDeadlinePerCall(t *testing.T) {
	backend, err := NewCredentialManager()
	if err != nil {
		t.Fatal(err)
	}
	h := sessionStoreMutex()
	if h == 0 {
		t.Skip("the session mutex could not be opened")
	}
	saved := storeLockWait
	storeLockWait = 500 * time.Millisecond
	t.Cleanup(func() { storeLockWait = saved })
	held, release, done := make(chan error, 1), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if event, err := windows.WaitForSingleObject(h, 30000); err != nil || (event != windows.WAIT_OBJECT_0 && event != windows.WAIT_ABANDONED) {
			held <- fmt.Errorf("hold the session mutex: %d %v", event, err)
			return
		}
		held <- nil
		<-release
		//unchecked: this thread owns the mutex it waited for
		windows.ReleaseMutex(h)
	}()
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	namespace, _ := testNamespace(t, backend)
	var wg sync.WaitGroup
	results := make([]error, 3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			_, err := backend.Get(namespace + "/absent")
			if elapsed := time.Since(start); !errors.Is(err, ErrUnavailable) || elapsed > storeLockWait*8/5 {
				results[i] = fmt.Errorf("Get %d: %v after %v", i, err, elapsed)
			}
		}(i)
	}
	wg.Wait()
	close(release)
	<-done
	for _, err := range results {
		if err != nil {
			t.Error(err)
		}
	}
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
