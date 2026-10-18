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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"golang.org/x/sys/windows"
)

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
