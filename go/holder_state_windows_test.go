package credentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"golang.org/x/sys/windows"
)

func holdStateWithoutDeleteShare(t *testing.T, path string) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	release := func() {
		if handle != windows.InvalidHandle {
			if err := windows.CloseHandle(handle); err != nil {
				t.Fatal(err)
			}
			handle = windows.InvalidHandle
		}
	}
	t.Cleanup(release)
	return release
}

func TestHolderStateRenameRetriesAfterReaderReleases(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "staged"), filepath.Join(dir, "holder.json")
	for path, data := range map[string]string{from: "new", to: "old"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	release := holdStateWithoutDeleteShare(t, to)
	started := time.Now()
	calls := 0
	err := retryStateRename(func() error {
		calls++
		err := os.Rename(from, to)
		if calls <= 3 {
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatalf("held destination rename: %v", err)
			}
			if calls == 3 {
				if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
					t.Fatalf("held destination stopped blocking after only %v", elapsed)
				}
				release()
			}
		} else if err != nil {
			t.Fatalf("rename after releasing destination: %v", err)
		}
		return err
	})
	if err != nil || calls != 4 {
		t.Fatalf("replacement after reader released: %d attempts, %v", calls, err)
	}
	if got, err := os.ReadFile(to); err != nil || string(got) != "new" {
		t.Fatalf("replacement readback: %q, %v", got, err)
	}
}

func TestHolderStateRenamePersistentDenialPreservesRegistration(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "holder.json")
	backend := newMemory()
	var reported error
	h := open(t, Config{StatePath: state, Backend: backend, OnError: func(err error) { reported = err }})
	if got := h.Store(owner, "", registration("kept")); got.Outcome != wire.StoreOutcomeStored {
		t.Fatalf("seed registration: %v (%v)", got.Outcome, reported)
	}
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	holdStateWithoutDeleteShare(t, state)
	if got := h.Store(owner, "", registration("blocked")); got.Outcome != wire.StoreOutcomeUnavailable {
		t.Fatalf("locked state registration: %v", got.Outcome)
	}
	if !errors.Is(reported, windows.ERROR_ACCESS_DENIED) && !errors.Is(reported, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("expected a Windows access denial or sharing violation, got %v", reported)
	}
	if after, err := os.ReadFile(state); err != nil || !bytes.Equal(before, after) || len(backend.items) != 1 {
		t.Fatalf("failed registration changed the original state or store: %v", err)
	}
	if leaves, err := os.ReadDir(dir); err != nil || len(leaves) != 1 || leaves[0].Name() != "holder.json" {
		t.Fatalf("failed replacement left temporary state: %v, %v", leaves, err)
	}
}
