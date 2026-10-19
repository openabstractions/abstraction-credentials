package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestFailedNoteOrMarkerWriteKeepsTheCredentialManager: a pending note that
// cannot be written, or a marker replacement that fails, leaves the binding
// on the Credential Manager with every registration applied, no copy in the
// new store and no note; the failure is reported once.
func TestFailedNoteOrMarkerWriteKeepsTheCredentialManager(t *testing.T) {
	t.Run("note", func(t *testing.T) {
		s := newMigrationState(t, 2)
		// A directory where the note goes makes its write fail.
		if err := os.MkdirAll(windowsMigrationPending(s.dir), 0o700); err != nil {
			t.Fatal(err)
		}
		store, outcomes := s.start(t, nil)
		if store != StoreWindowsCredentialManager || !allApplied(outcomes) {
			t.Fatalf("%s %v", store, outcomes)
		}
		if word := strings.TrimSpace(markerWord(t, s.dir)); word != StoreWindowsCredentialManager {
			t.Fatalf("marker %s", word)
		}
		if len(s.dpapi.items) != 0 || len(s.credman.items) != 2 || len(s.reports) != 1 {
			t.Fatalf("new store %d, Credential Manager %d, reports %v", len(s.dpapi.items), len(s.credman.items), s.reports)
		}
	})
	t.Run("marker", func(t *testing.T) {
		s := newMigrationState(t, 2)
		pending, attempt := windowsMigrationPending(s.dir), windowsMigrationAttempt(s.dir)
		failed := errors.New("marker write failed")
		err := migrateStore(s.dir, DefaultNamespace, s.credman, s.dpapi, pending, attempt,
			func() error { return failed }, func() bool { return false }, nil)
		if !errors.Is(err, failed) {
			t.Fatalf("migrate: %v", err)
		}
		for _, path := range []string{pending, attempt} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s left (%v)", filepath.Base(path), err)
			}
		}
		if len(s.dpapi.items) != 0 || len(s.credman.items) != 2 {
			t.Fatalf("new store %d, Credential Manager %d", len(s.dpapi.items), len(s.credman.items))
		}
		if word := strings.TrimSpace(markerWord(t, s.dir)); word != StoreWindowsCredentialManager {
			t.Fatalf("marker %s", word)
		}
		// The next start retries and completes the migration.
		if store, outcomes := s.start(t, nil); store != StoreWindowsDPAPIFile || !allApplied(outcomes) || len(s.credman.items) != 0 {
			t.Fatalf("next start: %s %v, Credential Manager %d", store, outcomes, len(s.credman.items))
		}
	})
}

// TestFailedCopyReportsOnce: the operator learns why the state stays on the
// Credential Manager, once per start.
func TestFailedCopyReportsOnce(t *testing.T) {
	s := newMigrationState(t, 2)
	s.dpapi.putFails = true
	if store, _ := s.start(t, nil); store != StoreWindowsCredentialManager {
		t.Fatalf("bound to %s", store)
	}
	if len(s.reports) != 1 || !errors.Is(s.reports[0], ErrUnavailable) {
		t.Fatalf("reports %v", s.reports)
	}
}

// TestMachineScopeAccountsOpenNoStore: a Windows service account or root is
// machine-wide; the public entry opens no store for it and writes no marker.
// A user account is not machine-wide.
func TestMachineScopeAccountsOpenNoStore(t *testing.T) {
	for _, account := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "0"} {
		if !MachineScopeAccount(account) {
			t.Fatalf("%s is not machine scope", account)
		}
		dir := filepath.Join(t.TempDir(), "credentials")
		b, release, err := OpenPlatformStore(dir, "", account, nil)
		release()
		if b != nil || err != nil {
			t.Fatalf("%s: opened %v %v", account, b, err)
		}
		entries, err := os.ReadDir(filepath.Dir(dir))
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s: wrote %v %v", account, entries, err)
		}
	}
	for _, account := range []string{"S-1-5-21-1-2-3-1001", "1000", ""} {
		if MachineScopeAccount(account) {
			t.Fatalf("user account %q read as machine scope", account)
		}
	}
}

// TestOpenPlatformStoreBindsAFreshState opens the public entry on a fresh
// state. On Windows it binds windows-dpapi-file in a temporary folder and
// never opens the Credential Manager; on Linux the file-0600 choice is used.
func TestOpenPlatformStoreBindsAFreshState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	want := StoreWindowsDPAPIFile
	switch runtime.GOOS {
	case "windows":
	case "linux":
		if err := WriteLinuxStoreChoice(dir, StoreFile); err != nil {
			t.Fatal(err)
		}
		want = StoreFile
	default:
		t.Skip("tests never open the user Keychain")
	}
	var reports []error
	b, release, err := OpenPlatformStore(dir, "", "S-1-5-21-1-2-3-1001", func(err error) { reports = append(reports, err) })
	defer release()
	if err != nil || b.Name() != want || len(reports) != 0 {
		t.Fatalf("%v %v %v", b, err, reports)
	}
	if runtime.GOOS == "windows" && strings.TrimSpace(markerWord(t, dir)) != StoreWindowsDPAPIFile {
		t.Fatal("marker not written")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("oa-test/acct/k/1", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get("oa-test/acct/k/1"); err != nil || string(got) != "v" {
		t.Fatalf("%q %v", got, err)
	}
}
