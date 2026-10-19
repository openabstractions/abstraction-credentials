package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationFlushesRemovedAttemptBeforeDeletingOldItems(t *testing.T) {
	s := newMigrationState(t, 2)
	old := syncMigrationDir
	t.Cleanup(func() { syncMigrationDir = old })
	calls := 0
	syncMigrationDir = func(dir string) error {
		calls++
		if dir != filepath.Dir(s.dir) {
			t.Fatal("wrong metadata directory", dir)
		}
		if calls == 1 {
			if len(s.credman.items) != 2 {
				t.Fatal("old items deleted before attempt unlink reached directory")
			}
			if _, err := os.Stat(windowsMigrationAttempt(s.dir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("attempt not removed", err)
			}
		} else if len(s.credman.items) != 0 {
			t.Fatal("pending note removed before old items")
		}
		return old(dir)
	}
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) || calls != 2 {
		t.Fatal(store, outcomes, calls, s.reports)
	}
}

func TestFailedAttemptDirectoryFlushRetainsOldItemsAndPendingRecovery(t *testing.T) {
	s := newMigrationState(t, 2)
	old := syncMigrationDir
	t.Cleanup(func() { syncMigrationDir = old })
	failure := errors.New("attempt directory flush failed")
	syncMigrationDir = func(string) error { return failure }
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) || len(s.credman.items) != 2 || len(s.dpapi.items) != 2 || len(s.reports) != 1 || !errors.Is(s.reports[0], failure) {
		t.Fatal(store, outcomes, s.credman.items, s.dpapi.items, s.reports)
	}
	if _, err := os.Stat(windowsMigrationPending(s.dir)); err != nil {
		t.Fatal("recovery note lost", err)
	}
	for retry := 0; retry < 2; retry++ {
		store, outcomes = s.start(t, nil)
		if store != StoreWindowsDPAPIFile || !allApplied(outcomes) || len(s.credman.items) != 2 || len(s.dpapi.items) != 2 || len(s.reports) != retry+2 || !errors.Is(s.reports[len(s.reports)-1], failure) {
			t.Fatal("failed retry crossed unlink barrier", retry, store, outcomes, len(s.credman.items), len(s.dpapi.items), s.reports)
		}
		if _, err := os.Stat(windowsMigrationPending(s.dir)); err != nil {
			t.Fatal("retry lost recovery note", err)
		}
	}
	syncMigrationDir = old
	store, outcomes = s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) || len(s.credman.items) != 0 {
		t.Fatal("recovery", store, outcomes, s.credman.items)
	}
}

func TestFailedFinalNoteFlushReportsAndKeepsTheDurableCopies(t *testing.T) {
	s := newMigrationState(t, 2)
	old := syncMigrationDir
	t.Cleanup(func() { syncMigrationDir = old })
	calls := 0
	failure := errors.New("pending directory flush failed")
	syncMigrationDir = func(dir string) error {
		calls++
		if calls == 2 {
			return failure
		}
		return old(dir)
	}
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) || len(s.credman.items) != 0 || len(s.dpapi.items) != 2 || len(s.reports) != 1 || !errors.Is(s.reports[0], failure) {
		t.Fatal(store, outcomes, s.credman.items, s.dpapi.items, s.reports)
	}
}
