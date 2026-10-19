package credentials

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// TestCredentialManagerHolderKeepsTheLockWhileItServes: start A's migration
// fails and its holder keeps serving the Credential Manager. Start B, with a
// working new store, runs while A serves; it neither migrates nor deletes the
// items A serves. A then applies every registration and stores once more, and
// a fresh start after both exited migrates all of them. No registration reads
// lost at any point.
func TestCredentialManagerHolderKeepsTheLockWhileItServes(t *testing.T) {
	wait := migrationLockWait
	migrationLockWait = 50 * time.Millisecond
	defer func() { migrationLockWait = wait }()
	s := newMigrationState(t, 2)
	s.dpapi.putFails = true
	storeA, outcomes, a, exitA := s.startHolder(t, nil)
	if storeA != StoreWindowsCredentialManager || !allApplied(outcomes) {
		t.Fatalf("start A: %s %v", storeA, outcomes)
	}
	s.dpapi.putFails = false
	storeB, outcomes, _, exitB := s.startHolder(t, nil)
	if storeB != StoreWindowsCredentialManager || !noneLost(outcomes) {
		t.Fatalf("start B while A serves: %s %v", storeB, outcomes)
	}
	exitB()
	if word := strings.TrimSpace(markerWord(t, s.dir)); word != StoreWindowsCredentialManager {
		t.Fatalf("start B moved the marker to %s while A serves", word)
	}
	if len(s.credman.items) != 2 || len(s.dpapi.items) != 0 {
		t.Fatalf("while A serves: Credential Manager %d, new store %d", len(s.credman.items), len(s.dpapi.items))
	}
	if outcomes := s.applyAll(a); !allApplied(outcomes) {
		t.Fatalf("start A after start B: %v", outcomes)
	}
	name := "hf2"
	if r := a.Store(owner, "", registration(name)); r.Outcome != wire.StoreOutcomeStored {
		t.Fatalf("store in A: %s", r.Outcome)
	}
	s.names = append(s.names, name)
	if outcomes := s.applyAll(a); !allApplied(outcomes) {
		t.Fatalf("start A after storing once more: %v", outcomes)
	}
	exitA()
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("fresh start: %s %v", store, outcomes)
	}
	if len(s.dpapi.items) != 3 || len(s.credman.items) != 0 {
		t.Fatalf("new store %d items, Credential Manager %d", len(s.dpapi.items), len(s.credman.items))
	}
}

// TestLostNoteWritesKeepTheOnlyCopies: an attempt copied every item and the
// old store's deletes persisted, while the marker and note writes before them
// were lost. The next start finds the Credential Manager marker and the attempt
// note; it keeps every copy the state refers to, removes a listed copy the
// state no longer refers to, and serves every registration from the new store.
func TestLostNoteWritesKeepTheOnlyCopies(t *testing.T) {
	s := newMigrationState(t, 2)
	keys, err := storeKeys(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	revoked := DefaultNamespace + "/revoked/hf/1"
	for _, key := range keys {
		secret, err := s.credman.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.dpapi.Put(key, secret); err != nil {
			t.Fatal(err)
		}
		if err := s.credman.Delete(key); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.dpapi.Put(revoked, []byte("old")); err != nil {
		t.Fatal(err)
	}
	note, err := json.Marshal(pendingNote{Store: StoreWindowsDPAPIFile, Keys: append(keys, revoked)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(windowsMigrationAttempt(s.dir), append(note, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("%s %v", store, outcomes)
	}
	if stray := s.strayCopies(t); len(stray) != 0 {
		t.Fatalf("new store keeps %v", stray)
	}
	if len(s.dpapi.items) != len(keys) {
		t.Fatalf("new store %d items, want %d", len(s.dpapi.items), len(keys))
	}
}
