package credentials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// namedMemory is a fake store with a store word. No platform store is touched.
type namedMemory struct {
	*memoryBackend
	name string
	// putFails, when set, fails every Put as a full or broken store would.
	putFails bool
	// deleteFails, when set, fails every Delete as a timed-out store would.
	deleteFails bool
	// corrupt, when set, reads back different bytes than were written.
	corrupt bool
}

func (n *namedMemory) Name() string { return n.name }
func (n *namedMemory) Delete(key string) error {
	if n.deleteFails {
		return fmt.Errorf("%w: store lock timed out", ErrUnavailable)
	}
	return n.memoryBackend.Delete(key)
}
func (n *namedMemory) Put(key string, secret []byte) error {
	if n.putFails {
		return fmt.Errorf("%w: store full", ErrUnavailable)
	}
	return n.memoryBackend.Put(key, secret)
}
func (n *namedMemory) Get(key string) ([]byte, error) {
	v, err := n.memoryBackend.Get(key)
	if err == nil && n.corrupt {
		v = append(v, 'x')
	}
	return v, err
}

// migrationState is a Credential Manager state with n registrations made by
// a holder, bound by its marker, with stores that persist across restarts.
type migrationState struct {
	dir     string
	credman *namedMemory
	dpapi   *namedMemory
	names   []string
	revs    []string
	// namespace is the holder namespace; lock overrides the migration lock.
	namespace string
	lock      func(string) (func(), bool)
	// reports are the migration failures the starts reported.
	reports []error
}

// noneLost reports whether no outcome reads lost.
func noneLost(outcomes []wire.ApplyOutcome) bool {
	for _, o := range outcomes {
		if o == wire.ApplyOutcomeLost {
			return false
		}
	}
	return true
}

// strayCopies are the new store's items the holder state no longer refers to.
func (s *migrationState) strayCopies(t *testing.T) []string {
	t.Helper()
	keys, err := storeKeys(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	var stray []string
	for key := range s.dpapi.items {
		if !slices.Contains(keys, key) {
			stray = append(stray, key)
		}
	}
	return stray
}

func newMigrationState(t *testing.T, n int) *migrationState {
	t.Helper()
	s := &migrationState{dir: filepath.Join(t.TempDir(), "credentials"),
		credman: &namedMemory{memoryBackend: newMemory(), name: StoreWindowsCredentialManager},
		dpapi:   &namedMemory{memoryBackend: newMemory(), name: StoreWindowsDPAPIFile}}
	s.register(t, n)
	if len(s.credman.items) != n {
		t.Fatalf("credential manager holds %d items", len(s.credman.items))
	}
	return s
}

// register makes n registrations on the Credential Manager binding.
func (s *migrationState) register(t *testing.T, n int) {
	t.Helper()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if b := newWindowsCredentialsBackend(s.dir, s.constructors()); b.Name() != StoreWindowsCredentialManager {
		t.Fatalf("existing state bound to %s", b.Name())
	}
	h := open(t, Config{Backend: s.credman, Namespace: s.namespace, StatePath: filepath.Join(s.dir, "holder.json"),
		OnError: func(err error) { t.Logf("register: %v", err) }})
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("hf%d", i)
		r := h.Store(owner, "", registration(name))
		if r.Outcome != wire.StoreOutcomeStored {
			t.Fatalf("store %s: %s", name, r.Outcome)
		}
		s.names = append(s.names, name)
		s.revs = append(s.revs, r.Revision)
	}
}

func (s *migrationState) constructors() windowsCredentialsConstructors {
	return windowsCredentialsConstructors{
		credentialManager: func() (Backend, error) { return s.credman, nil },
		dpapiFile:         func(string) (Backend, error) { return s.dpapi, nil },
		lock:              s.lock,
	}
}

// start runs one runtime start to its exit: select and migrate, then open the
// holder on the store it returned, apply every registration and release.
func (s *migrationState) start(t *testing.T, step func(string) error) (string, []wire.ApplyOutcome) {
	t.Helper()
	name, outcomes, _, release := s.startHolder(t, step)
	release()
	return name, outcomes
}

// startHolder runs one runtime start that keeps serving until release, its
// exit. The test's cleanup releases it too.
func (s *migrationState) startHolder(t *testing.T, step func(string) error) (string, []wire.ApplyOutcome, *Holder, func()) {
	t.Helper()
	backend, release := openWindowsStore(s.dir, s.namespace, s.constructors(), step, func(err error) { s.reports = append(s.reports, err) })
	t.Cleanup(release)
	h := open(t, Config{Backend: backend, Namespace: s.namespace, StatePath: filepath.Join(s.dir, "holder.json")})
	return backend.Name(), s.applyAll(h), h, release
}

// applyAll applies every registration through h.
func (s *migrationState) applyAll(h *Holder) []wire.ApplyOutcome {
	var outcomes []wire.ApplyOutcome
	for _, name := range s.names {
		outcomes = append(outcomes, h.Apply(context.Background(), use(name, "huggingface.co"), permit("permitted")).Outcome)
	}
	return outcomes
}

func allApplied(outcomes []wire.ApplyOutcome) bool {
	for _, o := range outcomes {
		if o != wire.ApplyOutcomeApplied {
			return false
		}
	}
	return true
}

var errCrash = errors.New("injected crash")

// TestWindowsMigrationSurvivesACrashAtEveryStep interrupts the migration at
// every step boundary on a state with N registrations. Every interrupted start
// serves N registrations as applied on the binding its marker names, the next
// start completes the migration, and the completed state reads
// windows-dpapi-file with N applied and no Credential Manager item left.
func TestWindowsMigrationSurvivesACrashAtEveryStep(t *testing.T) {
	const n = 3
	// Count the step boundaries of one uninterrupted migration.
	total := 0
	probe := newMigrationState(t, n)
	if store, outcomes := probe.start(t, func(string) error { total++; return nil }); store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("uninterrupted: %s %v", store, outcomes)
	}
	// copy and verify per item, the pending note, the marker, delete per item
	// and finished.
	if total != 3*n+3 {
		t.Fatalf("%d step boundaries, want %d", total, 3*n+3)
	}
	for crashAt := 0; crashAt < total; crashAt++ {
		for _, edit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/edit=%v", crashAt, edit), func(t *testing.T) {
				s := newMigrationState(t, n)
				seen, crashed := 0, ""
				store, outcomes, h, exit := s.startHolder(t, func(step string) error {
					if seen++; seen-1 == crashAt {
						crashed = step
						return errCrash
					}
					return nil
				})
				if !allApplied(outcomes) {
					t.Fatalf("crash at %s: %s reads %v", crashed, store, outcomes)
				}
				if word := strings.TrimSpace(markerWord(t, s.dir)); word != store {
					t.Fatalf("crash at %s: served %s, marker %s", crashed, store, word)
				}
				if edit {
					// Revoke and rotate on the binding the interrupted start serves.
					if r := h.Revoke(owner, s.revs[0], s.names[0]); r.Outcome != wire.RevokeOutcomeRevoked {
						t.Fatalf("revoke: %v", r.Outcome)
					}
					if r := h.Rotate(owner, s.revs[1], wire.Rotation{Name: s.names[1], Secret: []byte("rotated")}); r.Outcome != wire.RotateOutcomeRotated {
						t.Fatalf("rotate: %v", r.Outcome)
					}
				}
				exit()
				store, outcomes = s.start(t, nil)
				if edit {
					outcomes = outcomes[1:]
				}
				if store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
					t.Fatalf("after crash at %s: %s %v", crashed, store, outcomes)
				}
				if stray := s.strayCopies(t); len(stray) != 0 {
					t.Fatalf("after crash at %s: new store keeps %v", crashed, stray)
				}
				if _, err := os.Lstat(windowsMigrationAttempt(s.dir)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("after crash at %s: attempt note left (%v)", crashed, err)
				}
				if len(s.credman.items) != 0 {
					t.Fatalf("after crash at %s: %d Credential Manager items left", crashed, len(s.credman.items))
				}
				if _, err := os.Lstat(windowsMigrationPending(s.dir)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("after crash at %s: pending note left (%v)", crashed, err)
				}
			})
		}
	}
}

// TestEmptyNewStoreNeverTurnsRegistrationsLost: a new store that refuses
// writes or reads back other bytes leaves the state on the Credential Manager
// with every registration applied, and nothing is left in the new store.
func TestEmptyNewStoreNeverTurnsRegistrationsLost(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*namedMemory)
	}{
		{"refuses writes", func(m *namedMemory) { m.putFails = true }},
		{"reads back other bytes", func(m *namedMemory) { m.corrupt = true }},
		{"unreachable", func(m *namedMemory) { m.down = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newMigrationState(t, 2)
			c.set(s.dpapi)
			store, outcomes := s.start(t, nil)
			if store != StoreWindowsCredentialManager || !allApplied(outcomes) {
				t.Fatalf("%s %v", store, outcomes)
			}
			if word := strings.TrimSpace(markerWord(t, s.dir)); word != StoreWindowsCredentialManager {
				t.Fatalf("marker %s", word)
			}
			if len(s.credman.items) != 2 {
				t.Fatalf("credential manager holds %d items", len(s.credman.items))
			}
			s.dpapi.down = false
			if len(s.dpapi.items) != 0 {
				t.Fatalf("new store keeps %d partial copies", len(s.dpapi.items))
			}
		})
	}
}

// TestUnreachableCredentialManagerIsNotMigrated: an old store that cannot be
// read keeps its binding; its registrations read unavailable, never lost.
func TestUnreachableCredentialManagerIsNotMigrated(t *testing.T) {
	s := newMigrationState(t, 2)
	s.credman.down = true
	store, outcomes := s.start(t, nil)
	if store != StoreWindowsCredentialManager {
		t.Fatalf("bound to %s", store)
	}
	for _, o := range outcomes {
		if o != wire.ApplyOutcomeUnavailable {
			t.Fatalf("outcomes %v", outcomes)
		}
	}
	s.credman.down = false
	if store, outcomes := s.start(t, nil); store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("recovered: %s %v", store, outcomes)
	}
}

// TestLinuxStoreMarkerBesideTheFolder: the choice is written beside the
// credentials directory without creating it, replaces the older choice inside
// it, and the inside choice is still read when no marker is beside it.
func TestLinuxStoreMarkerBesideTheFolder(t *testing.T) {
	var opened []string
	constructors := linuxConstructors{
		file: func(dir string) (Backend, error) {
			opened = append(opened, StoreFile+" "+filepath.Base(dir))
			return keychainSelectionBackend(StoreFile), nil
		},
		secretService: func() (Backend, error) { return nil, errors.New("no session bus") },
	}
	dir := filepath.Join(t.TempDir(), "credentials")
	if b, err := openLinuxStore(dir, constructors); err != nil || b.Name() != StoreSecretService {
		t.Fatalf("default: %v %v", b, err)
	}
	if err := WriteLinuxStoreChoice(dir, StoreFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the choice created the credentials directory (%v)", err)
	}
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(dir), "credentials-linux-backend")); err != nil || string(data) != StoreFile+"\n" {
		t.Fatalf("marker %q %v", data, err)
	}
	if b, err := openLinuxStore(dir, constructors); err != nil || b.Name() != StoreFile || opened[0] != "file-0600 items" {
		t.Fatalf("file choice: %v %v %v", b, err, opened)
	}
	if err := WriteLinuxStoreChoice(dir, "plaintext"); err == nil {
		t.Fatal("unknown choice accepted")
	}

	legacy := filepath.Join(t.TempDir(), "credentials")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "backend"), []byte("file-0600\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := openLinuxStore(legacy, constructors); b.Name() != StoreFile {
		t.Fatalf("inside choice ignored: %s", b.Name())
	}
	if err := WriteLinuxStoreChoice(legacy, StoreSecretService); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(legacy, "backend")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inside choice left behind (%v)", err)
	}
	if b, _ := openLinuxStore(legacy, constructors); b.Name() != StoreSecretService {
		t.Fatalf("beside choice ignored: %s", b.Name())
	}

	for _, c := range []struct {
		name      string
		directory bool
		word      string
	}{{"unknown word", false, "plaintext\n"}, {"damaged file-0600", false, "file-06\n"}, {"marker is a directory", true, ""}} {
		damaged := filepath.Join(t.TempDir(), "credentials")
		marker := LinuxStoreMarker(damaged)
		var err error
		if c.directory {
			err = os.MkdirAll(marker, 0o700)
		} else {
			err = os.WriteFile(marker, []byte(c.word), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := openLinuxStore(damaged, constructors)
		if err != nil || b.Name() != unavailableLinuxStore {
			t.Fatalf("%s: %v %v", c.name, b, err)
		}
		if _, err := b.Get("k"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: read %v", c.name, err)
		}
	}
}

// noLock lets a nested start run as if the cross-process lock were absent.
func noLock(string) (func(), bool) { return func() {}, true }

// TestConcurrentStartsNeverTurnRegistrationsLost: a second start runs to
// completion inside the first start's verify, pending and marker steps. With
// the migration lock the nested start serves the marker's binding; without it
// the first start sees the completed migration and keeps the copies. Every
// registration stays applied and the new store keeps N items.
func TestConcurrentStartsNeverTurnRegistrationsLost(t *testing.T) {
	const n = 3
	wait := migrationLockWait
	migrationLockWait = 50 * time.Millisecond
	defer func() { migrationLockWait = wait }()
	for _, locked := range []bool{true, false} {
		for _, at := range []string{stepVerify, stepPending, stepMarker} {
			t.Run(fmt.Sprintf("lock=%v/%s", locked, at), func(t *testing.T) {
				s := newMigrationState(t, n)
				if !locked {
					s.lock = noLock
				}
				ran := false
				var inner *Holder
				store, outcomes, outer, _ := s.startHolder(t, func(step string) error {
					if step == at && !ran {
						ran = true
						innerStore, innerOutcomes, h, _ := s.startHolder(t, nil)
						inner = h
						// Without the lock the nested start migrates; with it, the
						// Credential Manager it cannot migrate reads unavailable.
						if locked && (innerStore != StoreWindowsCredentialManager || !noneLost(innerOutcomes) || allApplied(innerOutcomes)) {
							t.Fatalf("nested start under the lock: %s %v", innerStore, innerOutcomes)
						}
						if !locked && !allApplied(innerOutcomes) {
							t.Fatalf("nested start: %s %v", innerStore, innerOutcomes)
						}
					}
					return nil
				})
				if !ran || !allApplied(outcomes) {
					t.Fatalf("outer start: %v %s %v", ran, store, outcomes)
				}
				// Every participant applies every registration after both starts
				// finished; none reads lost.
				for _, name := range s.names {
					if o := inner.Apply(context.Background(), use(name, "huggingface.co"), permit("permitted")).Outcome; o == wire.ApplyOutcomeLost || (!locked && o != wire.ApplyOutcomeApplied) {
						t.Fatalf("nested start after both finished: %s %v", name, o)
					}
				}
				if outcomes := s.applyAll(outer); !allApplied(outcomes) {
					t.Fatalf("outer start after both finished: %v", outcomes)
				}
				store, outcomes = s.start(t, nil)
				if store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
					t.Fatalf("after: %s %v", store, outcomes)
				}
				if len(s.dpapi.items) != n || len(s.credman.items) != 0 {
					t.Fatalf("new store %d items, Credential Manager %d", len(s.dpapi.items), len(s.credman.items))
				}
			})
		}
	}
}

// TestRevokedSecretStaysGoneAfterAFailedDelete: a Credential Manager Delete
// that fails keeps the pending note; a revoke in that run removes the key from
// the holder state, and the next start still deletes it from the note's list.
func TestRevokedSecretStaysGoneAfterAFailedDelete(t *testing.T) {
	s := newMigrationState(t, 2)
	s.credman.deleteFails = true
	store, outcomes, h, _ := s.startHolder(t, nil)
	if store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("%s %v", store, outcomes)
	}
	if r := h.Revoke(owner, s.revs[0], s.names[0]); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatalf("revoke: %v", r.Outcome)
	}
	s.credman.deleteFails = false
	if store, _ := s.start(t, nil); store != StoreWindowsDPAPIFile {
		t.Fatalf("restart bound to %s", store)
	}
	if len(s.credman.items) != 0 {
		t.Fatalf("Credential Manager keeps %d items", len(s.credman.items))
	}
}

// TestCopiedStateKeepsTheOriginalsItems: state directories with their own
// namespaces over one Credential Manager, and a copy of the first under the
// second's namespace. Each migration deletes only its own namespace's items,
// so no state reads lost.
func TestCopiedStateKeepsTheOriginalsItems(t *testing.T) {
	credman := &namedMemory{memoryBackend: newMemory(), name: StoreWindowsCredentialManager}
	states := make([]*migrationState, 2)
	for i := range states {
		states[i] = &migrationState{dir: filepath.Join(t.TempDir(), "credentials"), credman: credman,
			dpapi: &namedMemory{memoryBackend: newMemory(), name: StoreWindowsDPAPIFile}, namespace: fmt.Sprintf("oa-state%d", i)}
		states[i].register(t, 2)
	}
	data, err := os.ReadFile(filepath.Join(states[0].dir, "holder.json"))
	if err != nil {
		t.Fatal(err)
	}
	copied := &migrationState{dir: filepath.Join(t.TempDir(), "credentials"), credman: credman,
		dpapi: &namedMemory{memoryBackend: newMemory(), name: StoreWindowsDPAPIFile}, namespace: states[1].namespace, names: states[0].names}
	if err := os.MkdirAll(copied.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied.dir, "holder.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if store, outcomes := copied.start(t, nil); store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
		t.Fatalf("copy: %s %v", store, outcomes)
	}
	for i, s := range states {
		if store, outcomes := s.start(t, nil); store != StoreWindowsDPAPIFile || !allApplied(outcomes) {
			t.Fatalf("state %d: %s %v", i, store, outcomes)
		}
	}
	if len(credman.items) != 0 {
		t.Fatalf("Credential Manager keeps %d items", len(credman.items))
	}
}
