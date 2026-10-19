package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	cas "github.com/openabstractions/abstraction-cas/go"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Migration steps, named for fault injection. A step hook that fails stops the
// migration where it stands, as a crash would.
const (
	stepCopy     = "copy"
	stepVerify   = "verify"
	stepPending  = "pending"
	stepMarker   = "marker"
	stepDelete   = "delete"
	stepFinished = "finished"
)

// migrationLockWait bounds how long a start waits for another start's
// selection and migration of the same state.
var migrationLockWait = 10 * time.Second

var syncMigrationDir = cas.SyncDir

// A removed attempt note must reach its directory before deleting old items.
// The same owner flushes removal of the terminal pending note and cleanup.
func removeMigrationNote(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Absence may be an earlier unlink whose directory flush failed. A retry
	// must receive that barrier before deleting any old Credential Manager item.
	return syncMigrationDir(filepath.Dir(path))
}

// errSuperseded stops a migration another start completed meanwhile.
var errSuperseded = errors.New("credentials: migration completed by another start")

// maxPendingNote bounds the pending note: the migrated key list.
const maxPendingNote = 4 << 20

// windowsMigrationPending is beside the credentials directory while the
// Credential Manager items of a completed migration are being removed.
func windowsMigrationPending(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-windows-migrated")
}

// windowsMigrationAttempt is beside the credentials directory while a
// migration copies items. It lists the keys the attempt may copy into the new
// store, so a later attempt removes copies an interrupted one left there.
func windowsMigrationAttempt(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-windows-migrating")
}

// windowsMigrationLock is beside the credentials directory. Every start holds
// it across selection and migration of the state, and a start serving the
// windows-credential-manager binding holds it until its release.
func windowsMigrationLock(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-windows-migrate.lock")
}

// heldLocks keeps every held lock file reachable until its release: a lock
// file the collector finalized would close and drop the lock while its holder
// still serves.
var heldLocks sync.Map

// lockMigration takes the state's migration lock, waiting up to
// migrationLockWait. It returns false when the lock is held elsewhere. The
// returned release closes the lock file once; later calls do nothing.
func lockMigration(dir string) (func(), bool) {
	path := windowsMigrationLock(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false
	}
	deadline := time.Now().Add(migrationLockWait)
	for !tryLockFile(f) {
		if time.Now().After(deadline) {
			f.Close()
			return nil, false
		}
		time.Sleep(20 * time.Millisecond)
	}
	heldLocks.Store(f, struct{}{})
	var once sync.Once
	return func() {
		once.Do(func() {
			heldLocks.Delete(f)
			//unchecked: closing drops the lock; a close failure leaves nothing to undo
			f.Close()
		})
	}, true
}

// pendingNote is the durable record of a migration whose old items are being
// removed: the old store and every key the migration moved.
type pendingNote struct {
	Store string   `json:"store"`
	Keys  []string `json:"keys"`
}

func readPendingNote(path string) (pendingNote, error) {
	var note pendingNote
	info, err := os.Lstat(path)
	if err != nil {
		return note, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPendingNote {
		return note, errors.New("credentials: invalid migration note")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return note, err
	}
	if json.Unmarshal(data, &note) != nil {
		// A note holding only the store word names no keys.
		note = pendingNote{Store: strings.TrimSpace(string(data))}
	}
	return note, nil
}

// storeKeys are the store items the holder state in dir refers to: every
// record's item and every item awaiting collection. A missing state has none.
func storeKeys(dir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "holder.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 {
		return nil, errors.New("credentials: state file unreadable")
	}
	var keys []string
	for _, records := range state.Accounts {
		for _, r := range records {
			if r != nil && r.Key != "" {
				keys = append(keys, r.Key)
			}
		}
	}
	keys = append(keys, state.Garbage...)
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

// ownedKeys are the keys under namespace. Only these are deleted from the old
// store: an item outside it belongs to another state that shares the store,
// such as the original of a copied state directory.
func ownedKeys(keys []string, namespace string) []string {
	var owned []string
	for _, key := range keys {
		if strings.HasPrefix(key, namespace+"/") {
			owned = append(owned, key)
		}
	}
	return owned
}

// migrateStore copies every item the holder state in dir refers to from one
// store to another, reads each copy back, and only then calls rebind, which
// durably moves the binding to the new store. Old items under namespace are
// deleted after the rebind. An item the old store does not hold is skipped:
// it is absent on either binding. Any failure before rebind leaves the old
// binding in force with all its items, so an empty or partial new store never
// turns a registration into lost (VISION.md "a stored secret stays"). rebound
// reports whether the binding already names the new store; copies are never
// deleted once it does. The attempt note lists the keys this attempt may copy;
// a later attempt first deletes those copies from the new store, so a copy an
// interrupted attempt left there never outlives a revoke or rotation on the
// old store. A listed key the state still refers to and the old store no
// longer holds keeps its copy: the old store's deletes may have persisted while
// the marker and note writes before them did not.
func migrateStore(dir, namespace string, from, to Backend, pending, attempt string, rebind func() error, rebound func() bool, step func(string) error) error {
	if step == nil {
		step = func(string) error { return nil }
	}
	keys, err := storeKeys(dir)
	if err != nil {
		return err
	}
	prior, err := readPendingNote(attempt)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, key := range prior.Keys {
		// A key the state still refers to and the old store no longer holds
		// keeps its copy: keys carry the revision, so the copy is that same
		// secret, and it may be the only one left.
		if slices.Contains(keys, key) {
			secret, err := from.Get(key)
			clear(secret)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
		}
		if err := to.Delete(key); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	record, err := json.Marshal(pendingNote{Store: to.Name(), Keys: keys})
	if err != nil {
		return err
	}
	if err := replaceMarker(attempt, string(record)+"\n"); err != nil {
		return err
	}
	var copied []string
	abandon := func(err error) error {
		if rebound() {
			return errSuperseded
		}
		left := false
		for _, key := range copied {
			if to.Delete(key) != nil {
				left = true
			}
		}
		if !left {
			err = errors.Join(err, removeMigrationNote(attempt))
		}
		return err
	}
	for _, key := range keys {
		if err := step(stepCopy); err != nil {
			return err
		}
		secret, err := from.Get(key)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return abandon(err)
		}
		err = to.Put(key, secret)
		clear(secret)
		if err != nil {
			return abandon(err)
		}
		copied = append(copied, key)
	}
	for _, key := range copied {
		if err := step(stepVerify); err != nil {
			return err
		}
		want, err := from.Get(key)
		if errors.Is(err, ErrNotFound) && rebound() {
			return errSuperseded
		}
		if err != nil {
			return abandon(err)
		}
		got, err := to.Get(key)
		same := err == nil && bytes.Equal(want, got)
		clear(want)
		clear(got)
		if !same {
			return abandon(fmt.Errorf("%w: copy of a migrated item did not read back", ErrUnavailable))
		}
	}
	if err := step(stepPending); err != nil {
		return err
	}
	note, err := json.Marshal(pendingNote{Store: from.Name(), Keys: ownedKeys(keys, namespace)})
	if err != nil {
		return abandon(err)
	}
	if err := replaceMarker(pending, string(note)+"\n"); err != nil {
		return abandon(err)
	}
	if err := step(stepMarker); err != nil {
		return err
	}
	if err := rebind(); err != nil {
		if rebound() {
			return errSuperseded
		}
		err = errors.Join(err, removeMigrationNote(pending))
		return abandon(err)
	}
	if err := removeMigrationNote(attempt); err != nil {
		return err
	}
	return finishMigration(ownedKeys(keys, namespace), from, pending, step)
}

// finishMigration deletes the old store's items after the binding moved, then
// removes the pending note. A failed delete keeps the note, which lists the
// keys; the next start repeats the deletes from that list.
func finishMigration(keys []string, from Backend, pending string, step func(string) error) error {
	for _, key := range keys {
		if err := step(stepDelete); err != nil {
			return err
		}
		if err := from.Delete(key); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	if err := step(stepFinished); err != nil {
		return err
	}
	return removeMigrationNote(pending)
}

// openWindowsStore binds dir's state (newWindowsCredentialsBackend) and moves
// a Credential Manager state to windows-dpapi-file (CRED-B3): at start, before
// the holder opens, under the state's migration lock. A migration that cannot
// complete leaves the state on the Credential Manager, which is returned, and
// is tried again at the next start. A start that cannot take the lock leaves
// migration to the start holding it: a state bound to windows-dpapi-file is
// served from it, and a Credential Manager state reads unavailable, since the
// start holding the lock may be moving its items. A start that returns the
// windows-credential-manager binding keeps the lock until it calls release, so
// no other start migrates and deletes the items it still serves; release is
// for when its holder stops serving. Every other start's release does nothing.
// report receives every migration failure once; nil reports nothing.
func openWindowsStore(dir, namespace string, constructors windowsCredentialsConstructors, step func(string) error, report func(error)) (Backend, func()) {
	if step == nil {
		step = func(string) error { return nil }
	}
	if report == nil {
		report = func(error) {}
	}
	if namespace == "" {
		namespace = DefaultNamespace
	}
	lock := constructors.lock
	if lock == nil {
		lock = lockMigration
	}
	unlock, locked := lock(dir)
	backend := openWindowsStoreLocked(dir, namespace, constructors, step, report, locked)
	if !locked {
		return backend, func() {}
	}
	if backend.Name() == StoreWindowsCredentialManager {
		return backend, unlock
	}
	unlock()
	return backend, func() {}
}

// openWindowsStoreLocked is openWindowsStore after the lock attempt; locked
// reports whether this start holds the lock.
func openWindowsStoreLocked(dir, namespace string, constructors windowsCredentialsConstructors, step func(string) error, report func(error), locked bool) Backend {
	backend := newWindowsCredentialsBackend(dir, constructors)
	if !locked {
		if backend.Name() == StoreWindowsCredentialManager {
			err := errors.New("credentials: another start holds the migration lock")
			report(err)
			return Unreachable(StoreWindowsCredentialManager, MaxSecretBytes, err)
		}
		return backend
	}
	switch backend.Name() {
	case StoreWindowsDPAPIFile:
		if err := removeMigrationNote(windowsMigrationAttempt(dir)); err != nil {
			report(fmt.Errorf("credentials: removing migration attempt note: %w", err))
			return backend
		}
		pending := windowsMigrationPending(dir)
		note, err := readPendingNote(pending)
		if errors.Is(err, fs.ErrNotExist) {
			return backend
		}
		if err != nil {
			report(fmt.Errorf("credentials: migration note: %w", err))
			return backend
		}
		old, err := constructors.credentialManager()
		if err == nil {
			keys := note.Keys
			if current, err := storeKeys(dir); err == nil {
				keys = append(keys, ownedKeys(current, namespace)...)
				slices.Sort(keys)
				keys = slices.Compact(keys)
			}
			err = finishMigration(keys, old, pending, step)
		}
		if err != nil {
			report(fmt.Errorf("credentials: removing migrated Credential Manager items: %w", err))
		}
		return backend
	case StoreWindowsCredentialManager:
	default:
		return backend
	}
	if _, isUnreachable := backend.(unreachable); isUnreachable {
		return backend
	}
	target, err := constructors.dpapiFile(filepath.Join(dir, "items"))
	if err != nil {
		report(fmt.Errorf("credentials: migration to windows-dpapi-file: %w", err))
		return backend
	}
	marker := windowsCredentialsMarker(dir)
	rebind := func() error {
		return replaceMarker(marker, StoreWindowsDPAPIFile+"\n")
	}
	rebound := func() bool {
		word, err := readWindowsCredentialsMarker(marker)
		return err == nil && word == StoreWindowsDPAPIFile
	}
	err = migrateStore(dir, namespace, backend, target, windowsMigrationPending(dir), windowsMigrationAttempt(dir), rebind, rebound, step)
	if err != nil && !errors.Is(err, errSuperseded) {
		report(fmt.Errorf("credentials: migration to windows-dpapi-file: %w", err))
	}
	if err == nil || rebound() {
		return target
	}
	return backend
}
