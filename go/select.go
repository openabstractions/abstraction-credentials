package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

const unavailableMacOSKeychain = "macos-keychain-unavailable"

type macOSKeychainSelection struct {
	Backend      string `json:"backend"`
	KeychainPath string `json:"keychain_path,omitempty"`
}

func validMacOSKeychainPath(path string) bool {
	return strings.HasPrefix(path, "/") && len(path) <= 4095 && !strings.ContainsRune(path, 0) && utf8.ValidString(path)
}

// The marker is beside the credentials directory so a fresh choice is durable
// before that directory is created. Concurrent starts cannot mistake the first
// start's new empty directory for legacy unmarked data-protection state.
func macOSKeychainMarker(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-keychain-backend")
}

func readMacOSKeychainMarker(path string) (macOSKeychainSelection, error) {
	var selection macOSKeychainSelection
	info, err := os.Lstat(path)
	if err != nil {
		return selection, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return selection, errors.New("credentials: invalid macOS Keychain backend marker")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return selection, err
	}
	name := strings.TrimSpace(string(data))
	if name == StoreMacOSKeychain {
		return macOSKeychainSelection{Backend: name}, nil
	}
	if name == StoreMacOSLoginKeychain {
		return macOSKeychainSelection{Backend: name}, errors.New("credentials: login-Keychain marker lacks its native store locator")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selection); err != nil {
		return macOSKeychainSelection{}, errors.New("credentials: unrecognized macOS Keychain backend marker")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return macOSKeychainSelection{}, errors.New("credentials: invalid macOS Keychain backend marker")
	}
	if selection.Backend == StoreMacOSLoginKeychain && validMacOSKeychainPath(selection.KeychainPath) {
		return selection, nil
	}
	if selection.Backend == StoreMacOSKeychain && selection.KeychainPath == "" {
		return selection, nil
	}
	return selection, errors.New("credentials: invalid macOS Keychain backend marker")
}

func selectMacOSKeychainBackend(dir string, loginPath func() (string, error)) (macOSKeychainSelection, error) {
	marker := macOSKeychainMarker(dir)
	if selection, err := readMacOSKeychainMarker(marker); !errors.Is(err, fs.ErrNotExist) {
		return selection, err
	}
	selection := macOSKeychainSelection{Backend: StoreMacOSKeychain}
	var pathErr error
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		selection.Backend = StoreMacOSLoginKeychain
		selection.KeychainPath, pathErr = loginPath()
		if pathErr == nil && !validMacOSKeychainPath(selection.KeychainPath) {
			pathErr = errors.New("credentials: native user Keychain locator is invalid")
		}
		if pathErr != nil {
			// Preserve the deliberate kind when native locator capture fails.
			// This unbound marker remains unavailable until explicitly repaired.
			selection.KeychainPath = ""
		}
	} else if err != nil {
		return selection, err
	}
	data := selection.Backend + "\n"
	if selection.KeychainPath != "" {
		encoded, encodeErr := json.Marshal(selection)
		if encodeErr != nil {
			return selection, encodeErr
		}
		data = string(encoded) + "\n"
	}
	if err := writeMarkerOnce(marker, data); errors.Is(err, fs.ErrExist) {
		// A partly written marker refuses rather than selecting another store.
		// Its complete durable word is used on the next start.
		return readMacOSKeychainMarker(marker)
	} else if err != nil {
		return selection, err
	}
	return selection, pathErr
}

// writeMarkerOnce creates a store marker exclusively and makes it durable. It
// returns an error wrapping fs.ErrExist when another start wrote it first.
func writeMarkerOnce(marker, data string) error {
	parentDir := filepath.Dir(marker)
	if err := os.MkdirAll(parentDir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.WriteString(data); err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	// On macOS, persist the directory entry as well as the marker's contents.
	// Cross-platform selector tests exercise the same exclusive-file behavior.
	if runtime.GOOS == "darwin" {
		parent, err := os.Open(parentDir)
		if err != nil {
			return err
		}
		err = parent.Sync()
		closed = parent.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
	}
	return nil
}

// unavailableWindowsStore is the store word of a Windows state whose marker
// names no store this runtime knows.
const unavailableWindowsStore = "windows-store-unavailable"

// windowsCredentialsMarker is beside the credentials directory, as the macOS
// marker is, so a fresh choice is durable before that directory exists.
func windowsCredentialsMarker(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-windows-backend")
}

func readWindowsCredentialsMarker(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		return "", errors.New("credentials: invalid Windows credentials store marker")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	switch name := strings.TrimSpace(string(data)); name {
	case StoreWindowsDPAPIFile, StoreWindowsCredentialManager:
		return name, nil
	}
	return "", errors.New("credentials: unrecognized Windows credentials store marker")
}

// selectWindowsCredentialsStore reads the state's durable store marker, or
// writes it once. A fresh state, with no credentials directory yet, binds to
// windows-dpapi-file. An unmarked existing state keeps
// windows-credential-manager, where its registrations' items are, until an
// explicit verified migration (abstraction-credentials CONTRACT.md CRED-B1).
func selectWindowsCredentialsStore(dir string) (string, error) {
	marker := windowsCredentialsMarker(dir)
	if name, err := readWindowsCredentialsMarker(marker); !errors.Is(err, fs.ErrNotExist) {
		return name, err
	}
	name := StoreWindowsCredentialManager
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		name = StoreWindowsDPAPIFile
	} else if err != nil {
		return "", err
	}
	if err := writeMarkerOnce(marker, name+"\n"); errors.Is(err, fs.ErrExist) {
		return readWindowsCredentialsMarker(marker)
	} else if err != nil {
		return "", err
	}
	return name, nil
}

type windowsCredentialsConstructors struct {
	credentialManager func() (Backend, error)
	dpapiFile         func(dir string) (Backend, error)
	// lock takes the state's migration lock; nil uses lockMigration.
	lock func(dir string) (func(), bool)
}

// newWindowsCredentialsBackend opens the store the state is bound to. A store
// that cannot be selected or opened stays configured and reads unavailable;
// nothing substitutes another store.
func newWindowsCredentialsBackend(dir string, constructors windowsCredentialsConstructors) Backend {
	name, err := selectWindowsCredentialsStore(dir)
	if err != nil {
		if name == "" {
			name = unavailableWindowsStore
		}
		return Unreachable(name, MaxSecretBytes, err)
	}
	var backend Backend
	if name == StoreWindowsDPAPIFile {
		backend, err = constructors.dpapiFile(filepath.Join(dir, "items"))
	} else {
		backend, err = constructors.credentialManager()
	}
	if err != nil {
		return Unreachable(name, MaxSecretBytes, err)
	}
	return backend
}

type macOSKeychainConstructors struct {
	dataProtection func() (Backend, error)
	loginPath      func() (string, error)
	loginAt        func(string) (Backend, error)
	disableUI      func() error
}

func newMacOSCredentialsBackend(dir string, constructors macOSKeychainConstructors) Backend {
	interactionDisabled := false
	selection, err := selectMacOSKeychainBackend(dir, func() (string, error) {
		if err := constructors.disableUI(); err != nil {
			return "", err
		}
		interactionDisabled = true
		return constructors.loginPath()
	})
	name := selection.Backend
	if name != StoreMacOSKeychain && name != StoreMacOSLoginKeychain {
		name = unavailableMacOSKeychain
	}
	if err != nil {
		return Unreachable(name, MaxSecretBytes, err)
	}
	var backend Backend
	if name == StoreMacOSLoginKeychain {
		if !interactionDisabled {
			err = constructors.disableUI()
		}
		if err == nil {
			backend, err = constructors.loginAt(selection.KeychainPath)
		}
	} else {
		backend, err = constructors.dataProtection()
	}
	if err != nil {
		return Unreachable(name, MaxSecretBytes, err)
	}
	if backend == nil {
		return Unreachable(name, MaxSecretBytes, errors.New("credentials: configured Keychain is unavailable"))
	}
	return backend
}

var loginKeychainReceiverInitialization struct {
	sync.Once
	err error
}

func initializeLoginKeychainReceiver() error {
	loginKeychainReceiverInitialization.Do(func() {
		loginKeychainReceiverInitialization.err = DisableLoginKeychainInteraction()
	})
	return loginKeychainReceiverInitialization.err
}

// machineScopeAccounts are the Windows well-known service accounts:
// LocalSystem, LocalService and NetworkService.
var machineScopeAccounts = []string{"S-1-5-18", "S-1-5-19", "S-1-5-20"}

// MachineScopeAccount reports whether account, a runtime's own account (a
// Windows SID or a POSIX uid), is machine-wide: a Windows service account,
// or root elsewhere. A machine-wide runtime holds no secrets in this version
// (CONTRACT.md CRED-H4): its holder sets Config.MachineScope, and
// OpenPlatformStore opens no store for it.
func MachineScopeAccount(account string) bool {
	return slices.Contains(machineScopeAccounts, account) || account == "0"
}

// OpenPlatformStore opens the platform store the credentials directory dir is
// bound to (CONTRACT.md CRED-B1). Call it before creating dir and before
// Open. account is the runtime's own account; a machine-wide account
// (MachineScopeAccount) opens no store and returns a nil Backend, which a
// holder reads as no_secure_store. A fresh state binds to the user Keychain on
// macOS and to the DPAPI file store on Windows; an unmarked existing Windows
// state is migrated from the Credential Manager by a verified copy (CRED-B3)
// and keeps the Credential Manager while the migration cannot complete. Linux uses Secret Service unless
// the operator chose the file store (WriteLinuxStoreChoice). A selected store
// that cannot be opened stays configured and reads unavailable; nothing
// substitutes another store. It reads no environment. namespace is the
// holder's Config.Namespace (empty: DefaultNamespace); a migration deletes
// only the old items under it, so a copied state never removes the items its
// original still uses. report receives every migration failure once (nil:
// none): the operator learns why a state stays on the Credential Manager.
// release is never nil. Call it once the holder using the store stops serving:
// a Windows state that stays on the Credential Manager holds the migration
// lock until then, so another start neither migrates nor deletes the items
// this one serves (CRED-B3). Elsewhere release does nothing.
func OpenPlatformStore(dir, namespace, account string, report func(error)) (backend Backend, release func(), err error) {
	release = func() {}
	if MachineScopeAccount(account) {
		return nil, release, nil
	}
	switch runtime.GOOS {
	case "windows":
		backend, release = openWindowsStore(dir, namespace, windowsCredentialsConstructors{
			credentialManager: NewCredentialManager,
			dpapiFile:         NewDPAPIFileBackend,
		}, nil, report)
		return backend, release, nil
	case "darwin":
		return newMacOSCredentialsBackend(dir, macOSKeychainConstructors{
			dataProtection: NewKeychain,
			loginPath:      DefaultLoginKeychainPath,
			loginAt:        NewLoginKeychainAt,
			disableUI:      initializeLoginKeychainReceiver,
		}), release, nil
	case "linux":
		backend, err = openLinuxStore(dir, linuxConstructors{
			file:          NewFileBackend,
			secretService: func() (Backend, error) { return NewSecretService("") },
		})
		return backend, release, err
	}
	return nil, release, ErrUnsupportedPlatform
}
