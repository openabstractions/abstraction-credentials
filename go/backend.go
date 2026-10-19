// Package credentials is the Go provider of abstraction.credentials: a holder of
// named secrets in one configured platform store, with metadata, revisions,
// tombstones, loss detection and a bounded audit journal.
package credentials

import (
	"errors"
	"fmt"
)

// Backend is one platform secret store. Keys are opaque, at most 256 bytes of
// printable ASCII. Implementations never log or wrap secret bytes into errors.
type Backend interface {
	// Name is the Limits.secure_store word for this store.
	Name() string
	// MaxSecretBytes is the largest secret this store accepts, at most 4096.
	MaxSecretBytes() int
	// Put writes or replaces the item. Failures wrap ErrUnavailable.
	Put(key string, secret []byte) error
	// Get returns a fresh copy of the item. An absent or undecryptable item
	// returns ErrNotFound; a store that cannot be reached wraps ErrUnavailable.
	Get(key string) ([]byte, error)
	// Delete removes the item. An absent item is success.
	Delete(key string) error
}

var (
	// ErrNotFound is an item the store no longer holds or can no longer decrypt.
	ErrNotFound = errors.New("credentials: item absent from the platform store")
	// ErrUnavailable is a platform store that could not be reached.
	ErrUnavailable = errors.New("credentials: platform store unavailable")
	// ErrUnsupportedPlatform is a backend constructor on a platform it does not serve.
	ErrUnsupportedPlatform = errors.New("credentials: backend unsupported on this platform")
)

// confirmNotFound reads a store's "no such item" answer as ErrNotFound only
// when probe, a second answer from the same store, shows it unlocked and
// entitled: the Keychain reads its canary item back, Secret Service finds the
// default collection unlocked. A store whose lookup cannot tell an absent item from
// a locked, replaced or unentitled store (Keychain, Secret Service) calls it
// before answering ErrNotFound, which a holder records as lost. A failed probe
// wraps ErrUnavailable and the record keeps its state.
func confirmNotFound(probe func() error) error {
	if probe == nil {
		return fmt.Errorf("%w: not-found answer without a store probe", ErrUnavailable)
	}
	if err := probe(); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return err
		}
		return fmt.Errorf("%w: store probe: %v", ErrUnavailable, err)
	}
	return ErrNotFound
}

// Secure store words reported in Limits.secure_store.
const (
	StoreWindowsCredentialManager = "windows-credential-manager"
	// StoreWindowsDPAPIFile is the runtime-only Windows store: DPAPI-sealed
	// item files under the state directory. A provider word, as
	// StoreMacOSLoginKeychain is.
	StoreWindowsDPAPIFile = "windows-dpapi-file"
	StoreSecretService    = "secret-service"
	StoreFile             = "file-0600"
	StoreMacOSKeychain    = "macos-keychain"
	// StoreMacOSLoginKeychain identifies the native user file-based Keychain.
	// This provider word preserves the separate data-protection store name.
	StoreMacOSLoginKeychain = "macos-login-keychain"
	StoreNone               = "none"
)

// MaxSecretBytes is the contract ceiling for any store.
const MaxSecretBytes = 4096

// Unreachable is a configured store that cannot be reached: every operation
// reads ErrUnavailable with cause. A runtime configures it when its default
// store is absent, for example Secret Service without a session bus, so calls
// read unavailable rather than no_secure_store and nothing substitutes a store.
func Unreachable(name string, maxSecretBytes int, cause error) Backend {
	return unreachable{name: name, max: maxSecretBytes, cause: cause}
}

type unreachable struct {
	name  string
	max   int
	cause error
}

func (u unreachable) Name() string               { return u.name }
func (u unreachable) MaxSecretBytes() int        { return u.max }
func (u unreachable) err() error                 { return fmt.Errorf("%w: %v", ErrUnavailable, u.cause) }
func (u unreachable) Put(string, []byte) error   { return u.err() }
func (u unreachable) Get(string) ([]byte, error) { return nil, u.err() }
func (u unreachable) Delete(string) error        { return u.err() }
