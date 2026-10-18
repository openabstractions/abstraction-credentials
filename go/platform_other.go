//go:build !darwin || !cgo

package credentials

// NewKeychain is the macOS Keychain backend. It needs darwin with cgo; every
// other build refuses with ErrUnsupportedPlatform.
func NewKeychain() (Backend, error) { return nil, ErrUnsupportedPlatform }

// NewLoginKeychain needs the native macOS Security framework and cgo.
func NewLoginKeychain() (Backend, error) { return nil, ErrUnsupportedPlatform }

// DefaultLoginKeychainPath needs the native macOS Security framework.
func DefaultLoginKeychainPath() (string, error) { return "", ErrUnsupportedPlatform }

// NewLoginKeychainAt needs the native macOS Security framework and cgo.
func NewLoginKeychainAt(string) (Backend, error) { return nil, ErrUnsupportedPlatform }

// DisableLoginKeychainInteraction needs the native macOS Security framework.
func DisableLoginKeychainInteraction() error { return ErrUnsupportedPlatform }
