//go:build !darwin || !cgo

package credentials

// NewKeychain is the macOS Keychain backend. It needs darwin with cgo; every
// other build refuses with ErrUnsupportedPlatform.
func NewKeychain() (Backend, error) { return nil, ErrUnsupportedPlatform }
