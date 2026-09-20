//go:build !windows

package credentials

// NewCredentialManager is Windows only.
func NewCredentialManager() (Backend, error) { return nil, ErrUnsupportedPlatform }
