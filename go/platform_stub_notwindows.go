//go:build !windows

package credentials

// NewCredentialManager is Windows only.
func NewCredentialManager() (Backend, error) { return nil, ErrUnsupportedPlatform }

// NewDPAPIFileBackend is Windows only.
func NewDPAPIFileBackend(string) (Backend, error) { return nil, ErrUnsupportedPlatform }
