//go:build !linux

package credentials

// NewSecretService is Linux only.
func NewSecretService(address string) (Backend, error) { return nil, ErrUnsupportedPlatform }

// NewFileBackend is Linux only.
func NewFileBackend(dir string) (Backend, error) { return nil, ErrUnsupportedPlatform }
