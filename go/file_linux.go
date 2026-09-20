//go:build linux

package credentials

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type fileBackend struct{ dir string }

// NewFileBackend selects the explicit opt-in file store: one file per item under
// dir, directory 0700 and files 0600 owned by this uid, opened without following
// symbolic links. Items are readable by every process of the same uid and by
// root; nothing is encrypted at rest.
func NewFileBackend(dir string) (Backend, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("credentials: file backend directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Getuid() {
		return nil, errors.New("credentials: file backend directory is not a directory owned by this uid")
	}
	if st.Mode&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return fileBackend{dir: dir}, nil
}

func (fileBackend) Name() string        { return StoreFile }
func (fileBackend) MaxSecretBytes() int { return MaxSecretBytes }

func (b fileBackend) path(key string) string {
	return filepath.Join(b.dir, hex.EncodeToString([]byte(key)))
}

func (b fileBackend) Put(key string, secret []byte) error {
	tmp, err := os.CreateTemp(b.dir, ".item-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	name := tmp.Name()
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(secret)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, b.path(key))
	}
	if err != nil {
		os.Remove(name)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (b fileBackend) Get(key string) ([]byte, error) {
	fd, err := unix.Open(b.path(key), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	f := os.NewFile(uintptr(fd), "credential item")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%w: item file permissions or owner changed", ErrUnavailable)
	}
	secret, err := io.ReadAll(io.LimitReader(f, MaxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(secret) == 0 || len(secret) > MaxSecretBytes {
		zero(secret)
		return nil, ErrNotFound
	}
	return secret, nil
}

func (b fileBackend) Delete(key string) error {
	if err := os.Remove(b.path(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}
