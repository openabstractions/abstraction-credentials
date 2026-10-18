//go:build windows

package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiMaxSealed bounds a sealed item file: a 4096-byte secret seals to a few
// hundred bytes more.
const dpapiMaxSealed = 64 << 10

type dpapiFile struct{ dir string }

// NewDPAPIFileBackend selects the runtime-only Windows store: one file per item
// under dir, sealed with CryptProtectData in the current user's scope with the
// item key as extra entropy. dir carries a protected DACL that grants the
// current user alone full control, inherited by every item file. Items are
// replaced atomically; the holder serializes writes. A process running as the
// same user can unseal an item, as it can read a Credential Manager item.
func NewDPAPIFileBackend(dir string) (Backend, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("credentials: DPAPI file store directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// A junction or symbolic link reads as a non-directory type here.
	if info.Mode().Type() != fs.ModeDir {
		return nil, errors.New("credentials: DPAPI file store directory is a link or not a directory")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return nil, fmt.Errorf("%w: owner-only access: %v", ErrUnavailable, err)
	}
	removeStaleTemporaries(dir, time.Now().Add(-staleTemporaryAge))
	return dpapiFile{dir: dir}, nil
}

// staleTemporaryAge is how old a Put's temporary file must be before a later
// open removes it; a Put in flight replaces or removes its own within it.
const staleTemporaryAge = time.Minute

// removeStaleTemporaries deletes ".item-*" files a crashed Put left behind
// that were last written before cutoff. Item files never carry that prefix.
func removeStaleTemporaries(dir string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".item-") || !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			//unchecked: best-effort removal of an abandoned temporary; one still open is left for the next open
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func (dpapiFile) Name() string        { return StoreWindowsDPAPIFile }
func (dpapiFile) MaxSecretBytes() int { return MaxSecretBytes }

// path names an item by the SHA-256 of its key, which keeps every name short;
// the key itself is the sealing entropy, so a file moved to another name does
// not unseal there.
func (b dpapiFile) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(b.dir, hex.EncodeToString(sum[:]))
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a DPAPI output blob, zeroes it and frees it.
func takeBlob(out windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	data := unsafe.Slice(out.Data, out.Size)
	copied := append([]byte(nil), data...)
	zero(data)
	//unchecked: LocalFree fails only for a handle LocalAlloc did not return; DPAPI allocated this one
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return copied
}

// seal and unseal are CryptProtectData and CryptUnprotectData in the current
// user's scope with no UI; tests stand in failures.
var (
	seal = func(data, entropy []byte) ([]byte, error) {
		var out windows.DataBlob
		if err := windows.CryptProtectData(blob(data), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
			return nil, err
		}
		return takeBlob(out), nil
	}
	unseal = func(sealed, entropy []byte) ([]byte, error) {
		var out windows.DataBlob
		if err := windows.CryptUnprotectData(blob(sealed), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
			return nil, err
		}
		return takeBlob(out), nil
	}
)

const (
	nteBadData     = windows.Errno(0x80090005) // NTE_BAD_DATA
	nteBadKeyState = windows.Errno(0x8009000B) // NTE_BAD_KEY_STATE
)

// unsealOutcome classifies a CryptUnprotectData failure (CRED-B2). A failure
// in the blob itself (damaged, without DPAPI's header, sealed to other
// entropy, which reads ERROR_INVALID_DATA, or no DPAPI header, which reads
// ERROR_INVALID_PARAMETER since every other argument is well formed) is an
// item the store no longer has: ErrNotFound. A key-state or
// password failure is ambiguous: the user's DPAPI key may be gone for good or
// only unreachable for now (profile not loaded, a batch or S4U logon, a
// roaming master key not yet synchronized). A fresh canary decides: when this
// process can seal and unseal now, the key works and the item is lost;
// otherwise the store is unavailable. Any other failure is unavailable.
func unsealOutcome(err error) error {
	for _, code := range []windows.Errno{windows.ERROR_INVALID_DATA, windows.ERROR_INVALID_PARAMETER, nteBadData} {
		if errors.Is(err, code) {
			return ErrNotFound
		}
	}
	if errors.Is(err, nteBadKeyState) || errors.Is(err, windows.ERROR_INVALID_PASSWORD) {
		if dpapiKeyWorks() {
			return ErrNotFound
		}
		return fmt.Errorf("%w: DPAPI user key unreachable: %v", ErrUnavailable, err)
	}
	return fmt.Errorf("%w: CryptUnprotectData: %v", ErrUnavailable, err)
}

// dpapiKeyWorks seals and unseals a throwaway value with the store's flags.
func dpapiKeyWorks() bool {
	canary := []byte("openabstractions dpapi canary")
	entropy := []byte("openabstractions/dpapi-canary")
	sealed, err := seal(canary, entropy)
	if err != nil {
		return false
	}
	opened, err := unseal(sealed, entropy)
	defer zero(opened)
	return err == nil && string(opened) == string(canary)
}

func (b dpapiFile) Put(key string, secret []byte) error {
	if len(secret) < 1 || len(secret) > MaxSecretBytes {
		return fmt.Errorf("%w: secret outside the store bound", ErrUnavailable)
	}
	sealed, err := seal(secret, []byte(key))
	if err != nil {
		return fmt.Errorf("%w: CryptProtectData: %v", ErrUnavailable, err)
	}
	tmp, err := os.CreateTemp(b.dir, ".item-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	name := tmp.Name()
	_, err = tmp.Write(sealed)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = moveReplace(name, b.path(key))
	}
	if err != nil {
		//unchecked: best-effort removal of the temporary file on a path that already returns a definite error
		os.Remove(name)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func moveReplace(from, to string) error {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func (b dpapiFile) Get(key string) ([]byte, error) {
	path, err := windows.UTF16PtrFromString(b.path(key))
	if err != nil {
		return nil, fmt.Errorf("%w: item path", ErrUnavailable)
	}
	// FILE_SHARE_DELETE lets a concurrent replace or delete proceed; the open
	// reparse-point flag keeps a planted link from being followed.
	h, err := windows.CreateFile(path, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	f := os.NewFile(uintptr(h), "credential item")
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, fmt.Errorf("%w: item is a link or a directory", ErrUnavailable)
	}
	sealed, err := io.ReadAll(io.LimitReader(f, dpapiMaxSealed+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(sealed) == 0 || len(sealed) > dpapiMaxSealed {
		return nil, ErrNotFound
	}
	secret, err := unseal(sealed, []byte(key))
	if err != nil {
		return nil, unsealOutcome(err)
	}
	if len(secret) == 0 || len(secret) > MaxSecretBytes {
		zero(secret)
		return nil, ErrNotFound
	}
	return secret, nil
}

func (b dpapiFile) Delete(key string) error {
	if err := os.Remove(b.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}
