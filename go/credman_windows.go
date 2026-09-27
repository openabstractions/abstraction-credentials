//go:build windows

package credentials

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// credentialManagerMaxBlob is CRED_MAX_CREDENTIAL_BLOB_SIZE.
const credentialManagerMaxBlob = 5 * 512

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW = advapi32.NewProc("CredWriteW")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

// credentialW mirrors CREDENTIALW.
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type credentialManager struct{}

// NewCredentialManager selects the Windows Credential Manager of the account the
// holder runs as: generic credentials with local-machine persistence.
func NewCredentialManager() (Backend, error) {
	if err := advapi32.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return credentialManager{}, nil
}

func (credentialManager) Name() string        { return StoreWindowsCredentialManager }
func (credentialManager) MaxSecretBytes() int { return credentialManagerMaxBlob }

func (credentialManager) Put(key string, secret []byte) error {
	if len(secret) < 1 || len(secret) > credentialManagerMaxBlob {
		return fmt.Errorf("%w: secret outside the Credential Manager bound", ErrUnavailable)
	}
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("%w: target name", ErrUnavailable)
	}
	//unchecked: UTF16PtrFromString only fails on an embedded NUL, and this source is a fixed literal
	user, _ := windows.UTF16PtrFromString("openabstractions")
	cred := credentialW{Type: credTypeGeneric, TargetName: target, CredentialBlobSize: uint32(len(secret)),
		CredentialBlob: &secret[0], Persist: credPersistLocalMachine, UserName: user}
	if r, _, e := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0); r == 0 {
		return fmt.Errorf("%w: CredWriteW: %v", ErrUnavailable, e)
	}
	return nil
}

func (credentialManager) Get(key string) ([]byte, error) {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return nil, fmt.Errorf("%w: target name", ErrUnavailable)
	}
	var cred *credentialW
	if r, _, e := procCredReadW.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&cred))); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		// A blob DPAPI can no longer decrypt is an item the store cannot return.
		if errors.Is(e, windows.ERROR_INVALID_PASSWORD) || errors.Is(e, windows.Errno(0x8009000B)) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: CredReadW: %v", ErrUnavailable, e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return nil, ErrNotFound
	}
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	secret := append([]byte(nil), blob...)
	zero(blob)
	return secret, nil
}

func (credentialManager) Delete(key string) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("%w: target name", ErrUnavailable)
	}
	if r, _, e := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("%w: CredDeleteW: %v", ErrUnavailable, e)
	}
	return nil
}
