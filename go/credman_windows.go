//go:build windows

package credentials

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
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
	// CredEnumerateW serves Targets alone.
	procCredEnumerateW = advapi32.NewProc("CredEnumerateW")
	procCredFree       = advapi32.NewProc("CredFree")
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

// Overlapping calls on an account's Credential Manager lose written items and
// bring deleted ones back, whether they come from one process or several, and
// reads take part: an item read during another call's write can vanish
// (TODO "Windows Credential Manager loses and restores OA items", 2026-10-07).
// Every call this backend makes holds storeSlot in its process and, across the
// processes of the logon session, the named mutex sessionStoreMutex opens.
// The Local\ namespace does not reach the same user's other logon sessions.
// Calls of other programs on the same store are not serialized by it.
var (
	storeSlot      = make(chan struct{}, 1)
	storeMutexOnce sync.Once
	storeMutex     windows.Handle
)

// storeLockWait bounds one call's whole wait for the store, in this process
// and across processes. Tests shorten it.
var storeLockWait = 10 * time.Second

// sessionStoreMutex is the account's Credential Manager lock in this logon
// session, or 0 when it cannot be opened; the process lock alone then remains
// and degraded reports it.
func sessionStoreMutex() windows.Handle {
	storeMutexOnce.Do(func() {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return
		}
		sid := user.User.Sid.String()
		name, err := windows.UTF16PtrFromString(`Local\openabstractions-credential-manager-` + sid)
		if err != nil {
			return
		}
		// An elevated process's default DACL leaves the user's unelevated
		// processes out, and its high label refuses them. The explicit
		// descriptor grants this user and SYSTEM, at medium integrity, so
		// whichever OA process creates the mutex first, the others open it.
		sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)S:(ML;;NW;;;ME)")
		if err != nil {
			return
		}
		sa := windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(sa))
		// CreateMutex returns the existing mutex with ERROR_ALREADY_EXISTS; a
		// name another account created first refuses access and returns 0.
		//unchecked: the handle carries the outcome; ERROR_ALREADY_EXISTS is the shared mutex and a zero handle selects the process lock alone
		if h, _ := windows.CreateMutex(&sa, false, name); h != 0 {
			storeMutex = h
		}
	})
	return storeMutex
}

// degraded names a weaker guarantee than the store word promises, or "".
// Holder.Open reports it once.
func (credentialManager) degraded() string {
	if sessionStoreMutex() == 0 {
		return "store_lock process_only"
	}
	return ""
}

// lockStore serializes one call on the store. The call has one deadline from
// entry: the wait for this process's slot and the wait for the session mutex
// share storeLockWait, so a queue of callers behind a stuck holder each read
// unavailable within it. An abandoned mutex (its holder exited inside a call)
// is taken over.
func lockStore() (func(), error) {
	deadline := time.Now().Add(storeLockWait)
	unavailable := fmt.Errorf("%w: Credential Manager lock", ErrUnavailable)
	timer := time.NewTimer(storeLockWait)
	defer timer.Stop()
	select {
	case storeSlot <- struct{}{}:
	case <-timer.C:
		return nil, unavailable
	}
	release := func() { <-storeSlot }
	h := sessionStoreMutex()
	if h == 0 {
		return release, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		release()
		return nil, unavailable
	}
	// A Windows mutex belongs to a thread.
	runtime.LockOSThread()
	event, err := windows.WaitForSingleObject(h, uint32(remaining.Milliseconds()))
	if err == nil && (event == windows.WAIT_OBJECT_0 || event == windows.WAIT_ABANDONED) {
		return func() {
			//unchecked: this thread owns the mutex it waited for; release fails only for a mutex the thread does not own
			windows.ReleaseMutex(h)
			runtime.UnlockOSThread()
			release()
		}, nil
	}
	runtime.UnlockOSThread()
	release()
	return nil, unavailable
}

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
	unlock, err := lockStore()
	if err != nil {
		return err
	}
	defer unlock()
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
	unlock, err := lockStore()
	if err != nil {
		return nil, err
	}
	defer unlock()
	var cred *credentialW
	if r, _, e := procCredReadW.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&cred))); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		// A blob DPAPI can no longer decrypt is an item the store cannot return,
		// unless the user's DPAPI key is only unreachable for now (CRED-B2).
		if errors.Is(e, windows.ERROR_INVALID_PASSWORD) || errors.Is(e, nteBadKeyState) {
			if dpapiKeyWorks() {
				return nil, ErrNotFound
			}
			return nil, fmt.Errorf("%w: DPAPI user key unreachable: %v", ErrUnavailable, e)
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

// Targets lists the generic credential target names that start with prefix,
// under the store lock. It is not part of Backend: test cleanup reaches it by
// a type assertion on the NewCredentialManager result, so a test that removes
// its own namespace orders its calls with every OA process.
func (credentialManager) Targets(prefix string) ([]string, error) {
	filter, err := windows.UTF16PtrFromString(prefix + "*")
	if err != nil {
		return nil, fmt.Errorf("%w: target filter", ErrUnavailable)
	}
	unlock, err := lockStore()
	if err != nil {
		return nil, err
	}
	defer unlock()
	var count uint32
	var list **credentialW
	if r, _, e := procCredEnumerateW.Call(uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list))); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: CredEnumerateW: %v", ErrUnavailable, e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(list)))
	names := []string{}
	for _, cred := range unsafe.Slice(list, count) {
		names = append(names, windows.UTF16PtrToString(cred.TargetName))
	}
	return names, nil
}

func (credentialManager) Delete(key string) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("%w: target name", ErrUnavailable)
	}
	unlock, err := lockStore()
	if err != nil {
		return err
	}
	defer unlock()
	if r, _, e := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0); r == 0 {
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("%w: CredDeleteW: %v", ErrUnavailable, e)
	}
	return nil
}
