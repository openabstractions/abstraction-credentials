//go:build darwin && cgo

package credentials

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static OSStatus oa_login_open(SecKeychainRef *out) {
    return SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, out);
}

static OSStatus oa_login_open_path(const char *path, SecKeychainRef *out) {
    return SecKeychainOpen(path, out);
}

static OSStatus oa_login_ready(SecKeychainRef keychain) {
    SecKeychainStatus flags = 0;
    OSStatus st = SecKeychainGetStatus(keychain, &flags);
    if (st != errSecSuccess) return st;
    // A locked store can still report a missing item. Require readable secret
    // material before interpreting any query as loss or applying a deletion.
    if (!(flags & kSecUnlockStateStatus)) return errSecInteractionNotAllowed;
    return errSecSuccess;
}

static CFMutableDictionaryRef oa_login_query(SecKeychainRef keychain, const char *key, int add) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!q) return NULL;
    CFStringRef account = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!account) { CFRelease(q); return NULL; }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, CFSTR("openabstractions"));
    CFDictionarySetValue(q, kSecAttrAccount, account);
    CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    if (add) {
        CFDictionarySetValue(q, kSecUseKeychain, keychain);
    } else {
        const void *one[] = {keychain};
        CFArrayRef list = CFArrayCreate(NULL, one, 1, &kCFTypeArrayCallBacks);
        if (!list) { CFRelease(account); CFRelease(q); return NULL; }
        CFDictionarySetValue(q, kSecMatchSearchList, list);
        CFRelease(list);
    }
    CFRelease(account);
    return q;
}

static OSStatus oa_login_put(SecKeychainRef keychain, const char *key, const unsigned char *secret, long length) {
    OSStatus st = oa_login_ready(keychain);
    if (st != errSecSuccess) return st;
    CFMutableDictionaryRef q = oa_login_query(keychain, key, 0);
    if (!q) return errSecAllocate;
    CFDataRef data = CFDataCreate(NULL, secret, length);
    if (!data) { CFRelease(q); return errSecAllocate; }
    CFMutableDictionaryRef update = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!update) { CFRelease(data); CFRelease(q); return errSecAllocate; }
    CFDictionarySetValue(update, kSecValueData, data);
    st = SecItemUpdate(q, update);
    CFRelease(update);
    CFRelease(q);
    if (st == errSecItemNotFound) {
        q = oa_login_query(keychain, key, 1);
        if (!q) { CFRelease(data); return errSecAllocate; }
        // The native default access policy trusts the creating receiver and
        // tracks its designated requirement. Keep this default creator policy;
        // custom ACLs need their own upgrade and native-authorization design.
        CFDictionarySetValue(q, kSecAttrLabel, CFSTR("OpenAbstractions credential"));
        CFDictionarySetValue(q, kSecValueData, data);
        st = SecItemAdd(q, NULL);
        CFRelease(q);
    }
    CFRelease(data);
    return st;
}

static OSStatus oa_login_get(SecKeychainRef keychain, const char *key, unsigned char **out, long *length) {
    *out = NULL;
    *length = 0;
    OSStatus st = oa_login_ready(keychain);
    if (st != errSecSuccess) return st;
    CFMutableDictionaryRef q = oa_login_query(keychain, key, 0);
    if (!q) return errSecAllocate;
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef data = NULL;
    st = SecItemCopyMatching(q, &data);
    CFRelease(q);
    if (st == errSecItemNotFound) {
        OSStatus ready = oa_login_ready(keychain);
        if (ready != errSecSuccess) return ready;
    }
    if (st != errSecSuccess) return st;
    if (!data || CFGetTypeID(data) != CFDataGetTypeID()) {
        if (data) CFRelease(data);
        return errSecDecode;
    }
    long n = CFDataGetLength((CFDataRef)data);
    if (n < 1 || n > 4096) { CFRelease(data); return errSecDecode; }
    *out = malloc(n);
    if (!*out) { CFRelease(data); return errSecAllocate; }
    memcpy(*out, CFDataGetBytePtr((CFDataRef)data), n);
    *length = n;
    CFRelease(data);
    return errSecSuccess;
}

static OSStatus oa_login_delete(SecKeychainRef keychain, const char *key) {
    OSStatus st = oa_login_ready(keychain);
    if (st != errSecSuccess) return st;
    CFMutableDictionaryRef q = oa_login_query(keychain, key, 0);
    if (!q) return errSecAllocate;
    st = SecItemDelete(q);
    CFRelease(q);
    return st;
}

static void oa_login_release(SecKeychainRef keychain) { CFRelease(keychain); }
static OSStatus oa_login_disable_ui(void) { return SecKeychainSetUserInteractionAllowed(false); }
*/
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"
	"unsafe"
)

type loginKeychain struct{ keychain C.SecKeychainRef }

// NewLoginKeychain pins the current account's default file-based Keychain.
// A locked store stays configured and its operations return ErrUnavailable.
// Its native item ACL trusts this receiving program. Signed upgrades need a
// compatible designated requirement; other programs use the receiver's IPC.
// The constructor leaves process-wide native UI interaction unchanged.
func NewLoginKeychain() (Backend, error) {
	var keychain C.SecKeychainRef
	if st := C.oa_login_open(&keychain); st != C.errSecSuccess {
		return nil, keychainStatus("SecKeychainCopyDomainDefault", st)
	}
	return retainLoginKeychain(keychain)
}

func retainLoginKeychain(keychain C.SecKeychainRef) (Backend, error) {
	if keychain == 0 {
		return nil, fmt.Errorf("%w: no default user Keychain", ErrUnavailable)
	}
	b := &loginKeychain{keychain: keychain}
	runtime.SetFinalizer(b, func(b *loginKeychain) { C.oa_login_release(b.keychain) })
	return b, nil
}

// DefaultLoginKeychainPath captures the native user-domain default Keychain's
// POSIX path without changing the default, search list or interaction policy.
// A receiver records this provider-specific locator before storing secrets.
func DefaultLoginKeychainPath() (string, error) {
	var keychain C.SecKeychainRef
	if st := C.oa_login_open(&keychain); st != C.errSecSuccess {
		return "", keychainStatus("SecKeychainCopyDomainDefault", st)
	}
	if keychain == 0 {
		return "", fmt.Errorf("%w: no default user Keychain", ErrUnavailable)
	}
	defer C.oa_login_release(keychain)
	var path [4096]C.char
	length := C.UInt32(len(path))
	if st := C.SecKeychainGetPath(keychain, &length, &path[0]); st != C.errSecSuccess {
		return "", keychainStatus("SecKeychainGetPath", st)
	}
	if length == 0 || length >= C.UInt32(len(path)) {
		return "", fmt.Errorf("%w: native Keychain path outside bound", ErrUnavailable)
	}
	name := C.GoStringN(&path[0], C.int(length))
	if err := loginKeychainPath(name); err != nil {
		return "", err
	}
	return name, nil
}

// NewLoginKeychainAt reopens a previously OS-selected file Keychain. It never
// creates a Keychain or searches a replacement store when this path is unusable.
// The caller retains this locator with its registration metadata.
func NewLoginKeychainAt(path string) (Backend, error) {
	if err := loginKeychainPath(path); err != nil {
		return nil, err
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var keychain C.SecKeychainRef
	if st := C.oa_login_open_path(cpath, &keychain); st != C.errSecSuccess {
		return nil, keychainStatus("SecKeychainOpen", st)
	}
	return retainLoginKeychain(keychain)
}

func loginKeychainPath(path string) error {
	if !strings.HasPrefix(path, "/") || len(path) > 4095 || strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
		return fmt.Errorf("%w: invalid native Keychain path", ErrUnavailable)
	}
	return nil
}

// DisableLoginKeychainInteraction disables Security-framework file-Keychain UI
// for this process. A dedicated background receiver calls it once before
// serving concurrent requests. General library constructors do not call it.
// Unlocking and native authorization remain explicit owner OS actions.
func DisableLoginKeychainInteraction() error {
	if st := C.oa_login_disable_ui(); st != C.errSecSuccess {
		return keychainStatus("SecKeychainSetUserInteractionAllowed", st)
	}
	return nil
}

func (*loginKeychain) Name() string        { return StoreMacOSLoginKeychain }
func (*loginKeychain) MaxSecretBytes() int { return MaxSecretBytes }

func loginKeychainKey(key string) error {
	if len(key) < 1 || len(key) > 256 {
		return fmt.Errorf("%w: Keychain item key outside bound", ErrUnavailable)
	}
	for _, b := range []byte(key) {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("%w: invalid Keychain item key", ErrUnavailable)
		}
	}
	return nil
}

func (b *loginKeychain) Put(key string, secret []byte) error {
	if err := loginKeychainKey(key); err != nil {
		return err
	}
	if len(secret) < 1 || len(secret) > MaxSecretBytes {
		return fmt.Errorf("%w: secret outside Keychain bound", ErrUnavailable)
	}
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	defer runtime.KeepAlive(b)
	if st := C.oa_login_put(b.keychain, ckey, (*C.uchar)(unsafe.Pointer(&secret[0])), C.long(len(secret))); st != C.errSecSuccess {
		return keychainStatus("SecItemUpdate/Add", st)
	}
	return nil
}

func (b *loginKeychain) Get(key string) ([]byte, error) {
	if err := loginKeychainKey(key); err != nil {
		return nil, err
	}
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	defer runtime.KeepAlive(b)
	var out *C.uchar
	var length C.long
	st := C.oa_login_get(b.keychain, ckey, &out, &length)
	if st == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if st != C.errSecSuccess {
		return nil, keychainStatus("SecItemCopyMatching", st)
	}
	defer C.free(unsafe.Pointer(out))
	blob := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(length))
	secret := append([]byte(nil), blob...)
	zero(blob)
	return secret, nil
}

func (b *loginKeychain) Delete(key string) error {
	if err := loginKeychainKey(key); err != nil {
		return err
	}
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	defer runtime.KeepAlive(b)
	if st := C.oa_login_delete(b.keychain, ckey); st != C.errSecSuccess && st != C.errSecItemNotFound {
		return keychainStatus("SecItemDelete", st)
	}
	return nil
}
