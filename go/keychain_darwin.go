//go:build darwin && cgo

package credentials

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// oa_query builds the generic-password query for one item in the data
// protection keychain, owned by service "openabstractions".
static CFMutableDictionaryRef oa_query(const char *key) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (q == NULL) return NULL;
	CFStringRef account = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
	if (account == NULL) { CFRelease(q); return NULL; }
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, CFSTR("openabstractions"));
	CFDictionarySetValue(q, kSecAttrAccount, account);
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFRelease(account);
	return q;
}

static OSStatus oa_put(const char *key, const unsigned char *secret, long length) {
	CFMutableDictionaryRef q = oa_query(key);
	if (q == NULL) return errSecAllocate;
	CFDataRef data = CFDataCreate(NULL, secret, length);
	if (data == NULL) { CFRelease(q); return errSecAllocate; }
	CFMutableDictionaryRef update = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (update == NULL) { CFRelease(data); CFRelease(q); return errSecAllocate; }
	CFDictionarySetValue(update, kSecValueData, data);
	OSStatus st = SecItemUpdate(q, update);
	if (st == errSecItemNotFound) {
		CFDictionarySetValue(q, kSecValueData, data);
		CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
		st = SecItemAdd(q, NULL);
	}
	CFRelease(update);
	CFRelease(data);
	CFRelease(q);
	return st;
}

// oa_get copies the item into a malloc'd buffer the caller zeroes and frees.
static OSStatus oa_get(const char *key, unsigned char **out, long *length) {
	*out = NULL;
	*length = 0;
	CFMutableDictionaryRef q = oa_query(key);
	if (q == NULL) return errSecAllocate;
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecItemNotFound;
	}
	long n = CFDataGetLength((CFDataRef)result);
	if (n > 0) {
		*out = malloc(n);
		if (*out == NULL) { CFRelease(result); return errSecAllocate; }
		memcpy(*out, CFDataGetBytePtr((CFDataRef)result), n);
	}
	*length = n;
	CFRelease(result);
	return errSecSuccess;
}

static OSStatus oa_delete(const char *key) {
	CFMutableDictionaryRef q = oa_query(key);
	if (q == NULL) return errSecAllocate;
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// oa_accounts copies the account names of every generic password of service
// "openabstractions" into a malloc'd buffer of NUL-terminated strings.
static OSStatus oa_accounts(char **out, long *length) {
	*out = NULL;
	*length = 0;
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (q == NULL) return errSecAllocate;
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, CFSTR("openabstractions"));
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecSuccess;
	}
	CFIndex n = CFArrayGetCount((CFArrayRef)result);
	long size = 0;
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef item = CFArrayGetValueAtIndex((CFArrayRef)result, i);
		CFStringRef account = CFDictionaryGetValue(item, kSecAttrAccount);
		if (account != NULL) size += CFStringGetMaximumSizeForEncoding(CFStringGetLength(account), kCFStringEncodingUTF8) + 1;
	}
	if (size == 0) { CFRelease(result); return errSecSuccess; }
	*out = calloc(size, 1);
	if (*out == NULL) { CFRelease(result); return errSecAllocate; }
	long used = 0;
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef item = CFArrayGetValueAtIndex((CFArrayRef)result, i);
		CFStringRef account = CFDictionaryGetValue(item, kSecAttrAccount);
		if (account == NULL) continue;
		if (CFStringGetCString(account, *out + used, size - used, kCFStringEncodingUTF8)) {
			used += strlen(*out + used) + 1;
		}
	}
	*length = used;
	CFRelease(result);
	return errSecSuccess;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"
)

const keychainMaxSecret = MaxSecretBytes

type keychain struct{}

// NewKeychain selects the data protection keychain of the account the holder
// runs as: generic passwords of service "openabstractions", accessible after
// first unlock on this device only. Process and path proof are unavailable on
// macOS, so the service host refuses every call over IPC until identity proof
// lands; registrations an in-process host makes stay in place.
//
// The data protection keychain serves only a program signed with a keychain
// access group entitlement. Without one, SecItemAdd and SecItemDelete answer
// errSecMissingEntitlement while SecItemCopyMatching answers errSecItemNotFound,
// which a holder would read as a lost item. NewKeychain probes with a delete of
// an item nobody writes and returns an error wrapping ErrUnavailable for such a
// program, so a runtime configures the store as unreachable.
func NewKeychain() (Backend, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("%w: entitlement probe: %v", ErrUnavailable, err)
	}
	ckey := C.CString("entitlement-probe/" + hex.EncodeToString(nonce[:]))
	defer C.free(unsafe.Pointer(ckey))
	if st := C.oa_delete(ckey); st == C.errSecMissingEntitlement {
		return nil, fmt.Errorf("%w: SecItemDelete: OSStatus %d: this program has no keychain access group entitlement, which the data protection keychain requires", ErrUnavailable, int(st))
	}
	return keychain{}, nil
}

func (keychain) Name() string        { return StoreMacOSKeychain }
func (keychain) MaxSecretBytes() int { return keychainMaxSecret }

func keychainStatus(op string, st C.OSStatus) error {
	return fmt.Errorf("%w: %s: OSStatus %d", ErrUnavailable, op, int(st))
}

func (keychain) Put(key string, secret []byte) error {
	if len(secret) < 1 || len(secret) > keychainMaxSecret {
		return fmt.Errorf("%w: secret outside the keychain bound", ErrUnavailable)
	}
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	if st := C.oa_put(ckey, (*C.uchar)(unsafe.Pointer(&secret[0])), C.long(len(secret))); st != C.errSecSuccess {
		return keychainStatus("SecItemAdd", st)
	}
	return nil
}

func (keychain) Get(key string) ([]byte, error) {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	var out *C.uchar
	var length C.long
	st := C.oa_get(ckey, &out, &length)
	if st == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if st != C.errSecSuccess {
		return nil, keychainStatus("SecItemCopyMatching", st)
	}
	if out == nil || length <= 0 {
		return nil, ErrNotFound
	}
	defer C.free(unsafe.Pointer(out))
	blob := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(length))
	secret := append([]byte(nil), blob...)
	zero(blob)
	return secret, nil
}

func (keychain) Delete(key string) error {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	if st := C.oa_delete(ckey); st != C.errSecSuccess && st != C.errSecItemNotFound {
		return keychainStatus("SecItemDelete", st)
	}
	return nil
}

// keychainKeys lists the item keys under prefix. Tests use it to find and
// remove every item of their namespace.
func keychainKeys(prefix string) ([]string, error) {
	var out *C.char
	var length C.long
	st := C.oa_accounts(&out, &length)
	if st == C.errSecItemNotFound {
		return nil, nil
	}
	if st != C.errSecSuccess {
		return nil, keychainStatus("SecItemCopyMatching", st)
	}
	if out == nil {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(out))
	var keys []string
	for _, key := range strings.Split(C.GoStringN(out, C.int(length)), "\x00") {
		if key != "" && strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
