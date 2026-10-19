package credentials

import (
	"errors"
	"fmt"
)

// OSStatus values of the Security framework the data protection keychain
// backend classifies. They are fixed by Apple's SecBase.h; keeping them here
// lets the classification compile and run without cgo on every platform.
const (
	osStatusSuccess               = 0
	osStatusItemNotFound          = -25300
	osStatusInteractionNotAllowed = -25308
	osStatusMissingEntitlement    = -34018
	keychainCanaryKey             = "store-canary"
	keychainCanaryValue           = "openabstractions store canary"
)

// keychainGetResult classifies the answer of SecItemCopyMatching for one item.
// errSecItemNotFound reads ErrNotFound only when probe confirms the store
// readable; empty data reads ErrUnavailable.
func keychainGetResult(st int32, data []byte, probe func() error) ([]byte, error) {
	switch {
	case st == osStatusItemNotFound:
		return nil, confirmNotFound(probe)
	case st != osStatusSuccess:
		return nil, osStatusError("SecItemCopyMatching", st)
	case len(data) == 0:
		return nil, fmt.Errorf("%w: SecItemCopyMatching returned no data", ErrUnavailable)
	}
	return data, nil
}

// keychainDeleteProbe classifies the delete of an item nobody writes. An
// entitled keychain answers success or errSecItemNotFound.
func keychainDeleteProbe(st int32) error {
	switch st {
	case osStatusSuccess, osStatusItemNotFound:
		return nil
	case osStatusMissingEntitlement:
		return fmt.Errorf("%w: SecItemDelete: OSStatus %d: this program has no keychain access group entitlement, which the data protection keychain requires", ErrUnavailable, st)
	}
	return osStatusError("SecItemDelete probe", st)
}

// keychainCanary reads the canary item, of the same accessibility class as
// every credential, with its data. A store that cannot decrypt items, such as
// a device before first unlock, fails the read or the write that creates a
// missing canary. get returns the status and data of a read; put writes the
// canary and returns its status.
func keychainCanary(get func() (int32, []byte), put func() int32) error {
	st, data := get()
	if st == osStatusItemNotFound {
		if st = put(); st != osStatusSuccess {
			return osStatusError("canary SecItemAdd", st)
		}
		st, data = get()
	}
	if st != osStatusSuccess {
		return osStatusError("canary SecItemCopyMatching", st)
	}
	if string(data) != keychainCanaryValue {
		return errors.Join(ErrUnavailable, errors.New("canary read back different data"))
	}
	return nil
}

func osStatusError(op string, st int32) error {
	return fmt.Errorf("%w: %s: OSStatus %d", ErrUnavailable, op, st)
}
