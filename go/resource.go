package credentials

import (
	"bytes"
	"errors"
	"strings"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

const (
	NamedUseResourceProfile    = "abstraction.credentials/named-use@1"
	ScopedUseResourceProfile   = "abstraction.credentials/named-use@2"
	NamedSecretResourceProfile = "abstraction.credentials/named-secret@1"
	FullControlBundle          = "abstraction.credentials/full-control@1"
	SavedSecretCollection      = "abstraction.credentials/saved-app-secrets@1"
	ReaderContract             = "abstraction.credentials/reader@1"
	ScopedHolderContract       = "abstraction.credentials/holder@2"
	ScopedApplierContract      = "abstraction.credentials/applier@2"
	ActionSecretRead           = "abstraction.credentials/secret.read"
	ActionSecretCreate         = "abstraction.credentials/secret.create"
	ActionSecretRotate         = "abstraction.credentials/secret.rotate"
	ActionSecretRevoke         = "abstraction.credentials/secret.revoke"
	ActionSecretMetadataRead   = "abstraction.credentials/secret.metadata.read"
)

var ErrCredentialTarget = errors.New("credentials: invalid credential target")

// PrepareCredentialTarget encodes one validated name slot in the owning wire
// format. Account and requester program remain receiver-bound evidence.
func PrepareCredentialTarget(name string) ([]byte, error) {
	if !namePattern.MatchString(name) {
		return nil, ErrCredentialTarget
	}
	return wire.EncodeCredentialResource(&wire.CredentialResource{Name: name}), nil
}

// DecodeCredentialTarget accepts only the canonical generated encoding. The
// codec grants no membership: each operation checks the current saved-secret
// collection under the holder lock. Runtime local keys are outside it.
func DecodeCredentialTarget(target []byte) (wire.CredentialResource, error) {
	if len(target) == 0 || len(target) > 256 {
		return wire.CredentialResource{}, ErrCredentialTarget
	}
	v, err := wire.DecodeCredentialResource(target)
	if err != nil || v == nil || !namePattern.MatchString(v.Name) || !bytes.Equal(target, wire.EncodeCredentialResource(v)) {
		return wire.CredentialResource{}, ErrCredentialTarget
	}
	return *v, nil
}

// ParseResource reads the current exact named-use profile with the holder's
// name validator. The receiving subject binds account and program separately.
func ParseResource(resource string) (wire.CredentialResource, bool) {
	name, ok := strings.CutPrefix(resource, "credential:")
	if !ok || !namePattern.MatchString(name) {
		return wire.CredentialResource{}, false
	}
	return wire.CredentialResource{Name: name}, true
}
