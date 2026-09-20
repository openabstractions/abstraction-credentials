package client

// The generated contract types this package's API reaches, re-exported so an
// application names them through this package and never imports the generated
// one. scripts/idiom_check.py refuses a reachable type this file leaves out.

import (
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

type Subject = wire.Subject

type Scope = wire.Scope

type Registration = wire.Registration

type Rotation = wire.Rotation

type Metadata = wire.Metadata

type StoreResult = wire.StoreResult

type RotateResult = wire.RotateResult

type RevokeResult = wire.RevokeResult

// SecureStore identifies a backend, including provider-defined names.
type SecureStore = wire.SecureStore

const (
	SecureStoreWindowsCredentialManager = wire.SecureStoreWindowsCredentialManager
	SecureStoreSecretService            = wire.SecureStoreSecretService
	SecureStoreFile0600                 = wire.SecureStoreFile0600
	SecureStoreMacosKeychain            = wire.SecureStoreMacosKeychain
	SecureStoreNone                     = wire.SecureStoreNone
)

// SecureStoreValues returns the standard backend names known to this version.
func SecureStoreValues() []SecureStore { return wire.SecureStoreValues() }

type Limits = wire.Limits

type MetadataPage = wire.MetadataPage

type AuditEntry = wire.AuditEntry

type AuditPage = wire.AuditPage

type Use = wire.Use

type CheckResult = wire.CheckResult

type ApplyResult = wire.ApplyResult

type ServiceError = wire.ServiceError

type State = wire.State

const (
	StateActive  = wire.StateActive
	StateExpired = wire.StateExpired
	StateRevoked = wire.StateRevoked
	StateLost    = wire.StateLost
)

// StateValues returns every member of State in declaration order, in a new slice.
func StateValues() []State { return wire.StateValues() }

type StoreOutcome = wire.StoreOutcome

const (
	StoreOutcomeStored          = wire.StoreOutcomeStored
	StoreOutcomeConflict        = wire.StoreOutcomeConflict
	StoreOutcomeInvalid         = wire.StoreOutcomeInvalid
	StoreOutcomeUnsupportedKind = wire.StoreOutcomeUnsupportedKind
	StoreOutcomeNoSecureStore   = wire.StoreOutcomeNoSecureStore
	StoreOutcomeExhausted       = wire.StoreOutcomeExhausted
	StoreOutcomeForbidden       = wire.StoreOutcomeForbidden
	StoreOutcomeUnavailable     = wire.StoreOutcomeUnavailable
)

// StoreOutcomeValues returns every member of StoreOutcome in declaration order, in a new slice.
func StoreOutcomeValues() []StoreOutcome { return wire.StoreOutcomeValues() }

type RotateOutcome = wire.RotateOutcome

const (
	RotateOutcomeRotated       = wire.RotateOutcomeRotated
	RotateOutcomeUnknown       = wire.RotateOutcomeUnknown
	RotateOutcomeConflict      = wire.RotateOutcomeConflict
	RotateOutcomeInvalid       = wire.RotateOutcomeInvalid
	RotateOutcomeNoSecureStore = wire.RotateOutcomeNoSecureStore
	RotateOutcomeForbidden     = wire.RotateOutcomeForbidden
	RotateOutcomeUnavailable   = wire.RotateOutcomeUnavailable
)

// RotateOutcomeValues returns every member of RotateOutcome in declaration order, in a new slice.
func RotateOutcomeValues() []RotateOutcome { return wire.RotateOutcomeValues() }

type RevokeOutcome = wire.RevokeOutcome

const (
	RevokeOutcomeRevoked     = wire.RevokeOutcomeRevoked
	RevokeOutcomeUnknown     = wire.RevokeOutcomeUnknown
	RevokeOutcomeConflict    = wire.RevokeOutcomeConflict
	RevokeOutcomeInvalid     = wire.RevokeOutcomeInvalid
	RevokeOutcomeForbidden   = wire.RevokeOutcomeForbidden
	RevokeOutcomeUnavailable = wire.RevokeOutcomeUnavailable
)

// RevokeOutcomeValues returns every member of RevokeOutcome in declaration order, in a new slice.
func RevokeOutcomeValues() []RevokeOutcome { return wire.RevokeOutcomeValues() }

type PageOutcome = wire.PageOutcome

const (
	PageOutcomePage        = wire.PageOutcomePage
	PageOutcomeGap         = wire.PageOutcomeGap
	PageOutcomeInvalid     = wire.PageOutcomeInvalid
	PageOutcomeForbidden   = wire.PageOutcomeForbidden
	PageOutcomeUnavailable = wire.PageOutcomeUnavailable
)

// PageOutcomeValues returns every member of PageOutcome in declaration order, in a new slice.
func PageOutcomeValues() []PageOutcome { return wire.PageOutcomeValues() }

type ApplyOutcome = wire.ApplyOutcome

const (
	ApplyOutcomeApplied         = wire.ApplyOutcomeApplied
	ApplyOutcomeUnknown         = wire.ApplyOutcomeUnknown
	ApplyOutcomeExpired         = wire.ApplyOutcomeExpired
	ApplyOutcomeRevoked         = wire.ApplyOutcomeRevoked
	ApplyOutcomeLost            = wire.ApplyOutcomeLost
	ApplyOutcomeNotPermitted    = wire.ApplyOutcomeNotPermitted
	ApplyOutcomeTargetRefused   = wire.ApplyOutcomeTargetRefused
	ApplyOutcomeConsumerRefused = wire.ApplyOutcomeConsumerRefused
	ApplyOutcomeUnsupportedKind = wire.ApplyOutcomeUnsupportedKind
	ApplyOutcomeInvalid         = wire.ApplyOutcomeInvalid
	ApplyOutcomeForbidden       = wire.ApplyOutcomeForbidden
	ApplyOutcomeUnavailable     = wire.ApplyOutcomeUnavailable
)

// ApplyOutcomeValues returns every member of ApplyOutcome in declaration order, in a new slice.
func ApplyOutcomeValues() []ApplyOutcome { return wire.ApplyOutcomeValues() }

type ServiceErrorCode = wire.ServiceErrorCode

const (
	ServiceErrorCodeHandlerError   = wire.ServiceErrorCodeHandlerError
	ServiceErrorCodeInvalidResult  = wire.ServiceErrorCodeInvalidResult
	ServiceErrorCodeUnknownVersion = wire.ServiceErrorCodeUnknownVersion
	ServiceErrorCodeUnknownService = wire.ServiceErrorCodeUnknownService
	ServiceErrorCodeUnknownMethod  = wire.ServiceErrorCodeUnknownMethod
	ServiceErrorCodeWrongMode      = wire.ServiceErrorCodeWrongMode
)

// ServiceErrorCodeValues returns every member of ServiceErrorCode in declaration order, in a new slice.
func ServiceErrorCodeValues() []ServiceErrorCode { return wire.ServiceErrorCodeValues() }
