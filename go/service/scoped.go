package service

import (
	"context"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	identity "github.com/openabstractions/abstraction-identity"
)

type nativePeerContextKey struct{}

// PeerFromContext returns only the peer this Credentials receiving boundary
// attached for the native subject's optional publisher explanation.
func PeerFromContext(ctx context.Context) *identity.Peer {
	peer, _ := ctx.Value(nativePeerContextKey{}).(*identity.Peer)
	return peer
}

// Operation is compiled receiving-host evidence for one owning target. It is
// never an authority field accepted from a requester.
type Operation struct {
	Action, Profile string
	Target          []byte
}

type ScopedDecision func(context.Context, wire.Subject, Operation, string) credentials.Authorization
type LegacyDecision func(context.Context, wire.Subject, string, string, *Operation) credentials.Authorization

// AuthorizationConfig injects the shared Rights owner. Configure before Serve.
// Quiet and Legacy must not admit Asks or reenter Holder/backend. Admit may
// admit a missing-permission Ask and therefore always runs outside Holder.mu.
type AuthorizationConfig struct {
	Admit  ScopedDecision
	Quiet  ScopedDecision
	Legacy LegacyDecision
}

func (h *Host) ScopedAvailable() bool {
	return h.Authorization.Admit != nil && h.Authorization.Quiet != nil && h.Authorization.Legacy != nil
}
func (h *Host) ScopedApplierAvailable() bool { return h.ScopedAvailable() && h.ApplierAvailable() }

func (r *receiver) bound(subject wire.Subject) bool {
	if r.ctx.Err() != nil || r.call.Recheck() != nil {
		return false
	}
	current, _, ok := r.caller()
	return ok && current == subject
}

func (r *receiver) scoped(subject wire.Subject, action, profile, name string) (credentials.ScopedAuthorization, bool) {
	target, err := credentials.PrepareCredentialTarget(name)
	if err != nil {
		return credentials.ScopedAuthorization{}, false
	}
	op := Operation{Action: action, Profile: profile, Target: target}
	_, peer, _ := r.caller()
	invoke := func(check ScopedDecision, expected string) credentials.Authorization {
		if !r.host.ScopedAvailable() {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		if !r.bound(subject) {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		if check == nil {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		v := check(context.WithValue(r.ctx, nativePeerContextKey{}, peer), subject, op, expected)
		if r.ctx.Err() != nil {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		if !r.bound(subject) {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		return v
	}
	return credentials.ScopedAuthorization{
		Admit: func() credentials.Authorization { return invoke(r.host.Authorization.Admit, "") },
		Check: func(expected string) credentials.Authorization { return invoke(r.host.Authorization.Quiet, expected) },
	}, true
}

// legacyAdmission uses the shared compatibility owner when configured. A bare
// @1 provider retains its original route and receives no typed-profile claims.
func (r *holderReceiver) legacyAdmission(action string, op *Operation) (wire.Subject, credentials.AuthorizationGuard, string) {
	return r.legacyAdmissionOperation(action, func() *Operation { return op })
}

func (r *holderReceiver) legacyAdmissionOperation(action string, operation func() *Operation) (wire.Subject, credentials.AuthorizationGuard, string) {
	if r.host.Authorization.Legacy == nil {
		subject, refusal := r.authorize(action)
		return subject, func() credentials.AuthorizationOutcome {
			if !r.bound(subject) {
				return credentials.AuthorizationDenied
			}
			return credentials.Authorized
		}, refusal
	}
	subject, _, ok := r.caller()
	if !ok {
		return wire.Subject{}, nil, "forbidden"
	}
	guard := func() credentials.AuthorizationOutcome {
		if !r.bound(subject) {
			return credentials.AuthorizationDenied
		}
		v := r.host.Authorization.Legacy(r.ctx, subject, action, credentials.ResourceAccount, operation())
		if r.ctx.Err() != nil {
			return credentials.AuthorizationUnavailable
		}
		if !r.bound(subject) {
			return credentials.AuthorizationDenied
		}
		return v.Outcome
	}
	switch guard() {
	case credentials.Authorized:
		return subject, guard, ""
	case credentials.AuthorizationDenied:
		return wire.Subject{}, nil, "forbidden"
	default:
		return wire.Subject{}, nil, "unavailable"
	}
}

// Membership is captured quietly by Holder again at the final mutation. An
// excluded or unknown slot uses the conservative whole legacy collection fence.
func (r *holderReceiver) legacyNamedAdmission(action, effect, name string) (wire.Subject, credentials.NamedAuthorizationGuard, string) {
	subject, _, ok := r.caller()
	member := ok && r.host.holder.LegacyNamedMembership(subject.Account, name)
	op := concrete(effect, name)
	bound, guard, refusal := r.legacyAdmissionOperation(action, func() *Operation {
		if member {
			return op
		}
		return nil
	})
	if refusal != "" {
		return bound, nil, refusal
	}
	return bound, func(current bool) credentials.AuthorizationOutcome {
		member = current
		return guard()
	}, ""
}

func concrete(action, name string) *Operation {
	target, err := credentials.PrepareCredentialTarget(name)
	if err != nil {
		return nil
	}
	return &Operation{Action: action, Profile: credentials.NamedSecretResourceProfile, Target: target}
}

func (r *applierReceiver) legacyAuthorization(use wire.Use) (credentials.Decider, credentials.AuthorizationGuard, *credentials.Authorization) {
	enforcer, _, ok := r.caller()
	target, err := credentials.PrepareCredentialTarget(use.Name)
	op := Operation{Action: credentials.ActionApply, Profile: credentials.ScopedUseResourceProfile, Target: target}
	decided := false
	evidence := &credentials.Authorization{}
	decide := func(ctx context.Context, subject wire.Subject, action, resource string) (string, error) {
		word, err := r.host.decide(ctx, subject, action, resource)
		decided = true
		return word, err
	}
	guard := func() credentials.AuthorizationOutcome {
		*evidence = credentials.Authorization{}
		if r.ctx.Err() != nil {
			return credentials.AuthorizationUnavailable
		}
		if !ok || err != nil || !r.bound(enforcer) {
			return credentials.AuthorizationDenied
		}
		if !decided || r.host.Authorization.Legacy == nil {
			return credentials.Authorized
		}
		v := r.host.Authorization.Legacy(r.ctx, use.Subject, credentials.ActionApply, credentials.ResourceFor(use.Name), &op)
		if r.ctx.Err() != nil {
			return credentials.AuthorizationUnavailable
		}
		if !r.bound(enforcer) {
			return credentials.AuthorizationDenied
		}
		*evidence = v
		return v.Outcome
	}
	return decide, guard, evidence
}

type secretReaderReceiver struct {
	receiver
	value []byte
}

func (r *secretReaderReceiver) Read(name string) (wire.SecretReadResult, error) {
	subject, _, ok := r.caller()
	if !ok {
		return wire.SecretReadResult{Outcome: wire.SecretReadOutcomeForbidden}, nil
	}
	authorization, valid := r.scoped(subject, credentials.ActionSecretRead, credentials.NamedSecretResourceProfile, name)
	if !valid {
		return wire.SecretReadResult{Outcome: wire.SecretReadOutcomeInvalid}, nil
	}
	result := r.host.holder.ReadSecret(subject, name, authorization)
	if result.Value != nil {
		r.value = result.Value.Secret
	}
	return result, nil
}

type scopedHolderReceiver struct{ receiver }

func (r *scopedHolderReceiver) Store(expected string, reg wire.Registration) (wire.StoreResult, error) {
	subject, _, ok := r.caller()
	if !ok {
		zero(reg.Secret)
		return wire.StoreResult{Outcome: wire.StoreOutcomeForbidden}, nil
	}
	authorization, valid := r.scoped(subject, credentials.ActionSecretCreate, credentials.NamedSecretResourceProfile, reg.Name)
	if !valid {
		zero(reg.Secret)
		return wire.StoreResult{Outcome: wire.StoreOutcomeInvalid}, nil
	}
	result := r.host.holder.StoreScoped(subject, expected, reg, authorization)
	if result.Outcome == wire.StoreOutcomeStored && r.host.OnStored != nil {
		if err := r.host.OnStored(r.ctx, subject, reg.Name); err != nil && r.host.OnError != nil {
			r.host.OnError(err)
		}
	}
	return result, nil
}
func (r *scopedHolderReceiver) Rotate(expected string, rotation wire.Rotation) (wire.RotateResult, error) {
	subject, _, ok := r.caller()
	if !ok {
		zero(rotation.Secret)
		return wire.RotateResult{Outcome: wire.RotateOutcomeForbidden}, nil
	}
	authorization, valid := r.scoped(subject, credentials.ActionSecretRotate, credentials.NamedSecretResourceProfile, rotation.Name)
	if !valid {
		zero(rotation.Secret)
		return wire.RotateResult{Outcome: wire.RotateOutcomeInvalid}, nil
	}
	return r.host.holder.RotateScoped(subject, expected, rotation, authorization), nil
}
func (r *scopedHolderReceiver) Revoke(expected, name string) (wire.RevokeResult, error) {
	subject, _, ok := r.caller()
	if !ok {
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeForbidden}, nil
	}
	authorization, valid := r.scoped(subject, credentials.ActionSecretRevoke, credentials.NamedSecretResourceProfile, name)
	if !valid {
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeInvalid}, nil
	}
	return r.host.holder.RevokeScoped(subject, expected, name, authorization), nil
}
func (r *scopedHolderReceiver) Metadata(name string) (wire.MetadataReadResult, error) {
	subject, _, ok := r.caller()
	if !ok {
		return wire.MetadataReadResult{Outcome: wire.MetadataReadOutcomeForbidden}, nil
	}
	authorization, valid := r.scoped(subject, credentials.ActionSecretMetadataRead, credentials.NamedSecretResourceProfile, name)
	if !valid {
		return wire.MetadataReadResult{Outcome: wire.MetadataReadOutcomeInvalid}, nil
	}
	return r.host.holder.Metadata(subject, name, authorization), nil
}

type scopedApplierReceiver struct{ applierReceiver }

func (r *scopedApplierReceiver) Check(use wire.Use) (wire.CheckResult, error) {
	if !r.designated(use) {
		return wire.CheckResult{Outcome: wire.ApplyOutcomeForbidden}, nil
	}
	if _, err := credentials.PrepareCredentialTarget(use.Name); err != nil {
		return wire.CheckResult{Outcome: wire.ApplyOutcomeInvalid}, nil
	}
	authorization := r.enforced(use)
	return r.host.holder.CheckScoped(r.ctx, use, authorization), nil
}
func (r *scopedApplierReceiver) Apply(use wire.Use) (wire.ApplyResult, error) {
	if !r.designated(use) {
		return wire.ApplyResult{Outcome: wire.ApplyOutcomeForbidden}, nil
	}
	if _, err := credentials.PrepareCredentialTarget(use.Name); err != nil {
		return wire.ApplyResult{Outcome: wire.ApplyOutcomeInvalid}, nil
	}
	authorization := r.enforced(use)
	return r.host.holder.ApplyScoped(r.ctx, use, authorization), nil
}
func (r *scopedApplierReceiver) enforced(use wire.Use) credentials.ScopedAuthorization {
	target, _ := credentials.PrepareCredentialTarget(use.Name)
	enforcer, _, ok := r.caller()
	op := Operation{Action: credentials.ActionApply, Profile: credentials.ScopedUseResourceProfile, Target: target}
	invoke := func(check ScopedDecision, expected string) credentials.Authorization {
		if !r.host.ScopedAvailable() {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		if !ok || !r.bound(enforcer) {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		if check == nil {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		v := check(r.ctx, use.Subject, op, expected)
		if r.ctx.Err() != nil {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		if !r.bound(enforcer) {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		return v
	}
	return credentials.ScopedAuthorization{Admit: func() credentials.Authorization { return invoke(r.host.Authorization.Admit, "") }, Check: func(expected string) credentials.Authorization { return invoke(r.host.Authorization.Quiet, expected) }}
}
