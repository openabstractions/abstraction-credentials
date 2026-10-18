package credentials

import (
	"context"
	"errors"
	"slices"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// SavedSecretKind is the owning collection predicate for metadata-only consumers.
func SavedSecretKind(kind string) bool {
	return kind != KindLocalKey && slices.Contains(SupportedKinds, kind)
}

func savedSecret(r *record) bool { return r == nil || SavedSecretKind(r.Kind) }

// LegacyNamedMembership is trusted receiving-host evidence only. An absent or
// excluded slot cannot be described as a concrete saved-secret operation.
func (h *Holder) LegacyNamedMembership(account, name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.legacyNamedMembership(account, name)
}

func (h *Holder) legacyNamedMembership(account, name string) bool {
	r := h.state.Accounts[account][name]
	return r != nil && SavedSecretKind(r.Kind)
}

// NamedAuthorizationGuard receives membership captured by Holder while its
// mutex is held. It must be quiet and must not reenter Holder or backend.
type NamedAuthorizationGuard func(savedSecret bool) AuthorizationOutcome

func (h *Holder) namedGuard(account, name string, check NamedAuthorizationGuard) AuthorizationGuard {
	if check == nil {
		return nil
	}
	return func() AuthorizationOutcome { return check(h.legacyNamedMembership(account, name)) }
}

func (h *Holder) StoreNamedAuthorized(caller wire.Subject, expected string, reg wire.Registration, guard NamedAuthorizationGuard) wire.StoreResult {
	return h.register(caller, expected, reg, false, h.namedGuard(caller.Account, reg.Name, guard), false)
}
func (h *Holder) RotateNamedAuthorized(caller wire.Subject, expected string, rotation wire.Rotation, guard NamedAuthorizationGuard) wire.RotateResult {
	return h.rotate(caller, expected, rotation, h.namedGuard(caller.Account, rotation.Name, guard), false)
}
func (h *Holder) RevokeNamedAuthorized(caller wire.Subject, expected, name string, guard NamedAuthorizationGuard) wire.RevokeResult {
	return h.revoke(caller, expected, name, h.namedGuard(caller.Account, name, guard), false)
}

func readAuthorization(v AuthorizationOutcome) wire.SecretReadOutcome {
	switch v {
	case AuthorizationDenied:
		return wire.SecretReadOutcomeForbidden
	case AuthorizationConflict:
		return wire.SecretReadOutcomeConflict
	default:
		return wire.SecretReadOutcomeUnavailable
	}
}

// ReadSecret exports only to a subject bound by the receiving host. Every
// state-bearing result follows the explicit raw-Read decision. The returned
// buffer belongs to the receiver, which must clear it after encoding/reply.
func (h *Holder) ReadSecret(caller wire.Subject, name string, authorization ScopedAuthorization) wire.SecretReadResult {
	refuse := func(v wire.SecretReadOutcome) wire.SecretReadResult { return wire.SecretReadResult{Outcome: v} }
	if !validSubject(caller) || !namePattern.MatchString(name) {
		return refuse(wire.SecretReadOutcomeInvalid)
	}
	guard, admission := authorization.prepare()
	if admission != Authorized {
		return refuse(readAuthorization(admission))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(caller.Account)
	if decision := runGuard(guard); decision != Authorized {
		return refuse(readAuthorization(decision))
	}
	r := h.state.Accounts[caller.Account][name]
	if !savedSecret(r) {
		return refuse(wire.SecretReadOutcomeUnsupportedKind)
	}
	if r == nil {
		return refuse(wire.SecretReadOutcomeUnknown)
	}
	if r.State != "active" {
		v, ok := wire.ParseSecretReadOutcome(string(r.State))
		if !ok {
			v = wire.SecretReadOutcomeUnavailable
		}
		return refuse(v)
	}
	backend := h.store()
	if backend == nil || r.Key == "" {
		return refuse(wire.SecretReadOutcomeUnavailable)
	}
	secret, err := backend.Get(r.Key)
	defer zero(secret)
	// A backend wait can outlast a permit, recipient or deadline. Never release
	// bytes or newly observed state after that authority changed.
	if decision := runGuard(guard); decision != Authorized {
		return refuse(readAuthorization(decision))
	}
	h.sweep(caller.Account)
	r = h.state.Accounts[caller.Account][name]
	if r == nil {
		return refuse(wire.SecretReadOutcomeUnknown)
	}
	if r.State != "active" {
		v, ok := wire.ParseSecretReadOutcome(string(r.State))
		if !ok {
			v = wire.SecretReadOutcomeUnavailable
		}
		return refuse(v)
	}
	if errors.Is(err, ErrNotFound) {
		r.State = "lost"
		h.report(h.save())
		h.appendAudit(caller.Account, wire.AuditEntry{Event: "lost", Name: name, Revision: r.Revision})
		return refuse(wire.SecretReadOutcomeLost)
	}
	if err != nil || len(secret) < 1 || len(secret) > MaxSecretBytes || len(secret) > backend.MaxSecretBytes() {
		// Backend implementations may return sensitive diagnostics. Raw Read
		// reports only this fixed classification.
		if err == nil {
			err = ErrUnavailable
		}
		h.reportBackend("read_get", err)
		return refuse(wire.SecretReadOutcomeUnavailable)
	}
	h.appendAudit(caller.Account, wire.AuditEntry{Event: "read", Name: name, Revision: r.Revision, Subject: subjectPtr(caller), Outcome: "read"})
	return wire.SecretReadResult{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: name, Revision: r.Revision, Secret: slices.Clone(secret)}}
}

// Metadata reads one saved name slot; it does not enumerate credentials.
func (h *Holder) Metadata(caller wire.Subject, name string, authorization ScopedAuthorization) wire.MetadataReadResult {
	refuse := func(v wire.MetadataReadOutcome) wire.MetadataReadResult { return wire.MetadataReadResult{Outcome: v} }
	if !validSubject(caller) || !namePattern.MatchString(name) {
		return refuse(wire.MetadataReadOutcomeInvalid)
	}
	guard, admission := authorization.prepare()
	mapAuthorization := func(v AuthorizationOutcome) wire.MetadataReadOutcome {
		switch v {
		case AuthorizationDenied:
			return wire.MetadataReadOutcomeForbidden
		case AuthorizationConflict:
			return wire.MetadataReadOutcomeConflict
		default:
			return wire.MetadataReadOutcomeUnavailable
		}
	}
	if admission != Authorized {
		return refuse(mapAuthorization(admission))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(caller.Account)
	if decision := runGuard(guard); decision != Authorized {
		return refuse(mapAuthorization(decision))
	}
	r := h.state.Accounts[caller.Account][name]
	if !savedSecret(r) {
		return refuse(wire.MetadataReadOutcomeForbidden)
	}
	if r == nil {
		return refuse(wire.MetadataReadOutcomeUnknown)
	}
	return wire.MetadataReadResult{Outcome: wire.MetadataReadOutcomeFound, Current: metadata(r)}
}

// Authorized variants share the legacy mutation bodies and preserve their
// collection. A receiving host supplies the final concrete block-fence guard.
func (h *Holder) StoreAuthorized(caller wire.Subject, expected string, reg wire.Registration, guard AuthorizationGuard) wire.StoreResult {
	return h.register(caller, expected, reg, false, guard, false)
}
func (h *Holder) RotateAuthorized(caller wire.Subject, expected string, rotation wire.Rotation, guard AuthorizationGuard) wire.RotateResult {
	return h.rotate(caller, expected, rotation, guard, false)
}
func (h *Holder) RevokeAuthorized(caller wire.Subject, expected, name string, guard AuthorizationGuard) wire.RevokeResult {
	return h.revoke(caller, expected, name, guard, false)
}

// Optional evidence belongs to this call and is overwritten by each quiet
// guard invocation. It preserves CRED-A5 Rights detail without changing grants.
func (h *Holder) CheckAuthorized(ctx context.Context, use wire.Use, decide Decider, guard AuthorizationGuard, evidence ...*Authorization) wire.CheckResult {
	outcome, revision, _ := h.evaluate(ctx, use, decide, false, guard, false, useEvidence(evidence))
	return wire.CheckResult{Outcome: outcome, Revision: revision}
}
func (h *Holder) ApplyAuthorized(ctx context.Context, use wire.Use, decide Decider, guard AuthorizationGuard, evidence ...*Authorization) wire.ApplyResult {
	outcome, revision, headers := h.evaluate(ctx, use, decide, true, guard, false, useEvidence(evidence))
	return wire.ApplyResult{Outcome: outcome, Revision: revision, Headers: headers}
}

func useEvidence(evidence []*Authorization) *Authorization {
	if len(evidence) == 1 {
		return evidence[0]
	}
	return nil
}

func (h *Holder) StoreScoped(caller wire.Subject, expected string, reg wire.Registration, authorization ScopedAuthorization) wire.StoreResult {
	guard, admission := authorization.prepare()
	if admission != Authorized {
		zero(reg.Secret)
		if admission == AuthorizationDenied {
			return wire.StoreResult{Outcome: wire.StoreOutcomeForbidden}
		}
		return wire.StoreResult{Outcome: wire.StoreOutcomeUnavailable}
	}
	return h.register(caller, expected, reg, false, guard, true)
}
func (h *Holder) RotateScoped(caller wire.Subject, expected string, rotation wire.Rotation, authorization ScopedAuthorization) wire.RotateResult {
	guard, admission := authorization.prepare()
	if admission != Authorized {
		zero(rotation.Secret)
		if admission == AuthorizationDenied {
			return wire.RotateResult{Outcome: wire.RotateOutcomeForbidden}
		}
		return wire.RotateResult{Outcome: wire.RotateOutcomeUnavailable}
	}
	return h.rotate(caller, expected, rotation, guard, true)
}
func (h *Holder) RevokeScoped(caller wire.Subject, expected, name string, authorization ScopedAuthorization) wire.RevokeResult {
	guard, admission := authorization.prepare()
	if admission != Authorized {
		if admission == AuthorizationDenied {
			return wire.RevokeResult{Outcome: wire.RevokeOutcomeForbidden}
		}
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeUnavailable}
	}
	return h.revoke(caller, expected, name, guard, true)
}

func (h *Holder) CheckScoped(ctx context.Context, use wire.Use, authorization ScopedAuthorization) wire.CheckResult {
	outcome, revision, _ := h.evaluateScoped(ctx, use, authorization, false)
	return wire.CheckResult{Outcome: outcome, Revision: revision}
}
func (h *Holder) ApplyScoped(ctx context.Context, use wire.Use, authorization ScopedAuthorization) wire.ApplyResult {
	outcome, revision, headers := h.evaluateScoped(ctx, use, authorization, true)
	return wire.ApplyResult{Outcome: outcome, Revision: revision, Headers: headers}
}
func (h *Holder) evaluateScoped(ctx context.Context, use wire.Use, authorization ScopedAuthorization, read bool) (wire.ApplyOutcome, string, map[string]string) {
	if !validUse(use) {
		return wire.ApplyOutcomeInvalid, "", nil
	}
	var evidence Authorization
	guard, admission := authorization.prepareWithEvidence(&evidence)
	if admission != Authorized {
		outcome := wire.ApplyOutcomeUnavailable
		if admission == AuthorizationDenied {
			outcome = wire.ApplyOutcomeNotPermitted
		}
		h.mu.Lock()
		detail := useAuthorizationDetail(evidence, admission)
		if detail == "" {
			detail = outcome.String()
		}
		h.appendAudit(use.Subject.Account, wire.AuditEntry{Event: "refused", Name: use.Name, Subject: subjectPtr(use.Subject), Consumer: use.Consumer, Target: use.Target, Outcome: detail})
		h.mu.Unlock()
		return outcome, "", nil
	}
	return h.evaluate(ctx, use, func(context.Context, wire.Subject, string, string) (string, error) { return "permitted", nil }, read, guard, true, &evidence)
}
