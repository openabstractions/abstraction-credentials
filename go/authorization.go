package credentials

// AuthorizationOutcome is the closed trusted receiving-host callback result.
// Matching and policy revisions belong to Rights; Holder never matches rules.
type AuthorizationOutcome uint8

const (
	Authorized AuthorizationOutcome = iota + 1
	AuthorizationDenied
	AuthorizationUnavailable
	AuthorizationConflict
)

type Authorization struct {
	Outcome  AuthorizationOutcome
	Revision string
	// RightsOutcome is optional audit evidence from this same decision. It
	// conveys no authority; the use audit owner accepts only closed Rights words.
	RightsOutcome string
}

// AuthorizationGuard runs only under Holder.mu. It must be quiet, bounded and
// non-reentrant: no Ask admission, Holder/backend callback or effect. The
// receiving host includes context and native subject rechecks in this guard.
type AuthorizationGuard func() AuthorizationOutcome

// ScopedAuthorization separates initial admission, which may admit a missing
// permission Ask outside the holder lock, from the final quiet snapshot.
// Check pins the admitted policy revision; raw Read repeats it after Get.
type ScopedAuthorization struct {
	Admit func() Authorization
	Check func(expectedRevision string) Authorization
}

func (a ScopedAuthorization) prepare() (AuthorizationGuard, AuthorizationOutcome) {
	return a.prepareWithEvidence(nil)
}

func (a ScopedAuthorization) prepareWithEvidence(evidence *Authorization) (AuthorizationGuard, AuthorizationOutcome) {
	retain := func(v Authorization) AuthorizationOutcome {
		v.Outcome = validAuthorizationOutcome(v.Outcome)
		if evidence != nil {
			*evidence = v
		}
		return v.Outcome
	}
	if a.Admit == nil || a.Check == nil {
		return nil, retain(Authorization{Outcome: AuthorizationUnavailable})
	}
	initial := a.Admit()
	if initial.Outcome != Authorized {
		return nil, retain(initial)
	}
	if initial.Revision == "" {
		return nil, retain(Authorization{Outcome: AuthorizationUnavailable})
	}
	retain(initial)
	return func() AuthorizationOutcome {
		v := a.Check(initial.Revision)
		if v.Outcome == Authorized && v.Revision != initial.Revision {
			v = Authorization{Outcome: AuthorizationConflict}
		}
		return retain(v)
	}, Authorized
}

func validAuthorizationOutcome(v AuthorizationOutcome) AuthorizationOutcome {
	switch v {
	case Authorized, AuthorizationDenied, AuthorizationUnavailable, AuthorizationConflict:
		return v
	}
	return AuthorizationUnavailable
}

func runGuard(guard AuthorizationGuard) AuthorizationOutcome {
	if guard == nil {
		return Authorized
	}
	return validAuthorizationOutcome(guard())
}
