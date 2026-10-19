package credentials

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-identity/remote"
)

func TestCanonicalRemoteUseRequiresExactCredentialDecision(t *testing.T) {
	backend := newMemory()
	state := filepath.Join(t.TempDir(), "holder.json")
	h := open(t, Config{Backend: backend, StatePath: state})
	stored := h.Store(owner, "", registration("hf"))
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal(stored)
	}
	subject := wire.Subject{Account: owner.Account, Program: remote.SubjectPrefix + strings.Repeat("a", 64)}
	use := wire.Use{Subject: subject, Consumer: consumer, Name: "hf", Target: "huggingface.co"}
	exact := func(_ context.Context, s wire.Subject, action, resource string) (string, error) {
		if s == subject && action == ActionApply && resource == ResourceFor("hf") {
			return "permitted", nil
		}
		return "not_granted", nil
	}
	for _, tc := range []struct {
		name   string
		use    wire.Use
		decide Decider
		want   wire.ApplyOutcome
	}{
		{"exact", use, exact, wire.ApplyOutcomeApplied},
		{"native-grant-only", use, func(_ context.Context, s wire.Subject, _, _ string) (string, error) {
			if s == owner {
				return "permitted", nil
			}
			return "not_granted", nil
		}, wire.ApplyOutcomeNotPermitted},
		{"deny", use, func(context.Context, wire.Subject, string, string) (string, error) { return "denied", nil }, wire.ApplyOutcomeNotPermitted},
		{"nil", use, nil, wire.ApplyOutcomeUnavailable},
		{"unavailable", use, func(context.Context, wire.Subject, string, string) (string, error) {
			return "unavailable", errors.New("policy down")
		}, wire.ApplyOutcomeUnavailable},
		{"other-key", func() wire.Use {
			v := use
			v.Subject.Program = remote.SubjectPrefix + strings.Repeat("b", 64)
			return v
		}(), exact, wire.ApplyOutcomeNotPermitted},
		{"other-account", func() wire.Use { v := use; v.Subject.Account = "other-account"; return v }(), exact, wire.ApplyOutcomeUnknown},
		{"other-credential", func() wire.Use { v := use; v.Name = "absent"; return v }(), exact, wire.ApplyOutcomeUnknown},
		{"malformed", func() wire.Use {
			v := use
			v.Subject.Program = remote.SubjectPrefix + strings.Repeat("A", 64)
			return v
		}(), exact, wire.ApplyOutcomeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := h.Apply(context.Background(), tc.use, tc.decide)
			if r.Outcome != tc.want {
				t.Fatalf("Apply %+v", r)
			}
			if tc.want != wire.ApplyOutcomeApplied && len(r.Headers) != 0 {
				t.Fatal("refusal released headers")
			}
			if c := h.Check(context.Background(), tc.use, tc.decide); c.Outcome != tc.want {
				t.Fatalf("Check %+v", c)
			}
		})
	}
	// The canonical subject reaches scoped Use too; the trusted authorization
	// callbacks still own the exact target and the current policy revision.
	authorization := ScopedAuthorization{Admit: func() Authorization { return Authorization{Outcome: Authorized, Revision: "explicit-remote-1"} }, Check: func(expected string) Authorization { return Authorization{Outcome: Authorized, Revision: expected} }}
	if r := h.ApplyScoped(context.Background(), use, authorization); r.Outcome != wire.ApplyOutcomeApplied {
		t.Fatal(r)
	}
	if r := h.ApplyScoped(context.Background(), use, ScopedAuthorization{}); r.Outcome != wire.ApplyOutcomeUnavailable || len(r.Headers) != 0 {
		t.Fatal(r)
	}
	// Manager and raw-reader actors retain their native-only subject validator.
	if r := h.Store(subject, "", registration("other")); r.Outcome != wire.StoreOutcomeInvalid {
		t.Fatal(r)
	}
	if r := h.Rotate(subject, stored.Revision, wire.Rotation{Name: "hf", Secret: []byte(testSecret)}); r.Outcome != wire.RotateOutcomeInvalid {
		t.Fatal(r)
	}
	if r := h.Revoke(subject, stored.Revision, "hf"); r.Outcome != wire.RevokeOutcomeInvalid {
		t.Fatal(r)
	}
	if r := h.ReadSecret(subject, "hf", authorization); r.Outcome != wire.SecretReadOutcomeInvalid {
		t.Fatal(r)
	}
	if r := h.Metadata(subject, "hf", authorization); r.Outcome != wire.MetadataReadOutcomeInvalid {
		t.Fatal(r)
	}
	// Native registration provenance survives reload; the bounded in-memory
	// audit retains the remote subject without granting it a manager identity.
	reopened := open(t, Config{Backend: backend, StatePath: state})
	if got := reopened.state.Accounts[owner.Account]["hf"].RegisteredBy; got != owner {
		t.Fatalf("registration provenance %+v", got)
	}
	found := false
	for _, entry := range h.Audit(owner.Account, "", 256).Entries {
		if entry.Subject != nil && *entry.Subject == subject && entry.Event == "applied" {
			found = true
		}
	}
	if !found {
		t.Fatal("remote Use audit subject lost")
	}
	if r := h.Revoke(owner, stored.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatal(r)
	}
	if r := h.Apply(context.Background(), use, exact); r.Outcome != wire.ApplyOutcomeRevoked || len(r.Headers) != 0 {
		t.Fatal(r)
	}
}
