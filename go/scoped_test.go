package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

func scopedPermit() ScopedAuthorization {
	return ScopedAuthorization{Admit: func() Authorization { return Authorization{Outcome: Authorized, Revision: "policy-1"} }, Check: func(expected string) Authorization { return Authorization{Outcome: Authorized, Revision: expected} }}
}
func scopedDenied() ScopedAuthorization {
	return ScopedAuthorization{Admit: func() Authorization { return Authorization{Outcome: AuthorizationDenied} }, Check: func(string) Authorization { panic("denied admission reached quiet check") }}
}

type countedBackend struct {
	*memoryBackend
	gets            atomic.Int32
	entered, resume chan struct{}
	last            []byte
	failure         error
}

func (m *countedBackend) Get(key string) ([]byte, error) {
	m.gets.Add(1)
	if m.entered != nil {
		close(m.entered)
		<-m.resume
	}
	v, err := m.memoryBackend.Get(key)
	m.last = v
	if m.failure != nil {
		return v, m.failure
	}
	return v, err
}

func TestScopedReadStateHiddenBehindPermission(t *testing.T) {
	m := &countedBackend{memoryBackend: newMemory()}
	h := open(t, Config{Backend: m})
	h.Store(owner, "", registration("alpha"))
	for _, name := range []string{"alpha", "absent"} {
		r := h.ReadSecret(owner, name, scopedDenied())
		if r.Outcome != wire.SecretReadOutcomeForbidden || r.Value != nil {
			t.Fatal("denied read exposed record state")
		}
	}
	if m.gets.Load() != 0 {
		t.Fatal("denied read touched backend")
	}
	r := h.ReadSecret(owner, "alpha", scopedPermit())
	if r.Outcome != wire.SecretReadOutcomeRead || r.Value == nil || r.Value.Name != "alpha" || len(r.Value.Secret) == 0 {
		t.Fatal("authorized read failed")
	}
	if bytes.Equal(m.last, r.Value.Secret) {
		t.Fatal("backend scratch survived read")
	}
	if !bytes.Equal(r.Value.Secret, []byte(testSecret)) {
		t.Fatal("wrong value returned")
	}
	zero(r.Value.Secret)
}

func TestScopedCollectionExcludesExistingAndTombstonedLocalKey(t *testing.T) {
	for _, tombstone := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "tombstoned"}[tombstone], func(t *testing.T) {
			m := &countedBackend{memoryBackend: newMemory()}
			h := open(t, Config{Backend: m})
			reg := registration("runtime-key")
			reg.Kind = KindLocalKey
			stored := h.StoreLocalKey(owner, reg)
			if stored.Outcome != wire.StoreOutcomeStored {
				t.Fatal("local fixture registration failed")
			}
			if tombstone {
				h.Revoke(owner, stored.Revision, reg.Name)
			}
			if r := h.ReadSecret(owner, reg.Name, scopedPermit()); r.Outcome != wire.SecretReadOutcomeUnsupportedKind || r.Value != nil {
				t.Fatal("local key exported or state disclosed")
			}
			if r := h.Metadata(owner, reg.Name, scopedPermit()); r.Outcome != wire.MetadataReadOutcomeForbidden || r.Current != nil {
				t.Fatal("local metadata disclosed")
			}
			if r := h.StoreScoped(owner, "", registration(reg.Name), scopedPermit()); r.Outcome != wire.StoreOutcomeUnsupportedKind || r.Current != nil || r.Revision != "" {
				t.Fatal("existing local slot conflict disclosed")
			}
			if r := h.RotateScoped(owner, stored.Revision, wire.Rotation{Name: reg.Name, Secret: []byte("replace")}, scopedPermit()); r.Outcome != wire.RotateOutcomeForbidden || r.Current != nil || r.Revision != "" {
				t.Fatal("local key rotated or disclosed")
			}
			if r := h.RevokeScoped(owner, stored.Revision, reg.Name, scopedPermit()); r.Outcome != wire.RevokeOutcomeForbidden || r.Revision != "" {
				t.Fatal("local key revoked or disclosed")
			}
			if r := h.CheckScoped(context.Background(), use(reg.Name, "huggingface.co"), scopedPermit()); r.Outcome != wire.ApplyOutcomeUnsupportedKind || r.Revision != "" {
				t.Fatal("local check admitted")
			}
			if r := h.ApplyScoped(context.Background(), use(reg.Name, "huggingface.co"), scopedPermit()); r.Outcome != wire.ApplyOutcomeUnsupportedKind || r.Revision != "" || len(r.Headers) != 0 {
				t.Fatal("local key applied")
			}
			if m.gets.Load() != 0 {
				t.Fatal("excluded collection read backend")
			}
		})
	}
}

func TestScopedReadRechecksAfterBackendWait(t *testing.T) {
	for _, decision := range []AuthorizationOutcome{AuthorizationDenied, AuthorizationConflict, AuthorizationUnavailable} {
		t.Run(map[AuthorizationOutcome]string{AuthorizationDenied: "revoked", AuthorizationConflict: "revision", AuthorizationUnavailable: "unavailable"}[decision], func(t *testing.T) {
			m := &countedBackend{memoryBackend: newMemory(), entered: make(chan struct{}), resume: make(chan struct{})}
			h := open(t, Config{Backend: m})
			h.Store(owner, "", registration("alpha"))
			var current atomic.Uint32
			current.Store(uint32(Authorized))
			a := scopedPermit()
			a.Check = func(expected string) Authorization {
				return Authorization{Outcome: AuthorizationOutcome(current.Load()), Revision: expected}
			}
			done := make(chan wire.SecretReadResult, 1)
			go func() { done <- h.ReadSecret(owner, "alpha", a) }()
			<-m.entered
			current.Store(uint32(decision))
			close(m.resume)
			r := <-done
			if r.Outcome != readAuthorization(decision) || r.Value != nil {
				t.Fatal("revoked/stale backend response exported")
			}
			if bytes.IndexByte(m.last, 1) >= 0 || !bytes.Equal(m.last, make([]byte, len(m.last))) {
				t.Fatal("refused backend bytes not cleared")
			}
		})
	}
}

func TestScopedReadCurrentStateAfterAdmissionWait(t *testing.T) {
	for _, change := range []string{"revoke", "expire", "rotate", "recreate"} {
		t.Run(change, func(t *testing.T) {
			c := &clock{time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
			m := &countedBackend{memoryBackend: newMemory()}
			h := open(t, Config{Backend: m, Now: c.Now, TombstoneRetention: time.Millisecond})
			reg := registration("alpha")
			reg.Expires = c.now.Add(time.Minute).Format(time.RFC3339)
			stored := h.Store(owner, "", reg)
			entered, resume := make(chan struct{}), make(chan struct{})
			a := scopedPermit()
			a.Admit = func() Authorization {
				close(entered)
				<-resume
				return Authorization{Outcome: Authorized, Revision: "policy-1"}
			}
			done := make(chan wire.SecretReadResult, 1)
			go func() { done <- h.ReadSecret(owner, "alpha", a) }()
			<-entered
			want := wire.SecretReadOutcomeRead
			wantRevision := stored.Revision
			switch change {
			case "revoke":
				h.Revoke(owner, stored.Revision, "alpha")
				want = wire.SecretReadOutcomeRevoked
			case "expire":
				c.now = c.now.Add(2 * time.Minute)
				want = wire.SecretReadOutcomeExpired
			case "rotate":
				wantRevision = h.Rotate(owner, stored.Revision, wire.Rotation{Name: "alpha", Secret: []byte("current-value")}).Revision
			case "recreate":
				h.Revoke(owner, stored.Revision, "alpha")
				c.now = c.now.Add(time.Second)
				wantRevision = h.Store(owner, "", registration("alpha")).Revision
			}
			close(resume)
			r := <-done
			if r.Outcome != want {
				t.Fatalf("current state not used: %s", r.Outcome)
			}
			if want == wire.SecretReadOutcomeRead {
				if r.Value == nil || r.Value.Revision != wantRevision {
					t.Fatal("returned stale slot revision")
				}
				zero(r.Value.Secret)
			} else if r.Value != nil || m.gets.Load() != 0 {
				t.Fatal("terminal record read/exported")
			}
		})
	}
}

func TestScopedMutationFinalGuardPrecedesEffectAndConflict(t *testing.T) {
	for _, operation := range []string{"store", "rotate", "revoke", "metadata", "check", "apply"} {
		t.Run(operation, func(t *testing.T) {
			m := &countedBackend{memoryBackend: newMemory()}
			h := open(t, Config{Backend: m})
			stored := h.Store(owner, "", registration("alpha"))
			a := scopedPermit()
			a.Check = func(string) Authorization { return Authorization{Outcome: AuthorizationDenied} }
			switch operation {
			case "store":
				r := h.StoreScoped(owner, "", registration("alpha"), a)
				if r.Outcome != wire.StoreOutcomeForbidden || r.Current != nil || r.Revision != "" {
					t.Fatal("store disclosed conflict or wrote")
				}
			case "rotate":
				r := h.RotateScoped(owner, "stale", wire.Rotation{Name: "alpha", Secret: []byte("replace")}, a)
				if r.Outcome != wire.RotateOutcomeForbidden || r.Current != nil || r.Revision != "" {
					t.Fatal("rotate disclosed conflict or wrote")
				}
			case "revoke":
				r := h.RevokeScoped(owner, stored.Revision, "alpha", a)
				if r.Outcome != wire.RevokeOutcomeForbidden || r.Revision != "" {
					t.Fatal("revoke wrote")
				}
			case "metadata":
				r := h.Metadata(owner, "alpha", a)
				if r.Outcome != wire.MetadataReadOutcomeForbidden || r.Current != nil {
					t.Fatal("metadata disclosed")
				}
			case "check":
				r := h.CheckScoped(context.Background(), use("alpha", "huggingface.co"), a)
				if r.Outcome != wire.ApplyOutcomeNotPermitted || r.Revision != "" {
					t.Fatal("check admitted")
				}
			case "apply":
				r := h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), a)
				if r.Outcome != wire.ApplyOutcomeNotPermitted || r.Revision != "" || len(r.Headers) != 0 {
					t.Fatal("apply admitted")
				}
			}
			if m.gets.Load() != 0 || h.List(owner.Account, "", 64).Records[0].Revision != stored.Revision || h.List(owner.Account, "", 64).Records[0].State != wire.StateActive {
				t.Fatal("refusal mutated or read saved value")
			}
		})
	}
}

func TestScopedReadSecretFreeAuditStateAndErrors(t *testing.T) {
	m := &countedBackend{memoryBackend: newMemory()}
	var diagnostics []string
	h := open(t, Config{Backend: m, OnError: func(err error) { diagnostics = append(diagnostics, err.Error()) }})
	h.Store(owner, "", registration("alpha"))
	r := h.ReadSecret(owner, "alpha", scopedPermit())
	if r.Value == nil {
		t.Fatal("read failed")
	}
	zero(r.Value.Secret)
	m.failure = errors.New("backend revealed " + testSecret)
	if r := h.ReadSecret(owner, "alpha", scopedPermit()); r.Outcome != wire.SecretReadOutcomeUnavailable || r.Value != nil {
		t.Fatal("backend failure exposed value")
	}
	if r := h.Apply(context.Background(), use("alpha", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeUnavailable || len(r.Headers) != 0 {
		t.Fatal("legacy backend failure carried headers")
	}
	if r := h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), scopedPermit()); r.Outcome != wire.ApplyOutcomeUnavailable || len(r.Headers) != 0 {
		t.Fatal("scoped backend failure carried headers")
	}
	evidence, _ := json.Marshal(struct {
		State  any
		Audit  any
		Errors any
	}{h.state, h.Audit(owner.Account, "", 256), diagnostics})
	for _, sensitive := range []string{testSecret, base64.StdEncoding.EncodeToString([]byte(testSecret))} {
		if bytes.Contains(evidence, []byte(sensitive)) {
			t.Fatal("secret entered metadata, audit or diagnostics")
		}
	}
}

func TestApplyExpiryAfterBackendWaitSharedOwner(t *testing.T) {
	for _, route := range []string{"legacy", "authorized", "scoped"} {
		t.Run(route, func(t *testing.T) {
			c := &clock{time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
			m := &countedBackend{memoryBackend: newMemory(), entered: make(chan struct{}), resume: make(chan struct{})}
			h := open(t, Config{Backend: m, Now: c.Now})
			reg := registration("alpha")
			reg.Expires = c.now.Add(time.Minute).Format(time.RFC3339)
			h.Store(owner, "", reg)
			done := make(chan wire.ApplyResult, 1)
			go func() {
				switch route {
				case "legacy":
					done <- h.Apply(context.Background(), use("alpha", "huggingface.co"), permit("permitted"))
				case "authorized":
					done <- h.ApplyAuthorized(context.Background(), use("alpha", "huggingface.co"), permit("permitted"), func() AuthorizationOutcome { return Authorized })
				case "scoped":
					done <- h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), scopedPermit())
				}
			}()
			<-m.entered
			c.now = c.now.Add(2 * time.Minute)
			close(m.resume)
			r := <-done
			if r.Outcome != wire.ApplyOutcomeExpired || len(r.Headers) != 0 {
				t.Fatal("expired backend response produced headers")
			}
			if !bytes.Equal(m.last, make([]byte, len(m.last))) {
				t.Fatal("expired scratch survived")
			}
			audit := h.Audit(owner.Account, "", 256)
			last := audit.Entries[len(audit.Entries)-1]
			if last.Event != "refused" || last.Outcome != "expired" {
				t.Fatal("expiry refusal audit lost")
			}
		})
	}
}
