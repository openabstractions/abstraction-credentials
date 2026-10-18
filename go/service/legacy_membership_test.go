package service

import (
	"context"
	"os"
	"os/user"
	"sync/atomic"
	"testing"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-credentials/go/client"
	identity "github.com/openabstractions/abstraction-identity"
)

func TestLegacyExcludedSlotUsesConservativeFence(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := wire.Subject{Account: current.Uid, Program: identity.CanonicalProgramPath(exe)}
	holder, err := credentials.Open(credentials.Config{Backend: &memory{items: map[string][]byte{}}})
	if err != nil {
		t.Fatal(err)
	}
	registration := func(name, kind string) wire.Registration {
		return wire.Registration{Name: name, Kind: kind, Secret: []byte(secret), Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}}
	}
	local := holder.StoreLocalKey(self, registration("runtime-key", credentials.KindLocalKey))
	saved := holder.Store(self, "", registration("alpha", "bearer"))
	if local.Outcome != wire.StoreOutcomeStored || saved.Outcome != wire.StoreOutcomeStored {
		t.Fatal("setup failed")
	}
	endpoint := programEndpoint(t)
	h, err := Listen(endpoint, holder, func(context.Context, wire.Subject, string, string) (string, error) { return "permitted", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	var blocked atomic.Bool
	blocked.Store(true)
	h.Authorization.Legacy = func(_ context.Context, subject wire.Subject, action, resource string, op *Operation) credentials.Authorization {
		if subject != self || action != credentials.ActionManage || resource != credentials.ResourceAccount {
			t.Fatal("wrong legacy effect")
		}
		if op != nil {
			target, e := credentials.DecodeCredentialTarget(op.Target)
			if e != nil || target.Name != "alpha" {
				t.Fatal("excluded or unknown slot fabricated as saved-secret effect")
			}
			return credentials.Authorization{Outcome: credentials.Authorized, Revision: "policy"}
		}
		if blocked.Load() {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied, Revision: "policy"}
		}
		return credentials.Authorization{Outcome: credentials.Authorized, Revision: "policy"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	old := client.NewHolder(endpoint)
	if r, e := old.Rotate(ctx, local.Revision, wire.Rotation{Name: "runtime-key", Secret: []byte("replacement")}); e != nil || r.Outcome != wire.RotateOutcomeForbidden || r.Current != nil || r.Revision != "" {
		t.Fatal("excluded rotation bypassed fence or disclosed state")
	}
	if r, e := old.Revoke(ctx, local.Revision, "runtime-key"); e != nil || r.Outcome != wire.RevokeOutcomeForbidden || r.Revision != "" {
		t.Fatal("excluded revoke bypassed fence or disclosed state")
	}
	if r, e := old.Store(ctx, "", registration("absent", "bearer")); e != nil || r.Outcome != wire.StoreOutcomeForbidden || r.Current != nil || r.Revision != "" {
		t.Fatal("unknown slot bypassed conservative fence")
	}
	if r, e := old.Rotate(ctx, saved.Revision, wire.Rotation{Name: "alpha", Secret: []byte("replacement")}); e != nil || r.Outcome != wire.RotateOutcomeRotated {
		t.Fatal("known saved slot lost concrete fence")
	}
	blocked.Store(false)
	if r, e := old.Rotate(ctx, local.Revision, wire.Rotation{Name: "runtime-key", Secret: []byte("replacement")}); e != nil || r.Outcome != wire.RotateOutcomeRotated {
		t.Fatal("legacy operation changed without related block")
	}
}

func TestLegacyApplierAdmissionPrecedesFinalQuietFence(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := wire.Subject{Account: current.Uid, Program: identity.CanonicalProgramPath(exe)}
	holder, err := credentials.Open(credentials.Config{Backend: &memory{items: map[string][]byte{}}})
	if err != nil {
		t.Fatal(err)
	}
	stored := holder.Store(self, "", wire.Registration{Name: "alpha", Kind: "bearer", Secret: []byte(secret), Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}})
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal("setup failed")
	}
	var permitted, fence atomic.Bool
	var admissions atomic.Int32
	endpoint := programEndpoint(t)
	h, err := Listen(endpoint, holder, func(context.Context, wire.Subject, string, string) (string, error) {
		admissions.Add(1)
		if permitted.Load() {
			return "permitted", nil
		}
		return "not_granted", nil
	}, func(context.Context, *identity.Peer, string, string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	h.Authorization.Legacy = func(context.Context, wire.Subject, string, string, *Operation) credentials.Authorization {
		if fence.Load() {
			return credentials.Authorization{Outcome: credentials.Authorized, Revision: "policy"}
		}
		return credentials.Authorization{Outcome: credentials.AuthorizationDenied, Revision: "policy"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	old := client.NewApplier(endpoint)
	use := wire.Use{Subject: self, Consumer: "abstraction.download/http-execution@1", Name: "alpha", Target: "huggingface.co"}
	if r, e := old.Check(ctx, use); e != nil || r.Outcome != wire.ApplyOutcomeNotPermitted {
		t.Fatal("missing Check did not refuse")
	}
	if r, e := old.Apply(ctx, use); e != nil || r.Outcome != wire.ApplyOutcomeNotPermitted || len(r.Headers) != 0 {
		t.Fatal("missing Apply did not refuse")
	}
	if admissions.Load() != 2 {
		t.Fatal("final quiet fence suppressed outside-lock missing-permit admission")
	}
	permitted.Store(true)
	fence.Store(true)
	if r, e := old.Apply(ctx, use); e != nil || r.Outcome != wire.ApplyOutcomeApplied || len(r.Headers) == 0 {
		t.Fatal("otherwise-permitting legacy control failed")
	}
	fence.Store(false)
	if r, e := old.Apply(ctx, use); e != nil || r.Outcome != wire.ApplyOutcomeNotPermitted || len(r.Headers) != 0 {
		t.Fatal("final quiet block did not stop headers")
	}
}
