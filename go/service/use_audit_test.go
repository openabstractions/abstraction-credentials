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

func TestNativeLegacyUseAuditRetainsQuietRightsDecision(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := wire.Subject{Account: account.Uid, Program: identity.CanonicalProgramPath(exe)}
	holder, err := credentials.Open(credentials.Config{Backend: &memory{items: map[string][]byte{}}})
	if err != nil {
		t.Fatal(err)
	}
	holder.Store(self, "", wire.Registration{Name: "alpha", Kind: "bearer", Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}, Secret: []byte(secret)})
	endpoint := programEndpoint(t)
	h, err := Listen(endpoint, holder, func(context.Context, wire.Subject, string, string) (string, error) { return "permitted", nil }, func(context.Context, *identity.Peer, string, string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Value
	current.Store("denied")
	h.Authorization.Legacy = func(_ context.Context, subject wire.Subject, action, resource string, op *Operation) credentials.Authorization {
		if subject != self || action != credentials.ActionApply || resource != "credential:alpha" || op == nil || op.Profile != credentials.ScopedUseResourceProfile {
			t.Error("quiet decision changed captured use")
		}
		word := current.Load().(string)
		v := credentials.Authorization{Outcome: credentials.AuthorizationUnavailable, Revision: "final-policy", RightsOutcome: word}
		if word == "denied" || word == "not_granted" || word == "unknown_action" {
			v.Outcome = credentials.AuthorizationDenied
		}
		return v
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	usage := wire.Use{Subject: self, Name: "alpha", Consumer: "abstraction.download/http-execution@1", Target: "huggingface.co"}
	applier := client.NewApplier(endpoint)
	for _, word := range []string{"denied", "not_granted", "unknown_action", "invalid", "forbidden", "unavailable"} {
		current.Store(word)
		for _, read := range []bool{false, true} {
			want, detail := wire.ApplyOutcomeNotPermitted, word
			if word == "invalid" || word == "forbidden" || word == "unavailable" {
				want, detail = wire.ApplyOutcomeUnavailable, "rights:"+word
			}
			var outcome wire.ApplyOutcome
			if read {
				r, e := applier.Apply(context.Background(), usage)
				if e != nil || len(r.Headers) != 0 {
					t.Fatal("refused native Apply returned headers or failed transport")
				}
				outcome = r.Outcome
			} else {
				r, e := applier.Check(context.Background(), usage)
				if e != nil {
					t.Fatal(e)
				}
				outcome = r.Outcome
			}
			if outcome != want {
				t.Fatalf("native use %s: %s", word, outcome)
			}
			page := holder.Audit(self.Account, "", 256)
			last := page.Entries[len(page.Entries)-1]
			if last.Event != "refused" || last.Outcome != detail {
				t.Fatalf("native final decision lost: %+v", last)
			}
		}
	}
	if page := holder.Audit(self.Account, "", 256); len(page.Entries) != 13 {
		t.Fatal("native use did not append exactly one audit entry per call")
	}
}
