package credentials

import (
	"context"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

func localKey(name, key string) wire.Registration {
	return wire.Registration{Name: name, Kind: KindLocalKey, Scope: wire.Scope{Targets: []string{"localhost"}, Consumers: []string{"abstraction.inference/chat@1"}}, Secret: []byte(key)}
}

// A local key is registered only in process, verified in constant time, never
// applied as a header, and refused once revoked or lost.
func TestLocalKeysAreVerifiedAndNeverApplied(t *testing.T) {
	store := newMemory()
	h := open(t, Config{Backend: store})
	const key = "oalk_0123456789abcdef_SECRET"
	if r := h.Store(owner, "", localKey("local-key.a", key)); r.Outcome != wire.StoreOutcomeUnsupportedKind {
		t.Fatalf("holder@1 Store of a local key: %s", r.Outcome)
	}
	if r := h.StoreLocalKey(owner, registration("local-key.b")); r.Outcome != wire.StoreOutcomeInvalid {
		t.Fatalf("StoreLocalKey of a bearer kind: %s", r.Outcome)
	}
	stored := h.StoreLocalKey(owner, localKey("local-key.a", key))
	if stored.Outcome != wire.StoreOutcomeStored || stored.Current.Kind != KindLocalKey {
		t.Fatalf("StoreLocalKey: %+v", stored)
	}
	for _, c := range []struct{ presented, want string }{{key, "verified"}, {key + "x", "mismatch"}, {"oalk_other", "mismatch"}} {
		if got := h.VerifyLocalKey(owner.Account, "local-key.a", []byte(c.presented)); got != c.want {
			t.Fatalf("verify %q: %s, want %s", c.presented, got, c.want)
		}
	}
	if got := h.VerifyLocalKey("S-1-5-21-other", "local-key.a", []byte(key)); got != "unknown" {
		t.Fatalf("another account: %s", got)
	}
	if got := h.VerifyLocalKey(owner.Account, "local-key.none", []byte(key)); got != "unknown" {
		t.Fatalf("an absent name: %s", got)
	}
	decided := false
	apply := h.Apply(context.Background(), wire.Use{Subject: owner, Consumer: "abstraction.inference/chat@1", Name: "local-key.a", Target: "localhost"},
		func(context.Context, wire.Subject, string, string) (string, error) {
			decided = true
			return "permitted", nil
		})
	if apply.Outcome != wire.ApplyOutcomeUnsupportedKind || apply.Headers != nil || decided {
		t.Fatalf("Apply of a local key: %+v decided=%v", apply, decided)
	}
	store.down = true
	if got := h.VerifyLocalKey(owner.Account, "local-key.a", []byte(key)); got != "unavailable" {
		t.Fatalf("store down: %s", got)
	}
	store.down = false
	if r := h.Revoke(owner, stored.Revision, "local-key.a"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatalf("revoke: %s", r.Outcome)
	}
	if got := h.VerifyLocalKey(owner.Account, "local-key.a", []byte(key)); got != "revoked" {
		t.Fatalf("after revoke: %s", got)
	}
	lost := h.StoreLocalKey(owner, localKey("local-key.c", key))
	store.mu.Lock()
	clear(store.items)
	store.mu.Unlock()
	if got := h.VerifyLocalKey(owner.Account, "local-key.c", []byte(key)); got != "lost" || lost.Outcome != wire.StoreOutcomeStored {
		t.Fatalf("store lost the item: %s", got)
	}
}
