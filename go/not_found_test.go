package credentials

import (
	"context"
	"errors"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// searchBackend models a store whose lookup cannot tell an absent item from an
// outage, as Keychain and Secret Service: a locked or replaced collection or a
// missing entitlement answers "no such item". Get confirms through probe, as
// the platform backends do. Fake only; no platform store is touched.
type searchBackend struct {
	*memoryBackend
	hidden bool
	probe  func() error
}

func (s *searchBackend) Get(key string) ([]byte, error) {
	if s.hidden {
		return nil, confirmNotFound(s.probe)
	}
	v, err := s.memoryBackend.Get(key)
	if errors.Is(err, ErrNotFound) {
		return nil, confirmNotFound(s.probe)
	}
	return v, err
}

func TestConfirmNotFound(t *testing.T) {
	if err := confirmNotFound(func() error { return nil }); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("healthy store: %v", err)
	}
	if err := confirmNotFound(func() error { return errors.New("collection locked") }); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) {
		t.Fatalf("failed probe: %v", err)
	}
	if err := confirmNotFound(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no probe: %v", err)
	}
}

// TestStoreOutageIsNotLost: a not-found answer during an outage reads
// unavailable and keeps the record active; only a confirmed absence is lost.
func TestStoreOutageIsNotLost(t *testing.T) {
	down := errors.New("default collection locked")
	store := &searchBackend{memoryBackend: newMemory()}
	store.probe = func() error { return nil }
	h := open(t, Config{Backend: store})
	ctx := context.Background()
	h.Store(owner, "", registration("hf"))

	store.hidden, store.probe = true, func() error { return down }
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeUnavailable {
		t.Fatalf("outage apply: %s", r.Outcome)
	}
	if r := h.ApplyScoped(ctx, use("hf", "huggingface.co"), scopedPermit()); r.Outcome != wire.ApplyOutcomeUnavailable {
		t.Fatalf("outage scoped apply: %s", r.Outcome)
	}

	store.hidden, store.probe = false, func() error { return nil }
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied {
		t.Fatalf("after outage: %s", r.Outcome)
	}

	store.hidden = true
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeLost {
		t.Fatalf("confirmed absence: %s", r.Outcome)
	}
}
