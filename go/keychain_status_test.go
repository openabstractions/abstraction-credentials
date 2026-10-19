package credentials

import (
	"context"
	"errors"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// statusBackend runs the data protection keychain's read classification over
// scripted OSStatus answers. Fake only; no Keychain is touched.
type statusBackend struct {
	*memoryBackend
	status int32 // overrides the read when nonzero
	probe  func() error
}

func TestKeychainReadClassificationTable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int32
		data     []byte
		probeErr error
		noProbe  bool
		want     error
		probes   int
	}{
		{name: "readable", data: []byte("inert item")},
		{name: "empty success", want: ErrUnavailable},
		{name: "authenticated absence", status: osStatusItemNotFound, want: ErrNotFound, probes: 1},
		{name: "locked second signal", status: osStatusItemNotFound, probeErr: osStatusError("canary", osStatusInteractionNotAllowed), want: ErrUnavailable, probes: 1},
		{name: "unentitled second signal", status: osStatusItemNotFound, probeErr: osStatusError("delete", osStatusMissingEntitlement), want: ErrUnavailable, probes: 1},
		{name: "uncertain second signal", status: osStatusItemNotFound, probeErr: errors.New("inert probe failure"), want: ErrUnavailable, probes: 1},
		{name: "missing second signal", status: osStatusItemNotFound, noProbe: true, want: ErrUnavailable},
		{name: "locked read", status: osStatusInteractionNotAllowed, want: ErrUnavailable},
		{name: "unentitled read", status: osStatusMissingEntitlement, want: ErrUnavailable},
		{name: "unknown read", status: -1, want: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probes := 0
			probe := func() error { probes++; return tc.probeErr }
			if tc.noProbe {
				probe = nil
			}
			got, err := keychainGetResult(tc.status, tc.data, probe)
			if !errors.Is(err, tc.want) || probes != tc.probes || (tc.want != nil && got != nil) {
				t.Fatalf("Get=%v probes=%d; want %v/%d", err, probes, tc.want, tc.probes)
			}
			if tc.want == ErrUnavailable && errors.Is(err, ErrNotFound) {
				t.Fatal("uncertain read classified lost")
			}
		})
	}
}

func (s *statusBackend) Get(key string) ([]byte, error) {
	if s.status != 0 {
		return keychainGetResult(s.status, nil, s.probe)
	}
	v, err := s.memoryBackend.Get(key)
	if errors.Is(err, ErrNotFound) {
		return keychainGetResult(osStatusItemNotFound, nil, s.probe)
	}
	return keychainGetResult(osStatusSuccess, v, s.probe)
}

// TestKeychainNotFoundNeedsCanary: errSecItemNotFound with a locked store
// (the canary read answers errSecInteractionNotAllowed) reads unavailable and
// keeps the record; with a readable canary it reads lost.
func TestKeychainNotFoundNeedsCanary(t *testing.T) {
	canary := []byte(keychainCanaryValue)
	lockedRead := func() (int32, []byte) { return osStatusInteractionNotAllowed, nil }
	readable := func() (int32, []byte) { return osStatusSuccess, canary }
	noPut := func() int32 { t.Fatal("canary written although present"); return 0 }
	locked := func() error { return keychainCanary(lockedRead, noPut) }
	ready := func() error { return keychainCanary(readable, noPut) }

	if _, err := keychainGetResult(osStatusSuccess, nil, ready); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty data: %v", err)
	}
	if _, err := keychainGetResult(osStatusMissingEntitlement, nil, ready); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("entitlement: %v", err)
	}

	store := &statusBackend{memoryBackend: newMemory(), probe: ready}
	h := open(t, Config{Backend: store})
	ctx := context.Background()
	h.Store(owner, "", registration("hf"))
	apply := func() wire.ApplyOutcome {
		return h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")).Outcome
	}

	store.status, store.probe = osStatusItemNotFound, locked
	if got := apply(); got != wire.ApplyOutcomeUnavailable {
		t.Fatalf("locked keychain: %s", got)
	}
	store.status, store.probe = 0, ready
	if got := apply(); got != wire.ApplyOutcomeApplied {
		t.Fatalf("record not kept: %s", got)
	}
	store.status = osStatusItemNotFound
	if got := apply(); got != wire.ApplyOutcomeLost {
		t.Fatalf("confirmed absence: %s", got)
	}
}

func TestKeychainCanaryAndDeleteProbe(t *testing.T) {
	var written []byte
	get := func() (int32, []byte) {
		if written == nil {
			return osStatusItemNotFound, nil
		}
		return osStatusSuccess, written
	}
	if err := keychainCanary(get, func() int32 { written = []byte(keychainCanaryValue); return osStatusSuccess }); err != nil {
		t.Fatalf("missing canary written: %v", err)
	}
	written = nil
	if err := keychainCanary(get, func() int32 { return osStatusInteractionNotAllowed }); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("locked canary write: %v", err)
	}
	if err := keychainCanary(func() (int32, []byte) { return osStatusSuccess, []byte("x") }, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong canary data: %v", err)
	}
	for st, ok := range map[int32]bool{osStatusSuccess: true, osStatusItemNotFound: true, osStatusMissingEntitlement: false, osStatusInteractionNotAllowed: false, -1: false} {
		if err := keychainDeleteProbe(st); (err == nil) != ok || (err != nil && !errors.Is(err, ErrUnavailable)) {
			t.Fatalf("delete probe %d: %v", st, err)
		}
	}
}
