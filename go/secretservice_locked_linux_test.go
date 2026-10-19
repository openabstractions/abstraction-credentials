//go:build linux

package credentials

import (
	"context"
	"errors"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// TestCollectionLockedReply: an empty search reads as an absent item only
// when the default collection answers unlocked.
func TestCollectionLockedReply(t *testing.T) {
	if err := collectionLocked([]any{variant{"b", false}}); err != nil {
		t.Fatalf("unlocked: %v", err)
	}
	for name, reply := range map[string][]any{
		"locked":           {variant{"b", true}},
		"empty":            nil,
		"not bool":         {variant{"s", "no"}},
		"no variant":       {false},
		"wrong typed bool": {variant{"b", "false"}},
		"extra value":      {variant{"b", false}, variant{"b", false}},
	} {
		if err := collectionLocked(reply); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

type classifiedReply struct {
	body []any
	err  error
}
type classificationBus struct {
	search, collection, secret classifiedReply
	probes                     int
}

func (b *classificationBus) call(dest, path, iface, member, sig string, args ...any) ([]any, error) {
	switch member {
	case "SearchItems":
		return b.search.body, b.search.err
	case "Get":
		b.probes++
		return b.collection.body, b.collection.err
	case "GetSecret":
		return b.secret.body, b.secret.err
	default:
		return nil, errors.New("unscripted native call")
	}
}

func TestSecretServiceReadClassificationTable(t *testing.T) {
	empty := classifiedReply{body: []any{[]any{}, []any{}}}
	found := classifiedReply{body: []any{[]any{"/inert/item"}, []any{}}}
	ready := classifiedReply{body: []any{variant{"b", false}}}
	for _, tc := range []struct {
		name                       string
		search, collection, secret classifiedReply
		want                       error
		probes                     int
	}{
		{name: "confirmed absence", search: empty, collection: ready, want: ErrNotFound, probes: 1},
		{name: "locked collection", search: empty, collection: classifiedReply{body: []any{variant{"b", true}}}, want: ErrUnavailable, probes: 1},
		{name: "missing collection", search: empty, collection: classifiedReply{err: &dbusError{name: "org.freedesktop.Secret.Error.NoSuchObject"}}, want: ErrUnavailable, probes: 1},
		{name: "unreachable collection", search: empty, collection: classifiedReply{err: errors.New("inert bus failure")}, want: ErrUnavailable, probes: 1},
		{name: "empty second signal", search: empty, want: ErrUnavailable, probes: 1},
		{name: "wrong typed second signal", search: empty, collection: classifiedReply{body: []any{variant{"b", "false"}}}, want: ErrUnavailable, probes: 1},
		{name: "locked item", search: classifiedReply{body: []any{[]any{}, []any{"/inert/item"}}}, want: ErrUnavailable},
		{name: "search failure", search: classifiedReply{err: errors.New("inert search failure")}, want: ErrUnavailable},
		{name: "missing search reply", want: ErrUnavailable},
		{name: "wrong typed search", search: classifiedReply{body: []any{"wrong", []any{}}}, collection: ready, want: ErrUnavailable},
		{name: "wrong typed item path", search: classifiedReply{body: []any{[]any{42}, []any{}}}, want: ErrUnavailable},
		{name: "empty secret reply", search: found, want: ErrUnavailable},
		{name: "wrong typed secret", search: found, secret: classifiedReply{body: []any{[]any{"/session", []byte{}, "wrong", "application/octet-stream"}}}, want: ErrUnavailable},
		{name: "empty secret", search: found, secret: classifiedReply{body: []any{[]any{"/session", []byte{}, []byte{}, "application/octet-stream"}}}, want: ErrUnavailable},
		{name: "secret call failure", search: found, secret: classifiedReply{err: errors.New("inert secret failure")}, want: ErrUnavailable},
		{name: "readable", search: found, secret: classifiedReply{body: []any{[]any{"/session", []byte{}, []byte{1, 0, 255}, "application/octet-stream"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bus := &classificationBus{search: tc.search, collection: tc.collection, secret: tc.secret}
			got, err := (secretService{}).read(bus, "/session", "inert")
			if !errors.Is(err, tc.want) || bus.probes != tc.probes || (tc.want != nil && got != nil) {
				t.Fatalf("read=%v probes=%d; want %v/%d", err, bus.probes, tc.want, tc.probes)
			}
			if tc.want == ErrUnavailable && errors.Is(err, ErrNotFound) {
				t.Fatal("uncertain store classified lost")
			}
			if tc.want == nil && (len(got) != 3 || got[0] != 1 || got[2] != 255) {
				t.Fatal("changed native data")
			}
		})
	}
}

// scriptedBus answers the Secret Service calls of a read from a memory store.
// hidden makes SearchItems answer no items, as a locked or replaced collection
// does; aliasMissing and locked script the default collection.
type scriptedBus struct {
	items                        *memoryBackend
	hidden, aliasMissing, locked bool
	malformedLocked              bool
}

func (b *scriptedBus) call(dest, path, iface, member, sig string, args ...any) ([]any, error) {
	switch member {
	case "SearchItems":
		key := args[0].([]any)[0].([]any)[1].(string)
		if _, err := b.items.Get(key); b.hidden || err != nil {
			return []any{[]any{}, []any{}}, nil
		}
		return []any{[]any{"/item/" + key}, []any{}}, nil
	case "Get":
		if b.aliasMissing {
			return nil, &dbusError{name: "org.freedesktop.Secret.Error.NoSuchObject", message: "no such alias"}
		}
		if b.malformedLocked {
			return []any{variant{"b", "false"}}, nil
		}
		return []any{variant{"b", b.locked}}, nil
	case "GetSecret":
		secret, err := b.items.Get(path[len("/item/"):])
		if err != nil {
			return nil, err
		}
		return []any{[]any{"/session", []byte{}, secret, "application/octet-stream"}}, nil
	}
	return nil, errors.New("unscripted call " + member)
}

// busBackend runs the Secret Service read path over a scripted bus.
type busBackend struct {
	*memoryBackend
	bus *scriptedBus
}

func (b busBackend) Get(key string) ([]byte, error) {
	return secretService{}.read(b.bus, "/session", key)
}

// TestSecretServiceReadNotFound drives secretService.read: an empty search
// reads unavailable while the default collection is missing or locked, and
// lost only once the collection answers unlocked.
func TestSecretServiceReadNotFound(t *testing.T) {
	mem := newMemory()
	bus := &scriptedBus{items: mem}
	h := open(t, Config{Backend: busBackend{memoryBackend: mem, bus: bus}})
	ctx := context.Background()
	h.Store(owner, "", registration("hf"))
	apply := func() wire.ApplyOutcome {
		return h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")).Outcome
	}

	bus.hidden, bus.locked = true, true
	if _, err := (busBackend{bus: bus}).Get("hf"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) {
		t.Fatalf("locked collection: %v", err)
	}
	if got := apply(); got != wire.ApplyOutcomeUnavailable {
		t.Fatalf("locked apply: %s", got)
	}
	bus.locked, bus.aliasMissing = false, true
	if got := apply(); got != wire.ApplyOutcomeUnavailable {
		t.Fatalf("missing alias apply: %s", got)
	}
	bus.aliasMissing, bus.malformedLocked = false, true
	if got := apply(); got != wire.ApplyOutcomeUnavailable {
		t.Fatalf("malformed collection apply: %s", got)
	}
	bus.malformedLocked = false
	bus.hidden, bus.aliasMissing = false, false
	if got := apply(); got != wire.ApplyOutcomeApplied {
		t.Fatalf("record not kept: %s", got)
	}
	bus.hidden = true
	if _, err := (busBackend{bus: bus}).Get("hf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlocked collection: %v", err)
	}
	if got := apply(); got != wire.ApplyOutcomeLost {
		t.Fatalf("confirmed absence: %s", got)
	}
}
