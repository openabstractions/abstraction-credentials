package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

type memoryBackend struct {
	mu    sync.Mutex
	items map[string][]byte
	down  bool
	max   int
}

func newMemory() *memoryBackend {
	return &memoryBackend{items: map[string][]byte{}, max: MaxSecretBytes}
}

func TestSecureStoreVocabularyPreservesWords(t *testing.T) {
	standard := map[wire.SecureStore]string{
		wire.SecureStoreWindowsCredentialManager: StoreWindowsCredentialManager,
		wire.SecureStoreSecretService:            StoreSecretService,
		wire.SecureStoreFile0600:                 StoreFile,
		wire.SecureStoreMacosKeychain:            StoreMacOSKeychain,
		wire.SecureStoreNone:                     StoreNone,
	}
	for value, word := range standard {
		if string(value) != word {
			t.Fatalf("secure store %q has wire word %q", word, value)
		}
	}
}

func (m *memoryBackend) Name() string        { return "memory-test" }
func (m *memoryBackend) MaxSecretBytes() int { return m.max }
func (m *memoryBackend) Put(key string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return ErrUnavailable
	}
	m.items[key] = append([]byte(nil), secret...)
	return nil
}
func (m *memoryBackend) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, ErrUnavailable
	}
	v, ok := m.items[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (m *memoryBackend) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return ErrUnavailable
	}
	delete(m.items, key)
	return nil
}

const testSecret = "hf_TESTSECRET_value_0123456789_EXAMPLE"

var (
	owner    = wire.Subject{Account: "S-1-5-21-test", Program: filepath.Join(os.TempDir(), "bin", "cli")}
	consumer = "abstraction.download/http-execution@1"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func registration(name string) wire.Registration {
	return wire.Registration{Name: name, Kind: "bearer", Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{consumer}}, Secret: []byte(testSecret)}
}

func permit(word string) Decider {
	return func(context.Context, wire.Subject, string, string) (string, error) { return word, nil }
}

func open(t *testing.T, cfg Config) *Holder {
	t.Helper()
	h, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func use(name, target string) wire.Use {
	return wire.Use{Subject: owner, Consumer: consumer, Name: name, Target: target}
}

func TestStoreValidationAndRefusals(t *testing.T) {
	c := &clock{time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	mem := newMemory()
	h := open(t, Config{Backend: mem, MaxCredentials: 2, Now: c.Now})
	if r := h.Store(owner, "", registration("hf")); r.Outcome != wire.StoreOutcomeStored || r.Revision == "" || r.Current == nil {
		t.Fatalf("store: %+v", r)
	}
	if r := h.Store(owner, "", registration("hf")); r.Outcome != wire.StoreOutcomeConflict || r.Current == nil {
		t.Fatalf("duplicate: %+v", r)
	}
	if r := h.Store(owner, "stale", registration("other")); r.Outcome != wire.StoreOutcomeConflict {
		t.Fatalf("expected revision on absent name: %+v", r)
	}
	for name, mutate := range map[string]func(*wire.Registration){
		"name":        func(r *wire.Registration) { r.Name = "bad name" },
		"target":      func(r *wire.Registration) { r.Scope.Targets = []string{"https://huggingface.co"} },
		"wildcard":    func(r *wire.Registration) { r.Scope.Targets = []string{"*.hf.co"} },
		"consumer":    func(r *wire.Registration) { r.Scope.Consumers = []string{"download"} },
		"header kind": func(r *wire.Registration) { r.Header = "X-Token" },
		"expired":     func(r *wire.Registration) { r.Expires = "2026-09-15T11:00:00Z" },
		"empty":       func(r *wire.Registration) { r.Secret = nil },
		"newline":     func(r *wire.Registration) { r.Secret = []byte("a\r\nX-Evil: 1") },
		"kind":        func(r *wire.Registration) { r.Kind = "Bearer!" },
	} {
		reg := registration("x")
		mutate(&reg)
		if r := h.Store(owner, "", reg); r.Outcome != wire.StoreOutcomeInvalid {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	reg := registration("registry")
	reg.Kind = "ollama/ed25519@1"
	if r := h.Store(owner, "", reg); r.Outcome != wire.StoreOutcomeUnsupportedKind {
		t.Fatalf("owned kind: %+v", r)
	}
	if r := h.Store(owner, "", registration("second")); r.Outcome != wire.StoreOutcomeStored {
		t.Fatal(r)
	}
	if r := h.Store(owner, "", registration("third")); r.Outcome != wire.StoreOutcomeExhausted {
		t.Fatalf("exhausted: %+v", r)
	}
	mem.max = 8
	if r := h.Rotate(owner, h.List(owner.Account, "", 64).Records[0].Revision, wire.Rotation{Name: "hf", Secret: []byte("0123456789")}); r.Outcome != wire.RotateOutcomeInvalid {
		t.Fatalf("store bound: %+v", r)
	}
	mem.max = MaxSecretBytes
	mem.down = true
	if r := h.Rotate(owner, h.List(owner.Account, "", 64).Records[0].Revision, wire.Rotation{Name: "hf", Secret: []byte("new")}); r.Outcome != wire.RotateOutcomeUnavailable {
		t.Fatalf("store down: %+v", r)
	}
}

func TestNoSecureStoreAndMachineScope(t *testing.T) {
	for name, cfg := range map[string]Config{"none": {}, "machine": {Backend: newMemory(), MachineScope: true}} {
		h := open(t, cfg)
		if r := h.Store(owner, "", registration("hf")); r.Outcome != wire.StoreOutcomeNoSecureStore {
			t.Fatalf("%s store: %+v", name, r)
		}
		if r := h.Rotate(owner, "1-00", wire.Rotation{Name: "hf", Secret: []byte("x")}); r.Outcome != wire.RotateOutcomeNoSecureStore {
			t.Fatalf("%s rotate: %+v", name, r)
		}
		if l := h.List(owner.Account, "", 8).Limits; l.SecureStore != StoreNone {
			t.Fatalf("%s limits: %+v", name, l)
		}
	}
	if _, err := NewKeychain(); runtime.GOOS != "darwin" && !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}

func TestApplyLifecycle(t *testing.T) {
	c := &clock{time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	mem := newMemory()
	h := open(t, Config{Backend: mem, Now: c.Now, TombstoneRetention: time.Hour})
	ctx := context.Background()
	stored := h.Store(owner, "", registration("hf"))
	header := registration("gh")
	header.Kind, header.Header = "header", "X-Api-Key"
	h.Store(owner, "", header)

	if r := h.Apply(ctx, use("hf", "cdn-lfs.huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Headers["Authorization"] != "Bearer "+testSecret {
		t.Fatalf("apply: %+v", r.Outcome)
	}
	if r := h.Apply(ctx, use("gh", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Headers["X-Api-Key"] != testSecret {
		t.Fatalf("header apply: %+v", r.Outcome)
	}
	if r := h.Check(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Revision != stored.Revision {
		t.Fatalf("check: %+v", r)
	}
	cases := []struct {
		use     wire.Use
		decide  Decider
		outcome wire.ApplyOutcome
	}{
		{use("hf", "evilhuggingface.co"), permit("permitted"), wire.ApplyOutcomeTargetRefused},
		{use("hf", "attacker.example"), permit("permitted"), wire.ApplyOutcomeTargetRefused},
		{wire.Use{Subject: owner, Consumer: "abstraction.model/resolver@1", Name: "hf", Target: "huggingface.co"}, permit("permitted"), wire.ApplyOutcomeConsumerRefused},
		{use("missing", "huggingface.co"), permit("permitted"), wire.ApplyOutcomeUnknown},
		{use("hf", "huggingface.co"), permit("denied"), wire.ApplyOutcomeNotPermitted},
		{use("hf", "huggingface.co"), permit("not_granted"), wire.ApplyOutcomeNotPermitted},
		{use("hf", "huggingface.co"), permit("forbidden"), wire.ApplyOutcomeUnavailable},
		{use("hf", "huggingface.co"), func(context.Context, wire.Subject, string, string) (string, error) { return "", errors.New("down") }, wire.ApplyOutcomeUnavailable},
		{wire.Use{Subject: owner, Consumer: consumer, Name: "hf", Target: "huggingface.co", Challenge: "x"}, permit("permitted"), wire.ApplyOutcomeInvalid},
		{use("hf", "HuggingFace.co"), permit("permitted"), wire.ApplyOutcomeInvalid},
	}
	for _, tc := range cases {
		if r := h.Apply(ctx, tc.use, tc.decide); r.Outcome != tc.outcome || r.Headers != nil {
			t.Fatalf("%+v: got %s", tc.use, r.Outcome)
		}
	}

	rotated := h.Rotate(owner, stored.Revision, wire.Rotation{Name: "hf", Secret: []byte("rotated-secret"), Expires: "2026-09-15T13:00:00Z"})
	if rotated.Outcome != wire.RotateOutcomeRotated || rotated.Revision == stored.Revision {
		t.Fatalf("rotate: %+v", rotated)
	}
	if r := h.Rotate(owner, stored.Revision, wire.Rotation{Name: "hf", Secret: []byte("again")}); r.Outcome != wire.RotateOutcomeConflict || r.Revision != rotated.Revision {
		t.Fatalf("stale rotate: %+v", r)
	}
	if _, err := mem.Get(h.storeKey(owner.Account, "hf", stored.Revision)); !errors.Is(err, ErrNotFound) {
		t.Fatal("rotation kept the previous item")
	}
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Headers["Authorization"] != "Bearer rotated-secret" {
		t.Fatal("rotation not applied on next request")
	}
	c.now = c.now.Add(2 * time.Hour)
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeExpired {
		t.Fatalf("expiry: %s", r.Outcome)
	}
	restored := h.Rotate(owner, rotated.Revision, wire.Rotation{Name: "hf", Secret: []byte("fresh")})
	if restored.Outcome != wire.RotateOutcomeRotated || restored.Current.State != "active" {
		t.Fatalf("rotate expired: %+v", restored)
	}
	// Loss: the store no longer has the item.
	mem.Delete(h.storeKey(owner.Account, "hf", restored.Revision))
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeLost {
		t.Fatalf("loss: %s", r.Outcome)
	}
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeLost {
		t.Fatalf("lost stays lost: %s", r.Outcome)
	}
	back := h.Rotate(owner, restored.Revision, wire.Rotation{Name: "hf", Secret: []byte("recovered")})
	if back.Outcome != wire.RotateOutcomeRotated {
		t.Fatalf("rotate lost: %+v", back)
	}
	mem.down = true
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeUnavailable {
		t.Fatalf("store outage: %s", r.Outcome)
	}
	if r := h.Revoke(owner, back.Revision, "hf"); r.Outcome != wire.RevokeOutcomeUnavailable {
		t.Fatalf("revoke outage: %+v", r)
	}
	mem.down = false
	if r := h.Revoke(owner, "stale", "hf"); r.Outcome != wire.RevokeOutcomeConflict || r.Revision != back.Revision {
		t.Fatalf("stale revoke: %+v", r)
	}
	if r := h.Revoke(owner, back.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatalf("revoke: %+v", r)
	}
	if len(mem.items) != 1 {
		t.Fatalf("revoke kept bytes: %d items", len(mem.items))
	}
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeRevoked {
		t.Fatalf("tombstone: %s", r.Outcome)
	}
	if r := h.Store(owner, "", registration("hf")); r.Outcome != wire.StoreOutcomeConflict {
		t.Fatalf("store over tombstone: %+v", r)
	}
	c.now = c.now.Add(2 * time.Hour)
	if r := h.Apply(ctx, use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeUnknown {
		t.Fatalf("retired: %s", r.Outcome)
	}
	if again := h.Store(owner, "", registration("hf")); again.Outcome != wire.StoreOutcomeStored || again.Revision == stored.Revision {
		t.Fatalf("re-register: %+v", again)
	}

	page := h.Audit(owner.Account, "", 256)
	events := []string{}
	for _, e := range page.Entries {
		events = append(events, e.Event)
	}
	for _, want := range []string{"stored", "applied", "refused", "checked", "rotated", "expired", "lost", "revoked", "retired"} {
		if !strings.Contains(strings.Join(events, ","), want) {
			t.Fatalf("audit lacks %s: %v", want, events)
		}
	}
	notPermitted := false
	for _, e := range page.Entries {
		if e.Outcome == "denied" && e.Event == "refused" {
			notPermitted = true
		}
	}
	if !notPermitted {
		t.Fatal("audit does not keep the exact rights word")
	}
	listing, _ := json.Marshal(h.List(owner.Account, "", 64))
	audit, _ := json.Marshal(page)
	for _, secret := range []string{testSecret, "rotated-secret", "fresh", "recovered"} {
		if strings.Contains(string(listing), secret) || strings.Contains(string(audit), secret) {
			t.Fatalf("secret %q in metadata or audit", secret)
		}
	}
}

func TestPagingAndGaps(t *testing.T) {
	h := open(t, Config{Backend: newMemory(), AuditCapacity: 4})
	for _, name := range []string{"a", "b", "c"} {
		h.Store(owner, "", registration(name))
	}
	first := h.List(owner.Account, "", 2)
	if first.Outcome != wire.PageOutcomePage || len(first.Records) != 2 || first.Complete || first.Next == "" {
		t.Fatalf("first page: %+v", first)
	}
	second := h.List(owner.Account, first.Next, 2)
	if len(second.Records) != 1 || second.Records[0].Name != "c" || !second.Complete {
		t.Fatalf("second page: %+v", second)
	}
	if g := h.List("other", first.Next, 2); g.Outcome != wire.PageOutcomeGap {
		t.Fatalf("scope mismatch: %+v", g)
	}
	if g := h.List(owner.Account, "", 0); g.Outcome != wire.PageOutcomeInvalid {
		t.Fatal(g)
	}
	a := h.Audit(owner.Account, "", 2)
	if a.Outcome != wire.PageOutcomePage || len(a.Entries) != 2 || a.AtEnd {
		t.Fatalf("audit page: %+v", a)
	}
	for i := 0; i < 6; i++ {
		h.Check(context.Background(), use("a", "huggingface.co"), permit("permitted"))
	}
	if g := h.Audit(owner.Account, a.Next, 2); g.Outcome != wire.PageOutcomeGap || g.Next != a.Next {
		t.Fatalf("pruned cursor: %+v", g)
	}
	restarted := open(t, Config{Backend: newMemory()})
	if g := restarted.Audit(owner.Account, a.Next, 2); g.Outcome != wire.PageOutcomeGap {
		t.Fatalf("foreign epoch: %+v", g)
	}
}

func TestStatePersistsAndCollectsGarbage(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state", "credentials.json")
	mem := newMemory()
	h := open(t, Config{Backend: mem, StatePath: state})
	stored := h.Store(owner, "", registration("hf"))
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testSecret) {
		t.Fatal("state file holds the secret")
	}
	// A crash between the item write and the record commit leaves a garbage key.
	mem.Put("openabstractions/orphan", []byte("x"))
	h.state.Garbage = append(h.state.Garbage, "openabstractions/orphan")
	if err := h.save(); err != nil {
		t.Fatal(err)
	}
	reopened := open(t, Config{Backend: mem, StatePath: state})
	if _, err := mem.Get("openabstractions/orphan"); !errors.Is(err, ErrNotFound) {
		t.Fatal("garbage survived reopen")
	}
	if r := reopened.Apply(context.Background(), use("hf", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeApplied || r.Revision != stored.Revision {
		t.Fatalf("reopened apply: %+v", r.Outcome)
	}
	if r := reopened.Store(owner, "", registration("next")); r.Outcome != wire.StoreOutcomeStored || r.Revision == stored.Revision {
		t.Fatalf("revision reuse: %+v", r)
	}
}
