package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-credentials/go/client"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

// memory is a platform store stand-in; the service tests judge the IPC
// boundary, not a platform store.
type memory struct {
	mu    sync.Mutex
	items map[string][]byte
}

func (m *memory) Name() string        { return "memory-test" }
func (m *memory) MaxSecretBytes() int { return credentials.MaxSecretBytes }
func (m *memory) Put(key string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = append([]byte(nil), secret...)
	return nil
}
func (m *memory) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[key]
	if !ok {
		return nil, credentials.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (m *memory) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

// policy is an exact-rule decision point keyed by program, action and resource.
type policy struct {
	mu    sync.Mutex
	rules map[string]string
	down  atomic.Bool
}

func (p *policy) set(program, action, resource, word string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[program+"\x00"+action+"\x00"+resource] = word
}

func (p *policy) decide(_ context.Context, s wire.Subject, action, resource string) (string, error) {
	if p.down.Load() {
		return "", errors.New("decision point down")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if word, ok := p.rules[s.Program+"\x00"+action+"\x00"+resource]; ok {
		return word, nil
	}
	return "not_granted", nil
}

// recorder keeps every reply frame the service sends to this client.
type recorder struct {
	inner   listen.FrameClient
	mu      sync.Mutex
	replies [][]byte
}

func (r *recorder) ExchangeFrame(frame []byte) ([]byte, error) {
	reply, err := r.inner.ExchangeFrame(frame)
	r.mu.Lock()
	r.replies = append(r.replies, append([]byte(nil), reply...))
	r.mu.Unlock()
	return reply, err
}

type fixture struct {
	endpoint   string
	policy     *policy
	designated atomic.Bool
	self       wire.Subject
	holder     *wire.HolderClient
	applier    *wire.ApplierClient
	recorded   *recorder
	errors     *bytes.Buffer
	errorsMu   sync.Mutex
}

func endpointFor(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\credentials-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	dir, err := os.MkdirTemp("/tmp", "cred-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func start(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("UNPROVEN: the Darwin transport cannot meet Program proof; every call is refused there")
	}
	f := &fixture{endpoint: endpointFor(t), policy: &policy{rules: map[string]string{}}, errors: &bytes.Buffer{}}
	holder, err := credentials.Open(credentials.Config{Backend: &memory{items: map[string][]byte{}}})
	if err != nil {
		t.Fatal(err)
	}
	designate := func(_ context.Context, peer *identity.Peer, consumer, _ string) bool {
		subject, err := SubjectFromPeer(peer)
		return err == nil && f.designated.Load() && subject.Program == f.self.Program && consumer == "abstraction.download/http-execution@1"
	}
	h, err := Listen(f.endpoint, holder, f.policy.decide, designate)
	if err != nil {
		t.Fatal(err)
	}
	h.OnError = func(err error) {
		f.errorsMu.Lock()
		fmt.Fprintln(f.errors, err)
		f.errorsMu.Unlock()
	}
	// The service binds this test program by Program proof; learn its subject
	// from the first decision it asks for.
	var seen atomic.Pointer[wire.Subject]
	decide := f.policy.decide
	h.decide = func(ctx context.Context, s wire.Subject, action, resource string) (string, error) {
		seen.CompareAndSwap(nil, &s)
		return decide(ctx, s, action, resource)
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
	f.recorded = &recorder{inner: listen.FrameClient{Endpoint: f.endpoint}.WithDefaults(5*time.Second, MaxFrameBytes)}
	f.holder = wire.NewHolderClient(f.recorded)
	f.applier = wire.NewApplierClient(f.recorded)
	if _, err := f.holder.List("", 1); err != nil {
		t.Fatal(err)
	}
	if seen.Load() == nil {
		t.Fatal("service asked no decision for List")
	}
	f.self = *seen.Load()
	current, err := user.Current()
	if err != nil || f.self.Account != current.Uid || !filepath.IsAbs(f.self.Program) {
		t.Fatalf("bound subject %+v, account %v", f.self, err)
	}
	return f
}

const secret = "hf_SERVICE_SECRET_5b9d2e71_EXAMPLE"

func (f *fixture) register(t *testing.T, name, value string) wire.StoreResult {
	t.Helper()
	f.policy.set(f.self.Program, credentials.ActionManage, credentials.ResourceAccount, "permitted")
	r, err := f.holder.Store("", wire.Registration{Name: name, Kind: "bearer", Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}, Secret: []byte(value)})
	if err != nil || r.Outcome != wire.StoreOutcomeStored {
		t.Fatalf("store %s: %+v %v", name, r.Outcome, err)
	}
	return r
}

func (f *fixture) usage(name string) wire.Use {
	return wire.Use{Subject: f.self, Consumer: "abstraction.download/http-execution@1", Name: name, Target: "huggingface.co"}
}

func TestHolderCallsAreRightsDecisions(t *testing.T) {
	f := start(t)
	reg := wire.Registration{Name: "hf", Kind: "bearer", Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}, Secret: []byte(secret)}
	if r, err := f.holder.Store("", reg); err != nil || r.Outcome != wire.StoreOutcomeForbidden {
		t.Fatalf("store without holder.manage: %+v %v", r, err)
	}
	f.policy.set(f.self.Program, credentials.ActionManage, credentials.ResourceAccount, "denied")
	if r, _ := f.holder.Store("", reg); r.Outcome != wire.StoreOutcomeForbidden {
		t.Fatalf("store denied: %+v", r)
	}
	f.policy.down.Store(true)
	if r, _ := f.holder.Store("", reg); r.Outcome != wire.StoreOutcomeUnavailable {
		t.Fatalf("store with decision point down: %+v", r)
	}
	if p, _ := f.holder.List("", 8); p.Outcome != wire.PageOutcomeUnavailable || string(p.Limits.SecureStore) != "" {
		t.Fatalf("list with decision point down: %+v", p)
	}
	f.policy.down.Store(false)
	stored := f.register(t, "hf", secret)
	if p, _ := f.holder.List("", 8); p.Outcome != wire.PageOutcomeForbidden || string(p.Limits.SecureStore) != "" {
		t.Fatalf("list without holder.read: %+v", p)
	}
	f.policy.set(f.self.Program, credentials.ActionRead, credentials.ResourceAccount, "permitted")
	page, err := f.holder.List("", 8)
	if err != nil || page.Outcome != wire.PageOutcomePage || page.Limits.SecureStore != wire.SecureStore("memory-test") || len(page.Records) != 1 || page.Records[0].RegisteredBy != f.self || page.Records[0].Revision != stored.Revision {
		t.Fatalf("list: %+v %v", page, err)
	}
	rotated, err := f.holder.Rotate(stored.Revision, wire.Rotation{Name: "hf", Secret: []byte("hf_rotated_value")})
	if err != nil || rotated.Outcome != wire.RotateOutcomeRotated {
		t.Fatalf("rotate: %+v %v", rotated, err)
	}
	audit, err := f.holder.Audit("", 64)
	if err != nil || audit.Outcome != wire.PageOutcomePage || len(audit.Entries) < 2 {
		t.Fatalf("audit: %+v %v", audit, err)
	}
	if r, _ := f.holder.Revoke(rotated.Revision, "hf"); r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatalf("revoke: %+v", r)
	}
}

func TestApplierServesOnlyDesignatedEnforcers(t *testing.T) {
	f := start(t)
	f.register(t, "hf", secret)
	f.policy.set(f.self.Program, credentials.ActionApply, credentials.ResourceFor("hf"), "permitted")
	ctx := context.Background()
	typed := client.NewApplier(f.endpoint)

	// The same program, undesignated, is an application: forbidden before any record.
	for _, u := range []wire.Use{f.usage("hf"), f.usage("missing")} {
		if r, err := typed.Apply(ctx, u); err != nil || r.Outcome != wire.ApplyOutcomeForbidden || r.Headers != nil {
			t.Fatalf("undesignated apply %s: %+v %v", u.Name, r, err)
		}
		if r, err := typed.Check(ctx, u); err != nil || r.Outcome != wire.ApplyOutcomeForbidden || r.Revision != "" {
			t.Fatalf("undesignated check %s: %+v %v", u.Name, r, err)
		}
	}

	f.designated.Store(true)
	r, err := typed.Apply(ctx, f.usage("hf"))
	if err != nil || r.Outcome != wire.ApplyOutcomeApplied || r.Headers["Authorization"] != "Bearer "+secret {
		t.Fatalf("designated apply: %s %v", r.Outcome, err)
	}
	other := f.usage("hf")
	other.Consumer = "abstraction.model/resolver@1"
	if r, _ := typed.Apply(ctx, other); r.Outcome != wire.ApplyOutcomeForbidden {
		t.Fatalf("designation is per consumer: %s", r.Outcome)
	}
	foreign := f.usage("hf")
	foreign.Subject.Account = "S-1-5-21-0-0-0-1001"
	if r, _ := typed.Apply(ctx, foreign); r.Outcome != wire.ApplyOutcomeForbidden {
		t.Fatalf("another account's subject: %s", r.Outcome)
	}
	app := f.usage("hf")
	app.Subject.Program = filepath.Join(filepath.Dir(f.self.Program), "application")
	if r, _ := typed.Apply(ctx, app); r.Outcome != wire.ApplyOutcomeNotPermitted || r.Headers != nil {
		t.Fatalf("subject without an apply rule: %s", r.Outcome)
	}
	f.policy.set(app.Subject.Program, credentials.ActionApply, credentials.ResourceFor("hf"), "permitted")
	if r, _ := typed.Apply(ctx, app); r.Outcome != wire.ApplyOutcomeApplied {
		t.Fatalf("subject with an apply rule: %s", r.Outcome)
	}
	f.policy.down.Store(true)
	if r, _ := typed.Apply(ctx, app); r.Outcome != wire.ApplyOutcomeUnavailable || r.Headers != nil {
		t.Fatalf("decision point down: %s", r.Outcome)
	}
}

// encodings are the spellings a secret could take inside a reply frame.
func encodings(value []byte) [][]byte {
	return [][]byte{
		value,
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(hex.EncodeToString(value)),
		[]byte(strings.ToUpper(hex.EncodeToString(value))),
	}
}

// TestNoReplyCarriesSecretBytesToAnApplication drives random holder and
// applier calls from an application peer, including the operator calls it is
// granted, and searches every reply frame and every reported service error for
// every secret registered or rotated.
func TestNoReplyCarriesSecretBytesToAnApplication(t *testing.T) {
	f := start(t)
	f.policy.set(f.self.Program, credentials.ActionRead, credentials.ResourceAccount, "permitted")
	secrets := [][]byte{}
	revisions := map[string]string{}
	names := []string{"hf", "gh", "ollama-cloud", "missing", "bad name", ""}
	targets := []string{"huggingface.co", "cdn-lfs.huggingface.co", "attacker.example", "HuggingFace.co", ""}
	consumers := []string{"abstraction.download/http-execution@1", "abstraction.model/resolver@1", "abstraction.inference/chat@1", "nope"}
	rng := rand.New(rand.NewSource(20260916))
	cursor := ""
	auditCursor := ""
	for i := 0; i < 400; i++ {
		name := names[rng.Intn(len(names))]
		switch rng.Intn(8) {
		case 0, 1:
			value := make([]byte, 8+rng.Intn(48))
			for j := range value {
				value[j] = byte(0x21 + rng.Intn(0x5e))
			}
			secrets = append(secrets, append([]byte(nil), value...))
			if rng.Intn(4) == 0 {
				f.policy.set(f.self.Program, credentials.ActionManage, credentials.ResourceAccount, "not_granted")
			} else {
				f.policy.set(f.self.Program, credentials.ActionManage, credentials.ResourceAccount, "permitted")
			}
			kind, header := "bearer", ""
			if rng.Intn(3) == 0 {
				kind, header = "header", "X-Api-Key"
			}
			r, err := f.holder.Store("", wire.Registration{Name: name, Kind: kind, Header: header, Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: consumers[:1+rng.Intn(3)]}, Secret: value})
			if err == nil && r.Outcome == wire.StoreOutcomeStored {
				revisions[name] = r.Revision
			}
		case 2:
			value := []byte(fmt.Sprintf("rotated-%d-%x", i, rng.Uint64()))
			secrets = append(secrets, append([]byte(nil), value...))
			r, err := f.holder.Rotate(revisions[name], wire.Rotation{Name: name, Secret: value})
			if err == nil && r.Outcome == wire.RotateOutcomeRotated {
				revisions[name] = r.Revision
			}
		case 3:
			if rng.Intn(3) == 0 {
				f.holder.Revoke(revisions[name], name)
			}
		case 4:
			p, err := f.holder.List(cursor, int64(1+rng.Intn(3)))
			if err == nil && p.Outcome == wire.PageOutcomePage {
				cursor = p.Next
			}
		case 5:
			p, err := f.holder.Audit(auditCursor, int64(1+rng.Intn(8)))
			if err == nil && p.Outcome == wire.PageOutcomePage && rng.Intn(2) == 0 {
				auditCursor = p.Next
			}
		case 6, 7:
			u := wire.Use{Subject: f.self, Consumer: consumers[rng.Intn(len(consumers))], Name: name, Target: targets[rng.Intn(len(targets))]}
			f.policy.set(f.self.Program, credentials.ActionApply, credentials.ResourceFor(name), []string{"permitted", "denied", "not_granted"}[rng.Intn(3)])
			if rng.Intn(2) == 0 {
				f.applier.Check(u)
			} else {
				r, err := f.applier.Apply(u)
				if err == nil && (r.Outcome != wire.ApplyOutcomeForbidden || r.Headers != nil) {
					t.Fatalf("application apply: %+v", r.Outcome)
				}
			}
		}
	}
	stored := 0
	for _, r := range revisions {
		if r != "" {
			stored++
		}
	}
	if stored == 0 || len(f.recorded.replies) < 300 {
		t.Fatalf("fuzz exercised too little: %d stored names, %d replies", stored, len(f.recorded.replies))
	}
	f.errorsMu.Lock()
	reported := f.errors.Bytes()
	f.errorsMu.Unlock()
	for _, value := range secrets {
		for _, spelled := range encodings(value) {
			for i, reply := range f.recorded.replies {
				if bytes.Contains(reply, spelled) {
					t.Fatalf("reply %d carries secret bytes %q", i, spelled)
				}
			}
			if bytes.Contains(reported, spelled) {
				t.Fatal("a reported service error carries secret bytes")
			}
		}
	}
	t.Logf("%d replies searched for %d secrets in %d spellings", len(f.recorded.replies), len(secrets), len(encodings(nil)))
}
