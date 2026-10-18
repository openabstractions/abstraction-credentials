package credentials

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

type useReadBackend struct {
	*memoryBackend
	reads atomic.Int32
}

func (b *useReadBackend) Get(key string) ([]byte, error) {
	b.reads.Add(1)
	return b.memoryBackend.Get(key)
}

func TestUseRechecksCurrentRecordAfterDecisionWait(t *testing.T) {
	for _, read := range []bool{false, true} {
		method := "Check"
		if read {
			method = "Apply"
		}
		for _, change := range []string{"expiry", "revoked", "retired", "replacement-target", "replacement-consumer", "replacement-compatible", "rotate-compatible"} {
			t.Run(method+"/"+change, func(t *testing.T) {
				start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
				c := &clock{start}
				backend := &useReadBackend{memoryBackend: newMemory()}
				h := open(t, Config{Backend: backend, Now: c.Now, TombstoneRetention: time.Hour})
				reg := registration("decision-wait")
				if change == "expiry" {
					reg.Expires = start.Add(time.Hour).Format(time.RFC3339)
				}
				stored := h.Store(owner, "", reg)
				if stored.Outcome != wire.StoreOutcomeStored {
					t.Fatalf("store outcome: %s", stored.Outcome)
				}
				entered, resume := make(chan struct{}), make(chan struct{})
				defer func() {
					select {
					case <-resume:
					default:
						close(resume)
					}
				}()
				decision := func(_ context.Context, subject wire.Subject, action, resource string) (string, error) {
					if subject != owner || action != ActionApply || resource != ResourceFor(reg.Name) {
						return "invalid", nil
					}
					close(entered)
					<-resume
					return "permitted", nil
				}
				done := make(chan wire.ApplyResult, 1)
				go func() {
					usage := use(reg.Name, "cdn-lfs.huggingface.co")
					if read {
						done <- h.Apply(context.Background(), usage, decision)
						return
					}
					result := h.Check(context.Background(), usage, decision)
					done <- wire.ApplyResult{Outcome: result.Outcome, Revision: result.Revision}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("use did not reach the decision")
				}
				want, revision := wire.ApplyOutcomeApplied, stored.Revision
				currentSecret := testSecret
				switch change {
				case "expiry":
					c.now = start.Add(2 * time.Hour)
					want = wire.ApplyOutcomeExpired
				case "rotate-compatible":
					currentSecret = testSecret + "-rotated"
					rotated := h.Rotate(owner, stored.Revision, wire.Rotation{Name: reg.Name, Secret: []byte(currentSecret)})
					if rotated.Outcome != wire.RotateOutcomeRotated {
						t.Fatalf("rotate outcome: %s", rotated.Outcome)
					}
					revision = rotated.Revision
				default:
					revoked := h.Revoke(owner, stored.Revision, reg.Name)
					if revoked.Outcome != wire.RevokeOutcomeRevoked {
						t.Fatalf("revoke outcome: %s", revoked.Outcome)
					}
					revision = revoked.Revision
					if change == "revoked" {
						want = wire.ApplyOutcomeRevoked
						break
					}
					c.now = start.Add(2 * time.Hour)
					if page := h.List(owner.Account, "", 64); page.Outcome != wire.PageOutcomePage || len(page.Records) != 0 {
						t.Fatal("revoked name did not retire")
					}
					if change == "retired" {
						want, revision = wire.ApplyOutcomeUnknown, ""
						break
					}
					fresh := registration(reg.Name)
					currentSecret = testSecret + "-replacement"
					fresh.Secret = []byte(currentSecret)
					switch change {
					case "replacement-target":
						fresh.Scope.Targets = []string{"example.org"}
						want = wire.ApplyOutcomeTargetRefused
					case "replacement-consumer":
						fresh.Scope.Consumers = []string{"abstraction.model/resolver@1"}
						want = wire.ApplyOutcomeConsumerRefused
					}
					replacement := h.Store(owner, "", fresh)
					if replacement.Outcome != wire.StoreOutcomeStored {
						t.Fatalf("replacement outcome: %s", replacement.Outcome)
					}
					revision = replacement.Revision
				}
				close(resume)
				var result wire.ApplyResult
				select {
				case result = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("use did not finish after the decision")
				}
				if result.Outcome != want || result.Revision != revision {
					t.Fatalf("current use outcome/revision: %s/%s; want %s/%s", result.Outcome, result.Revision, want, revision)
				}
				wantReads := int32(0)
				if read && want == wire.ApplyOutcomeApplied {
					wantReads = 1
					if result.Headers["Authorization"] != "Bearer "+currentSecret {
						t.Fatal("apply did not use the current compatible revision")
					}
				} else if len(result.Headers) != 0 {
					t.Fatal("check or refused apply returned headers")
				}
				if backend.reads.Load() != wantReads {
					t.Fatalf("backend reads: %d; want %d", backend.reads.Load(), wantReads)
				}
				audit := h.Audit(owner.Account, "", 256)
				if audit.Outcome != wire.PageOutcomePage || len(audit.Entries) == 0 {
					t.Fatal("missing use audit")
				}
				last := audit.Entries[len(audit.Entries)-1]
				if last.Name != reg.Name || last.Revision != revision || last.Outcome != want.String() {
					t.Fatalf("audit outcome/revision: %s/%s; want %s/%s", last.Outcome, last.Revision, want, revision)
				}
				encoded, err := json.Marshal(audit)
				if err != nil || strings.Contains(string(encoded), testSecret) {
					t.Fatal("audit serialization failed or contained secret bytes")
				}
			})
		}
	}
}
