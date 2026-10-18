package credentials

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

func useAuditDecision(word string) Authorization {
	v := Authorization{Outcome: AuthorizationUnavailable, Revision: "policy-1", RightsOutcome: word}
	switch word {
	case "permitted":
		v.Outcome = Authorized
	case "denied", "not_granted", "unknown_action":
		v.Outcome = AuthorizationDenied
	}
	return v
}

func assertUseAudit(t *testing.T, h *Holder, want string) {
	t.Helper()
	page := h.Audit(owner.Account, "", 256)
	if len(page.Entries) != 2 || page.Entries[1].Event != "refused" || page.Entries[1].Outcome != want {
		t.Fatalf("one refused use with exact decision %q: %+v", want, page.Entries)
	}
	data, err := json.Marshal(page)
	if err != nil || strings.Contains(string(data), testSecret) {
		t.Fatal("use audit disclosed a value")
	}
}

func TestUseAuditRetainsFinalRightsDecision(t *testing.T) {
	for _, word := range []string{"denied", "not_granted", "unknown_action", "forbidden", "invalid", "unavailable"} {
		for _, scoped := range []bool{false, true} {
			for _, phase := range []string{"check", "before_get", "after_get"} {
				name := word + "/" + map[bool]string{false: "authorized", true: "scoped"}[scoped] + "/" + phase
				t.Run(name, func(t *testing.T) {
					m := &countedBackend{memoryBackend: newMemory()}
					h := open(t, Config{Backend: m})
					h.Store(owner, "", registration("alpha"))
					finalAt := 2
					if phase == "after_get" {
						finalAt = 3
					}
					calls := 0
					current := func() Authorization {
						calls++
						if calls == finalAt {
							return useAuditDecision(word)
						}
						return useAuditDecision("permitted")
					}
					var outcome wire.ApplyOutcome
					var headers map[string]string
					if scoped {
						authorization := ScopedAuthorization{Admit: func() Authorization { return useAuditDecision("permitted") }, Check: func(string) Authorization { return current() }}
						if phase == "check" {
							outcome = h.CheckScoped(context.Background(), use("alpha", "huggingface.co"), authorization).Outcome
						} else {
							r := h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), authorization)
							outcome, headers = r.Outcome, r.Headers
						}
					} else {
						var evidence Authorization
						guard := func() AuthorizationOutcome {
							evidence = current()
							return evidence.Outcome
						}
						if phase == "check" {
							outcome = h.CheckAuthorized(context.Background(), use("alpha", "huggingface.co"), permit("permitted"), guard, &evidence).Outcome
						} else {
							r := h.ApplyAuthorized(context.Background(), use("alpha", "huggingface.co"), permit("permitted"), guard, &evidence)
							outcome, headers = r.Outcome, r.Headers
						}
					}
					want, detail := wire.ApplyOutcomeNotPermitted, word
					if useAuditDecision(word).Outcome == AuthorizationUnavailable {
						want, detail = wire.ApplyOutcomeUnavailable, "rights:"+word
					}
					if outcome != want || len(headers) != 0 || calls != finalAt {
						t.Fatalf("final refusal: %s, headers=%d, calls=%d", outcome, len(headers), calls)
					}
					wantGets := int32(0)
					if phase == "after_get" {
						wantGets = 1
					}
					if m.gets.Load() != wantGets || strings.Contains(string(m.last), testSecret) {
						t.Fatal("refusal read early or retained backend scratch")
					}
					assertUseAudit(t, h, detail)
				})
			}
		}
	}
}

func TestUseAuditDoesNotReuseStaleOrUntrustedRightsEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, word, want string
		decision         AuthorizationOutcome
		write            bool
	}{
		{"native_refusal", "", "not_permitted", AuthorizationDenied, false},
		{"context_refusal", "", "unavailable", AuthorizationUnavailable, false},
		{"untrusted_detail", testSecret, "not_permitted", AuthorizationDenied, true},
		{"inconsistent_detail", "denied", "unavailable", AuthorizationUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := open(t, Config{Backend: newMemory()})
			h.Store(owner, "", registration("alpha"))
			evidence := useAuditDecision("denied")
			calls := 0
			guard := func() AuthorizationOutcome {
				calls++
				if calls == 1 {
					// A prior Rights word cannot survive the later guard.
					evidence = useAuditDecision("denied")
					return Authorized
				}
				if tc.write {
					evidence = Authorization{Outcome: tc.decision, RightsOutcome: tc.word}
				}
				return tc.decision
			}
			r := h.ApplyAuthorized(context.Background(), use("alpha", "huggingface.co"), permit("permitted"), guard, &evidence)
			if r.Outcome == wire.ApplyOutcomeApplied || len(r.Headers) != 0 || calls != 2 {
				t.Fatal("final non-Rights refusal applied")
			}
			assertUseAudit(t, h, tc.want)
		})
	}
}

func TestScopedUseAdmissionAuditRetainsRightsDecision(t *testing.T) {
	for _, word := range []string{"denied", "not_granted", "unknown_action", "forbidden", "invalid", "unavailable"} {
		for _, read := range []bool{false, true} {
			t.Run(word+map[bool]string{false: "/check", true: "/apply"}[read], func(t *testing.T) {
				m := &countedBackend{memoryBackend: newMemory()}
				h := open(t, Config{Backend: m})
				h.Store(owner, "", registration("alpha"))
				authorization := ScopedAuthorization{Admit: func() Authorization { return useAuditDecision(word) }, Check: func(string) Authorization { panic("refused admission reached quiet check") }}
				if read {
					h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), authorization)
				} else {
					h.CheckScoped(context.Background(), use("alpha", "huggingface.co"), authorization)
				}
				if m.gets.Load() != 0 {
					t.Fatal("refused admission read value")
				}
				detail := word
				if useAuditDecision(word).Outcome == AuthorizationUnavailable {
					detail = "rights:" + word
				}
				assertUseAudit(t, h, detail)
			})
		}
	}
}

func TestUseAuditBlockDuringBackendWait(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(map[bool]string{false: "authorized", true: "scoped"}[scoped], func(t *testing.T) {
			m := &countedBackend{memoryBackend: newMemory(), entered: make(chan struct{}), resume: make(chan struct{})}
			h := open(t, Config{Backend: m})
			h.Store(owner, "", registration("alpha"))
			var blocked atomic.Bool
			current := func() Authorization {
				if blocked.Load() {
					return useAuditDecision("denied")
				}
				return useAuditDecision("permitted")
			}
			done := make(chan wire.ApplyResult, 1)
			go func() {
				if scoped {
					a := ScopedAuthorization{Admit: current, Check: func(string) Authorization { return current() }}
					done <- h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), a)
				} else {
					var evidence Authorization
					guard := func() AuthorizationOutcome {
						evidence = current()
						return evidence.Outcome
					}
					done <- h.ApplyAuthorized(context.Background(), use("alpha", "huggingface.co"), permit("permitted"), guard, &evidence)
				}
			}()
			<-m.entered
			blocked.Store(true)
			close(m.resume)
			r := <-done
			if r.Outcome != wire.ApplyOutcomeNotPermitted || len(r.Headers) != 0 || m.gets.Load() != 1 || strings.Contains(string(m.last), testSecret) {
				t.Fatal("otherwise-permitted backend wait released blocked headers or scratch")
			}
			assertUseAudit(t, h, "denied")
		})
	}
}
