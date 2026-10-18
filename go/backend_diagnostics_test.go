package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

type diagnosticBackend struct {
	*memoryBackend
	failPut, failGet, failDelete bool
	afterPut                     func()
	last                         []byte
}

func diagnosticFailure() error { return errors.New("provider diagnostic contains " + testSecret) }
func (m *diagnosticBackend) Put(key string, value []byte) error {
	if m.failPut {
		return diagnosticFailure()
	}
	err := m.memoryBackend.Put(key, value)
	if m.afterPut != nil {
		m.afterPut()
	}
	return err
}
func (m *diagnosticBackend) Get(key string) ([]byte, error) {
	v, err := m.memoryBackend.Get(key)
	m.last = v
	if m.failGet {
		return v, diagnosticFailure()
	}
	return v, err
}
func (m *diagnosticBackend) Delete(key string) error {
	if m.failDelete {
		return diagnosticFailure()
	}
	return m.memoryBackend.Delete(key)
}

type degradedBackend struct{ *memoryBackend }

func (degradedBackend) degraded() string { return "store_lock process_only" }

// TestOpenReportsADegradedBackend: a backend running with a weaker guarantee
// than its store word, such as the Credential Manager without its session
// lock, is reported once when the holder opens.
func TestOpenReportsADegradedBackend(t *testing.T) {
	var reports []string
	if _, err := Open(Config{Backend: degradedBackend{newMemory()}, OnError: func(err error) { reports = append(reports, err.Error()) }}); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0] != "credentials: backend store_lock process_only" {
		t.Fatalf("reports: %q", reports)
	}
	reports = nil
	if _, err := Open(Config{Backend: newMemory(), OnError: func(err error) { reports = append(reports, err.Error()) }}); err != nil || len(reports) != 0 {
		t.Fatalf("a whole backend reported %q (%v)", reports, err)
	}
}

func TestAllHolderBackendDiagnosticsUseSafeOwner(t *testing.T) {
	for _, operation := range []string{"store_put", "rotate_put", "apply_get", "scoped_apply_get", "read_get", "verify_get", "revoke_delete", "rotate_delete", "garbage_delete", "store_cleanup_delete", "rotate_cleanup_delete"} {
		t.Run(operation, func(t *testing.T) {
			m := &diagnosticBackend{memoryBackend: newMemory()}
			var reports []string
			h := open(t, Config{Backend: m, OnError: func(err error) { reports = append(reports, err.Error()) }})
			reg := registration("alpha")
			if operation == "verify_get" {
				reg.Kind = KindLocalKey
			}
			var stored wire.StoreResult
			if operation != "store_put" && operation != "store_cleanup_delete" {
				if operation == "verify_get" {
					stored = h.StoreLocalKey(owner, reg)
				} else {
					stored = h.Store(owner, "", reg)
				}
				if stored.Outcome != wire.StoreOutcomeStored {
					t.Fatal("otherwise-valid fixture failed")
				}
			}
			if strings.HasSuffix(operation, "cleanup_delete") {
				path := filepath.Join(t.TempDir(), "state-is-directory")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				m.failDelete = true
				m.afterPut = func() { h.cfg.StatePath = path }
			}
			switch operation {
			case "store_put":
				m.failPut = true
				if r := h.StoreScoped(owner, "", registration("alpha"), scopedPermit()); r.Outcome != wire.StoreOutcomeUnavailable {
					t.Fatal("failed Put admitted Store")
				}
			case "rotate_put":
				m.failPut = true
				if r := h.RotateScoped(owner, stored.Revision, wire.Rotation{Name: "alpha", Secret: []byte(testSecret)}, scopedPermit()); r.Outcome != wire.RotateOutcomeUnavailable {
					t.Fatal("failed Put admitted Rotate")
				}
			case "apply_get":
				m.failGet = true
				if r := h.Apply(context.Background(), use("alpha", "huggingface.co"), permit("permitted")); r.Outcome != wire.ApplyOutcomeUnavailable || len(r.Headers) != 0 {
					t.Fatal("failed Get exported headers")
				}
			case "scoped_apply_get":
				m.failGet = true
				if r := h.ApplyScoped(context.Background(), use("alpha", "huggingface.co"), scopedPermit()); r.Outcome != wire.ApplyOutcomeUnavailable || len(r.Headers) != 0 {
					t.Fatal("failed scoped Get exported headers")
				}
			case "read_get":
				m.failGet = true
				if r := h.ReadSecret(owner, "alpha", scopedPermit()); r.Outcome != wire.SecretReadOutcomeUnavailable || r.Value != nil {
					t.Fatal("failed Read exported bytes")
				}
			case "verify_get":
				m.failGet = true
				if result := h.VerifyLocalKey(owner.Account, "alpha", []byte(testSecret)); result != "unavailable" {
					t.Fatal("failed local Get verified")
				}
			case "revoke_delete":
				m.failDelete = true
				if r := h.Revoke(owner, stored.Revision, "alpha"); r.Outcome != wire.RevokeOutcomeUnavailable {
					t.Fatal("failed Delete revoked")
				}
			case "rotate_delete":
				m.failDelete = true
				if r := h.Rotate(owner, stored.Revision, wire.Rotation{Name: "alpha", Secret: []byte(testSecret)}); r.Outcome != wire.RotateOutcomeRotated {
					t.Fatal("cleanup failure changed committed rotation")
				}
			case "garbage_delete":
				m.failDelete = true
				h.state.Garbage = append(h.state.Garbage, "opaque-key")
				h.collectGarbage()
			case "store_cleanup_delete":
				if r := h.Store(owner, "", registration("alpha")); r.Outcome != wire.StoreOutcomeUnavailable {
					t.Fatal("state failure admitted store")
				}
			case "rotate_cleanup_delete":
				if r := h.Rotate(owner, stored.Revision, wire.Rotation{Name: "alpha", Secret: []byte(testSecret)}); r.Outcome != wire.RotateOutcomeUnavailable {
					t.Fatal("state failure admitted rotate")
				}
			}
			if len(reports) == 0 {
				t.Fatal("provider failure was not classified")
			}
			for _, report := range reports {
				for _, sensitive := range []string{testSecret, base64.StdEncoding.EncodeToString([]byte(testSecret))} {
					if strings.Contains(report, sensitive) {
						t.Fatal("provider value entered report sink")
					}
				}
			}
			if m.last != nil && !bytes.Equal(m.last, make([]byte, len(m.last))) {
				t.Fatal("failed Get retained scratch")
			}
		})
	}
}
