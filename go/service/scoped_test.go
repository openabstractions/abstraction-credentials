package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-credentials/go/client"
	identity "github.com/openabstractions/abstraction-identity"
)

func TestScopedSecretReadChild(t *testing.T) {
	endpoint := os.Getenv("OA_CREDENTIAL_READ_CHILD_ENDPOINT")
	if endpoint == "" {
		t.Skip("child-only native identity check")
	}
	r, err := client.NewSecretReader(endpoint).Read(context.Background(), "alpha")
	if err != nil || r.Outcome != wire.SecretReadOutcomeForbidden || r.Value != nil {
		t.Fatal("other executable received secret authority")
	}
}

func TestScopedAvailabilityRequiresCompleteLegacyFence(t *testing.T) {
	decision := func(context.Context, wire.Subject, Operation, string) credentials.Authorization {
		return credentials.Authorization{Outcome: credentials.Authorized, Revision: "one"}
	}
	h := &Host{Authorization: AuthorizationConfig{Admit: decision, Quiet: decision}}
	if h.ScopedAvailable() {
		t.Fatal("typed profile available without shared legacy fence")
	}
	h.Authorization.Legacy = func(context.Context, wire.Subject, string, string, *Operation) credentials.Authorization {
		return credentials.Authorization{Outcome: credentials.Authorized, Revision: "one"}
	}
	if !h.ScopedAvailable() {
		t.Fatal("complete scoped owner unavailable")
	}
	h.Authorization = AuthorizationConfig{}
	if h.ScopedAvailable() {
		t.Fatal("legacy-only host advertised scoped profiles")
	}
}

func TestScopedNativeRecipientAndVersionedAuthority(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := wire.Subject{Account: current.Uid, Program: identity.CanonicalProgramPath(exe)}
	m := &memory{items: map[string][]byte{}}
	holder, err := credentials.Open(credentials.Config{Backend: m})
	if err != nil {
		t.Fatal(err)
	}
	legacy := func(context.Context, wire.Subject, string, string) (string, error) { return "permitted", nil }
	var designated, readAllowed atomic.Bool
	endpoint := programEndpoint(t)
	h, err := Listen(endpoint, holder, legacy, func(_ context.Context, peer *identity.Peer, consumer, _ string) bool {
		bound, e := SubjectFromPeer(peer)
		return e == nil && bound == self && designated.Load() && consumer == "abstraction.download/http-execution@1"
	})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(ctx context.Context, subject wire.Subject, op Operation, expected string) credentials.Authorization {
		target, e := credentials.DecodeCredentialTarget(op.Target)
		if e != nil || subject != self || target.Name != "alpha" {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		if op.Action == credentials.ActionSecretRead && !readAllowed.Load() {
			return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
		}
		if expected != "" && expected != "native-policy-1" {
			return credentials.Authorization{Outcome: credentials.AuthorizationConflict}
		}
		if op.Profile != credentials.NamedSecretResourceProfile && op.Profile != credentials.ScopedUseResourceProfile {
			return credentials.Authorization{Outcome: credentials.AuthorizationUnavailable}
		}
		if op.Action == credentials.ActionSecretRead {
			peer := PeerFromContext(ctx)
			bound, e := SubjectFromPeer(peer)
			if e != nil || bound != subject {
				return credentials.Authorization{Outcome: credentials.AuthorizationDenied}
			}
		}
		return credentials.Authorization{Outcome: credentials.Authorized, Revision: "native-policy-1"}
	}
	h.Authorization = AuthorizationConfig{Admit: decide, Quiet: decide, Legacy: func(context.Context, wire.Subject, string, string, *Operation) credentials.Authorization {
		return credentials.Authorization{Outcome: credentials.Authorized, Revision: "native-policy-1"}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	testScopedNativeCalls(t, endpoint, self, readAllowed.Store, designated.Store)
}

func testScopedNativeCalls(t *testing.T, endpoint string, self wire.Subject, setRead func(bool), setDesignated func(bool)) {
	t.Helper()
	old := client.NewHolder(endpoint)
	stored, err := old.Store(context.Background(), "", wire.Registration{Name: "alpha", Kind: "bearer", Scope: wire.Scope{Targets: []string{"huggingface.co"}, Consumers: []string{"abstraction.download/http-execution@1"}}, Secret: []byte(secret)})
	if err != nil || stored.Outcome != wire.StoreOutcomeStored {
		t.Fatal("legacy setup failed")
	}
	reader := client.NewSecretReader(endpoint)
	for _, name := range []string{"alpha", "absent"} {
		r, e := reader.Read(context.Background(), name)
		if e != nil || r.Outcome != wire.SecretReadOutcomeForbidden || r.Value != nil {
			t.Fatal("legacy grant implied raw Read or leaked state")
		}
	}
	setRead(true)
	r, e := reader.Read(context.Background(), "alpha")
	if e != nil || r.Outcome != wire.SecretReadOutcomeRead || r.Value == nil || r.Value.Name != "alpha" || r.Value.Revision != stored.Revision || !bytes.Equal(r.Value.Secret, []byte(secret)) {
		t.Fatal("native requester did not receive current named value")
	}
	zero(r.Value.Secret)
	if r, e := reader.Read(context.Background(), "absent"); e != nil || r.Outcome != wire.SecretReadOutcomeForbidden || r.Value != nil {
		t.Fatal("grant for alpha implied another name")
	}
	otherExe := filepath.Join(t.TempDir(), "other-credential-reader.exe")
	image, e := os.ReadFile(self.Program)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(otherExe, image, 0700); e != nil {
		t.Fatal(e)
	}
	child := exec.Command(otherExe, "-test.run=^TestScopedSecretReadChild$", "-test.count=1")
	child.Env = append(os.Environ(), "OA_CREDENTIAL_READ_CHILD_ENDPOINT="+endpoint)
	output, e := child.CombinedOutput()
	if e != nil {
		t.Fatalf("distinct native program refusal failed: %s", output)
	}
	if bytes.Contains(output, []byte(secret)) {
		t.Fatal("raw value entered child diagnostics")
	}
	use := wire.Use{Subject: self, Consumer: "abstraction.download/http-execution@1", Name: "alpha", Target: "huggingface.co"}
	applier := client.NewScopedApplier(endpoint)
	if r, e := applier.Apply(context.Background(), use); e != nil || r.Outcome != wire.ApplyOutcomeForbidden || len(r.Headers) != 0 {
		t.Fatal("undesignated app received service Use headers")
	}
	setDesignated(true)
	if r, e := applier.Apply(context.Background(), use); e != nil || r.Outcome != wire.ApplyOutcomeApplied || len(r.Headers) == 0 {
		t.Fatal("designated typed Use failed")
	}
	use.Target = "other.invalid"
	if r, e := applier.Apply(context.Background(), use); e != nil || r.Outcome != wire.ApplyOutcomeTargetRefused || len(r.Headers) != 0 {
		t.Fatal("typed grant bypassed current website restrictions")
	}
	use.Target = "huggingface.co"
	use.Subject.Program = self.Program + "-other"
	if r, e := applier.Apply(context.Background(), use); e != nil || r.Outcome != wire.ApplyOutcomeNotPermitted || len(r.Headers) != 0 {
		t.Fatal("enforcer supplied subject bypassed shared permission")
	}
	scoped := client.NewScopedHolder(endpoint)
	if r, e := scoped.Metadata(context.Background(), "alpha"); e != nil || r.Outcome != wire.MetadataReadOutcomeFound || r.Current == nil {
		t.Fatal("named metadata unavailable")
	}
	if r, e := scoped.Metadata(context.Background(), "absent"); e != nil || r.Outcome != wire.MetadataReadOutcomeForbidden || r.Current != nil {
		t.Fatal("metadata grant widened name")
	}
	rotated, e := scoped.Rotate(context.Background(), stored.Revision, wire.Rotation{Name: "alpha", Secret: []byte("current-rotation")})
	if e != nil || rotated.Outcome != wire.RotateOutcomeRotated {
		t.Fatal("scoped rotation failed")
	}
	if r, e := reader.Read(context.Background(), "alpha"); e != nil || r.Value == nil || r.Value.Revision != rotated.Revision {
		t.Fatal("Read ignored current slot revision")
	} else {
		zero(r.Value.Secret)
	}
	if r, e := scoped.Revoke(context.Background(), rotated.Revision, "alpha"); e != nil || r.Outcome != wire.RevokeOutcomeRevoked {
		t.Fatal("scoped revoke failed")
	}
	if r, e := reader.Read(context.Background(), "alpha"); e != nil || r.Outcome != wire.SecretReadOutcomeRevoked || r.Value != nil {
		t.Fatal("holder revoke returned raw value")
	}
	audit, e := old.Audit(context.Background(), "", 256)
	if e != nil {
		t.Fatal(e)
	}
	evidence, _ := json.Marshal(audit)
	for _, value := range []string{secret, "current-rotation", base64.StdEncoding.EncodeToString([]byte(secret))} {
		if strings.Contains(string(evidence), value) {
			t.Fatal("secret entered audit")
		}
	}
}
