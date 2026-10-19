package credentials

import (
	"errors"
	"testing"
)

type resetBackend struct {
	Backend
	calls []string
	fail  string
}

func (b *resetBackend) Delete(k string) error {
	b.calls = append(b.calls, k)
	if k == b.fail {
		return errors.New("injected delete refusal")
	}
	return nil
}
func TestResetSecretPartialReportsEffectsWithoutReadingValues(t *testing.T) {
	keys := []string{DefaultNamespace + "/account/a/1", DefaultNamespace + "/account/b/1", DefaultNamespace + "/account/c/1"}
	b := &resetBackend{fail: keys[1]}
	r, err := deleteResetTargets(b, "account", keys)
	var partial *SecretResetPartial
	if !errors.As(err, &partial) || len(r.Deleted) != 1 || len(r.Remaining) != 2 || len(b.calls) != 2 {
		t.Fatalf("%+v %+v %v", r, b.calls, err)
	}
}

func TestResetSecretsPrevalidatesWholeAccountBatch(t *testing.T) {
	b := &resetBackend{}
	keys := []string{DefaultNamespace + "/account/a/1", DefaultNamespace + "/foreign/b/1"}
	r, err := deleteResetTargets(b, "account", keys)
	if err == nil || len(b.calls) != 0 || len(r.Deleted) != 0 || len(r.Remaining) != 2 {
		t.Fatalf("%+v %+v %v", r, b.calls, err)
	}
}
