package client

import (
	"bytes"
	"context"
	"errors"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

type readFixture struct{ result wire.SecretReadResult }

func (f *readFixture) Read(string) (wire.SecretReadResult, error) { return f.result, nil }

type recordedExchange struct {
	handler           wire.ServedService
	calls             int
	request, response []byte
}

func (f *recordedExchange) ExchangeFrame(frame []byte) ([]byte, error) {
	f.calls++
	f.request = frame
	var response []byte
	var err error
	if f.handler == nil {
		response, err = wire.ServeEndpoint(frame, "old-provider", "")
	} else {
		response, err = wire.ServeEndpoint(frame, "fixture", "", f.handler)
	}
	f.response = response
	return response, err
}

func TestRawReadSDKClearsTransientFramesAndNeverFallsBack(t *testing.T) {
	old := &recordedExchange{}
	r, err := readSecret(context.Background(), "alpha", old)
	var service *wire.ServiceError
	if !errors.As(err, &service) || service.Code != wire.ServiceErrorCodeUnknownService || r.Value != nil || old.calls != 1 {
		t.Fatal("old provider failure hidden or retried")
	}
	for _, name := range []string{"alpha", "other"} {
		fixture := &recordedExchange{handler: &wire.SecretReaderDispatcher{Handler: &readFixture{result: wire.SecretReadResult{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: name, Revision: "current", Secret: []byte("private-test-value")}}}}}
		r, err := readSecret(context.Background(), "alpha", fixture)
		if name == "other" {
			if !errors.Is(err, ErrInconsistent) || r.Value != nil {
				t.Fatal("wrong-name value retained")
			}
		} else {
			if err != nil || r.Value == nil || !bytes.Equal(r.Value.Secret, []byte("private-test-value")) {
				t.Fatal("valid value lost")
			}
			clear(r.Value.Secret)
		}
		if !bytes.Equal(fixture.request, make([]byte, len(fixture.request))) || !bytes.Equal(fixture.response, make([]byte, len(fixture.response))) {
			t.Fatal("raw route kept transport frame bytes")
		}
	}
}

func TestRawReadReplyValidation(t *testing.T) {
	valid := wire.SecretReadResult{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: "alpha", Revision: "current", Secret: []byte("private")}}
	if !validateRead(valid, "alpha") {
		t.Fatal("valid reply refused")
	}
	for _, v := range []wire.SecretReadResult{
		{Outcome: wire.SecretReadOutcomeRead},
		{Outcome: wire.SecretReadOutcomeForbidden, Value: valid.Value},
		{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: "other", Revision: "current", Secret: []byte("private")}},
		{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: "alpha", Secret: []byte("private")}},
		{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: "alpha", Revision: "current"}},
		{Outcome: wire.SecretReadOutcomeRead, Value: &wire.SecretValue{Name: "alpha", Revision: "current", Secret: make([]byte, 4097)}},
	} {
		if validateRead(v, "alpha") {
			t.Fatal("inconsistent read reply accepted")
		}
	}
}
