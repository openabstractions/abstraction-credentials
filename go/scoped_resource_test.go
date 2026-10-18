package credentials

import (
	"testing"
)

func TestCredentialTargetCanonicalOwner(t *testing.T) {
	target, err := PrepareCredentialTarget("demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeCredentialTarget(target)
	if err != nil || v.Name != "demo-secret" {
		t.Fatalf("canonical target: %v", err)
	}
	for _, malformed := range [][]byte{
		[]byte(`{"name":"demo-secret"}`),
		[]byte(" {\"name\":\"demo-secret\"}\n"),
		[]byte("{\"name\":\"demo-secret\",\"other\":true}\n"),
		[]byte("{\"name\":\"demo-secret\",\"name\":\"other\"}\n"),
		[]byte("{\"name\":\"../secret\"}\n"),
		append(append([]byte{}, target...), target...),
	} {
		if _, err := DecodeCredentialTarget(malformed); err == nil {
			t.Fatal("accepted noncanonical or malformed target")
		}
	}
	for _, name := range []string{"", "../secret", "credential:secret", "name with space"} {
		if _, err := PrepareCredentialTarget(name); err == nil {
			t.Fatal("accepted invalid name")
		}
	}
}
