package credentials

import (
	"strings"
	"testing"
)

func TestNamedUseResourceSharesHolderNameGrammar(t *testing.T) {
	for _, name := range []string{"hf", "demo-secret", "UPPER_1.2", ".", strings.Repeat("x", 64)} {
		resource, ok := ParseResource(ResourceFor(name))
		if !ok || resource.Name != name {
			t.Fatalf("valid name %q refused", name)
		}
	}
	for _, value := range []string{"account", "credential:", "credential:*", "credential:bad name", "credential:a/b", "credential:a\n", "Credential:hf", "credential:" + strings.Repeat("x", 65), "credential:λ"} {
		if _, ok := ParseResource(value); ok {
			t.Fatalf("malformed resource %q accepted", value)
		}
	}
}
