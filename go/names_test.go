package credentials

import (
	"strings"
	"testing"
)

// TestNameValidators is the shared table every caller's validator agrees with:
// gateway, Connect panel and serve call ValidName, ValidConsumer and ValidKind.
func TestNameValidators(t *testing.T) {
	for _, c := range []struct {
		check func(string) bool
		which string
		in    string
		want  bool
	}{
		{ValidName, "name", "hf", true},
		{ValidName, "name", "HF_token.v2-x", true},
		{ValidName, "name", strings.Repeat("a", 64), true},
		{ValidName, "name", strings.Repeat("a", 65), false},
		{ValidName, "name", "", false},
		{ValidName, "name", "a b", false},
		{ValidName, "name", "a/b", false},
		{ValidName, "name", "é", false},
		{ValidName, "name", "hf\n", false},
		{ValidConsumer, "consumer", "abstraction.download/http-execution@1", true},
		{ValidConsumer, "consumer", "abstraction.download/http-execution", false},
		{ValidConsumer, "consumer", "Abstraction.download/x@1", false},
		{ValidConsumer, "consumer", "a/b@0", false},
		{ValidConsumer, "consumer", "a/b@1234567", false},
		{ValidKind, "kind", "bearer", true},
		{ValidKind, "kind", "header", true},
		{ValidKind, "kind", "acme/token@2", true},
		{ValidKind, "kind", "basic", false},
		{ValidKind, "kind", "acme/token", false},
		{ValidKind, "kind", "", false},
	} {
		if got := c.check(c.in); got != c.want {
			t.Errorf("%s %q: %v, want %v", c.which, c.in, got, c.want)
		}
	}
}
