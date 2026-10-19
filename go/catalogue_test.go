package credentials

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// contractPage reads this unit's CONTRACT.md.
func contractPage(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "CONTRACT.md"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// contractSection is the text of one "## " section of the page.
func contractSection(t *testing.T, page, heading string) string {
	t.Helper()
	i := strings.Index(page, "\n## "+heading+"\n")
	if i < 0 {
		t.Fatalf("CONTRACT.md has no %q section", heading)
	}
	rest := page[i+len(heading)+5:]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

var consumerDeclaration = regexp.MustCompile(`CredentialConsumers? *= *(?:\[\]string\{([^}]*)\}|"([^"]+)")`)
var quoted = regexp.MustCompile(`"([^"]+)"`)

// TestContractConsumersNameEveryDeclaredConsumer: every credential consumer
// a module of the private tree declares is a row of the Consumers table
// (CRED-R1), and it is either in the generated wire seed `Consumers` or
// named in "Not built" as a row that seed lacks. When W1-23a regenerates
// the seed, the "Not built" entry can go.
func TestContractConsumersNameEveryDeclaredConsumer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "openabstractions-flat")); err != nil {
		t.Skip("outside the private tree: the other modules are not beside this one")
	}
	page := contractPage(t)
	table := contractSection(t, page, "Consumers")
	notBuilt := contractSection(t, page, "Not built")
	seed := map[string]bool{}
	for _, c := range wire.Consumers {
		seed[c] = true
	}
	found := 0
	for _, dir := range []string{filepath.Join(root, "openabstractions-flat"), filepath.Join(root, "serve")} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == ".split" || name == "node_modules" || name == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range consumerDeclaration.FindAllStringSubmatch(string(b), -1) {
				names := []string{m[2]}
				if m[2] == "" {
					names = nil
					for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
						names = append(names, q[1])
					}
				}
				for _, name := range names {
					found++
					if !strings.Contains(table, "| `"+name+"` |") {
						t.Errorf("%s declares credential consumer %q, absent from CONTRACT.md's Consumers table", path, name)
					}
					if !seed[name] && !strings.Contains(notBuilt, "`"+name+"`") {
						t.Errorf("%s declares credential consumer %q, absent from the generated seed Consumers and from CONTRACT.md's Not built", path, name)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found == 0 {
		t.Fatal("no CredentialConsumer declaration found; the scan is broken")
	}
}

var storeConstant = regexp.MustCompile(`(?m)^\s*(Store[A-Za-z0-9]+)\s*=\s*"([^"]+)"`)

// TestContractNamesEveryStoreWord: every Store* word backend.go declares is
// either a standard `SecureStore` word with a secure_store row, or a row
// marked as a provider word that "Not built" names as missing from the
// `SecureStore` enum. When W1-23a adds the provider words to the enum, the
// standard branch takes them and the provider-word branch goes.
func TestContractNamesEveryStoreWord(t *testing.T) {
	b, err := os.ReadFile("backend.go")
	if err != nil {
		t.Fatal(err)
	}
	standard := map[string]bool{}
	for _, w := range wire.SecureStoreValues() {
		standard[string(w)] = true
	}
	page := contractPage(t)
	notBuilt := contractSection(t, page, "Not built")
	words := storeConstant.FindAllStringSubmatch(string(b), -1)
	if len(words) == 0 {
		t.Fatal("no Store constant found in backend.go; the scan is broken")
	}
	for _, m := range words {
		word := m[2]
		switch {
		case standard[word]:
			if !strings.Contains(page, "| `"+word+"` |") {
				t.Errorf("standard store word %s (%s) has no secure_store row", word, m[1])
			}
		case !strings.Contains(page, "| `"+word+"` (provider word) |"):
			t.Errorf("store word %s (%s) is neither in SecureStore nor a provider-word row", word, m[1])
		case !strings.Contains(notBuilt, "`"+word+"`"):
			t.Errorf("store word %s (%s) is outside SecureStore and Not built does not name it", word, m[1])
		}
	}
}
