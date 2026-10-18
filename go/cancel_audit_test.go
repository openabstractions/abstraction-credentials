package credentials

import (
	"encoding/json"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// CRED-A7: a cancel sent with headers whose use was refused appends one
// `cancel` entry naming the use and the credential's revision, reads no
// secret, and leaves no value in the audit.
func TestRecordCancelAppendsOneCancelEntry(t *testing.T) {
	m := &countedBackend{memoryBackend: newMemory()}
	h := open(t, Config{Backend: m})
	stored := h.Store(owner, "", registration("alpha"))
	if stored.Outcome != wire.StoreOutcomeStored {
		t.Fatalf("store %+v", stored)
	}
	before := len(h.Audit(owner.Account, "", 256).Entries)
	gets := m.gets.Load()
	use := wire.Use{Subject: owner, Consumer: consumer, Name: "alpha", Target: "huggingface.co"}
	h.RecordCancel(use)
	page := h.Audit(owner.Account, "", 256)
	if len(page.Entries) != before+1 {
		t.Fatalf("RecordCancel appended %d entries", len(page.Entries)-before)
	}
	entry := page.Entries[len(page.Entries)-1]
	if entry.Event != "cancel" || entry.Outcome != "cancel" || entry.Name != "alpha" || entry.Consumer != consumer ||
		entry.Target != "huggingface.co" || entry.Subject == nil || *entry.Subject != owner || entry.Revision == "" {
		t.Fatalf("cancel entry %+v", entry)
	}
	if m.gets.Load() != gets {
		t.Fatal("recording a cancel read the secret")
	}
	data, err := json.Marshal(page)
	if err != nil || strings.Contains(string(data), testSecret) {
		t.Fatal("the cancel entry disclosed a value")
	}
	h.RecordCancel(wire.Use{Subject: owner, Consumer: consumer, Name: "", Target: "huggingface.co"})
	if n := len(h.Audit(owner.Account, "", 256).Entries); n != before+1 {
		t.Fatalf("an invalid use was recorded: %d entries", n)
	}
}
