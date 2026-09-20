package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	identity "github.com/openabstractions/abstraction-identity"
)

// Rights actions the holder and applier enforce, and their resources.
const (
	ActionManage    = "abstraction.credentials/holder.manage"
	ActionRead      = "abstraction.credentials/holder.read"
	ActionApply     = "abstraction.credentials/apply"
	ResourceAccount = "account"
	// HolderContract and ApplierContract are the wire contract names.
	HolderContract  = "abstraction.credentials/holder@1"
	ApplierContract = "abstraction.credentials/applier@1"
)

// ResourceFor is the rights resource of applying one named credential.
func ResourceFor(name string) string { return "credential:" + name }

// Decider asks the decision point about one subject. It returns the rights
// DecisionOutcome word; an error means no decision was obtained.
type Decider func(ctx context.Context, subject wire.Subject, action, resource string) (string, error)

// Config selects the store and bounds. Zero bounds take the defaults below.
type Config struct {
	// Backend is the one configured platform store. Nil means no_secure_store.
	Backend Backend
	// MachineScope marks a machine-scope runtime, which refuses with
	// no_secure_store in this version whatever Backend is.
	MachineScope bool
	// Namespace prefixes every platform store key: <namespace>/<account>/<name>/<revision>.
	// Empty selects DefaultNamespace. Tests use a unique namespace so they never
	// touch the items of a real installation.
	Namespace string
	// StatePath is the absolute service-owned metadata file. Empty keeps
	// metadata in memory for the holder's lifetime.
	StatePath          string
	MaxCredentials     int
	TombstoneRetention time.Duration
	AuditRetention     time.Duration
	AuditCapacity      int
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// OnError receives provider failures that no reply carries. Messages never
	// contain secret bytes.
	OnError func(error)
}

const (
	DefaultNamespace          = "openabstractions"
	DefaultMaxCredentials     = 64
	DefaultTombstoneRetention = 24 * time.Hour
	DefaultAuditRetention     = 30 * 24 * time.Hour
	DefaultAuditCapacity      = 4096
	maxCursorBytes            = 256
)

// SupportedKinds are the kinds this provider's applier can apply.
var SupportedKinds = []string{"bearer", "header"}

// KindLocalKey is the kind the runtime holds a gateway window's local key as
// (abstraction.inference local_key_kinds). Only StoreLocalKey registers it;
// Store refuses it as unsupported_kind, Apply and Check read unsupported_kind,
// and VerifyLocalKey compares a presented key with it.
const KindLocalKey = "openabstractions/local-key@1"

type record struct {
	Name         string       `json:"name"`
	Kind         string       `json:"kind"`
	Revision     string       `json:"revision"`
	State        wire.State   `json:"state"`
	Scope        wire.Scope   `json:"scope"`
	RegisteredBy wire.Subject `json:"registered_by"`
	Registered   time.Time    `json:"registered"`
	Expires      *time.Time   `json:"expires,omitempty"`
	Header       string       `json:"header,omitempty"`
	LastApplied  *time.Time   `json:"last_applied,omitempty"`
	Revoked      *time.Time   `json:"revoked,omitempty"`
	Key          string       `json:"key,omitempty"`
}

type stateFile struct {
	Version  int                           `json:"version"`
	Counter  uint64                        `json:"counter"`
	Garbage  []string                      `json:"garbage"`
	Accounts map[string]map[string]*record `json:"accounts"`
}

type journal struct {
	next    int64
	entries []wire.AuditEntry
	times   []time.Time
}

// Holder is safe for concurrent use.
type Holder struct {
	mu    sync.Mutex
	cfg   Config
	epoch string
	state stateFile
	audit map[string]*journal
}

// Open loads StatePath when present and removes store items a crash left
// behind. It performs no discovery and reads no environment.
func Open(cfg Config) (*Holder, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = DefaultNamespace
	}
	if !namespacePattern.MatchString(cfg.Namespace) {
		return nil, errors.New("credentials: invalid store namespace")
	}
	if cfg.MaxCredentials == 0 {
		cfg.MaxCredentials = DefaultMaxCredentials
	}
	if cfg.TombstoneRetention == 0 {
		cfg.TombstoneRetention = DefaultTombstoneRetention
	}
	if cfg.AuditRetention == 0 {
		cfg.AuditRetention = DefaultAuditRetention
	}
	if cfg.AuditCapacity == 0 {
		cfg.AuditCapacity = DefaultAuditCapacity
	}
	if cfg.MaxCredentials < 1 || cfg.MaxCredentials > 64 || cfg.TombstoneRetention < 0 || cfg.AuditRetention < 0 || cfg.AuditCapacity < 1 {
		return nil, errors.New("credentials: invalid bounds")
	}
	if cfg.StatePath != "" && !filepath.IsAbs(cfg.StatePath) {
		return nil, errors.New("credentials: state path must be absolute")
	}
	if cfg.Backend != nil && (cfg.Backend.MaxSecretBytes() < 1 || cfg.Backend.MaxSecretBytes() > MaxSecretBytes) {
		return nil, errors.New("credentials: backend secret bound outside 1..4096")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var epoch [8]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, err
	}
	h := &Holder{cfg: cfg, epoch: hex.EncodeToString(epoch[:]), audit: map[string]*journal{},
		state: stateFile{Version: 1, Accounts: map[string]map[string]*record{}}}
	if cfg.StatePath != "" {
		data, err := os.ReadFile(cfg.StatePath)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("credentials: read state: %w", err)
		default:
			var loaded stateFile
			if err := json.Unmarshal(data, &loaded); err != nil || loaded.Version != 1 {
				return nil, errors.New("credentials: state file unreadable")
			}
			if loaded.Accounts == nil {
				loaded.Accounts = map[string]map[string]*record{}
			}
			h.state = loaded
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.collectGarbage()
	return h, nil
}

func (h *Holder) report(err error) {
	if err != nil && h.cfg.OnError != nil {
		h.cfg.OnError(err)
	}
}

func (h *Holder) collectGarbage() {
	if h.cfg.Backend == nil || len(h.state.Garbage) == 0 {
		return
	}
	kept := h.state.Garbage[:0]
	for _, key := range h.state.Garbage {
		if err := h.cfg.Backend.Delete(key); err != nil {
			kept = append(kept, key)
		}
	}
	h.state.Garbage = kept
	h.report(h.save())
}

func (h *Holder) save() error {
	if h.cfg.StatePath == "" {
		return nil
	}
	data, err := json.Marshal(h.state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(h.cfg.StatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, h.cfg.StatePath)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// Limits reports the provider-declared bounds.
func (h *Holder) Limits() wire.Limits {
	store, max := StoreNone, int64(MaxSecretBytes)
	if h.cfg.Backend != nil && !h.cfg.MachineScope {
		store, max = h.cfg.Backend.Name(), int64(h.cfg.Backend.MaxSecretBytes())
	}
	return wire.Limits{MaxCredentials: int64(h.cfg.MaxCredentials), MaxSecretBytes: max,
		TombstoneRetentionMs: h.cfg.TombstoneRetention.Milliseconds(), AuditRetentionMs: h.cfg.AuditRetention.Milliseconds(),
		AuditCapacity: int64(h.cfg.AuditCapacity), SecureStore: wire.SecureStore(store), SupportedKinds: slices.Clone(SupportedKinds)}
}

func (h *Holder) store() Backend {
	if h.cfg.MachineScope {
		return nil
	}
	return h.cfg.Backend
}

var (
	namePattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	ownedKind        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9_.-]{0,62}@[1-9][0-9]{0,5}$`)
	consumerPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}/[a-z0-9][a-z0-9._-]{0,62}@[1-9][0-9]{0,5}$`)
	hostLabel        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerToken      = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
)

func validHost(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validSubject(s wire.Subject) bool {
	return s.Account != "" && len(s.Account) <= 128 && identity.ValidSubjectProgram(s.Program) &&
		!strings.ContainsAny(s.Account+s.Program, "\x00\r\n")
}

func unique(values []string, min, max int, valid func(string) bool) bool {
	if len(values) < min || len(values) > max {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !valid(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// headerSafe refuses bytes that could end or split a header line.
func headerSafe(secret []byte) bool {
	for _, c := range secret {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func (h *Holder) validExpiry(value string) (*time.Time, bool) {
	if value == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !t.After(h.cfg.Now()) {
		return nil, false
	}
	t = t.UTC()
	return &t, true
}

func (h *Holder) nextRevision() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	h.state.Counter++
	return strconv.FormatUint(h.state.Counter, 10) + "-" + hex.EncodeToString(suffix[:]), nil
}

func (h *Holder) storeKey(account, name, revision string) string {
	return h.cfg.Namespace + "/" + account + "/" + name + "/" + revision
}

// stamp spells the definition's rfc3339-micros write grammar.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

func metadata(r *record) *wire.Metadata {
	m := &wire.Metadata{Name: r.Name, Kind: r.Kind, Revision: r.Revision, State: r.State,
		Scope:        wire.Scope{Targets: slices.Clone(r.Scope.Targets), Consumers: slices.Clone(r.Scope.Consumers)},
		RegisteredBy: r.RegisteredBy, Registered: stamp(r.Registered), Header: r.Header}
	if r.Expires != nil {
		m.Expires = stamp(*r.Expires)
	}
	if r.LastApplied != nil {
		m.LastApplied = stamp(*r.LastApplied)
	}
	return m
}

func (h *Holder) appendAudit(account string, entry wire.AuditEntry) {
	j := h.audit[account]
	if j == nil {
		j = &journal{next: 1}
		h.audit[account] = j
	}
	now := h.cfg.Now()
	entry.Sequence, entry.Time = j.next, stamp(now)
	j.next++
	j.entries = append(j.entries, entry)
	j.times = append(j.times, now)
	if extra := len(j.entries) - h.cfg.AuditCapacity; extra > 0 {
		j.entries = slices.Delete(j.entries, 0, extra)
		j.times = slices.Delete(j.times, 0, extra)
	}
}

// sweep moves due records to expired and retires elapsed tombstones.
func (h *Holder) sweep(account string) {
	records := h.state.Accounts[account]
	now, changed := h.cfg.Now(), false
	for name, r := range records {
		switch {
		case r.State == "active" && r.Expires != nil && !now.Before(*r.Expires):
			r.State, changed = "expired", true
			h.appendAudit(account, wire.AuditEntry{Event: "expired", Name: name, Revision: r.Revision})
		case r.State == "revoked" && r.Revoked != nil && now.Sub(*r.Revoked) >= h.cfg.TombstoneRetention:
			delete(records, name)
			changed = true
			h.appendAudit(account, wire.AuditEntry{Event: "retired", Name: name, Revision: r.Revision})
		}
	}
	if changed {
		h.report(h.save())
	}
}

func subjectPtr(s wire.Subject) *wire.Subject { return &s }

// Store registers one secret for caller's account. The caller is the subject
// the receiving boundary bound; authorization happens before this call. The
// secret slice is zeroed before Store returns.
func (h *Holder) Store(caller wire.Subject, expected string, reg wire.Registration) wire.StoreResult {
	return h.register(caller, expected, reg, false)
}

// StoreLocalKey registers a local key the runtime minted, as kind
// KindLocalKey, for caller's account. It is not reachable through holder@1.
func (h *Holder) StoreLocalKey(caller wire.Subject, reg wire.Registration) wire.StoreResult {
	if reg.Kind != KindLocalKey {
		defer zero(reg.Secret)
		return wire.StoreResult{Outcome: wire.StoreOutcomeInvalid}
	}
	return h.register(caller, "", reg, true)
}

func (h *Holder) register(caller wire.Subject, expected string, reg wire.Registration, localKey bool) wire.StoreResult {
	defer zero(reg.Secret)
	refuse := func(outcome wire.StoreOutcome) wire.StoreResult { return wire.StoreResult{Outcome: outcome} }
	if !validSubject(caller) || !namePattern.MatchString(reg.Name) || len(expected) > 128 ||
		!unique(reg.Scope.Targets, 1, 16, validHost) || !unique(reg.Scope.Consumers, 1, 8, func(c string) bool { return consumerPattern.MatchString(c) }) {
		return refuse(wire.StoreOutcomeInvalid)
	}
	if !localKey && !slices.Contains(SupportedKinds, reg.Kind) {
		if ownedKind.MatchString(reg.Kind) {
			return refuse(wire.StoreOutcomeUnsupportedKind)
		}
		return refuse(wire.StoreOutcomeInvalid)
	}
	if (reg.Kind == "header") != (reg.Header != "") || (reg.Header != "" && !headerToken.MatchString(reg.Header)) {
		return refuse(wire.StoreOutcomeInvalid)
	}
	expires, ok := h.validExpiry(reg.Expires)
	if !ok || len(reg.Secret) < 1 || len(reg.Secret) > MaxSecretBytes || !headerSafe(reg.Secret) {
		return refuse(wire.StoreOutcomeInvalid)
	}
	backend := h.store()
	if backend == nil {
		return refuse(wire.StoreOutcomeNoSecureStore)
	}
	if len(reg.Secret) > backend.MaxSecretBytes() {
		return refuse(wire.StoreOutcomeInvalid)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(caller.Account)
	records := h.state.Accounts[caller.Account]
	if existing := records[reg.Name]; existing != nil {
		return wire.StoreResult{Outcome: wire.StoreOutcomeConflict, Revision: existing.Revision, Current: metadata(existing)}
	}
	if expected != "" {
		return refuse(wire.StoreOutcomeConflict)
	}
	if len(records) >= h.cfg.MaxCredentials {
		return refuse(wire.StoreOutcomeExhausted)
	}
	revision, err := h.nextRevision()
	if err != nil {
		h.report(err)
		return refuse(wire.StoreOutcomeUnavailable)
	}
	key := h.storeKey(caller.Account, reg.Name, revision)
	if !h.write(backend, key, reg.Secret) {
		return refuse(wire.StoreOutcomeUnavailable)
	}
	r := &record{Name: reg.Name, Kind: reg.Kind, Revision: revision, State: "active",
		Scope:        wire.Scope{Targets: slices.Clone(reg.Scope.Targets), Consumers: slices.Clone(reg.Scope.Consumers)},
		RegisteredBy: caller, Registered: h.cfg.Now().UTC(), Expires: expires, Header: reg.Header, Key: key}
	if records == nil {
		records = map[string]*record{}
		h.state.Accounts[caller.Account] = records
	}
	records[reg.Name] = r
	h.forget(key)
	if err := h.save(); err != nil {
		delete(records, reg.Name)
		h.report(err)
		h.report(backend.Delete(key))
		return refuse(wire.StoreOutcomeUnavailable)
	}
	h.appendAudit(caller.Account, wire.AuditEntry{Event: "stored", Name: reg.Name, Revision: revision, Subject: subjectPtr(caller), Outcome: "stored"})
	return wire.StoreResult{Outcome: wire.StoreOutcomeStored, Revision: revision, Current: metadata(r)}
}

// write records key as garbage, then writes the item. A crash between the two
// leaves a garbage key that the next Open removes.
func (h *Holder) write(backend Backend, key string, secret []byte) bool {
	h.state.Garbage = append(h.state.Garbage, key)
	if err := h.save(); err != nil {
		h.state.Garbage = h.state.Garbage[:len(h.state.Garbage)-1]
		h.report(err)
		return false
	}
	if err := backend.Put(key, secret); err != nil {
		h.report(err)
		h.forget(key)
		h.report(h.save())
		return false
	}
	return true
}

func (h *Holder) forget(key string) {
	if i := slices.Index(h.state.Garbage, key); i >= 0 {
		h.state.Garbage = slices.Delete(h.state.Garbage, i, i+1)
	}
}

// Rotate replaces the bytes and expiry of an existing record. The secret slice
// is zeroed before Rotate returns.
func (h *Holder) Rotate(caller wire.Subject, expected string, rotation wire.Rotation) wire.RotateResult {
	name, secret := rotation.Name, rotation.Secret
	defer zero(secret)
	refuse := func(outcome wire.RotateOutcome) wire.RotateResult { return wire.RotateResult{Outcome: outcome} }
	due, ok := h.validExpiry(rotation.Expires)
	if !validSubject(caller) || !namePattern.MatchString(name) || expected == "" || len(expected) > 128 || !ok ||
		len(secret) < 1 || len(secret) > MaxSecretBytes || !headerSafe(secret) {
		return refuse(wire.RotateOutcomeInvalid)
	}
	backend := h.store()
	if backend == nil {
		return refuse(wire.RotateOutcomeNoSecureStore)
	}
	if len(secret) > backend.MaxSecretBytes() {
		return refuse(wire.RotateOutcomeInvalid)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(caller.Account)
	r := h.state.Accounts[caller.Account][name]
	if r == nil || r.State == "revoked" {
		return refuse(wire.RotateOutcomeUnknown)
	}
	if expected != r.Revision {
		return wire.RotateResult{Outcome: wire.RotateOutcomeConflict, Revision: r.Revision, Current: metadata(r)}
	}
	revision, err := h.nextRevision()
	if err != nil {
		h.report(err)
		return refuse(wire.RotateOutcomeUnavailable)
	}
	key := h.storeKey(caller.Account, name, revision)
	if !h.write(backend, key, secret) {
		return refuse(wire.RotateOutcomeUnavailable)
	}
	previous := *r
	oldKey := r.Key
	r.Revision, r.Key, r.State, r.Expires = revision, key, "active", due
	h.forget(key)
	if oldKey != "" {
		h.state.Garbage = append(h.state.Garbage, oldKey)
	}
	if err := h.save(); err != nil {
		*r = previous
		h.forget(oldKey)
		h.report(err)
		h.report(backend.Delete(key))
		return refuse(wire.RotateOutcomeUnavailable)
	}
	if oldKey != "" && backend.Delete(oldKey) == nil {
		h.forget(oldKey)
		h.report(h.save())
	}
	h.appendAudit(caller.Account, wire.AuditEntry{Event: "rotated", Name: name, Revision: revision, Subject: subjectPtr(caller), Outcome: "rotated"})
	return wire.RotateResult{Outcome: wire.RotateOutcomeRotated, Revision: revision, Current: metadata(r)}
}

// Revoke destroys the bytes and keeps a tombstone.
func (h *Holder) Revoke(caller wire.Subject, expected, name string) wire.RevokeResult {
	if !validSubject(caller) || !namePattern.MatchString(name) || expected == "" || len(expected) > 128 {
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeInvalid}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(caller.Account)
	r := h.state.Accounts[caller.Account][name]
	if r == nil || r.State == "revoked" {
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeUnknown}
	}
	if expected != r.Revision {
		return wire.RevokeResult{Outcome: wire.RevokeOutcomeConflict, Revision: r.Revision}
	}
	if r.Key != "" {
		backend := h.cfg.Backend
		if backend == nil {
			return wire.RevokeResult{Outcome: wire.RevokeOutcomeUnavailable}
		}
		if err := backend.Delete(r.Key); err != nil {
			h.report(err)
			return wire.RevokeResult{Outcome: wire.RevokeOutcomeUnavailable}
		}
	}
	now := h.cfg.Now().UTC()
	previous := *r
	r.State, r.Revoked, r.Key = "revoked", &now, ""
	if err := h.save(); err != nil {
		// The bytes are gone; keep the tombstone in memory and report the state failure.
		h.report(err)
		_ = previous
	}
	h.appendAudit(caller.Account, wire.AuditEntry{Event: "revoked", Name: name, Revision: r.Revision, Subject: subjectPtr(caller), Outcome: "revoked"})
	return wire.RevokeResult{Outcome: wire.RevokeOutcomeRevoked, Revision: r.Revision}
}

func accountTag(account string) string {
	sum := sha256.Sum256([]byte(account))
	return hex.EncodeToString(sum[:8])
}

// RefusedMetadataPage is the contract's refusal shape: zero limits, no records,
// empty next and complete=false.
func RefusedMetadataPage(outcome wire.PageOutcome) wire.MetadataPage {
	return wire.MetadataPage{Outcome: outcome, Limits: wire.Limits{SupportedKinds: []string{}}, Records: []wire.Metadata{}}
}

// List pages the account's records, tombstones included, in name order.
func (h *Holder) List(account, cursor string, limit int64) wire.MetadataPage {
	refuse := func(outcome wire.PageOutcome) wire.MetadataPage {
		return RefusedMetadataPage(outcome)
	}
	if account == "" || limit < 1 || limit > 64 || len(cursor) > maxCursorBytes {
		return refuse(wire.PageOutcomeInvalid)
	}
	after := ""
	if cursor != "" {
		parts := strings.SplitN(cursor, ".", 3)
		if len(parts) != 3 {
			return refuse(wire.PageOutcomeInvalid)
		}
		if parts[0] != h.epoch || parts[1] != accountTag(account) {
			return refuse(wire.PageOutcomeGap)
		}
		raw, err := hex.DecodeString(parts[2])
		if err != nil {
			return refuse(wire.PageOutcomeInvalid)
		}
		after = string(raw)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(account)
	records := h.state.Accounts[account]
	names := make([]string, 0, len(records))
	for name := range records {
		if name > after {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	page := wire.MetadataPage{Outcome: wire.PageOutcomePage, Limits: h.Limits(), Records: []wire.Metadata{}, Complete: true}
	if int64(len(names)) > limit {
		names, page.Complete = names[:limit], false
	}
	for _, name := range names {
		page.Records = append(page.Records, *metadata(records[name]))
	}
	if !page.Complete {
		page.Next = h.epoch + "." + accountTag(account) + "." + hex.EncodeToString([]byte(names[len(names)-1]))
	}
	return page
}

// Audit pages the account's retained journal after cursor.
func (h *Holder) Audit(account, cursor string, maxEntries int64) wire.AuditPage {
	refuse := func(outcome wire.PageOutcome) wire.AuditPage {
		return wire.AuditPage{Outcome: outcome, Entries: []wire.AuditEntry{}, Next: cursor}
	}
	if account == "" || maxEntries < 1 || maxEntries > 256 || len(cursor) > maxCursorBytes {
		return refuse(wire.PageOutcomeInvalid)
	}
	var after int64
	if cursor != "" {
		parts := strings.SplitN(cursor, ".", 3)
		if len(parts) != 3 {
			return refuse(wire.PageOutcomeInvalid)
		}
		n, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || n < 0 {
			return refuse(wire.PageOutcomeInvalid)
		}
		if parts[0] != h.epoch || parts[1] != accountTag(account) {
			return refuse(wire.PageOutcomeGap)
		}
		after = n
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep(account)
	j := h.audit[account]
	if j == nil {
		j = &journal{next: 1}
		h.audit[account] = j
	}
	cutoff := h.cfg.Now().Add(-h.cfg.AuditRetention)
	drop := 0
	for drop < len(j.times) && j.times[drop].Before(cutoff) {
		drop++
	}
	j.entries, j.times = slices.Delete(j.entries, 0, drop), slices.Delete(j.times, 0, drop)
	oldest := j.next
	if len(j.entries) > 0 {
		oldest = j.entries[0].Sequence
	}
	if after >= j.next || (cursor != "" && after < oldest-1) {
		return refuse(wire.PageOutcomeGap)
	}
	page := wire.AuditPage{Outcome: wire.PageOutcomePage, Entries: []wire.AuditEntry{}, Next: cursor, AtEnd: true}
	for _, entry := range j.entries {
		if entry.Sequence <= after {
			continue
		}
		if int64(len(page.Entries)) == maxEntries {
			page.AtEnd = false
			break
		}
		if entry.Subject != nil {
			entry.Subject = subjectPtr(*entry.Subject)
		}
		page.Entries = append(page.Entries, entry)
	}
	if n := len(page.Entries); n > 0 {
		page.Next = h.epoch + "." + accountTag(account) + "." + strconv.FormatInt(page.Entries[n-1].Sequence, 10)
	} else if cursor == "" {
		page.Next = h.epoch + "." + accountTag(account) + "." + strconv.FormatInt(oldest-1, 10)
	}
	return page
}

// VerifyLocalKey compares presented with the local key held under name in
// account, in constant time, without applying or returning it. It returns
// verified, mismatch, unknown (no local key of that name), revoked, expired,
// lost, or unavailable when the platform store cannot be read.
func (h *Holder) VerifyLocalKey(account, name string, presented []byte) string {
	if account == "" || !namePattern.MatchString(name) || len(presented) == 0 || len(presented) > MaxSecretBytes {
		return "unknown"
	}
	h.mu.Lock()
	h.sweep(account)
	r := h.state.Accounts[account][name]
	switch {
	case r == nil || r.Kind != KindLocalKey:
		h.mu.Unlock()
		return "unknown"
	case r.State != "active":
		state := string(r.State)
		h.mu.Unlock()
		return state
	}
	backend, key, revision := h.store(), r.Key, r.Revision
	h.mu.Unlock()
	if backend == nil || key == "" {
		return "unavailable"
	}
	held, err := backend.Get(key)
	if errors.Is(err, ErrNotFound) {
		h.mu.Lock()
		if r := h.state.Accounts[account][name]; r != nil && r.Revision == revision && r.State == "active" {
			r.State = "lost"
			h.report(h.save())
			h.appendAudit(account, wire.AuditEntry{Event: "lost", Name: name, Revision: revision})
		}
		h.mu.Unlock()
		return "lost"
	}
	if err != nil {
		h.report(err)
		return "unavailable"
	}
	defer zero(held)
	if subtle.ConstantTimeCompare(held, presented) != 1 {
		return "mismatch"
	}
	return "verified"
}

// Check evaluates a use without reading the secret.
func (h *Holder) Check(ctx context.Context, use wire.Use, decide Decider) wire.CheckResult {
	outcome, revision, _ := h.evaluate(ctx, use, decide, false)
	return wire.CheckResult{Outcome: outcome, Revision: revision}
}

// Apply evaluates a use and returns the headers for one request.
func (h *Holder) Apply(ctx context.Context, use wire.Use, decide Decider) wire.ApplyResult {
	outcome, revision, headers := h.evaluate(ctx, use, decide, true)
	return wire.ApplyResult{Outcome: outcome, Revision: revision, Headers: headers}
}

func matchesTarget(scope []string, target string) bool {
	for _, host := range scope {
		if target == host || strings.HasSuffix(target, "."+host) {
			return true
		}
	}
	return false
}

func (h *Holder) evaluate(ctx context.Context, use wire.Use, decide Decider, read bool) (wire.ApplyOutcome, string, map[string]string) {
	event := "checked"
	if read {
		event = "applied"
	}
	if !validSubject(use.Subject) || !consumerPattern.MatchString(use.Consumer) || !namePattern.MatchString(use.Name) || !validHost(use.Target) || len(use.Challenge) > 4096 {
		return wire.ApplyOutcomeInvalid, "", nil
	}
	h.mu.Lock()
	account := use.Subject.Account
	finish := func(outcome wire.ApplyOutcome, revision, detail string) {
		if detail == "" {
			detail = outcome.String()
		}
		word := event
		if outcome != wire.ApplyOutcomeApplied {
			word = "refused"
		}
		h.appendAudit(account, wire.AuditEntry{Event: word, Name: use.Name, Revision: revision, Subject: subjectPtr(use.Subject), Consumer: use.Consumer, Target: use.Target, Outcome: detail})
	}
	h.sweep(account)
	r := h.state.Accounts[account][use.Name]
	var outcome wire.ApplyOutcome
	switch {
	case r == nil:
		outcome = wire.ApplyOutcomeUnknown
	case r.State == "revoked" || r.State == "expired" || r.State == "lost":
		outcome, _ = wire.ParseApplyOutcome(string(r.State))
	case !slices.Contains(SupportedKinds, r.Kind):
		outcome = wire.ApplyOutcomeUnsupportedKind
	case use.Challenge != "":
		outcome = wire.ApplyOutcomeInvalid
	case !slices.Contains(r.Scope.Consumers, use.Consumer):
		outcome = wire.ApplyOutcomeConsumerRefused
	case !matchesTarget(r.Scope.Targets, use.Target):
		outcome = wire.ApplyOutcomeTargetRefused
	}
	if outcome != 0 {
		revision := ""
		if r != nil {
			revision = r.Revision
		}
		finish(outcome, revision, "")
		h.mu.Unlock()
		return outcome, revision, nil
	}
	h.mu.Unlock()
	word := "unavailable"
	if decide != nil {
		decided, err := decide(ctx, use.Subject, ActionApply, ResourceFor(use.Name))
		if err == nil {
			word = decided
		} else {
			h.report(err)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r = h.state.Accounts[account][use.Name]
	if r == nil {
		finish(wire.ApplyOutcomeUnknown, "", "")
		return wire.ApplyOutcomeUnknown, "", nil
	}
	switch word {
	case "permitted":
	case "denied", "not_granted", "unknown_action":
		finish(wire.ApplyOutcomeNotPermitted, r.Revision, word)
		return wire.ApplyOutcomeNotPermitted, r.Revision, nil
	default:
		finish(wire.ApplyOutcomeUnavailable, r.Revision, "rights:"+word)
		return wire.ApplyOutcomeUnavailable, r.Revision, nil
	}
	if r.State != "active" {
		stateOutcome, _ := wire.ParseApplyOutcome(string(r.State))
		finish(stateOutcome, r.Revision, "")
		return stateOutcome, r.Revision, nil
	}
	if !read {
		finish(wire.ApplyOutcomeApplied, r.Revision, "")
		return wire.ApplyOutcomeApplied, r.Revision, nil
	}
	backend := h.cfg.Backend
	if backend == nil || r.Key == "" {
		finish(wire.ApplyOutcomeUnavailable, r.Revision, "")
		return wire.ApplyOutcomeUnavailable, r.Revision, nil
	}
	secret, err := backend.Get(r.Key)
	if errors.Is(err, ErrNotFound) {
		r.State = "lost"
		h.report(h.save())
		h.appendAudit(account, wire.AuditEntry{Event: "lost", Name: use.Name, Revision: r.Revision})
		finish(wire.ApplyOutcomeLost, r.Revision, "")
		return wire.ApplyOutcomeLost, r.Revision, nil
	}
	if err != nil {
		h.report(err)
		finish(wire.ApplyOutcomeUnavailable, r.Revision, "")
		return wire.ApplyOutcomeUnavailable, r.Revision, nil
	}
	defer zero(secret)
	headers := map[string]string{}
	if r.Kind == "bearer" {
		headers["Authorization"] = "Bearer " + string(secret)
	} else {
		headers[r.Header] = string(secret)
	}
	now := h.cfg.Now().UTC()
	r.LastApplied = &now
	finish(wire.ApplyOutcomeApplied, r.Revision, "")
	return wire.ApplyOutcomeApplied, r.Revision, headers
}
