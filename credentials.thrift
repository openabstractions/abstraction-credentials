namespace * abstraction.credentials.api

// Secrets an account's programs register by name and reference afterwards.
// No call returns secret bytes to an application; the applier profile hands
// them to an explicitly designated consuming service for one request.
encoding json {
 escape="minimal"
 indent="2"
 map_keys="utf8-bytes"
 numbers="integer-decimal"
 opaque="verbatim"
 terminator="newline"
 duplicate_keys="refuse"
 depth_limit="64"
}
refusal {
 1: malformed(stage="grammar")
 2: bad_string(stage="grammar")
 3: number_spelling(stage="grammar")
 4: wrong_type(stage="grammar")
 5: bad_timestamp(stage="grammar")
 6: depth_exceeded(stage="grammar")
 7: duplicate_key(stage="grammar")
 8: duplicate_field(stage="structure")
 9: unknown_field(stage="structure")
 10: missing_field(stage="structure")
 11: bad_binary(stage="structure")
 12: bad_enum(stage="structure")
 13: trailing_bytes(stage="document")
}
typedef string timestamp(write="rfc3339-micros",read="rfc3339-wide")

// Open catalogue of kinds. The two seeds are applied as request headers. An
// application-owned kind is "<owner>/<name>@<n>" (for example
// "ollama/ed25519@1") and is accepted by Store only when an applier on this
// runtime lists it in Limits.supported_kinds; the holder never interprets a
// kind itself. Growth is by applier support.
const list<string> credential_kinds = ["bearer", "header"]
// Rights actions this capability enforces. The host registers them into its
// decision policy through rights action registration; applications extend the
// rights catalogue there, never here. Closed by CRED-R1; the next name this list
// would reserve is abstraction.credentials/holder.delegate.
const list<string> resource_actions = ["abstraction.credentials/holder.manage", "abstraction.credentials/holder.read", "abstraction.credentials/apply"] (catalogue = "closed", closed_by = "CRED-R1")
// Job guarantee a submission naming a credential requires. A provider without
// an applier refuses it at resolution as unmet.
const list<string> execution_guarantees = ["abstraction.download/credentials@1"]
// Standard configured platform stores reported in Limits.secure_store. Provider
// extensions and the empty value in refusal-page zero limits are retained.
enum SecureStore {
 1: windows_credential_manager(wire="windows-credential-manager")
 2: secret_service(wire="secret-service")
 3: file_0600(wire="file-0600")
 4: macos_keychain(wire="macos-keychain")
 5: none
}(unknown="grant",reader="display")
// Consuming service contracts this version names in Scope.consumers and
// Use.consumer: download HTTP execution, model registry resolution and hosted
// inference. A consuming service outside the seed uses its own wire contract
// name <owner>/<name>@<n>; the receiving host's enforcer designation, never
// this list, decides whether a program may apply credentials as that consumer.
const list<string> consumers = ["abstraction.download/http-execution@1", "abstraction.model/resolver@1", "abstraction.inference/chat@1"]

struct Subject {
 1: required string account
 2: required string program
}(unknown_fields="refuse",doc="Account identifier and normalized absolute executable path, the same shape as abstraction.rights Subject. It is an assertion by the party that bound native Program proof: the holder for registered_by and audit entries of holder calls, the designated enforcer for Use.subject. It contains no proof.")
enum State {
 1: active
 2: expired
 3: revoked
 4: lost
}(unknown="grant",reader="display")
struct Scope {
 1: required list<string> targets
 2: required list<string> consumers
}(unknown_fields="refuse",doc="targets: 1..16 lowercase host names, each covering itself and its subdomains; no scheme, port, path or wildcard characters. consumers: 1..8 wire contract names of services that may apply the credential. Both lists are exact; a host or contract outside them is refused at Apply.")
struct Metadata {
 1: required string name
 2: required string kind
 3: required string revision
 4: required State state
 5: required Scope scope
 6: required Subject registered_by
 7: required timestamp registered
 8: optional timestamp expires(omit="absent")
 9: optional string header(omit="absent")
 10: optional timestamp last_applied(omit="absent")
}(unknown_fields="refuse",doc="Metadata only. registered_by is the subject the receiving boundary bound from native Program proof when the record was stored, asserted by the holder; it is provenance and carries no proof. No field derives from the secret bytes: no length, hash, prefix or suffix. header is present exactly for kind header.")
struct Registration {
 1: required string name
 2: required string kind
 3: required Scope scope
 4: optional timestamp expires(omit="absent")
 5: optional string header(omit="absent")
 6: required binary secret
}(document="true",unknown_fields="refuse",doc="name is 1..64 bytes of A-Z a-z 0-9 _ - . and unique within the receiving account. kind is a seed or <owner>/<name>@<n>. secret is 1..Limits.max_secret_bytes bytes with no control character other than tab, and is written only to the configured platform store; this document is never retained, logged or echoed. header is an HTTP field name, required for kind header and refused otherwise. expires, when present, is after the receiving clock.")
struct Rotation {
 1: required string name
 2: optional timestamp expires(omit="absent")
 3: required binary secret
}(unknown_fields="refuse",doc="Replacement bytes and expiry for an existing record. secret follows Registration.secret and is never retained, logged or echoed. Absent expires clears expiry; a present expires is after the receiving clock.")
enum StoreOutcome {
 1: stored
 2: conflict
 3: invalid
 4: unsupported_kind
 5: no_secure_store
 6: exhausted
 7: forbidden
 8: unavailable
}(unknown="refuse",reader="act")
enum RotateOutcome {
 1: rotated
 2: unknown
 3: conflict
 4: invalid
 5: no_secure_store
 6: forbidden
 7: unavailable
}(unknown="refuse",reader="act")
enum RevokeOutcome {
 1: revoked
 2: unknown
 3: conflict
 4: invalid
 5: forbidden
 6: unavailable
}(unknown="refuse",reader="act")
struct StoreResult {
 1: required StoreOutcome outcome
 2: required string revision
 3: optional Metadata current(omit="absent")
}(unknown_fields="refuse",doc="stored carries the new revision and current metadata. conflict carries the revision and current metadata observed inside the conditional edit. Other outcomes carry an empty revision and no current. An empty expected revision requires that the name not exist; a tombstoned name conflicts until retention elapses. A stale expected revision conflicts even when the desired state already holds. A lost reply is uncertain: reconcile from current or List before another edit. no_secure_store means this runtime has no configured platform store, or is a machine-scope runtime; nothing was retained anywhere. exhausted means the account holds its maximum number of records.")
struct RotateResult {
 1: required RotateOutcome outcome
 2: required string revision
 3: optional Metadata current(omit="absent")
}(unknown_fields="refuse",doc="rotated carries the new revision; the previous bytes are destroyed once the new item is written, and an in-flight Apply uses the new bytes on its next request. A lost or expired record returns to active. conflict carries current metadata. A revoked record reads unknown.")
struct RevokeResult {
 1: required RevokeOutcome outcome
 2: required string revision
}(unknown_fields="refuse",doc="revoked destroys the bytes at once and keeps a tombstone for Limits.tombstone_retention_ms, during which Apply reads revoked; afterwards the name reads unknown and may be registered again. conflict carries the current revision. invalid is a malformed name or revision. A platform store that cannot destroy the bytes reads unavailable and the record is unchanged.")
enum PageOutcome {
 1: page
 2: gap
 3: invalid
 4: forbidden
 5: unavailable
}(unknown="refuse",reader="act")
struct Limits {
 1: required i64 max_credentials
 2: required i64 max_secret_bytes
 3: required i64 tombstone_retention_ms
 4: required i64 audit_retention_ms
 5: required i64 audit_capacity
 6: required SecureStore secure_store
 7: required list<string> supported_kinds
}(unknown_fields="refuse",doc="Provider-declared bounds, read through List. max_secret_bytes is at most 4096 and is lower where the configured store bounds it. secure_store names the configured store: SecureStore names this version's standard backends, provider extensions are retained, and refusal-page zero limits carry the empty word. supported_kinds are the kinds an applier on this runtime can apply; Store refuses any other.")
struct MetadataPage {
 1: required PageOutcome outcome
 2: required Limits limits
 3: required list<Metadata> records
 4: required string next
 5: required bool complete
}(unknown_fields="refuse",doc="page carries 0..limit records of the receiving account in name order, including tombstones inside retention. Cursors are at most 256 bytes, bind receiving account and provider epoch, and return gap after restart or scope mismatch; restart from an empty cursor. A noncomplete page has a nonempty next. Refusals carry zero limits, no records, empty next and complete=false.")
struct AuditEntry {
 1: required i64 sequence
 2: required timestamp time
 3: required string event
 4: required string name
 5: required string revision
 6: optional Subject subject(omit="absent")
 7: optional string consumer(omit="absent")
 8: optional string target(omit="absent")
 9: optional string outcome(omit="absent")
}(unknown_fields="refuse",doc="One retained event in journal order. event is an open word: stored, rotated, revoked, expired, lost, retired, checked, applied, refused. subject is the asserted submitting or registering subject; consumer and target are present for checked, applied and refused; outcome is the exact holder or rights outcome word. Entries carry names and never values.")
struct AuditPage {
 1: required PageOutcome outcome
 2: required list<AuditEntry> entries
 3: required string next
 4: required bool at_end
}(unknown_fields="refuse",doc="page carries at most max_entries entries after the cursor. The journal retains Limits.audit_capacity entries for Limits.audit_retention_ms per account; a cursor older than the retained journal, or from another provider epoch, returns gap. Refusals carry no entries, an unchanged cursor and at_end=false.")
service Holder {
 StoreResult Store(1:string expected_revision,2:Registration registration)(doc="Conditionally register one secret for the receiving account. Gated by abstraction.credentials/holder.manage on resource account for the bound receiving subject; authorization precedes every store effect. The secret leaves the request only into the configured platform store. Returns stored, conflict, invalid, unsupported_kind, no_secure_store, exhausted, forbidden or unavailable.")
 RotateResult Rotate(1:string expected_revision,2:Rotation rotation)(doc="Conditionally replace the bytes of an existing record and its expiry; kind and scope are unchanged. Gated by holder.manage.")
 RevokeResult Revoke(1:string expected_revision,2:string name)(doc="Conditionally destroy the bytes and tombstone the record. Gated by holder.manage. A failed or uncertain reply claims no destruction; inspect List before another intent.")
 MetadataPage List(1:string cursor,2:i64 limit)(doc="Read the receiving account's records and the provider limits. Gated by abstraction.credentials/holder.read on resource account; every continuation rechecks. limit is 1..64.")
 AuditPage Audit(1:string cursor,2:i64 max_entries)(doc="Read the receiving account's retained credential events. Gated by holder.read. Empty cursor starts at the oldest retained entry; max_entries is 1..256.")
}(wire_name="abstraction.credentials/holder@1",doc="Register, rotate, revoke and inspect credentials by name in the receiving account. Same-account identity alone grants nothing; each call is a rights decision on the bound receiving subject. No call returns secret bytes, and metadata derives nothing from them. An absent policy service reads unavailable. An unconfigured platform store or a machine-scope runtime reads no_secure_store; the provider substitutes no environment, file or configuration source.")

enum ApplyOutcome {
 1: applied
 2: unknown
 3: expired
 4: revoked
 5: lost
 6: not_permitted
 7: target_refused
 8: consumer_refused
 9: unsupported_kind
 10: invalid
 11: forbidden
 12: unavailable
}(unknown="refuse",reader="act")
struct Use {
 1: required Subject subject
 2: required string consumer
 3: required string name
 4: required string target
 5: optional string challenge(omit="absent")
}(unknown_fields="refuse",doc="subject is the submitting caller as bound at the consuming service's own boundary and asserted by that authorized enforcer; serialization conveys no proof. consumer is the calling service's wire contract name: a consumers seed or <owner>/<name>@<n>. target is the lowercase host the request will open. challenge carries kind-specific input, for example a registry authenticate challenge, and is refused as invalid for the seed kinds.")
struct CheckResult {
 1: required ApplyOutcome outcome
 2: required string revision
}(unknown_fields="refuse",doc="applied means Apply with the same Use would carry headers now. revision is present for evaluated records. No secret is read for a check.")
struct ApplyResult {
 1: required ApplyOutcome outcome
 2: required string revision
 3: optional map<string,string> headers(omit="zero")
}(unknown_fields="refuse",doc="headers is present exactly for applied and holds the request headers for this one request: Authorization for bearer and challenge kinds, the registered header name for kind header. The consuming service sends them once, keeps them out of every record, log and reply, and calls Apply again for the next request, redirect or resumed range. Other outcomes carry no headers. not_permitted means the rights decision for subject, abstraction.credentials/apply and credential:<name> was anything except permitted; the exact word is in the audit trail. target_refused and consumer_refused name Scope mismatches. forbidden means the calling peer is not a designated enforcer, or the subject could not be bound on this platform. unavailable means the rights service or the platform store could not be reached; nothing was applied.")
service Applier {
 CheckResult Check(1:Use usage)(doc="Evaluate whether Apply would succeed for this use, for admission and adopter preflight. Same designation and policy as Apply; reads no secret; appends a checked or refused audit entry.")
 ApplyResult Apply(1:Use usage)(doc="Read the secret for one outgoing request. Only an explicitly designated enforcer program, bound by native Program proof, is accepted; same-account access alone is forbidden. The holder rechecks rights on every call and never caches a decision or a value across calls.")
}(wire_name="abstraction.credentials/applier@1",doc="Enforcer-only application of a named credential to one request. The receiving host designates the consuming services by program, as rights DecideFor designates enforcers; nil designation refuses every call. Headers cross this boundary to a designated service only, never to an application client, and never to a remote host. A remote provider holds its own applier and registrations; delegation carries the name. On platforms without process and path proof every Apply is forbidden.")
