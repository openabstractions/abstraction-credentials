# abstraction.credentials contract

`credentials.thrift` defines versioned services. `abstraction.credentials/holder@1`
— prose name credential manager — registers, rotates, revokes and inspects
named secrets for the receiving account. `abstraction.credentials/applier@1`
applies a named secret to one outgoing request for a designated consuming
service. This file states the obligations a provider meets; [README.md](README.md)
holds the walkthrough. The explicit `reader@1`, `holder@2` and `applier@2`
profiles below use typed named-resource permissions for saved application secrets.

Binds: `credentials.thrift`

Any same-account process can already read the platform's credential store;
the credential manager raises that bar to a process that speaks the
platform's credential API as this account, and it keeps secret bytes out of
job records, configuration, argv, environment, logs and audit entries
entirely. Authorization is per calling program and per credential name: a
name inside a request grants nothing, `Store`, `Rotate` and `Revoke` require
the account's `credentials/manage` rule, and `Apply` requires a rights
decision for the calling subject, `abstraction.credentials/apply` and
`credential:<name>`, evaluated inside the receiving host's own designated
enforcer program. `Scope.targets` and `Scope.consumers` keep a compromised
record from reaching another host or another service, and a rights or
platform-store outage fails the call instead of falling back to a substitute
secret source.

## Reading this page

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

The rule ids below, such as `CRED-H1`, are what tests and refusals cite. A
retired id is never reused; [HISTORY.md](HISTORY.md) keeps it with the
release it left.

| Letter | Meaning |
| --- | --- |
| H | credential manager |
| A | applier |
| R | catalogues and remote delegation |

`CRED-H` rules judge the credential manager; `CRED-A1` to `CRED-A5` judge the
applier; `CRED-A6` judges each consuming service.

| Prose | Wire (until its own release) |
| --- | --- |
| `credentials/manager@1`, credential manager | `abstraction.credentials/holder@1`; the dual reader lands with this module at `research/vocabulary/RENAME-PLAN.md` §4's first release |
| `credentials/manage` | `abstraction.credentials/holder.manage`, owned by rights' stored policy; the dual reader lands with that module, not here |
| `credentials/read` | `abstraction.credentials/holder.read`, owned by rights' stored policy; the dual reader lands with that module, not here |

## Credential manager

**[CRED-H1] Peer binding.** Every credential-manager call MUST bind the
receiving peer by native Program proof: kernel user and process, bound path.
A peer of another account reads `forbidden`. The bound account and program
form the subject of every rights decision.

**[CRED-H2] Rights precede every effect.** `Store`, `Rotate` and `Revoke`
MUST ask rights for `abstraction.credentials/manage` on resource `account`;
`List` and `Audit` MUST ask for `abstraction.credentials/read` on resource
`account`. Only `permitted` proceeds. `denied`, `not_granted` and
`unknown_action` read `forbidden`; a decision point that cannot answer reads
`unavailable`. Authorization MUST precede every store effect and every read.
An application holds `credentials/manage` only through an explicit rule; a
host grants it by default to its own operator programs and to nothing else.
A host's operator programs are fixed when it starts: its own executable and
the operator programs installed beside it. An isolated runtime, one with
its own derived endpoints and its own state directory, also names the one
executable its operator passed at start; the installed runtime MUST refuse
such a program.

**[CRED-H3] Legacy holder replies contain no secret.** No `holder@1` or
`holder@2` reply, audit entry, log record or error message MUST carry secret
bytes or anything derived from them: no length, hash, prefix or suffix.
The separately admitted `reader@1` raw disclosure is governed by CRED-S2.

**[CRED-H4] No configured store, no substitute.** A runtime for which the
platform's credential store is not configured MUST answer `Store` and
`Rotate` with `no_secure_store` and MUST report `Limits.secure_store =
"none"`. A machine-wide runtime answers the same in this version. The
provider MUST NOT read an environment variable, configuration value or plain
file as a substitute. The `file-0600` store is configured only by an
explicit operator choice.

**[CRED-H5] Conditional edits by revision.** Conditional edits MUST compare
`expected_revision` inside the edit. An empty expected revision requires an
absent name. A stale revision reads `conflict` against the current metadata,
also when the desired state already holds. A lost reply is uncertain;
callers reconcile from `current` or `List`.

**[CRED-H6] No control characters in a secret.** `Store` and `Rotate` MUST
refuse a secret containing a control character other than tab, as `invalid`,
because the applier places it inside one header line.

## Applier

**[CRED-A1] Peer binding for enforcers.** The receiving host designates
enforcer programs per consumer service. A peer the designation refuses, a
nil designation, a subject of another account, and every call on a platform
without process and path proof MUST read `forbidden` before any record is
read.

**[CRED-A2] Evaluation order.** `Check` and `Apply` MUST evaluate in this
order: argument shape (`invalid`), record (`unknown`, `revoked`, `expired`,
`lost`), kind (`unsupported_kind`), scope (`consumer_refused`, then
`target_refused`), then the rights decision for `Use.subject`,
`abstraction.credentials/apply` and `credential:<name>` (`not_permitted`, or
`unavailable` when the decision point cannot answer). `Apply` then reads the
secret; an unreachable platform's credential store reads `unavailable`, and
an item the store no longer has marks the record `lost`.

**[CRED-A3] Target matches a scope host.** A target matches a scope host
when it equals the host or ends with `.` followed by the host. Redirect
hosts are separate uses.

**[CRED-A4] No cache; headers only for applied.** The applier MUST cache no
decision and no secret across calls. `headers` is present exactly for
`applied`: `Authorization: Bearer <secret>` for kind `bearer`,
`<header>: <secret>` for kind `header`. A challenge on a seed kind reads
`invalid`.

**[CRED-A5] One audit entry per call.** Each `Check` and `Apply` MUST append
one audit entry: `checked`, `applied` or `refused`, with the exact outcome
word. A `not_permitted` entry carries the exact rights outcome. A decision
point's `forbidden` or `invalid` reads `unavailable`, and its entry carries
`rights:<word>`.

**[CRED-A6] Applied headers stay on one request.** A consuming service MUST
send applied headers on one request and MUST keep them out of every record,
log, reply and error. Each redirect, retry and resumed range is a new
`Apply`. A refused `Apply` fails that request; the service MUST NOT send the
request without the credential it named.

**[CRED-A7] A cancel with refused headers is recorded.** A consuming
service whose use of a credential was refused while upstream work it paid
for still runs MAY send the headers its earlier `Apply` returned once more,
only to cancel that work (abstraction-inference INF-A6), as the one exception
to CRED-A6. It MUST then append one audit entry with event and outcome
`cancel`, naming the use's subject, consumer, target and credential
(`Holder.RecordCancel`). The entry reads no secret and decides nothing.

## Catalogues

**[CRED-R1] Closed and open catalogues.** `resource_actions` names exactly
the eight actions this capability's own rules use; a host registers them
into its rights decision policy through rights action registration, and the
next name reserved for growth is `abstraction.credentials/holder.delegate`.
`credential_kinds` is open: an application-owned kind, `<owner>/<name>@<n>`,
is accepted by `Store` only when an applier on the runtime lists it in
`Limits.supported_kinds`; the credential manager never interprets a kind
itself. The runtime also holds `openabstractions/local-key@1` records, the
inference gateway's own gateway keys (inference INF-K2): only the runtime
registers them in process, `Store` refuses the kind as `unsupported_kind`,
`Check` and `Apply` read `unsupported_kind` and never return them, and
`List` shows their metadata. `SecureStore` names the standard backends this
version defines; provider extension names are retained, and a refusal
page's zero limits carry an empty store word. `consumers` is a seed, not a
closed list: a consuming service outside it extends the list with its own
`<owner>/<name>@<n>` wire service name, and the receiving host's enforcer
designation, not a name in this document, is what registers it.

## Consumers

`consumers` seeds the wire services that apply credentials today; CRED-R1
states that the list is a seed, not a closed one.

| Consumer | Applies for |
|---|---|
| `abstraction.download/http-execution@1` | every HTTP(S) request of an accepted download whose source names a credential |
| `abstraction.model/resolver@1` | a registry metadata request made during `Lookup` for a `Ref` naming a credential |
| `abstraction.inference/chat@1` | each outgoing request to a hosted inference server |
| `abstraction.inference/embed@1` | each outgoing request to a hosted embedding server |
| `abstraction.inference/transcription@1` | each outgoing request to a hosted transcription server |
| `abstraction.inference/speech@1` | each outgoing request to a hosted speech server |
| `abstraction.inference/image@1` | each outgoing request to a hosted image server |
| `abstraction.inference/live@1` | each outgoing request to a hosted live-audio server |

A consuming service outside the seed uses its own `<owner>/<name>@<n>` wire
service name. The receiving host's enforcer designation decides which
program may act as which consumer. The site glossary's Consumer entry
carries each consumer's Panel plain-phrase label; this contract states only
the wire service name.

## Remote providers

A local service delegates by credential name and never forwards applied
headers or secret bytes. A remote provider holds its own credential manager
and applier. It resolves a delegated name in the scope its host mapped from
the verified client certificate, and its own rights decide. A remote
credential manager that lacks the name refuses at its own admission, and the
local service reports that refusal unchanged, without fetching locally. The
download layer's remote job delegate implements this (download CONTRACT
DL-K3).

A consuming service checks a named credential at admission with `Check` and
refuses the submission before any work is recorded (job CONTRACT JOB-A16,
download CONTRACT DL-K1). Each redirect host is a separate `Apply` (CRED-A3,
download CONTRACT DL-K2).

## Outcomes

| Call | Outcome | Meaning |
|---|---|---|
| `Store` | `stored` | The secret was written; the result carries the new revision and current metadata (CRED-H5). |
| `Store` | `conflict` | `expected_revision` is stale against the current metadata, or an empty expected revision named an existing name (CRED-H5). |
| `Store` | `unsupported_kind` | No applier on this runtime lists the kind in `Limits.supported_kinds` (CRED-R1). |
| `Store`, `Rotate` | `no_secure_store` | The platform's credential store is not configured, or the runtime is machine-wide (CRED-H4). |
| `Store` | `exhausted` | The account already holds `Limits.max_credentials` records. |
| `Store`, `Rotate` | `invalid` | An argument is malformed or over its bound (Bounds), or the secret carries a control character other than tab (CRED-H6). |
| `Rotate` | `rotated` | The bytes were replaced; a lost or expired record returns to `active`. |
| `Rotate`, `Revoke` | `unknown` | No record of that name exists, or its tombstone has expired. |
| `Revoke` | `revoked` | The bytes were destroyed at once; the name reads `revoked` for `tombstone_retention_ms` (Bounds). |
| `Store`, `Rotate`, `Revoke`, `List`, `Audit` | `forbidden` | The peer could not be bound by native Program proof (CRED-H1), or the rights decision was `denied`, `not_granted` or `unknown_action` (CRED-H2). |
| `Store`, `Rotate`, `Revoke`, `List`, `Audit` | `unavailable` | The rights decision point, or the platform's credential store, could not be reached (CRED-H2, CRED-H4). |
| `List`, `Audit` | `page` | One page of the receiving account's records or audit entries. |
| `List`, `Audit` | `gap` | The cursor is older than the retained history, or names another provider epoch (Bounds). |
| `Check` | `applied` | `Apply` with the same `Use` would carry headers now; no secret is read for a check. |
| `Apply` | `applied` | The secret was read; `headers` carries the request headers for this one request (CRED-A4). |
| `Check`, `Apply` | `unknown` | No record of that name exists. |
| `Check`, `Apply` | `expired` | The record's `expires` is past. |
| `Check`, `Apply` | `revoked` | The name is inside `tombstone_retention_ms` of a `Revoke`. |
| `Check`, `Apply` | `lost` | The platform's credential store no longer has the item. |
| `Check`, `Apply` | `not_permitted` | The rights decision for `Use.subject`, `abstraction.credentials/apply` and `credential:<name>` was anything except `permitted` (CRED-A2). |
| `Check`, `Apply` | `target_refused` | `Use.target` is not in the record's `Scope.targets` (CRED-A3). |
| `Check`, `Apply` | `consumer_refused` | `Use.consumer` is not in the record's `Scope.consumers`. |
| `Check`, `Apply` | `unsupported_kind` | The kind is not one an applier on this runtime supports, including the `openabstractions/local-key@1` kind (CRED-R1). |
| `Check`, `Apply` | `invalid` | An argument is malformed, or a seed-kind `Use.challenge` was present (CRED-A4). |
| `Check`, `Apply` | `forbidden` | The peer was not a designated enforcer, or the subject could not be bound on this platform (CRED-A1). |
| `Check`, `Apply` | `unavailable` | The rights decision point, or the platform's credential store, could not be reached. |

Every outcome above is the typed refusal a caller reads directly; a
consuming service maps it onto its own failure cause (`abstraction.job`
`FailureCause`), and this definition declares no cause enum of its own.

## Bounds

A secret is at most `Limits.max_secret_bytes`, never above 4096 bytes, and
fits one control frame; Windows Credential Manager bounds it to 2560 bytes.
Names are 1..64 bytes, targets 1..16, consumers 1..8, list pages 1..64
records and audit pages 1..256 entries. The tombstone left by a removal
reads `revoked` for `tombstone_retention_ms`, after which the name reads
`unknown`; the audit journal retains `audit_capacity` entries for
`audit_retention_ms` per account, and a cursor older than that, or from
another provider epoch, reads `gap`. `Metadata.registered_by` and
credential-manager audit subjects are asserted by the credential manager
from native Program proof; `Use.subject` is asserted by the designated
enforcer from its own receiving boundary. An audit entry with no subject
means the event had no caller — `expired`, removed (the audit event word
itself stays `retired`), or `lost`, each detected during listing. `State` is
display-grade and grants unknown members; every outcome enum is acted on and
refuses unknown members. Two fields sharing one key inside one request
document are refused.

## Divergences

None declared for this release.

## Not built

This capability stores no secret outside the configured platform's
credential store: `file-0600` is chosen by explicit operator choice, never a
default (CRED-H4). It validates no secret's value against its own upstream
service; a wrong bearer token is a failure the consuming service discovers
at its own request, not one this definition detects. It rotates nothing on
its own clock: `Rotate` runs only when a caller calls it. A credential
registered by one account is invisible to another account's `List`, `Audit`
or `Apply`.

## Platform stores

**[CRED-D1] The named Use definition follows the account-owned name slot.**
`CredentialResource` names exactly `credential:<name>` using the holder's
existing 1..64 ASCII name validator. The receiving subject binds the account and
program separately. An exact apply grant follows the current slot, including
rotation and a recreated registration's current consumer/target restrictions.
It conveys no holder management authority and freezes no current host/consumer
list. Check and Apply MUST revalidate the current registration and expiry after
their fresh rights decision, before success or secret access. A missing exact
permit may admit the runtime's structured first-use request; the original use
remains refused until an answer's exact rule effect succeeds and the caller
retries. Raw secret Read uses the distinct receiving profile and right in CRED-S2.

## Scoped saved-secret profiles

**[CRED-S1] Owning target and collection.** `CredentialResource{name}` MUST
use the generated owning codec and canonical byte equality. A name is 1..64
ASCII bytes accepted by the holder validator. `named-secret@1` and
`named-use@2` fix the account-bound `saved-app-secrets@1` collection: only
user-stored kinds supported by Store (`bearer`, `header` today). Runtime
`openabstractions/local-key@1` keys are outside this collection. A malformed or
unknown profile/version MUST refuse; legacy exact strings, including `*`,
retain their existing interpretation. An exact selector follows the current
name slot, including rotation and a later recreated registration. All covers
present and future members of this fixed collection. Neither selection freezes
registration restrictions or grants authority to administer permission policy.

**[CRED-S2] Explicit raw Read and recipient.** `reader@1.Read(name)` MUST bind
the receiving same-account Program peer as its subject and recipient. It MUST
authorize `secret.read` on `named-secret@1` before revealing any record state
or revision. Use, legacy metadata and holder-management permits confer no Read
authority. Only `read` carries `SecretValue{name,revision,secret}`; every other
outcome MUST omit it. The response contains the current stored 1..4096-byte
value, within the configured backend bound. Raw Read exports the value to the
requester; the requester can copy and use it elsewhere. Registration consumer
and website restrictions constrain service Use; they do not constrain raw
disclosure or onward use. The shared permission explanation MUST say this.
The receiving native account/program MUST be rechecked before disclosure.
Bytes MUST stay out of Asks, policy, audit, logs, history and errors. A failed
reply remains uncertain and MUST NOT trigger a fallback or automatic retry.
Mutable transient buffers MUST be cleared after encoding/reply or refusal;
this obligation makes no universal heap-erasure claim.
Every holder backend failure MUST reach report sinks only as a compiled
operation/status classification. Put, Get, Delete, cleanup and garbage
collection MUST NOT forward backend diagnostic text or wrapped causes.

**[CRED-S3] Scoped management and finite bundle.** `holder@2` enforces
`secret.create`, `secret.rotate`, `secret.revoke` and `secret.metadata.read`
on the named-secret profile for Store, Rotate, Revoke and Metadata respectively.
Metadata returns one name and MUST NOT imply enumeration. Conditional data
revision checks, persistence, tombstones and reconciliation reuse CRED-H5.
`full-control@1` expands into exactly those four operations, raw `secret.read`
and `apply` on `named-use@2`. List, Audit, policy administration and future
operations are outside this immutable six-member bundle.

**[CRED-S4] Membership refusals.** Every scoped target operation MUST check
the current kind under the holder lock. Read and scoped Check/Apply return
`unsupported_kind` without value/headers for an excluded slot. Store returns
`unsupported_kind` with no current metadata or revision for either an excluded
input kind or an existing/tombstoned excluded slot, before its ordinary conflict
response. Rotate, Revoke and Metadata return `forbidden` without current
metadata or revision for an excluded slot. No new reserved future-name policy
is implied. Legacy methods retain their separately admitted collection.

**[CRED-S5] Atomic owner and final permission snapshot.** Missing-permit Ask
admission runs outside the holder mutex and the original call remains refused.
After any wait, each scoped operation MUST hold the holder mutex, sweep and
reload current state, and call the quiet shared Rights batch before state
disclosure, success or backend access. The quiet callback MUST sample one
policy revision/clock and MUST NOT admit Asks, call Holder/backend or perform
effects. An optional expected policy revision detects a stale admission.
Read MUST repeat that quiet check and native recipient check after Backend.Get
immediately before releasing bytes; failure discards the value. Check and Apply
reuse the current consumer/target/expiry owner and do not cache authority.
Revokes before the final policy snapshot are honored; later revokes stop later
calls, not an already admitted mutation. There is no distributed lease.
Policy conflict returns Read/Metadata `conflict`; mutation/apply methods using
legacy outcome enums return `unavailable`, without inventing a data revision
conflict. Holder-lock callbacks are quiet and non-reentrant.

**[CRED-S6] Version routing and explicit block fences.** `applier@2` enforces
the new typed Use profile. Its designated enforcer and per-call registration
scope checks retain CRED-A1/A3/A6. `applier@1` retains its original exact grant
route. Permits remain specific to their versioned key. The shared Rights owner
imports explicit blocks bidirectionally across registered equivalent effects:
legacy apply to typed Use, holder.manage to create/rotate/revoke, and
holder.read to named metadata. Legacy mutations supply an actual concrete
saved-secret name only when Holder's current snapshot proves collection
membership, rechecked at the final mutation. Excluded runtime-key slots and
unknown slots use nil concrete evidence, the conservative whole legacy
collection fence. A related typed block can therefore refuse an old broad
holder operation on a runtime key even though typed operations cannot target
that key. This compatibility limitation confers no new runtime-key authority
or export API. Coarse List/Audit are refused when an
intersecting metadata block exists. Raw Read has no legacy equivalent. The
original granted @1 operation set/transport remain, with these explicit-block
restrictions; a caller cannot switch versions to evade a block. All matching
belongs to Rights. No local selector matcher or fallback is allowed.
Scoped profile readiness MUST require both the scoped authorization callbacks
and the complete shared legacy fence. An incomplete composition MUST refuse
scoped calls and MUST NOT advertise the new profiles.
Download's explicit `abstraction.download/credentials@2` required guarantee
selects `applier@2` for the whole submitted request. Selecting both versions
MUST refuse; unavailable @2 MUST NOT fall back to @1. The persisted required
guarantees and prepared route preserve that selection through recovery.

| `secure_store` | Platform | Limitation |
|---|---|---|
| `windows-dpapi-file` (provider word) | Windows per-user runtime with fresh credentials state; one file per item under the state directory's `credentials/items`, sealed with `CryptProtectData` in user scope with the target `<namespace>/<account>/<name>/<revision>` as extra entropy, replaced atomically, protected DACL granting the user alone | Only the runtime writes it. A process running as the same user can unseal an item. A damaged item, one moved to another name, or a lost DPAPI user key reads `lost`; an unreachable one reads `unavailable` (CRED-B2). Temporary files of an interrupted write older than a minute are removed when the store opens. Items do not appear in the Windows Credential Manager view. |
| `windows-credential-manager` | Windows per-user runtime whose state is bound to it (CRED-B1); generic credentials, local-machine persistence, target `openabstractions/<account>/<name>/<revision>` | Every process of the same logon session can read the item. A lost DPAPI user key reads `lost`. Overlapping calls on the account's store, from any program, can lose a new item or restore a deleted one; the provider orders its own calls with a per-session lock and reports `store_lock process_only` when that lock cannot be opened. |
| `secret-service` | Linux with a session bus and an unlocked default collection | Without the bus or the `org.freedesktop.secrets` owner every store call reads `unavailable`. |
| `file-0600` | Linux, chosen explicitly by the operator | Directory 0700, files 0600, no encryption at rest; readable by the same uid and root. |
| `macos-keychain` | macOS; data protection keychain, generic passwords, this-device-only after first unlock | Requires a user login context and profile-authorized Keychain access-group entitlements. A runtime lacking them reports the configured store as `unavailable`. This store retains its existing meaning for previously configured state. |
| `macos-login-keychain` (provider word) | macOS; native default user file-based Keychain, generic passwords, creator-only item access policy | Uses native Keychain encryption and access-control lists. The creating receiver's designated requirement governs signed upgrade access; other programs may require genuine OS authorization. It has no data-protection accessibility class or promise to lock when the screen locks. A locked store, denied authorization or unavailable native interaction reads `unavailable`. |
| `none` | any runtime without a configured store, and every machine-wide runtime | `Store` and `Rotate` read `no_secure_store`. |

The native macOS credential receiver requires message-bound Program proof from
XPC. The recorded AF_UNIX proof ceiling cannot admit these calls. Neither store
grants an application's payload identity any authority.

The runtime binds a fresh credentials state to its deliberately selected native
user Keychain with a durable marker recording both the backend kind and the
OS-selected Keychain path before opening the credential manager. It reopens
that bound native store after a restart, including when the account's default
Keychain changes. A missing, locked or unusable bound store reads `unavailable`.
Preexisting unmarked credentials state keeps the data-protection selection.
An unknown or invalid marker, including a login-Keychain marker without its
native locator, reads `unavailable` and selects no second store. Existing
registration metadata must remain associated with its original store until
explicit verified migration or re-registration. An empty new store must not
turn a registration in the old store into `lost`.

**[CRED-B1] Windows state binds to one store.** Before it creates the
credentials directory or opens the holder, a Windows runtime reads the durable
marker `credentials-windows-backend` beside that directory. A marker naming
`windows-dpapi-file` or `windows-credential-manager` selects that store on
every start. Without a marker, a fresh state (no credentials directory) binds
to `windows-dpapi-file` and an existing state binds to
`windows-credential-manager`, where its registrations' items are; the runtime
writes the marker exclusively and durably, and a concurrent start reads the
marker the first one wrote. An unknown or unreadable marker, or a bound store
that cannot open, reads `unavailable` and selects no second store. Moving
registrations between the two stores needs an explicit verified migration; an
empty new store must not turn a registration in the old store into `lost`.

**[CRED-B2] A DPAPI failure reads lost only when the item itself is gone.**
Both Windows stores seal with DPAPI in user scope. A read maps its failure:

| DPAPI failure on read | Outcome |
|---|---|
| `ERROR_INVALID_DATA`, `NTE_BAD_DATA`, `ERROR_INVALID_PARAMETER` (damaged blob, other entropy, no DPAPI header; `windows-dpapi-file` only) | `lost` |
| `NTE_BAD_KEY_STATE`, `ERROR_INVALID_PASSWORD`, while a fresh canary sealed and unsealed with the same flags succeeds | `lost` |
| `NTE_BAD_KEY_STATE`, `ERROR_INVALID_PASSWORD`, while the canary fails (profile not loaded, batch or S4U logon, roaming master key not yet synchronized) | `unavailable`; the record keeps its state |
| any other failure | `unavailable` |

The native login-Keychain library constructor leaves process-wide Security UI
unchanged. A dedicated background receiver disables file-Keychain interaction
once before serving concurrent calls. Native unlocking and authorization remain
owner OS actions; the provider collects no Keychain password and changes no
Keychain default, search list or existing item access policy. Store outages and
authorization failures preserve metadata. [Apple's Mac Keychain guide](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
describes the two implementations, and its
[code signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html)
describes creator identity tracking.
