# abstraction.credentials contract

`credentials.thrift` defines two services. `abstraction.credentials/holder@1`
— prose name credential manager — registers, rotates, revokes and inspects
named secrets for the receiving account. `abstraction.credentials/applier@1`
applies a named secret to one outgoing request for a designated consuming
service. This file states the obligations a provider meets; [README.md](README.md)
holds the walkthrough.

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

**[CRED-H3] No secret in any reply.** No reply, audit entry, log record or
error message MUST NOT carry secret bytes or anything derived from them: no
length, hash, prefix or suffix.

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

## Catalogues

**[CRED-R1] Closed and open catalogues.** `resource_actions` names exactly
the three actions this capability's own rules use; a host registers them
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

| `secure_store` | Platform | Limitation |
|---|---|---|
| `windows-credential-manager` | Windows per-user runtime; generic credentials, local-machine persistence, target `openabstractions/<account>/<name>/<revision>` | Every process of the same logon session can read the item. A lost DPAPI user key reads `lost`. |
| `secret-service` | Linux with a session bus and an unlocked default collection | Without the bus or the `org.freedesktop.secrets` owner every store call reads `unavailable`. |
| `file-0600` | Linux, chosen explicitly by the operator | Directory 0700, files 0600, no encryption at rest; readable by the same uid and root. |
| `macos-keychain` | macOS; data protection keychain, generic passwords, this-device-only after first unlock | Process and path proof are unavailable on macOS, so every credential-manager and applier call over IPC reads `forbidden` until identity proof lands. Registrations made by an in-process host remain in place. The data protection keychain serves only a program signed with a keychain access group entitlement; in any other program, an unsigned build included, every store call reads `unavailable`. |
| `none` | any runtime without a configured store, and every machine-wide runtime | `Store` and `Rotate` read `no_secure_store`. |
