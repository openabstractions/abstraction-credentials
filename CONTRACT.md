# abstraction.credentials contract

`credentials.thrift` defines two wire contracts. `abstraction.credentials/holder@1`
registers, rotates, revokes and inspects named secrets for the receiving
account. `abstraction.credentials/applier@1` applies a named secret to one
outgoing request for a designated consuming service. The design and threat
model are in the private note `feedback/credentials-holder-design.md`; this
file states the obligations a provider meets.

## Holder

- **CRED-H1.** Every holder call binds the receiving peer by native Program
  proof (kernel user and process, bound path). A peer of another account is
  `forbidden`. The bound account and program form the subject of every rights
  decision.
- **CRED-H2.** `Store`, `Rotate` and `Revoke` ask rights for
  `abstraction.credentials/holder.manage` on resource `account`. `List` and
  `Audit` ask for `abstraction.credentials/holder.read` on resource `account`.
  Only `permitted` proceeds. `denied`, `not_granted` and `unknown_action` read
  `forbidden`. A decision point that cannot answer reads `unavailable`.
  Authorization precedes every store effect and every read. An application
  holds `holder.manage` only through an explicit rule; a host grants it by
  default to its own operator programs and to nothing else.
- **CRED-H3.** No reply, audit entry, log record or error message carries
  secret bytes or anything derived from them (length, hash, prefix, suffix).
- **CRED-H4.** A runtime with no configured platform store answers `Store` and
  `Rotate` with `no_secure_store` and reports `Limits.secure_store = "none"`.
  A machine-scope runtime answers the same in this version. The provider reads
  no environment variable, configuration value or plain file as a substitute.
  The `file-0600` store is configured only by an explicit operator choice.
- **CRED-H5.** Conditional edits compare `expected_revision` inside the edit.
  An empty expected revision requires an absent name. A stale revision is
  `conflict` with the current metadata, also when the desired state already
  holds. A lost reply is uncertain; callers reconcile from `current` or `List`.
- **CRED-H6.** `Store` and `Rotate` refuse a secret containing a control
  character other than tab as `invalid`, because the applier places it inside
  one header line.

## Applier

- **CRED-A1.** The receiving host designates enforcer programs per consumer
  contract. A peer the designation refuses, a nil designation, a subject of
  another account, and every call on a platform without process and path proof
  read `forbidden` before any record is read.
- **CRED-A2.** `Check` and `Apply` evaluate in this order: argument shape
  (`invalid`), record (`unknown`, `revoked`, `expired`, `lost`), kind
  (`unsupported_kind`), scope (`consumer_refused`, then `target_refused`), then
  the rights decision for `Use.subject`, `abstraction.credentials/apply` and
  `credential:<name>` (`not_permitted`, or `unavailable` when the decision
  point cannot answer). `Apply` then reads the secret; a platform store that
  cannot be reached reads `unavailable`, and an item the store no longer has
  marks the record `lost`.
- **CRED-A3.** A target matches a scope host when it equals the host or ends
  with `.` followed by the host. Redirect hosts are separate uses.
- **CRED-A4.** The holder caches no decision and no secret across calls.
  `headers` is present exactly for `applied`: `Authorization: Bearer <secret>`
  for kind `bearer`, `<header>: <secret>` for kind `header`. A challenge on a
  seed kind is `invalid`.
- **CRED-A5.** Each `Check` and `Apply` appends one audit entry, `checked`,
  `applied` or `refused`, with the exact outcome word. A `not_permitted` entry
  carries the exact rights outcome. A decision point's `forbidden` or `invalid`
  reads `unavailable`, and its entry carries `rights:<word>`.
- **CRED-A6.** A consuming service sends applied headers on one request and
  keeps them out of every record, log, reply and error. Each redirect, retry
  and resumed range is a new `Apply`. A refused `Apply` fails that request;
  the service never sends the request without the credential it named.

## Consumers

`consumers` seeds the wire contracts that apply credentials today:

| Consumer | Applies for |
|---|---|
| `abstraction.download/http-execution@1` | every HTTP(S) request of an accepted download whose source names a credential |
| `abstraction.model/resolver@1` | a registry metadata request made during `Lookup` for a `Ref` naming a credential |
| `abstraction.inference/chat@1` | each outgoing request to a hosted inference host |

A consuming service outside the seed uses its own `<owner>/<name>@<n>` wire
contract name. The host's enforcer designation decides which program may act
as which consumer.

## Remote providers

A local service delegates by credential name and never forwards applied
headers or secret bytes. A remote provider holds its own holder and applier.
It resolves a delegated name in the scope its host mapped from the verified
client certificate, and its own rights decide. A remote holder that lacks the
name refuses at its own admission, and the local service reports that refusal
unchanged, without fetching locally. The download layer's remote job delegate
implements this (download CONTRACT DL-K3).

A consuming service checks a named credential at admission with `Check` and
refuses the submission before any work is recorded (job CONTRACT JOB-A16,
download CONTRACT DL-K1). Each redirect host is a separate `Apply` (CRED-A3,
download CONTRACT DL-K2).

## Rule answers

The ten rules of "Writing a contract", and rule 11, answered before generation.

1. **Outcomes.** Every call returns one outcome enum. Every call reserves
   `forbidden`, `unavailable` and `invalid`. Calls naming a record reserve
   `unknown`; conditional writes reserve `conflict`. An unreachable decision
   point is `unavailable` (CRED-H2, CRED-A2).
2. **Retained records.** A record is identified by account and name; its
   retry dimension is `revision`, an opaque value unique within the provider
   state, so a re-registered name never matches an older revision. Retention is
   readable in `Limits`. Loss is the typed state `lost`. `holder.manage`
   retires by `Revoke`; the tombstone reads `revoked` for
   `tombstone_retention_ms`, after which the name reads `unknown`. The audit
   journal retains `audit_capacity` entries for `audit_retention_ms`; an older
   or foreign-epoch cursor reads `gap`.
3. **Failures.** Holder outcomes are the typed refusal; consuming services map
   them onto their own failure cause (`abstraction.job` `FailureCause`). The
   definition declares no cause enum.
4. **Catalogues.** `credential_kinds` is open: `<owner>/<name>@<n>` kinds are
   accepted when an applier on the runtime lists them in
   `Limits.supported_kinds`. The runtime also holds
   `openabstractions/local-key@1` records, the gateway window's local keys
   (inference INF-P3): only the runtime registers them in process, holder@1
   `Store` refuses the kind as `unsupported_kind`, `Check` and `Apply` read
   `unsupported_kind` and never return them, and `List` shows their metadata.
   `resource_actions` is closed by CRED-R1: the three
   actions are the capability's own, and a host registers them into its rights
   decision policy through rights action registration. The next name it would
   reserve is `abstraction.credentials/holder.delegate`. `SecureStore` names
   the standard backends this version defines. Provider extension names are
   retained, and refusal-page zero limits carry an empty store word.
   `consumers` is a seed; a consuming
   service extends it with its own wire contract name, and the host's enforcer
   designation is the registration.
5. **Identity fields.** `Metadata.registered_by` and holder audit subjects are
   asserted by the holder from native Program proof. `Use.subject` is asserted
   by the designated enforcer from its own receiving boundary. The absent
   subject on an audit entry means the event had no caller (`expired`,
   `retired`, `lost` detected during listing).
6. **Bounds.** A secret is at most `Limits.max_secret_bytes`, never above 4096
   bytes, and fits one control frame. Windows Credential Manager bounds it to
   2560 bytes. Names are 1..64 bytes, targets 1..16, consumers 1..8, list pages
   1..64 records and audit pages 1..256 entries.
7. **Unknown members.** `State` is display-grade and grants unknown members.
   Every outcome enum is acted on and refuses unknown members.
8. **Entry points.** CRED-H rules judge the holder service; CRED-A1 to A5
   judge the applier service; CRED-A6 judges each consuming service.
9. **Duplicate keys.** Refused.
10. **First definition.** Recorded as a "none" entry in
    `docs/BASE-PROTOCOL-CHANGES.md`; rules 1 to 6 were answered here before
    generation.
11. **Reserved words.** `Check` and `Apply` take `usage`, since `use` is a
    Rust keyword. No other name maps to a reserved word.

## Platform stores

| `secure_store` | Platform | Limitation |
|---|---|---|
| `windows-credential-manager` | Windows per-user runtime; generic credentials, local-machine persistence, target `openabstractions/<account>/<name>/<revision>` | Every process of the same logon session can read the item. A lost DPAPI user key reads `lost`. |
| `secret-service` | Linux with a session bus and an unlocked default collection | Without the bus or the `org.freedesktop.secrets` owner every store call reads `unavailable`. |
| `file-0600` | Linux, chosen explicitly by the operator | Directory 0700, files 0600, no encryption at rest; readable by the same uid and root. |
| `macos-keychain` | macOS; data protection keychain, generic passwords, this-device-only after first unlock | Process and path proof are unavailable on macOS, so every holder and applier call over IPC reads `forbidden` until identity proof lands. Registrations made by an in-process host remain in place. The data protection keychain serves only a program signed with a keychain access group entitlement; in any other program, an unsigned build included, every store call reads `unavailable`. |
| `none` | any runtime without a configured store, and every machine-scope runtime | `Store` and `Rotate` read `no_secure_store`. |
