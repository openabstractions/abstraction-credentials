# abstraction-credentials

Register a secret once and let an authorized service apply it to one outgoing
request. Applications and models keep a credential name. They never receive the
stored bytes.

This supports downloads, model lookup and hosted inference without placing an
API key in an application configuration file, prompt, MCP argument or provider
request. The Holder owns registration, metadata, revisions, expiry, revocation
and audit. The Applier checks the calling account and program, consumer contract
and target host before producing request headers inside the consuming service.

## Register and use a credential

The CLI reads values from a terminal with echo disabled or from standard input.
It refuses a secret in command arguments.

```console
openabstractions credentials add openrouter \
  --target openrouter.ai \
  --for abstraction.inference/chat@1 \
  --for abstraction.router/router@1 \
  --use-by /absolute/path/to/application \
  --from-stdin
```

`--target` covers that host and its subdomains. `--for` names every service
contract allowed to apply the credential. `--use-by` creates the exact-program
apply rule for the application. Repeat each option when the scope contains more
than one value.

The application request now carries only `openrouter`. A hosted inference host
can reference the same name:

```console
openabstractions inference host add openrouter \
  --base https://openrouter.ai/api/v1 \
  --wire openai-compatible \
  --credential openrouter
```

Inspect metadata and attributed use without reading the value:

```console
openabstractions credentials list --json
openabstractions credentials audit --json
```

Rotate in place with `credentials rotate openrouter --from-stdin`. Revoke with
`credentials revoke openrouter`; revocation destroys the stored value, retains
a tombstone and stops later applications before provider I/O.

## Service contracts

| Contract | Used by |
| --- | --- |
| `abstraction.credentials/holder@1` | User or operator registration, listing, rotation, revocation and audit |
| `abstraction.credentials/applier@1` | A designated service applying one named credential to one target |

[CONTRACT.md](CONTRACT.md) defines validation, authorization, expiry, audit and
failure behavior. [credentials.thrift](credentials.thrift) is the schema. The
generated Go, C++, Python, Rust and JavaScript protocol packages live under
`go/`, `cpp/`, `py/`, `rs/` and `javascript/`.

## Go provider

`credentials.Holder` owns records, revisions, tombstones, expiry, loss and a
bounded audit journal. It stores metadata in an explicit state file and secret
bytes in exactly one configured backend.

Available backends are Windows Credential Manager, Linux Secret Service, an
explicit Linux file backend for controlled deployments, and macOS Keychain with
cgo. A holder with no backend returns `no_secure_store`. Machine-scope runtimes
also return `no_secure_store` because these stores are per-account.

`service.Listen` serves Holder and Applier over shared framed IPC. Every call is
authorized. Check and Apply additionally require an enforcer designation for
the calling service. `client.Holder` and `client.Applier` are typed Go clients.

## Current limits

- The provider is development source and has no published release.
- Protected IPC calls require trustworthy program identity. The current macOS
  transport lacks that proof and fails closed.
- The explicit Linux file backend protects a controlled state directory with
  file permissions. Operators choose it deliberately; it is not the production
  secure-store default.
- Credential application is scoped by exact program path. Interpreters such as
  Python share one executable identity across scripts unless a stronger host
  boundary supplies a narrower principal.

Go provider tests cover secure-store failure, exact rights, scope, rotation,
revocation, audit and secret-free results. The parent repository adds runtime,
download and real OpenCode controlled integration tests. Those fixtures use
loopback providers and make no paid-provider claim.

## Requirements and licence

The Go implementation requires Go 1.26 or newer. Platform backends carry their
own OS requirements. Apache-2.0; see [LICENSE](LICENSE).
