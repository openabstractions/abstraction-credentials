# abstraction-credentials

*For applications that name a stored key on a call. Operators store keys as
[Register and use a credential](#register-and-use-a-credential) shows.*

A person stores a credential once, through the command line or the Panel. An
application using the current Holder and Use interfaces holds the credential's
name; the service keeps the secret bytes.

The [permission journey](https://github.com/openabstractions/abstractions/blob/main/examples/rights-playground/README.md)
explains named Use, separate raw-value Read, one/all scope and finite full
control. The implemented requester-bound reader discloses bytes to its authorized
caller. The connected runtime advertises its current receiving support; the
journey records platform and human acceptance separately.

**What's new here:** Applications hold a credential's name. The service holds
the secret, applies it to each request inside the service, and only for the
targets the credential names.

A stored credential is applied only by the OA consumers registered today:
download's HTTP execution, the model resolver, and each inference modality
— chat, embed, transcription, speech, image and live (CONTRACT.md's
Consumers table). This layer does not apply a credential to an
application's own HTTP calls; the operating system's own credential store is
the place for that key.

## The rule

A person registers a secret with `openabstractions credentials add` or the
Panel's Credentials page. No other path stores one: the CLI refuses a secret
in a command argument and reads it from a terminal with echo off or from
standard input.

An application holds a name, for example `openrouter`. It names that
credential on the call it makes; it never reads the value back. A hosted
inference call names the credential on the request:

```go
package main

import (
	"context"
	"log"

	facade "github.com/openabstractions/abstraction-facade/go"
	inference "github.com/openabstractions/abstraction-inference/go/client"
)

func main() {
	ctx := context.Background()
	chat, err := facade.Discover().ResolveInference(ctx, facade.Requirements{})
	if err != nil {
		log.Fatal(err)
	}
	reply, err := chat.Complete(ctx, inference.Request{
		Model: "openrouter/anthropic/claude-sonnet-4.5",
		Messages: []inference.Message{
			{Role: inference.RoleUser, Parts: []inference.Part{{Kind: inference.PartKindText, Text: "hello"}}},
		},
		Credential: "openrouter",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(reply.Outcome)
}
```

`Request.Credential` names a registration the person already made and scoped
to `abstraction.inference/chat@1`. The runtime turns the name into a header
inside the service that calls the provider. The application process holds
`"openrouter"` and nothing more.

`credentials/manage` (the wire still carries `holder.manage` until this
module's own release, CONTRACT.md's "Reading this page") is an operator
right: registration, rotation, revocation. The runtime grants it, at
installation, to its own operator programs, the command line and the Panel,
and to nothing else. An application gets `credentials/manage` only through a
rule a person grants explicitly.

A credential an application names but that was never registered reads
`unknown`. A credential that exists but carries no rule for that
application, host or consumer reads `forbidden` on the credential manager's
calls (`Store`, `Rotate`, `Revoke`, `List`, `Audit`) and `not_permitted`,
`target_refused` or `consumer_refused` on `Apply` (see CONTRACT.md). Each
outcome is a word, never an explanation; the application logs the outcome
and tells the person to register or scope the credential.

**macOS.** Current source binds protected calls to Program proof over XPC.
The Unix-socket path still refuses calls requiring that proof. The published
0.2.0 package predates XPC support; its protected calls remain unqualified.

## Obtain

- **Go.** `go get github.com/openabstractions/abstraction-credentials/go`.
  The module has a `go/v0.1.0` tag; current source may contain later work.
  Standard library plus
  [abstraction-identity](https://github.com/openabstractions/abstraction-identity)
  (which brings `golang.org/x/sys`).
- **Other languages.** See generated protocol and shared transport/client packages
  in this repository and the facade. Native provider support is separate.

Applications resolve the credential manager and the applier through the
facade's `ResolveCredentials` and `ResolveCredentialsApplier`, the same way
every other capability resolves. An application holding no operator right
calls neither: it names a registered credential on the request of the
capability that consumes it, as `Request.Credential` does for inference
above, and never calls the credential manager or the applier on its own
account.

## Register and use a credential

Install the runtime first: https://openabstractions.org/adopt.html

The CLI reads values from a terminal with echo disabled or from standard input.
It refuses a secret in command arguments.

```console
openabstractions credentials add openrouter \
  --target openrouter.ai \
  --for abstraction.inference/chat@1 \
  --for abstraction.inference/embed@1 \
  --for abstraction.inference/transcription@1 \
  --for abstraction.inference/speech@1 \
  --for abstraction.inference/image@1 \
  --for abstraction.inference/live@1 \
  --for abstraction.router/router@1 \
  --use-by /absolute/path/to/application \
  --from-stdin
```

`--target` covers that host and its subdomains. `--for` names every service
contract allowed to apply the credential; a contract name ends in `@1` and is
not a rights action (`abstraction.router/route`) or resource
(`abstraction.router/routes`), which the rights layer spells without the
version. Naming only `chat@1` leaves the other inference modalities unable
to apply the credential (`/v1/embeddings` among them); the six inference
`--for` entries above cover chat, embed, transcription, speech, image and
live (CONTRACT.md's Consumers table). `--use-by` creates the exact-program
apply rule for the application. Repeat each option when the scope contains more
than one value.

The application request now carries only `openrouter`. A hosted model server
can reference the same name:

```console
openabstractions inference server add openrouter \
  --base https://openrouter.ai/api/v1 \
  --api openai-compatible \
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
| `abstraction.credentials/holder@1` (prose name credential manager) | User or operator registration, listing, rotation, revocation and audit |
| `abstraction.credentials/applier@1` | A designated service applying one named credential to one target |

[CONTRACT.md](CONTRACT.md) defines validation, authorization, expiry, audit and
failure behavior. [credentials.thrift](credentials.thrift) is the schema. The
generated Go, C++, Python, Rust and JavaScript protocol packages live under
`go/`, `cpp/`, `py/`, `rs/` and `javascript/`.

## Go provider

`credentials.Holder` owns records, revisions, tombstones, expiry, loss and a
bounded audit journal. It stores metadata in an explicit state file and secret
bytes in exactly one configured backend.

Available backends are the Windows DPAPI-sealed file store a fresh Windows
state binds to, Windows Credential Manager for state already bound to it, Linux
Secret Service, an explicit Linux file backend for controlled deployments, and
macOS Keychain with cgo. A credential manager with no backend returns `no_secure_store`.
Machine-wide runtimes also return `no_secure_store` because these stores are
per-account.

`service.Listen` serves Holder and Applier over shared framed IPC. Every call is
authorized. Check and Apply additionally require an enforcer designation for
the calling service. `client.Holder` and `client.Applier`
(`github.com/openabstractions/abstraction-credentials/go/client`) are typed
Go clients.

## Current limits

- Current provider source includes development work beyond the tagged Go
  module; check `go/v0.1.0` for its released behavior.
- Protected IPC calls require trustworthy program identity. Current macOS
  source supplies it over XPC; the Unix-socket path fails closed. Native XPC
  evidence does not qualify the published 0.2.0 package.
- The explicit Linux file backend protects a controlled state directory with
  file permissions. Operators choose it deliberately; it is not the production
  secure-store default.
- Credential application is scoped by exact program path. Interpreters such as
  Python share one executable identity across scripts unless a stronger host
  boundary supplies a narrower subject.

Go provider tests cover secure-store failure, exact rights, scope, rotation,
revocation, audit and secret-free results. The parent repository adds runtime,
download and real OpenCode controlled integration tests. Those fixtures use
loopback providers and make no paid-provider claim.

## Requirements and licence

The Go implementation requires Go 1.26 or newer. Platform backends carry their
own OS requirements. Apache-2.0; see [LICENSE](LICENSE).

<!-- BEGIN GENERATED PERMISSION DEFINITIONS -->

## Permission definitions

Generated from the existing compiled catalogue. [RIGHTS.json](RIGHTS.json) contains the complete action/profile records, disclosure, lifecycle, first-use behavior, selector support and finite bundles.

This reference records compiled receiving support; RIGHTS.json names the compilation context. A connected runtime advertises current availability and selector support. These definitions supply no grant.

| Action | Resource profile | Owning operations | First-use targets | Compiled receiver |
|---|---|---|---|---|
| `abstraction.credentials/apply` | `abstraction.credentials/named-use@1` | `abstraction.credentials/applier@1#Check`, `abstraction.credentials/applier@1#Apply` | Legacy `exact` | served in compiled context |
| `abstraction.credentials/apply` | `abstraction.credentials/named-use@2` | `abstraction.credentials/applier@2#Check`, `abstraction.credentials/applier@2#Apply` | One, All | served in compiled context |
| `abstraction.credentials/holder.manage` | `abstraction.rights/legacy-exact-string@1` | `abstraction.credentials/holder@1#Store`, `abstraction.credentials/holder@1#Rotate`, `abstraction.credentials/holder@1#Revoke` | `none` | served in compiled context |
| `abstraction.credentials/holder.read` | `abstraction.rights/legacy-exact-string@1` | `abstraction.credentials/holder@1#List`, `abstraction.credentials/holder@1#Audit` | `none` | served in compiled context |
| `abstraction.credentials/secret.create` | `abstraction.credentials/named-secret@1` | `abstraction.credentials/holder@2#Store` | One, All | served in compiled context |
| `abstraction.credentials/secret.metadata.read` | `abstraction.credentials/named-secret@1` | `abstraction.credentials/holder@2#Metadata` | One, All | served in compiled context |
| `abstraction.credentials/secret.read` | `abstraction.credentials/named-secret@1` | `abstraction.credentials/reader@1#Read` | One, All | served in compiled context |
| `abstraction.credentials/secret.revoke` | `abstraction.credentials/named-secret@1` | `abstraction.credentials/holder@2#Revoke` | One, All | served in compiled context |
| `abstraction.credentials/secret.rotate` | `abstraction.credentials/named-secret@1` | `abstraction.credentials/holder@2#Rotate` | One, All | served in compiled context |

The finite `abstraction.credentials/full-control@1` bundle contains these exact action/profile pairs:

- `abstraction.credentials/apply` on `abstraction.credentials/named-use@2`
- `abstraction.credentials/secret.create` on `abstraction.credentials/named-secret@1`
- `abstraction.credentials/secret.metadata.read` on `abstraction.credentials/named-secret@1`
- `abstraction.credentials/secret.read` on `abstraction.credentials/named-secret@1`
- `abstraction.credentials/secret.revoke` on `abstraction.credentials/named-secret@1`
- `abstraction.credentials/secret.rotate` on `abstraction.credentials/named-secret@1`

Use, raw value Read, Create a new slot, Rotate its value, Delete its value with retained revoked metadata, and named metadata Read. Raw Read lets this app export, copy or use the secret elsewhere. This frozen six-operation list includes no enumeration, policy administration, future operation, profile version or runtime-managed local key.

<!-- END GENERATED PERMISSION DEFINITIONS -->
