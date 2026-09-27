# History: abstraction-credentials

Linked from [CONTRACT.md](CONTRACT.md)'s "Reading this page."

## Superseded ids

None retired this release. `CRED-H1`..`CRED-H6` and `CRED-A1`..`CRED-A6`
keep their numbers, converted from `- **CRED-H1.**` bullet form to
`**[CRED-H1] Title.**` form (`research/vocabulary/RENAME-PLAN.md`
credentials step 1, `research/vocabulary/DECISION.md` S3/S4). `CRED-R1` is a
new id: the former "Rule answers" item 4 ("Catalogues") cited it in prose
and `credentials.thrift`'s `resource_actions` constant already carried
`closed_by = "CRED-R1"`, but no rule paragraph ever declared it. This
release gives it one.

## Design records

- `research/vocabulary/DECISION.md` D4, D18, D19, D26, D30, D35, D45, D59,
  D60, D79 — service (not wire contract), `Scope` kept in the OAuth sense,
  per-user and machine-wide, credential manager, deprecated, the platform's
  credential store, remove (not retire), gateway key, inference gateway,
  host (URL sense). Applied this release: D26 (credential manager in prose;
  `holder@1`, `holder.manage` and `holder.read` stay on the wire, table in
  "Reading this page"), D19 (machine-wide), D35 (the platform's credential
  store), D45 (removed in prose; the audit event word stays `retired`),
  D59/D60 (inference gateway, gateway key, inside `CRED-R1`).
- `research/vocabulary/DECISION.md` §3 (S1-S13) — the contract shape this
  page and its "Reading this page" section follow.

## Reviewed and applied

- `research/reviews/inference-facade-2026-09-23.md` finding 8 — the
  credential consumers seed and the README's worked setup excluded every
  inference modality but chat, so a credential scoped to the seed could
  never serve `/v1/embeddings` or the other modalities. The Consumers table
  now lists `abstraction.inference/embed@1`, `transcription@1`, `speech@1`,
  `image@1` and `live@1` alongside `chat@1`; README.md's worked `credentials
  add` example names all six. `INF-W5`'s own amendment, naming which
  consumer a gateway key admits for `/v1/embeddings` and `/v1/realtime`,
  belongs to `abstraction-inference` and is not this worker's to make.

## Reviewed and not changed here

- `research/reviews/inference-facade-2026-09-23.md` finding 2 — one
  credential's daily cap lives in two records (`INF-H3`, `REG-1`). The
  finding names `abstraction-inference` and `abstraction-facade` rules;
  nothing in `abstraction-credentials` duplicates the cap, so no change was
  made here.

## Generation record

`- **CRED-R1.**` did not exist as a declared rule before this release. The
former "Rule answers" section answered the ten rules of "Writing a
contract", and an eleventh, before generation. Its content is recorded here;
the ongoing behavioral content moved into the contract's own sections:

1. Outcomes — folded into the Outcomes table.
2. Retained records — revision, tombstone and audit-retention language moved
   into Bounds.
3. Failures — folded into the Outcomes section's own closing sentence.
4. Catalogues — became `CRED-R1`.
5. Identity fields — folded into Bounds.
6. Bounds — became the Bounds section.
7. Unknown members — folded into Bounds.
8. Entry points — folded into "Reading this page".
9. Duplicate keys — folded into Bounds, one sentence.
10. First definition — recorded here only: a "none" entry in
    `docs/BASE-PROTOCOL-CHANGES.md`; rules 1 to 6 were answered before
    generation.
11. Reserved words — recorded here only: `Check` and `Apply` take `usage` as
    a parameter name, since `use` is a Rust keyword; no other name in this
    definition maps to a reserved word.
