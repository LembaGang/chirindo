# examples/evidence-bundle: an offline verifier for dispute evidence bundles

**The worked example's limit, first.** In WE-1, the example this folder builds,
Headless Oracle is the operator (it ran the gate and holds the example operator
key), the payer (the example's own test payer, on a test network) and the
witness. The example shows the format and the checks, not independence between
those parties.

This folder holds `check-bundle.mjs`, an offline verifier for evidence bundles
of the format `evidence-bundle/0.9`: one JSON document that carries a gated
action's signed log, its witness receipt, the keys needed to check them, and
the payment that followed, each piece as the bytes as captured with its
SHA-256. The verifier checks each piece, then how the pieces bind to each
other: the action to its log, the log to its checkpoint and witness, and the
decision to the payment, and writes one JSON verdict object
(`evidence-bundle-verdict/0.9`, schema in `schema/`).

It also holds `build-we1.mjs`, which builds WE-1 from the committed files of
`examples/ordering-evidence/case-a`; the WE-1 sweep (`sweep.mjs`); and the
vectors this folder can build from the repository's own bytes (`vectors/`).
It is not part of the npm package.

## Setup

Both this folder and `examples/ordering-evidence-h4`, whose `lib/formats.mjs`
and `lib/evm.mjs` it imports unchanged, need their dependencies:

```
cd examples/ordering-evidence-h4 && npm ci
cd ../evidence-bundle && npm ci
```

Node 20 or later. The dependencies are pinned: viem 2.56.9 and canonicalize
2.1.0.

## Commands

```
node build-we1.mjs --out we1.json
node check-bundle.mjs we1.json --authorizer 0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673 --tx 0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3
```

- `--authorizer <address>`: the account the payment must come from, as the
  person running the verifier knows it from the dispute, never from the bundle.
  All lowercase or exactly its EIP-55 checksum form.
- `--tx <hash>`: the disputed transaction, `0x` and 64 hex digits, any case.
- `--pins <dir>`: read `<dir>/pins.json` in place of `pins/pins.json` (the
  witness key history, the operator key ids, the issuer profiles, the token
  pins). A bundle never supplies pins.

`build-we1.mjs` checks every source file against its committed sha256 before
it writes anything, and exits 2 naming a file that differs (a checkout that
rewrote line ends, for example); it refuses rather than repairs.

## Exit codes

- `0`: one verdict object on stdout, whatever the verdict (FAILS included).
- `2`: nothing on stdout and one line on stderr: a usage error (an
  `--authorizer` or `--tx` that is malformed or given twice, an unknown option,
  `--online` or `--rpc`, a missing or unreadable bundle, invalid pins), or a
  bundle outside the shape this build judges (`not supported in this build:
  <code>`).
- `1`: an internal error, with nothing on stdout.

## What an offline run never says

This build is offline only. It trusts, as the bundle's assembler supplied them,
the bundle's copies of the payment's chain data and of the witness receipts, so
no verdict it gives contains the word VERIFIES: with every other link in place
the verdict is PAYMENT NOT VERIFIED with the reason `offline-chain-data`, and
the output still lists every check and binding. Each online check that applies
is listed as NOT-EVALUATED with the reason `offline`. The chain binding is
`SUPPLIED`, and the witness binding is never `BOUND`.

## The shape this build judges

This build gives a verdict other than FAILS only for bundles of the shape its
tests cover. It evaluates in this order: the stated inputs and the bundle and
manifest checks (any FAIL gives FAILS, whatever the bundle's shape); then the
declared roles and profiles; then the per-member checks of the logs,
checkpoints, witness receipts, payment, arguments and keys (any FAIL gives
FAILS); then the decoded shape; then the bindings and the verdict. At either
shape step, a bundle outside the shape below exits 2 with
`not supported in this build: <code>`, naming the first property, in this
order, that is outside it. A refusal is not a verdict and writes none.

| code | the bundle must have |
|---|---|
| `role:<role>` | members of the roles `gate-log`, `action-arguments`, `witness-sidecar`, `operator-key`, `witness-key`, `payment-transaction`, `payment-receipt`, `payment-block` only |
| `profile:<role>` | the profiles `chirindo-evidence.action/1`, `jcs-json`, `chirindo-witness-sidecar/1`, `jwks` (or `jwk-okp-ed25519` in the legacy shape), `ho-v5-keys`, `eth-rpc-json` |
| `legacy-shape` | a log of `evidence.action/0` records (or a `jwk-okp-ed25519` key) only as exactly one legacy-kid log, one such key, no sidecar, and an EVM payment claimed as `none` |
| `jwks-uri` | no record that names a `jwks_uri` |
| `log-prefix` | no two logs with one kid and session id |
| `truncated` | no checkpoint or witness receipt whose count is above its log's record count |
| `chain` | an EVM payment on Base Sepolia (`eip155:84532`) |
| `type` | a transaction of type `0x2` |
| `call` | a top-level nine-argument `transferWithAuthorization` (the v, r, s form) to the token `0x036cbd53842c5426634e7929541ec2318f3dcf7e` |
| `trailer` | nothing after the call's ABI-encoded arguments |
| `contract-signer` | an authorization signature that recovers to its `from` |
| `unread-carrier` | the cited entry hash found only as the authorization's nonce, or not at all |
| `no-payment` | an authorization of a value above 0 to an account other than its `from` |

A card subject skips the last seven rows. A row whose input does not exist (a
cited record beyond the log's end, for example) does not apply.

## WE-1's members, and where `fetched_at` comes from

| member | file | `fetched_at` |
|---|---|---|
| `log-a` | `examples/ordering-evidence/case-a/ordering-evidence-case-a-1.jsonl` | `2026-10-09T14:50:23Z`, the commit time of `ba15707`, which added it (no fetch record) |
| `args-a` | rebuilt from `examples/ordering-evidence/client.mjs:105` as its RFC 8785 bytes | the same commit time |
| `sidecar-a` | `case-a/ordering-evidence-case-a-1.jsonl.witness.ndjson` | the same commit time |
| `opkey-a` | `examples/ordering-evidence/keys/operator-jwks.json` | the same commit time |
| `wkey` | `examples/ordering-evidence/keys/v5-keys.response.json` | `2026-10-09T13:03:22Z`, from `keys/witness-key.pin.json` |
| `tx-a`, `rc-a`, `blk-a` | `case-a/rpc/{transaction,receipt,block}.sealed.json` | `2026-10-09T14:45:09.847Z`, `14:45:10.269Z`, `14:45:10.614Z`, from `case-a/rpc/fetched.sealed.json` |

`created_at` is fixed, so every build gives the same bytes. No check reads
`created_at`, `assembled_by`, `source`, `fetched_at`, `capture` or
`media_type`; they are reported.

## Tests, vectors and the sweep

```
npm test             # reuse, jcs, cli, schema, we1, vectors, refusals
npm run test:sweep   # the WE-1 sweep (a few minutes)
```

`vectors/evidence-bundle-0.9.json` lists each vector this folder builds from
the repository's own bytes: a recipe (a base bundle and a change, never bundle
bytes), its arguments, and the verifier's output projected to what every
implementation must reproduce. It is a snapshot of this verifier's own output,
written by `node vectors/make-vectors.mjs --write`; the tests rebuild it and
compare. The independent checks are the tests' assertions of the values the
specification states.

The sweep (`node sweep.mjs`) changes every byte of every WE-1 member (with the
member's digest recomputed, and again with it left as it was) and every byte
of the bundle document outside the members' base64, one change at a time, and
runs the verifier on each. A change after which the verdict is not FAILS is
classed `same-values` (the member reads as the same values: whitespace, an
address in its other valid spelling) or `listed` (it changes only a value the
format leaves uncovered, such as a receipt's gas fields or a block's other
transaction hashes); any other is `UNEXPECTED`, and the sweep passes only with
none. `we1/sweep-positions.json` holds every change that did not give FAILS,
with its member, byte offset, original and new byte, and class.
