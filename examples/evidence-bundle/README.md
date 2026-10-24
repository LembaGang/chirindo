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
`--root <dir>` reads the sources under another directory in place of the
repository root; `test/builder.mjs` uses it to show both outcomes on a copy.

## Exit codes

- `0`: one verdict object on stdout, whatever the verdict (FAILS included).
- `2`: nothing on stdout and one line on stderr: a usage error (an
  `--authorizer` or `--tx` that is malformed or given twice, an unknown option,
  `--online` or `--rpc`, a missing or unreadable bundle, invalid pins), or a
  bundle outside the shape this build judges (`not supported in this build:
  <code>`).
- `1`: an internal error, with nothing on stdout. No test reaches exit 1:
  no input is known to cause one, here or in `build-we1.mjs`.

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
| `role:<role>` | members of the roles of table 3-1 only: `instruction`, `action-arguments`, `action-result`, `gate-log`, `gate-receipt`, `issuer-profile`, `witness-sidecar`, `checkpoint`, `witness-receipt`, `witness-key`, `operator-key`, `payment-transaction`, `payment-receipt`, `payment-block`, `payment-parent-block`, `account-proof`, `payment-block-transactions`, `supporting` |
| `profile:<role>` | the profiles of table 3-1 for those roles: `signed-instruction-ed25519/0.2` (checked, M6), `vi-0.1-draft` and `ap2-0.2` (carried as PRESENT, not checked); `chirindo-evidence.action/1` and `jcs-sha256-chain/0.1` (Annex B); `eip712-gate-receipt/0.1`, read through an issuer profile of `chirindo-h4-issuer-profile/2` or `/1`; `witness-spec-0.5-checkpoint`; `witness.checkpoint/1`; `jcs-json`; `chirindo-witness-sidecar/1`; `jwks`, `jwk-okp-ed25519`; `ho-v5-keys`; `eth-rpc-json`; `eth-proof-json`; `eth-raw-transactions`; `opaque` |
| `legacy-shape` | a log of `evidence.action/0` records only as exactly one legacy-kid log, one `jwk-okp-ed25519` key, no sidecar, and an EVM payment claimed as `none` |
| `chain` | an EVM payment on Base Sepolia (`eip155:84532`) |
| `type` | a transaction of type `0x0`, `0x1`, `0x2`, `0x3` or `0x4` (type `0x3` is UNSUPPORTED-PATH `unsupported-type`; the deposit type `0x7e` is refused) |
| `call` | a `transferWithAuthorization` the EIP-3009 path reads (the nine-argument v, r, s form, or the `bytes signature` form with a 65-byte signature) only to the token `0x036cbd53842c5426634e7929541ec2318f3dcf7e`; any other call is judged: one that rule 2 does not read is UNSUPPORTED-PATH `unsupported-call`, and any other follows the calldata path |

Judged since the first build, each with the checks it needs (`lib/unlocks.mjs`,
tied by `test/unlocks.mjs`): instructions (M6 and B-INS, which compares an
Annex A instruction's constraints with the payment from a derived payer),
action results (M8.result), Annex B logs (M2), gate receipts and issuer
profiles (M7, M9.issuer-profile, B-GRC, and the receipt's verdict in the cited
decision under the pins' `permit` and `refuse` values: the shipped pins pin no
issuer profile), checkpoints and witness receipts as members of their own,
supporting members, an operator key as one JWK outside the legacy shape,
records that name a `jwks_uri` (B-KEY offline: SUPPLIED or NOT-EVALUATED), two
logs of one session (M2.prefix), and a log a checkpoint or witness receipt
shows to be truncated (B-CKP or B-WIT TRUNCATED). On the payment side:
legacy (EIP-155), type `0x1` and EIP-7702 transactions, blob transactions as
UNSUPPORTED-PATH; the cited hash as raw bytes anywhere in the calldata, and
found only where it does not bind (B-PAY NOT-EVALUATED `unread-carrier`);
bytes after a call's arguments, signed by the sender alone (a facilitator's
suffix: CARRIED-BY-OTHER); the `bytes signature` form; the calls rule 2 does
not read; the calldata path from the stated account, with the outflow reading
of the receipt's logs that B-INS compares with the instruction (an outflow it
cannot judge gives `unread-outflow`); an authorization that does not recover
to its `from` (`contract-signer`) or that moves nothing (NO-PAYMENT); and the
payment block's parent, account proofs and raw transactions (M5.parent-block,
M5.account-proof, M5.block-transactions, which an offline run reads for the
code window of B-PAY rule 10e with the payment's own authorization tuples:
code or a tuple at the stated account gives `account-has-code`, an earlier
entry this version cannot read gives `prerequisite-failed:O7.account-code`, and
a carried list that does not match the block is flagged
`carried-transactions-mismatch` and not used).

A card subject skips the last three rows. A row whose input does not exist (a
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
npm test             # reuse, jcs, cli, schema, we1, vectors, refusals, unlocks, builder
npm run test:sweep   # the WE-1 sweep (a few minutes)
```

`vectors/evidence-bundle-0.9.json` lists each vector this folder builds from
the repository's own bytes and from throwaway test keys derived from public
seed strings (`vectors/synth.mjs`; the rows of the shapes judged since the
first build are in `vectors/rows-a2.mjs` and `vectors/rows-a2b.mjs`): a recipe (a base bundle and a
change, never bundle bytes), its arguments, and the verifier's output
projected to what every
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
