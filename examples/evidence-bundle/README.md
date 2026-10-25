# examples/evidence-bundle: an offline verifier for dispute evidence bundles

**The worked example's limit, first.** In WE-1, the example this folder builds,
Headless Oracle is the operator (it ran the gate and holds the example operator
key), the payer (the example's own test payer, on a test network) and the
witness. The example shows the format and the checks, not independence between
those parties.

This folder holds `check-bundle.mjs`, an offline verifier for evidence bundles
of the format `evidence-bundle/0.10` (it reads `evidence-bundle/0.9` bundles
too, whose members are the same): one JSON document that carries a gated
action's signed log, its witness receipt, the keys needed to check them, and
the payment that followed, each piece as the bytes as captured with its
SHA-256. The verifier checks each piece, then how the pieces bind to each
other: the action to its log, the log to its checkpoint and witness, and the
decision to the payment, or, for a card payment, the order the gate recorded
to the charge the person running the verifier states; it writes one JSON
verdict object (`evidence-bundle-verdict/0.10`, schema in `schema/`).

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
- For a `card-payment` subject, the disputed charge, as the person running the
  verifier takes it from the dispute record they hold, never from the bundle:
  `--charge-id <text>`, `--charge-amount <minor units>`,
  `--charge-currency <code>`, `--charge-authorized-at <time>`, and optionally
  `--merchant-order-id <text>` and `--checkout-ref <text>` ("Card subjects",
  below).
- In place of a bundle path, the Agent Evidence Pointer an order carries:
  `--evidence-uri <https URL>` and `--evidence-entry sha256:<64 hex>`, and
  optionally `--evidence-sha256 sha256:<64 hex>` ("The Agent Evidence
  Pointer", below).

`build-we1.mjs` checks every source file against its committed sha256 before
it writes anything, and exits 2 naming a file that differs (a checkout that
rewrote line ends, for example); it refuses rather than repairs.
`--root <dir>` reads the sources under another directory in place of the
repository root; `test/builder.mjs` uses it to show both outcomes on a copy.

## Exit codes

- `0`: one verdict object on stdout, whatever the verdict (FAILS included).
- `2`: nothing on stdout and one line on stderr: a usage error (an
  `--authorizer` or `--tx` that is malformed or given twice, an unknown option,
  `--online` or `--rpc`, a missing or unreadable bundle, invalid pins; a charge
  option outside its form, given twice, without the other required ones, or for
  an `evm-payment` subject; a pointer URI that is not https or carries user
  information, an entry or digest outside its form, the URI or the entry
  alone, or a bundle path with the pointer), or a bundle outside the shape this
  build judges (`not supported in this build: <code>`).
- `1`: an internal error, with nothing on stdout. No test reaches exit 1:
  no input is known to cause one, here or in `build-we1.mjs`.

## What an offline run never says

This build is offline only: the pointer's one fetch of the bundle file is the
only network read it makes, and it reads nothing a bundle names. It trusts, as
the bundle's assembler supplied them, the bundle's copies of the payment's
chain data and of the witness receipts, so no verdict it gives contains the
word VERIFIES: with every other link in place the verdict is PAYMENT NOT
VERIFIED with the reason `offline-chain-data`, and the output still lists every
check and binding. Each online check that applies is listed as NOT-EVALUATED
with the reason `offline`. The chain binding is `SUPPLIED`, and the witness
binding is never `BOUND`. For a card subject with a stated charge, the witness
receipt is the bundle's copy, so no card verdict is `RECORDED-BEFORE-CHARGE`,
`RECORDED-WITH-GAPS` or `OUTSIDE-INSTRUCTION`: with every other link in place it
is PAYMENT NOT VERIFIED with the reason `offline-witness-data` (rule C3).

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
| `profile:<role>` | the profiles of table 3-1 for those roles: `signed-instruction-ed25519/0.2` and `signed-instruction-ed25519/0.3` (checked, M6; 0.3 only in an `evidence-bundle/0.10` bundle, and in a 0.9 bundle it FAILs M1), `vi-0.1-draft` and `ap2-0.2` (carried as PRESENT, not checked); `chirindo-evidence.action/1` and `jcs-sha256-chain/0.1` (Annex B); `eip712-gate-receipt/0.1`, read through an issuer profile of `chirindo-h4-issuer-profile/2` or `/1`; `witness-spec-0.5-checkpoint`; `witness.checkpoint/1`; `jcs-json`; `chirindo-witness-sidecar/1`; `jwks`, `jwk-okp-ed25519`; `ho-v5-keys`; `eth-rpc-json`; `eth-proof-json`; `eth-raw-transactions`; `opaque` |
| `legacy-shape` | a log of `evidence.action/0` records only as exactly one legacy-kid log, one `jwk-okp-ed25519` key, no sidecar, and an EVM payment claimed as `none` |
| `instruction:card-only` | for an `evm-payment` subject, no `signed-instruction-ed25519/0.3` instruction for card orders only (one without `chain_id`, `asset`, `max_amount` and `payees`): the specification gives such an instruction no outcome against a payment |
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

Judged in v0.10 (this build's part A3a): bundles of type `evidence-bundle/0.10`;
a disputed charge stated for a card subject (`S3.charge`); an order committed in
the cited action's arguments (`M8.order`, B-CARD); instructions of profile 0.3
(M6, B-INS for a card subject); and the Agent Evidence Pointer (`P1.pointer`,
`P2.entry`).

A card subject skips the last four rows. A row whose input does not exist (a
cited record beyond the log's end, for example) does not apply.

## Card subjects

**The limit, first (L24).** For a card payment, the payment proof is the card
network's authorization record, which the issuer holds; this bundle neither
carries nor verifies it. What this verdict shows is whether the decision and
the order the gate recorded were witnessed before the charge's authorization
time as stated, and whether that order matches the stated charge: the stated
charge and its time are the statements of the person running the verifier,
taken from the processor's records.

For a `card-payment` subject the person running the verifier states the
disputed charge (`S3.charge`): the processor's charge id (1 to 256 printable
ASCII characters, reported and compared with nothing), the amount in the
currency's minor units (a decimal string with no sign and no leading zero), the
currency (three upper-case letters, ISO 4217), the authorization time (the time
form of the specification's 4.1) and, optionally, the merchant's order id and
the `checkout_ref` the processor's record carries. The four required options
are given together or not at all. Without them `S3.charge` is NOT EVALUATED
(`charge-not-stated`), and a card subject reads as in v0.9: PAYMENT NOT
VERIFIED, `card-subject`.

The cited record must be a gated decision call, separate from the call that
charges the card, whose arguments commit to the order: `order`, with
`merchant_id`, `merchant_order_id` or `checkout_ref`, `currency`, `total_minor`
and `items` (each with `sku`, `quantity` and `unit_price_minor`, and optionally
`name`, `category`, `refundable`, `service_from`, `service_until` and
`location`). An `order` of any other shape FAILs `M8.order`. B-CARD then
compares the order with the stated charge: the amount with `total_minor` (as
integers), the currency, and each reference the order commits to that the
stated charge carries (DIFFERS when one differs); a stated charge that carries
neither reference is a stated gap (`reference-not-stated`), never FAIL. Its
time rule compares the selected witness receipt's `received_at` with the stated
authorization time, as instants, flagged `two-clock-comparison`: equal or later
is AFTER-AUTHORIZATION. The output's `card` member gives the order's summary
(with its items' sum beside its total), each field's match, the two times and
whether the receipt came before. L25: the committed order is the agent's
statement at decision time, as the gate recorded it; the bundle does not show
that the merchant fulfilled that order, that the charge was for it beyond the
fields compared, or that an item's attributes are true.

## Instructions of profile 0.3

`signed-instruction-ed25519/0.3` (Annex A.3) is profile 0.2, signed and
digested the same way, with `v` `signed-instruction-ed25519/0.3`, whose
`constraints` may also hold `card`: `currency` and at least one other member
that limits something, among `max_total_minor`, `max_unit_price_minor`,
`merchants`, `items`, `categories`, `refundable_only` (false limits nothing, so a
`card` of `currency` and `refundable_only` false FAILs M6), `service_window`
and `locations`. With `card`, `chain_id`, `asset`, `max_amount` and `payees` are
all four or none. For a card subject with a stated charge, B-INS compares the
cited instruction with the committed order: every limit of `card` is listed in
`instructions[].card_limits` as `inside`, `outside`, `not-declared` (the
instruction does not set it, and it is never shown as a pass) or
`not-evaluated` (the order lacks a field the limit needs:
`order-field-missing`). Strings are compared exactly, so a city written two ways
is two values. The instruction's `agent_kid`, `max_uses` and its window against
the stated authorization time (flagged `two-clock-comparison`) are judged too. A
0.2 instruction declares no card limit (`no-card-limits`), nor does a 0.3 one
without `card` (`card-limits-not-declared`): B-INS is BOUND for a card subject
only when the instruction carries `card` limits. L12 and L13 apply as for 0.2.

## The card verdicts

**The limit, first (L24),** as "Card subjects" states it: the card network's
authorization record is the payment proof, and this bundle neither carries nor
verifies it.

For a card subject with a stated charge, table 4-6c replaces table 4-6a. B-PAY
and B-CHAIN stay NOT EVALUATED (`card-subject`), B-CARD takes their place, and a
card verdict has a code of its own, never VERIFIES. In order:

| rule | when | code |
|---|---|---|
| C1 | any check or binding is FAIL | `FAILS` |
| C2 | B-CARD is DIFFERS | `DOES-NOT-MATCH-CHARGE` |
| C3 | B-CARD is NOT EVALUATED or AFTER-AUTHORIZATION (its reason); or B-WIT is not BOUND (`offline-witness-data`); or, with no breach shown, the cited decision is not read (`decision-not-read`) or B-INS is NOT EVALUATED `order-field-missing` | `PAYMENT-NOT-VERIFIED` |
| C4 | B-CARD is BOUND and a breach is shown: the cited decision refuses (`decision-not-allow`) or B-INS is EXCEEDS | `OUTSIDE-INSTRUCTION` |
| C5 | the decision allows, B-CARD, B-INS, B-LOG, B-CKP, B-WIT and B-KEY are BOUND with no reference left unstated, and B-GRC is BOUND or ABSENT with no reason | `RECORDED-BEFORE-CHARGE` |
| C6 | otherwise | `RECORDED-WITH-GAPS` |

Offline, B-WIT is SUPPLIED, so this build gives C1, C2 or C3 only.
`test/never-verifies.mjs` runs every card vector and checks that no verdict is a
VERIFIES code and that no output says the payment is proven or verified.

## The Agent Evidence Pointer

At checkout the merchant, or its agent platform, attaches to the order:
`agent_evidence_entry`, the cited record's entry hash, which exists at decision
time; `agent_evidence_uri`, an https URL of at most 2,048 characters from which
the bundle file can be fetched when a dispute comes; and, optionally,
`agent_evidence_sha256`, the bundle file's digest. The person running the
verifier copies them from the order record they hold and gives them as
`--evidence-uri`, `--evidence-entry` and `--evidence-sha256`, in place of a
bundle path. The entry is what binds: the URI's origin gives the bundle no
standing.

The fetch (`lib/pointer.mjs`, which takes the fetch function as a parameter:
the CLI passes Node's `fetch` with `redirect: "manual"`, the tests a fake): one
GET with no cookies, no credentials and no other header; at most 5 redirects,
each to https, followed by the verifier's own code so that each hop is checked;
a final status of 200, a body of at most 67,108,864 bytes, all within 60
seconds. The digest is over the body after fetch has removed any content coding.
`P1.pointer` PASSes once the bytes are fetched (`pointer.status` `fetched`), or
when they have the stated digest (`match`); another digest FAILs it
(`mismatch`, both digests in the output) and nothing else runs: FAILS. A fetch
that fails is NOT EVALUATED `pointer-unfetchable`, nothing else runs, and the
verdict is PAYMENT NOT VERIFIED with that reason (`bundle_sha256` null). Then
`P2.entry`: the entry hash of the record `subject.cites` names must equal the
stated entry, or FAILS (its `detail` names the cited entry and any carried
record that has the stated one).

## WE-4 and WE-5

**The limit, first.** In WE-4 and WE-5 the gate's operator and the witness are
the example's own, and the customer, the merchant and the charge are test
parties the example makes. The examples show the format and the checks, not
independence between those parties (L14, L3). The card data is test data only:
no card number, expiry, security code, network token or last four digits
appears in any bundle, stated input or output, because B-CARD reads none of
them; the charge id and every merchant and item value are labelled test values
(`TEST`, and domains under `.example`). In this folder they are offline
vectors (`vectors/rows-a3.mjs`), built from throwaway test keys derived from
public seed strings, a TEST witness key and TEST pins among them; nothing those
keys sign is evidence of anything.

WE-4 is a physical order under a signed instruction: a profile 0.3 instruction
whose `card` limits are `{"currency": "USD", "max_total_minor": "5000",
"merchants": ["test-merchant.example"], "refundable_only": true}`, and a gated
decision call whose arguments cite it and commit to the order TEST-1001 (one
TEST jacket, 4800 USD minor units), witnessed before the stated charge
TEST-ch-we4-1 of 4800 USD. Variant 1 (V-10): B-CARD BOUND, B-INS BOUND with those
four limits inside and the others not declared; offline PAYMENT NOT VERIFIED
(rule C3, `offline-witness-data`). Variant 2 (V-11, a final-sale item): B-INS
EXCEEDS [`refundable_only`]; offline PAYMENT NOT VERIFIED.

WE-5 is a hotel booking: the `card` limits `{"currency": "EUR",
"max_unit_price_minor": "15000", "service_window": {"from": "2026-11-10",
"until": "2026-11-12"}, "locations": ["Lisbon"], "categories": ["lodging"],
"refundable_only": true}`, and the order TEST-H-2001 (two nights at 14000 EUR
minor units). Variant 1 (V-12): every declared limit inside. Variant 2 (V-13, a
non-refundable rate): B-INS EXCEEDS [`refundable_only`]. The vectors also cover a
night above the cap, a stay outside the window, the city written `Lisboa`
(V-27a to V-27c, each `outside`) and an item without `refundable` (V-28,
`order-field-missing`). The dates of WE-5's stay are test values.

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
npm test             # reuse, jcs, cli, schema, we1, vectors, refusals, unlocks, builder, card, pointer, errata, never-verifies
npm run test:sweep   # the WE-1 sweep (a few minutes)
```

`vectors/evidence-bundle-0.10.json` lists each vector this folder builds from
the repository's own bytes and from throwaway test keys derived from public
seed strings (`vectors/synth.mjs`; the rows of the shapes judged since the
first build are in `vectors/rows-a2.mjs` and `vectors/rows-a2b.mjs`, and the
card rows of v0.10 in `vectors/rows-a3.mjs`; the pointer's cases, run through
the library entry with a fake fetch, are in `vectors/pointer-cases.mjs`): a recipe (a base bundle and a
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
