# Chirindo Delivery-Proof Receipt — Specification v1

**Status:** IMPLEMENTED (2026-08-02). Written spec-before-code; the first
implementation now exists and satisfies it. This document remains the contract a
second, independent implementation MUST be able to verify against without asking
a follow-up question.

Implementation map (Chirindo, `evidence.action/1`):
- field — `src/vendor/recorder/record.ts` (`RecordContent.x402_payment_ref?`)
- hash — `src/vendor/recorder/hash.ts` (`paymentRef`)
- subset + registry gate — `src/vendor/recorder/payment-ref.ts`,
  `src/vendor/recorder/x402-registry.ts`
- emission — `src/vendor/recorder/chain.ts` (`Chain.append` opts), `src/receipt.ts`
- verdict + exit gate — `src/vendor/recorder/cli/verify.ts`, `src/cli.ts`
- tests — `test/payment-ref.test.ts`, `test/delivery-proof-verify.test.ts`,
  `test/byte-invariance-payment-ref.test.ts`, `test/cli-delivery-e2e.test.ts`

**Applies to:** `evidence.action/1` receipts (`RECORD_VERSION_V1`). Additive; does
not introduce a new record version. See §7 for why no version bump is required.

**Motive.** x402's `PAYMENT-RESPONSE` proves *settlement* — that a payment was
made — and nothing about *delivery*. This is the gap named across the x402
fulfillment-obligation discussion — [x402-foundation/x402
#2332](https://github.com/x402-foundation/x402/issues/2332) ("Post-settlement
accountability layer: tamper-evident proof of agent action after payment"), with
related context in [#2291](https://github.com/x402-foundation/x402/issues/2291)
(x402-signals / fulfillment obligations) and
[#2357](https://github.com/x402-foundation/x402/issues/2357)
(independently-verifiable receipts in `PAYMENT-RESPONSE`): a paid action
can settle and still deliver nothing, or deliver garbage, with no artifact tying
the money to the goods. A delivery-proof receipt is a signed, recomputable
commitment that binds a non-sensitive reference to the settled payment to the
hash of the output that was delivered for it. It is operator-side evidence
(§6 states the limits plainly).

---

## 1. Scope and non-goals

**In scope.** One new OPTIONAL top-level signed field on `evidence.action/1`
receipts — `x402_payment_ref` — plus verifier semantics that read it together
with the *already-existing* `event.result_hash` to emit a machine-checkable
delivery verdict.

**Explicit non-goals.**
- No `delivered_output_hash` field. The delivered output is already committed by
  `event.result_hash` (§4). A second top-level hash of the same object would be a
  second source of truth for one fact — rejected by design.
- No new record version. `evidence.action/1` is unchanged; the field is additive
  and absent-by-default (§7).
- No wallet internals, no raw payment blobs, no PII in the signed bytes (§3).
- No receiver-side / consumer counter-signature. That is the open item in §6, not
  a property this spec ships.

---

## 2. The field: `x402_payment_ref`

`x402_payment_ref` is an OPTIONAL top-level member of `RecordContent` (the signed
preimage assembled in `src/vendor/recorder/chain.ts` `Chain.append()`), sitting
alongside `key_thumbprint`, `iss`, `jwks_uri`, etc. It is inside the signed bytes,
so it cannot be rewritten after signing — the operator commits to it.

```
x402_payment_ref?: string   // "sha256:" + lowercase-hex( sha256( JCS(payment_ref_subset) ) )
```

- Format: the same `"sha256:" + hex` convention as `args_hash`, `result_hash`, and
  `entry_hash`. It reuses the ONE canonicalization path (`jcsBytes`,
  `src/vendor/recorder/canonicalize.ts`, RFC 8785 JCS via the vendored
  `canonicalize` package — decision D1) and the ONE hash primitive
  (`sha256Hex`, `src/vendor/recorder/hash.ts`). No second implementation of either.
- It is a **hash of a subset**, never the subset itself and never the raw
  `PAYMENT-RESPONSE`. The receipt carries the commitment; the preimage
  (`payment_ref_subset`) is reproduced out-of-band by whoever wants to check it.
- Absent by default. A receipt that makes no payment claim omits the key entirely
  (§7 proves this is byte-invisible).

### 2.1 Hash helper (BUILT)

A single helper sits next to `argsHash` / `resultHash` in `hash.ts`:

```
paymentRef(subset: unknown): string   // "sha256:" + sha256Hex(jcsBytes(subset))
```

and a JSON-string convenience mirroring `resultHashFromJsonString`, in
`payment-ref.ts`:

```
paymentRefFromJsonStrings(json: X402ArtifactJson, selector): string
```

**Signature change from the draft (resolved by capture).** The draft named a
single-argument `paymentRefFromJsonString(paymentResponseJson)`, written under
the assumption that the subset is drawn from one artifact. The 2026-08-02
capture refuted that assumption (§3.4.2b): the six values span the
`PaymentRequirements` and the `SettleResponse`. The JSON-string form therefore
takes the artifacts it needs — `{ requirements?, payload?, settle? }` — plus the
selector that names the registry row and the paid `accepts[]` index. The subset
math, the hash, and the field are unchanged; only the ingest surface widened to
match the wire.

The JSON-string form MUST route EVERY artifact's raw text through
`strictJsonParse` (`src/vendor/recorder/strict-json.ts`, decision D7) **before**
extracting the subset and hashing. Skipping the strict gate reintroduces the
F3/F4 recomputability hole (unsafe integers silently truncated by `Number`;
duplicate members resolved last-wins before JCS ever sees them) — a payment
artifact is exactly the kind of integer-bearing document where `unsafe_number`
bites. Fail-closed: a `StrictJsonParseError` propagates and MUST NOT be hashed,
identical to the contract on `argsHashFromJsonString` /
`resultHashFromJsonString`.

**Stricter than the args/result path — deliberate.** `argsHashFromJsonString`
keeps a raw-UTF-8 fallback for the pre-existing "not valid JSON at all" case, so
an observe-only recorder still records a stable hash of whatever bytes it saw.
The payment-ref path has NO fallback of any kind: a subset cannot be extracted
from unparseable bytes, and hashing the raw text would produce a commitment no
independent verifier could ever reproduce *as a subset*. A `SyntaxError`
propagates alongside `StrictJsonParseError`.

---

## 3. `payment_ref_subset` — exact, recomputable field set

`payment_ref_subset` is a JSON object built by selecting EXACTLY the six keys
below from the x402 exchange, and no others. Determinism and independent
recomputability require the selection to be fully specified — an independent
verifier given the same exchange artifacts MUST derive byte-identical JCS and
thus an identical `x402_payment_ref`.

**Where the values come from (RESOLVED 2026-08-02).** The draft loosely said "the
x402 `PAYMENT-RESPONSE`". The live capture confirmed the §3.4.2 structural
caveat: the six values span more than one artifact. WHICH artifact and WHICH
field supplies each key is fixed per scheme by the §3.4 registry — that mapping,
not this section, is the contract.

### 3.1 Selection rules

1. Include a key **only if** its source value is present and non-null in the
   `PAYMENT-RESPONSE`. An absent source field is an absent subset key — never a
   `null` placeholder (a `null` would change the JCS bytes; absence does not).
2. Values are copied verbatim as the types below. No coercion, no normalization
   beyond what rule 4 mandates.
3. No key outside this list is ever included. Unknown/extra `PAYMENT-RESPONSE`
   fields are dropped — this is what keeps wallet internals and PII out of the
   signed bytes.
4. `amount` is carried as a **decimal string in the asset's base units** (the
   integer atomic unit, e.g. wei / smallest token unit), never as a JS number.
   Rationale: base-unit amounts routinely exceed `2^53-1`; representing them as a
   JSON number would be caught and rejected by `strictJsonParse` (`unsafe_number`)
   and would be lossy besides. A string is exact and JCS-stable.

### 3.2 The subset schema

| subset key    | type            | meaning (source field is fixed per §3.4 row) | required | notes |
|---------------|-----------------|------------------------------|----------|-------|
| `scheme`      | string          | payment scheme id (e.g. `"exact"`) | yes | identifies the x402 scheme |
| `network`     | string          | settlement network id (observed: CAIP-2, e.g. `"eip155:84532"`) | yes | chain / network identity |
| `asset`       | string          | asset/token identifier (contract address or canonical asset id) | yes | what was paid in |
| `amount`      | string          | amount, **base units, decimal string** | yes | see rule 4; never a number |
| `resource`    | string          | the resource/endpoint the payment was for | yes | binds payment to the thing bought |
| `settlement`  | string          | on-chain tx hash or settlement id, when the exchange carries one | no | present ⇒ included; absent ⇒ omitted |

- **Required** keys: if any required key is missing from the `PAYMENT-RESPONSE`, an
  implementation MUST NOT fabricate a subset. It either declines to emit
  `x402_payment_ref` (the receipt then makes no payment claim) or fails closed at
  the adapter boundary. It MUST NOT emit a subset with a required key absent, since
  that would silently produce a different, weaker commitment.
- **`settlement`** is the one optional member: some schemes/networks surface a tx
  hash, some surface an opaque settlement id, some (pre-confirmation) surface
  neither. Present-and-non-null ⇒ include; otherwise omit (rule 1).

### 3.3 Worked example (illustrative — not a frozen vector)

Field names and structure below are the ones OBSERVED in the 2026-08-02 capture
(§3.4.2b); values are placeholders.

Artifact A — `PaymentRequirements`, decoded from the `PAYMENT-REQUIRED`
**response header** (the 402 body was `{}`):

```json
{
  "x402Version": 2,
  "error": "Payment required",
  "resource": {
    "url": "https://api.example.com/v1/summarize",
    "description": "…",
    "mimeType": "application/json"
  },
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:84532",
      "amount": "1000",
      "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      "payTo": "0xRECIPIENT…",        // dropped — not in subset
      "maxTimeoutSeconds": 300,        // dropped — not in subset
      "extra": { "name": "USDC", "version": "2" }
    }
  ]
}
```

Artifact C — `SettleResponse`, decoded from the `PAYMENT-RESPONSE` header:

```json
{
  "success": true,
  "payer": "0xWALLET…",              // dropped — wallet internal
  "transaction": "0xabc123…",
  "network": "eip155:84532"
}
```

`payment_ref_subset` (only the six specified keys; five from A, `settlement`
from C `transaction`):

```json
{
  "amount": "1000",
  "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "network": "eip155:84532",
  "resource": "https://api.example.com/v1/summarize",
  "scheme": "exact",
  "settlement": "0xabc123…"
}
```

`x402_payment_ref = "sha256:" + hex(sha256(JCS(subset)))`. JCS re-sorts the
members by UTF-16 code unit of the key regardless of authoring order, so any
conforming implementation that selects the same six values derives the same bytes.
(The mapping from raw x402 field names to subset keys is NORMATIVE and pinned
per scheme+version in §3.4. The example above is illustrative; §3.4 is the
contract.)

---

## 3.4 Normative x402 scheme-mapping registry (versioned)

The §3.2 subset defines *which six keys* exist. This registry defines, **per x402
scheme + version + facilitator**, *exactly which source field* supplies each key.
It is **normative, not advisory**: two implementations can agree byte-for-byte on
JCS and still produce **non-comparable commitments** if they read different source
fields into the same subset key. The mapping is therefore part of the wire
contract, and a commitment is only meaningful relative to the registry row it was
built under.

### 3.4.1 Registry rules (NORMATIVE)

1. **Fail closed on unknown schemes.** An implementation MUST NOT emit
   `x402_payment_ref` for a `(scheme, network, facilitator)` tuple it has no
   registered mapping row for. It does not guess field names. No row ⇒ no
   commitment (the receipt then makes no delivery claim, per §5 outcome 3).
2. **Versioned independently and additively.** This registry carries its own
   version, incremented separately from the record/spec version. New scheme rows
   are ADDED; an existing row's field mapping is NEVER mutated. Changing what a
   row maps would silently invalidate every commitment previously built under it —
   forbidden. A correction to a shipped row is a NEW row at a new registry version,
   with the old row retained (and marked superseded) so past commitments stay
   recomputable.
3. **Row status gates production use.** Each row carries a status:
   - `VERIFIED` — the field mapping has been confirmed against **real, observed**
     x402 output for that scheme/network. Only a `VERIFIED` row may produce a
     production `x402_payment_ref`.
   - `PROVISIONAL` — the mapping is registered for review but derived from
     documentation / protocol knowledge and **not yet confirmed against live
     output**. A conformant implementation MUST treat a `PROVISIONAL` row as
     *not-yet-registered* for the purpose of rule 1 (fail closed — do not emit in
     production). It exists so the mapping can be reviewed and promoted, not so it
     can be shipped on trust.
   - `UNSPECIFIED` — we have not defined a mapping for this scheme at all. Same
     effect as no row: fail closed.
4. **Provenance is recorded per field.** Every mapped field name states whether it
   came from **observed** real output or from **documentation**. A field name MUST
   NOT be invented; if unknown, its cell is `UNSPECIFIED` and the row cannot be
   `VERIFIED`.

### 3.4.1a Registry version history

| registry version | change |
|---|---|
| v0 | DRAFT. One row — (`exact`, `base-sepolia`, CDP) — `PROVISIONAL`; every field name documentation-derived. Zero VERIFIED rows, so no conformant implementation could emit at all. |
| v1 | **Adds (`exact`, `eip155:84532`, Coinbase CDP) as `VERIFIED`** against the 2026-08-02 live capture. Additive: the v0 row is RETAINED below, unmutated, marked superseded (rule 2). Exactly one VERIFIED row exists. |
| v2 | Adds the `amount` **cross-check** source (B `payload.authorization.value`) to the v1 row, per the §8.1.1a amendment. **No mapped field changes**, so every commitment built under v1 recomputes identically under v2 — a cross-check can only cause a refusal, never supply a value. Not a rule-2 mutation; the version bump signals the behavioural change (a v1 reader emits on an A/B amount disagreement, a v2 reader refuses). Still exactly one VERIFIED row. |
| **v3** | **Adds a SECOND VERIFIED row — (`exact`, `eip155:84532`, `x402org`)** (§3.4.2c), against the 2026-08-02 live x402.org-facilitator capture. Purely additive: a new tuple, no existing row read or written, so every commitment built under v1/v2 recomputes identically under v3. Two VERIFIED rows now exist, differing only in the facilitator dimension. |

The machine-readable form of this registry is
`src/vendor/recorder/x402-registry.ts` (`X402_REGISTRY_VERSION`,
`X402_REGISTRY`). The two MUST agree; the code is what fails closed at runtime,
this document is what a second implementation reads.

### 3.4.2 Registry v0 row — RETAINED, SUPERSEDED (historical)

Superseded by the v1 row in §3.4.2b. Kept unmutated per rule 2 so the promotion
history stays legible and any commitment ever built under it would remain
recomputable (none was: it never reached `VERIFIED`, so it never authorized
emission — and still does not).

Two of its hypotheses were **refuted** by the capture, which is precisely why
the correction is a NEW row rather than an edit:
- network id `base-sepolia` → observed CAIP-2 `eip155:84532`;
- amount key `maxAmountRequired` → observed `amount`.

**Target scheme:** x402 `"exact"` scheme, network `base` / `base-sepolia`,
facilitator **Coinbase CDP**. This is the scheme Chirindo targets.

**Honest status: this entire row is `PROVISIONAL`.** As of this spec draft we have
**not** captured a real end-to-end `base-sepolia` payment exchange. Every field
name below is **documentation / protocol-knowledge derived, NOT observed** — and
model-recalled documentation at that, which is exactly the kind of thing that is
wrong often enough to demand verification. Per rule 3, a conformant implementation
**MUST NOT** emit `x402_payment_ref` under this row until it is promoted to
`VERIFIED` against live output.

> **Structural caveat that MUST be resolved during verification.** §3 loosely says
> the subset is drawn from "the x402 `PAYMENT-RESPONSE`." In reality the six values
> almost certainly span **three** artifacts of the x402 exchange, not one:
> - the `X-PAYMENT-RESPONSE` header (the facilitator's *settle* response) —
>   plausibly carries `settlement`/tx + `network`;
> - the `PaymentRequirements` (the `accepts` entry from the 402 response) —
>   plausibly carries `scheme`, `network`, `asset`, `resource`, and the required
>   amount;
> - the `PaymentPayload` (the `X-PAYMENT` request header) — plausibly carries the
>   signed authorization `value` (the actually-authorized amount).
>
> Which artifact is authoritative for each subset key is **exactly what
> verification against real output must pin.** Until then, treat the "source
> artifact" column as a hypothesis, not a fact.

| subset key   | hypothesized source field | source artifact (hypothesis) | provenance | status |
|--------------|---------------------------|------------------------------|------------|--------|
| `scheme`     | `scheme` (value `"exact"`) | `PaymentRequirements` / `PaymentPayload` | documentation — NOT observed | PROVISIONAL |
| `network`    | `network` (value `"base-sepolia"`) | settle response / `PaymentRequirements` | documentation — NOT observed | PROVISIONAL |
| `asset`      | `asset` (token contract address) | `PaymentRequirements` | documentation — NOT observed | PROVISIONAL |
| `amount`     | `maxAmountRequired` **or** `payload.authorization.value` (unresolved — see caveat) | `PaymentRequirements` **or** `PaymentPayload` | documentation — NOT observed | PROVISIONAL |
| `resource`   | `resource` | `PaymentRequirements` | documentation — NOT observed | PROVISIONAL |
| `settlement` | `transaction` (tx hash) | `X-PAYMENT-RESPONSE` settle response | documentation — NOT observed | PROVISIONAL |

Notes on the two openly-unresolved cells:
- **`amount`.** For the `"exact"` scheme the authorized `value` and
  `maxAmountRequired` are expected to be equal, but the spec must commit to ONE
  authoritative source so two implementations don't diverge when they are not.
  Which one is authoritative is deferred to verification. Whichever is chosen, it
  is carried per §3.1 rule 4 as a **base-unit decimal string**.
- **`settlement`.** The x402 settle response field carrying the on-chain
  transaction identifier is hypothesized to be `transaction`; this is the single
  most important cell to confirm, since it is the direct link to the settled
  payment.

### 3.4.2b Registry v1 row — **VERIFIED** (`exact` / `eip155:84532` / Coinbase CDP)

**Status: `VERIFIED`.** This was the only VERIFIED row at registry v1/v2; as of
v3 it is one of two (see §3.4.2c, which adds the same scheme+network under a
different facilitator). Nothing in this row changed — the sentence is corrected
because it was a claim about the registry as a whole, not about this mapping.

**Provenance.** *Captured against live base-sepolia / Coinbase CDP facilitator on
2026-08-02; every field name read from raw artifact files
(`x402-capture-rig/capture/`), not documentation.* The raw artifacts live
outside this repository (they contain wallet addresses, an EIP-3009 signature,
and a transaction hash) and are referenced by path only.

Facilitator identity: the Coinbase CDP x402 facilitator at
`api.cdp.coinbase.com/platform/v2/x402` (observed in the capture rig's run
metadata); registry key `coinbase-cdp`.

| subset key   | observed source field | source artifact | provenance | status |
|--------------|-----------------------|-----------------|------------|--------|
| `scheme`     | `accepts[i].scheme` (value `"exact"`) | A — `PaymentRequirements` | **observed** (echoed in B at `accepted.scheme`) | VERIFIED |
| `network`    | `accepts[i].network` (value `"eip155:84532"`, CAIP-2) | A — `PaymentRequirements` | **observed** (agrees with C `.network`) | VERIFIED |
| `asset`      | `accepts[i].asset` (USDC contract; `extra:{name:"USDC",version:"2"}`) | A — `PaymentRequirements` | **observed** (C carries NO asset field — not comparable; the on-chain token matched A) | VERIFIED |
| `amount`     | `accepts[i].amount` — a JSON **string**, base units | A — `PaymentRequirements` | **observed** (agrees with B `payload.authorization.value`, also a string) | VERIFIED |
| `resource`   | `resource.url` | A — `PaymentRequirements`, **top level** | **observed** (A's `resource` is an object `{url, description, mimeType}` beside `accepts[]`, not inside the accepts entry; the subset takes the `url`) | VERIFIED |
| `settlement` | `transaction` (0x + 64 hex; resolved on-chain) | C — `SettleResponse` | **observed** | VERIFIED (optional member) |

`accepts[i]` is the `accepts[]` entry the payer actually paid against. A 402 may
offer several and only the payer knows which one it signed, so the index is an
explicit input to the extractor — it is never defaulted to 0. (In the captured
exchange there was exactly one offer.)

**Resolutions this row records (the two draft `UNRESOLVED` cells, plus one).**
- **`amount` source — RESOLVED to A `accepts[i].amount`.** Both candidates were
  captured and agree: A carried `"1000"` and B's signed
  `payload.authorization.value` carried `"1000"`, both JSON strings. The
  hypothesized key `maxAmountRequired` does not appear on the wire at all. A is
  authoritative because it is the requirement the payment was constructed
  against and it exists before settlement; B is recorded as a corroborating
  cross-check, not as a second source — and per §8.1.1a (registry v2), a B that
  is present and DISAGREES with A blocks emission entirely
  (`amount_disagreement`). Interaction with the D7 strict-parse gate is clean:
  a base-unit decimal string is never an `unsafe_number` (§3.1 rule 4).
- **`settlement` field name — RESOLVED to C `transaction`.** The hypothesis held.
  The value was 0x + 64 hex and resolved on the base-sepolia explorer
  (Status Success), confirming it is the on-chain identifier and not an internal
  id.
- **Structural caveat — RESOLVED.** The six values span TWO artifacts, not one:
  five from A, `settlement` from C. B supplied no subset value (only
  corroboration).

**Deliberately NOT strengthened from a single observation.** `settlement` was
present on the one successful settle observed. Whether it is ALWAYS present on
success is **UNESTABLISHED** from one sample, so `settlement` remains the
optional member per §3.2. One observation does not license a stronger rule.

### 3.4.2c Registry v3 row — **VERIFIED** (`exact` / `eip155:84532` / `x402org`)

**Status: `VERIFIED`.** The same scheme and network as §3.4.2b, settled through
the **x402.org facilitator** (`https://x402.org/facilitator`) instead of
Coinbase CDP. Registry key `x402org` — the id the reference demo's
`FACILITATOR=x402org` resolves to. A NEW tuple, so this is a pure rule-2
addition: §3.4.2b and §3.4.2 are untouched and every commitment built under
v1/v2 recomputes identically under v3.

**Provenance.** *Captured against live base-sepolia / x402.org facilitator
(`https://x402.org/facilitator`) on 2026-08-02 with zero credentials; same
wallet pair as the CDP capture; settled tx block 44965211; artifact shape
byte-equivalent to the CDP row's A/B, C same four-key shape, no asset field;
field names from raw artifacts (`x402-capture-rig/capture/`, `.dup3` +
`exchange-4` series).* The raw artifacts live outside this repository and are
referenced by path only.

| subset key   | observed source field | source artifact | provenance | status |
|--------------|-----------------------|-----------------|------------|--------|
| `scheme`     | `accepts[i].scheme` (value `"exact"`) | A — `PaymentRequirements` | **observed** (echoed in B at `accepted.scheme`) | VERIFIED |
| `network`    | `accepts[i].network` (value `"eip155:84532"`, CAIP-2) | A — `PaymentRequirements` | **observed** (agrees with C `.network`) | VERIFIED |
| `asset`      | `accepts[i].asset` | A — `PaymentRequirements` | **observed** (C again carries NO `asset` field — A is the only source) | VERIFIED |
| `amount`     | `accepts[i].amount` — a JSON **string**, base units | A — `PaymentRequirements` | **observed** (agrees with B `payload.authorization.value`) | VERIFIED |
| `resource`   | `resource.url` | A — `PaymentRequirements`, **top level** | **observed** | VERIFIED |
| `settlement` | `transaction` (0x + 64 hex) | C — `SettleResponse` | **observed** | VERIFIED (optional member) |

Cross-check (§8.1.1a): `amount` ← B `payload.authorization.value`, carried onto
this row **on its own observation** — B again matched A. A row that omitted the
cross-check would be weaker than §3.4.2b on identical evidence.

**What the capture established, stated narrowly.** The facilitator is a
registry dimension precisely because a mapping cannot be assumed to survive a
change of facilitator. Here it did — and that is a finding about this pair, not
a licence to skip the capture for the next facilitator:
- **A was BYTE-IDENTICAL** to the CDP run's `PaymentRequirements`. Expected in
  hindsight — the 402 is emitted by the resource server, not the facilitator —
  but it is now observed rather than assumed, and it is what carries all five
  A-sourced paths over unchanged.
- **B had the same shape**; only per-payment values (`nonce`, `validBefore`,
  `signature`) differed.
- **C had the same four keys** (`success`, `payer`, `transaction`, `network`)
  and, again, no `asset`. The `transaction` was a different tx on the same
  network.

**`settlement` presence is now observed TWICE, across two independent
facilitators — and is still `observed`, NOT `always`.** Two samples do not
establish that a successful settle must carry `transaction`. The member stays
optional per §3.2 and a verifier MUST NOT read its absence as anomalous. A rule
is not strengthened by counting samples.

**Every other x402 scheme (e.g. non-`exact` schemes, other networks, other
facilitators): `UNSPECIFIED`.** No rows. Fail closed — do not guess. In
particular this row grants nothing facilitator-wide: `x402org` on any other
scheme or network is unregistered.

### 3.4.3 Promotion procedure (PROVISIONAL → VERIFIED)

*Executed for the §3.4.2b row on 2026-08-02 (capture plan and results:
`docs/spec/delivery-proof-capture.md`). Retained below as the procedure any
FUTURE row must follow.*

To promote registry v0's `exact`/`base-sepolia`/CDP row to `VERIFIED`:
1. Capture a **real** `base-sepolia` payment exchange end-to-end (402 →
   `PaymentRequirements`; `X-PAYMENT` request payload; `X-PAYMENT-RESPONSE` settle
   response), from live CDP facilitator output — not documentation.
2. Confirm the exact field name and source artifact for each of the six keys,
   resolving the `amount` source and the `settlement` field name.
3. Flip each cell's provenance to **observed**, resolve any `UNSPECIFIED` cell, and
   set the row status to `VERIFIED` at a new registry version (additive; the
   PROVISIONAL row is retained as superseded per rule 2).
4. Only then may an implementation emit `x402_payment_ref` for this scheme in
   production, and only then are the `DP*` corpus vectors (§8) built from a real
   captured response.

---

## 4. Delivered output is committed by `event.result_hash` — precisely what it hashes

A delivery-proof receipt does NOT add a hash of the delivered output. It commits
to the delivered output through the field that already carries it:
`event.result_hash` on a `tool_call` or `mcp_call` event
(`src/vendor/recorder/record.ts` `ToolCallEvent.result_hash?` /
`McpCallEvent.result_hash?`).

**Definition (exact).** `event.result_hash = resultHash(result)` where
`resultHash` (`src/vendor/recorder/hash.ts`) is:

```
resultHash(result) = "sha256:" + hex( sha256( jcsBytes(result) ) )
```

and `result` is **the MCP tool result** — the JSON-RPC `result` field of the tool
response, i.e. the `{ content, isError }` envelope the server returned to the
agent. When the wire source is a JSON-encoded string (Cursor's
`afterMCPExecution.result_json`, `src/vendor/recorder/adapter/payloads.ts`), the
hash is produced by `resultHashFromJsonString`, which strict-parses (D7) that
string and then JCS-canonicalizes the parsed value. The preimage is therefore the
canonical form of the exact `result` object, independent of how the server
serialized it.

**Why reuse, not duplicate.** Two signed hashes of one object are two things that
can disagree. A verifier would then have to define which one "wins," and an
attacker (or a bug) has two preimages to make inconsistent. One field, one source
of truth. `x402_payment_ref` binds the *payment*; `event.result_hash` binds the
*output*; the receipt's signature binds them to each other and to the key.

**Scope note.** "Delivered output" in this spec means the MCP `result` envelope as
defined above. If a future consumer needs a narrower preimage (e.g. `content` only,
excluding `isError`), that is a NEW, separately-specified commitment — not this
one — and would require its own field and its own vector. This spec deliberately
fixes delivered-output := the `{content, isError}` result envelope so the two
implementations cannot drift on what was hashed.

---

## 5. Verifier semantics — three machine-readable outcomes

The verifier reads `x402_payment_ref` and `event.result_hash` together and emits
exactly one of three delivery outcomes, each distinguishable by an agent without a
follow-up question. Evaluated **after** the record's signature verifies — a
delivery claim is only meaningful once the bytes are proven authentic; an
unverified receipt's fields are attacker-controlled and get no delivery verdict at
all (the chain fails earlier with `TAMPERED`/`INVALID`).

| # | `x402_payment_ref` | `event.result_hash` | outcome | meaning |
|---|--------------------|---------------------|---------|---------|
| 1 | present | present | **delivery commitment proven** | operator committed, in signed+recomputable bytes, to both a payment reference and the delivered-output hash |
| 2 | present | absent | **`delivery_unproven`** (fail closed) | payment referenced but nothing committed about what was delivered — exactly x402-foundation/x402 #2332 |
| 3 | absent | (any) | **no delivery claim** | ordinary v1 receipt; verifies unchanged (§7) |

- Outcome 1 is an *attestation of commitment*, not of correctness — see §6.
- Outcome 2 is fail-closed: a paid receipt that commits to no output MUST NOT read
  as a delivery. It is the machine-checkable form of "settled, delivery unproven."
- Outcome 3 is the status quo: absent field ⇒ the delivery logic is never entered;
  the receipt is a normal `evidence.action/1` record.

### 5.1 Verdict placement — dedicated surface, NOT `INVALID`

**Decision: delivery outcomes are a SEPARATE verdict axis from the existing
`VerifyResult` kinds — they are NOT folded into `INVALID`.**

Justification:
- `INVALID` (`src/vendor/recorder/cli/verify.ts`) is defined as a **key/trust**
  failure — `key_binding_mismatch`, `untrusted_key`, `insecure_jwks_uri` — and its
  result shape **forces a resolved-key surface** (`key: ResolvedKey`). Every
  `INVALID` names which key failed the trust check. Delivery is not a key-trust
  fact: a `delivery_unproven` receipt can be signed by a perfectly trusted, pinned
  key. Overloading `INVALID` would either require a fake key surface for a non-key
  failure or split the meaning of `INVALID` — both are the kind of ambiguity this
  project fails closed against.
- `TAMPERED` is chain-integrity (linkage/signature/sequence). A `delivery_unproven`
  chain is fully intact and authentic; calling it `TAMPERED` would be a lie.

Therefore the delivery outcome is reported as its own field on a **`VALID`**
result (the chain IS valid — intact, authentic, key-trusted), e.g. a
`delivery: "proven" | "unproven" | "none"` discriminant carried alongside `key`.

### 5.2 Exit codes — `delivery_unproven` exits non-zero by default (NORMATIVE)

| `delivery` | chain verdict | default exit | verdict line |
|------------|---------------|--------------|--------------|
| `none`     | `VALID`       | **0**        | ordinary `VALID` — no delivery claim was made |
| `proven`   | `VALID`       | **0**        | `VALID — … | DELIVERY PROVEN` |
| `unproven` | `VALID`       | **non-zero** | `VALID — … | DELIVERY UNPROVEN (payment referenced, no output commitment)` |

**Ruling: `delivery_unproven` MUST exit non-zero by default.** The chain is
cryptographically `VALID` (intact, authentic, key-trusted), but the *delivery
claim* is not satisfied, and the exit code is the answer to the only question a
scripted caller is really asking: **"can I rely on this?"**

- **The tool's posture is fail-closed.** `delivery_unproven` is precisely the
  x402-foundation/x402 #2332 failure — settled payment, no committed output. Returning `0` by
  default would wave through the exact case this feature exists to expose. An agent
  or CI job that gates on `$? == 0` would treat "paid for nothing, provably" as
  success. That is the one outcome the feature must never silently pass.
- **Precedent inside this verifier.** `UNVERIFIABLE` already exits non-zero
  (`formatVerifyResult`, `src/vendor/recorder/cli/verify.ts`) even though the chain
  itself may be perfectly intact — the reason there is identical: we could not
  establish the property the caller needs, so we fail closed. `delivery_unproven`
  is the same shape (chain fine, required property absent) and gets the same
  treatment.
- **Leniency is opt-in; safety is default.** A caller who only wants chain
  integrity and does NOT care about delivery passes an explicit
  **`--allow-unproven-delivery`** flag. With that flag, `delivery: "unproven"`
  exits `0` (the `delivery` discriminant is still reported in the output line, so
  the information is never hidden — only the exit gate is relaxed). Without the
  flag, the safe/restricted default holds. No flag ever makes `unproven` masquerade
  as `proven`; the flag only changes the exit gate, never the reported verdict.

The machine-readable `delivery` discriminant remains the load-bearing contract for
programmatic consumers; the exit code is the coarse, fail-closed signal for the
shell/CI caller who reads nothing but `$?`. Both must agree in direction: default
non-zero on `unproven`.

### 5.3 Chain-level aggregation (ADDED at implementation — fail-closed)

§5 is written per-receipt, but a verifier is handed a CHAIN. The aggregation rule
was not specified by the draft; it is resolved here, fail-closed:

> **ANY record that references a payment without an output commitment makes the
> WHOLE chain `unproven`, regardless of how many other records are proven.**
> `unproven` is sticky — a later proven record can never lift it — and the
> reported entry is the FIRST offending record.

A chain is `proven` only when at least one record is proven and none is
unproven; `none` when no record carries `x402_payment_ref` at all. Letting a
later proven record mask an earlier paid-and-undelivered one would hide exactly
the fact the caller needs, and "some of your paid calls delivered" is not a
statement any consumer can act on.

### 5.4 Malformed commitment (ADDED at implementation — fail-closed)

The §5 table keys purely on PRESENCE. A third possibility exists once the field
is real: a receipt whose `x402_payment_ref` is present, inside authentic signed
bytes, but is not of the form `"sha256:" + 64 lowercase hex` — i.e. a value that
cannot be recomputed against any subset by anyone.

Such a receipt is `unproven`, never `proven`, reported with the distinct reason
`malformed_payment_ref` so it is not confused with "settled, nothing delivered".
The three-value `delivery` discriminant is unchanged — a consumer's contract
stays `proven | unproven | none` — and the reason is the detail underneath it.
Rationale: a non-recomputable commitment is not a commitment, and the one thing
this feature must never do is let it read as proven. Emission-side, the value
cannot arise at all: both writer paths reject a malformed ref at the boundary.

This keeps the three verdict axes orthogonal and agent-legible: *is the chain
intact* (`TAMPERED`), *is the key trusted/bound* (`INVALID`), *is delivery
committed* (`delivery`). An agent reads three independent answers, never a
collapsed one.

---

## 6. Honest limits (load-bearing — do not soften)

This section is a first-class part of the spec. A delivery-proof receipt is
**operator-side evidence**, and its guarantees stop exactly where the operator's
honesty stops. Stating this plainly is what keeps the feature trustworthy as
infrastructure.

1. **Chirindo signs operator-side.** The receipt is signed by the operator's key,
   published at the operator's JWKS. It proves: *the operator committed, in bytes
   it cannot later alter, to (a) a reference to a settled payment and (b) a hash of
   an output — both recomputable by an independent party against the operator's
   published key.* That commitment either exists and recomputes, or it does not.

2. **It does NOT prove the output was correct, useful, or what the agent actually
   consumed.** A malicious or broken operator can *honestly* hash a useless,
   truncated, or wrong output and produce a perfectly valid "delivery commitment
   proven" receipt. `event.result_hash` binds to *an* output the operator claims it
   delivered — not to the output the agent received and used. There is no property
   here that detects a hash of the wrong-but-real bytes.

3. **Closing that gap requires receiver-side signing.** The only way to bind the
   commitment to what the *consumer* actually received is for the consumer to
   counter-sign the received-output hash (a second party in the preimage). That is
   an **open item**, not a shipped property of this spec. Until it exists, "proven"
   means "operator-committed and recomputable," never "agent-verified-received."

4. **What the value actually is today.** The commitment either exists and
   recomputes, or it does not — and crucially, its **absence after settlement is
   itself machine-checkable evidence.** An x402 `PAYMENT-RESPONSE` proves
   settlement and stops there; it can never, by construction, tell a third party
   whether delivery was even *claimed*. A delivery-proof receipt makes "the
   operator committed to a delivery for this payment" a checkable boolean: outcome
   2 (`delivery_unproven`) is a positive, non-repudiable signal that money settled
   with no output commitment attached. That is strictly more than settlement-only
   provides, and it is useful precisely because it fails closed.

### 6.1 Carried-forward open items (still open, restated so a second implementer inherits them)

- **`unsafe_number` exponent-overflow (`1e400`).** `strictJsonParse` (D7) rejects
  integer-form tokens outside `[-(2^53-1), 2^53-1]`, but exponent-form tokens that
  overflow to `Infinity` (e.g. `1e400`) are NOT yet covered. Any JSON value that
  reaches the payment-ref or result-hash preimage is subject to this same gap.
  Mitigated for `amount` specifically by §3.1 rule 4 (amount is a string, never a
  number), but the gap remains for any other numeric field in a hashed object.
- **`entry_hash` is a written convention, not yet a cross-language spec.**
  `entry_hash = sha256(JCS(contentOf(record)))` with the sig STRIPPED (decision D2)
  is deliberate and correct (malleability-insensitive), but currently only
  committed in Chirindo's TypeScript. A second-language verifier needs the
  `entry_hash` and genesis-preimage rules written down independently. This
  delivery-proof spec depends on that convention (it hashes `contentOf` including
  `x402_payment_ref`) and inherits its documentation gap.

---

## 7. Byte-invariance proof — absent field changes nothing

**Claim.** Adding `x402_payment_ref` as an OPTIONAL, absent-by-default member of
`RecordContent` changes ZERO bytes of: (a) any existing receipt's signed preimage
and signature, (b) the genesis `prev_hash`, (c) any `entry_hash` / chain linkage,
and (d) the frozen conformance vectors (`conformance/vectors-v1.json`). No version
bump is required.

**JCS reasoning.** RFC 8785 canonicalization (the vendored `canonicalize` package,
D1) is a pure function of the members **present** in the object: it takes the
existing members, sorts keys by UTF-16 code unit, and emits `"key":value` with no
whitespace. A TypeScript optional property that is never assigned is **not a member
of the runtime object** — JCS never sees the key. There is no reserved slot, no
`null` placeholder, no positional gap.

- **(a) Existing receipts.** A receipt that does not set `x402_payment_ref` has no
  such key in its runtime object. Its member set is identical before and after the
  type gains the optional field ⇒ `jcsBytes(content)` is byte-identical ⇒ the
  signature over those bytes is identical ⇒ verification is unchanged.
- **(b) Genesis.** The genesis preimage is the fixed three-key object
  `{v, session_id, marker:"genesis"}` (`src/vendor/recorder/hash.ts`
  `genesisInput`). `x402_payment_ref` is never added there, so genesis `prev_hash`
  is untouched by construction.
- **(c) `entry_hash` / linkage.** `entry_hash = sha256(JCS(contentOf(record)))`.
  Same argument as (a): absent key ⇒ unchanged preimage ⇒ unchanged `entry_hash` ⇒
  unchanged `prev_hash` linkage down the chain.
- **(d) Frozen vectors.** `conformance/vectors-v1.json` is a static document of
  fixed inputs and pinned expected hashes. Adding an optional property to a
  TypeScript interface does not edit that file, and none of its receipt objects
  contain the new key, so every canonicalization / thumbprint / chain vector is
  unaffected. The three-way agreement and byte-parity checks still hold.

**Precedent.** This is exactly the pattern `jwks_uri` already proved: an optional,
absent-by-default, inside-the-signed-bytes field that shipped with no version bump
and no vector churn (`src/vendor/recorder/record.ts`, the `jwks_uri` field
comment). `x402_payment_ref` is the same shape.

**PROVEN, not argued (2026-08-02).** The reasoning above is now backed by an
executable test: `test/byte-invariance-payment-ref.test.ts`. Its expected values
— the full JCS string, the `entry_hash`, and the raw Ed25519 signature for a
`Chain.append` record and for an `appendReceipt` receipt, built from a fixed
32-byte seed with fixed timestamps — were generated on the commit BEFORE
`x402_payment_ref` existed and pasted in verbatim. The test recomputes nothing;
it compares current output to frozen pre-change bytes. A signature is the
sharpest available witness, since Ed25519 over a preimage differing by one byte
produces entirely different output. The pre-existing `test/fixtures/legacy-v0`
golden chain is also asserted still-VALID with `delivery: "none"`, and the full
93-test pre-change baseline plus the independent conformance harness
(`ref-self-test`, `check-vectors`, `check-thumbprint`, `check-chain`) pass
unchanged.

**Boundary (honest).** Byte-invariance holds only while the field is ABSENT. A
receipt that DOES set `x402_payment_ref` produces new signed bytes — correctly, as
the commitment is inside the signature. If the frozen corpus is to *prove* the
delivery-proof math the way `SP1`/`SP2` prove strict-parse, new vectors are added
through the documented `.candidate` → promotion cycle (additive; existing vectors
are never mutated).

---

## 8. Conformance requirements for an independent implementation

A second implementation is delivery-proof-conformant iff:

1. It selects EXACTLY the §3.2 subset (six keys, optional `settlement`), applies
   the §3.1 rules (absent ⇒ omit; `amount` as base-unit decimal string), maps
   source fields ONLY per a `VERIFIED` §3.4 registry row (failing closed on any
   scheme without one — a `PROVISIONAL`/`UNSPECIFIED` row does not authorize
   emission), and derives `x402_payment_ref` via
   `"sha256:" + hex(sha256(JCS(subset)))` using an RFC 8785 canonicalizer.

   **1a. Amount cross-check (NORMATIVE; amendment 2026-08-02, registry v2).**
   When BOTH the requirements amount (artifact A, the row's mapped source) and
   the signed authorization value (artifact B, the row's `crossCheck.amount`
   source) are available to the emitter and they **disagree**, the emitter MUST
   NOT emit `x402_payment_ref`. Refusal reason: **`amount_disagreement`** —
   ambiguous payment evidence. When only one source is available, it emits from
   the source that is present.

   Rationale: the row commits to ONE authoritative source so two
   implementations cannot diverge on the bytes. But a disagreement between the
   requested amount and the amount actually authorized on-chain means the
   exchange is telling two stories about how much was paid, and a commitment
   built from either one would be a commitment to a number the other artifact
   contradicts. Refusing is the fail-closed reading; picking a side is not the
   emitter's call to make.

   Comparison is strict and untyped-coercion-free: a JSON number `1000` does
   not equal the observed decimal string `"1000"`, and a type mismatch between
   the two sources is itself a disagreement, not something to normalize away.

   Note the cross-check can only ever cause a REFUSAL — it never supplies a
   subset value. Adding it therefore leaves every previously-built commitment
   byte-for-byte recomputable; what changes is the set of exchanges an emitter
   is willing to commit to at all. That is why registry v2 carries it without a
   new row and without touching a single mapped field (§3.4.1a).
2. It routes any JSON-string ingest of the `PAYMENT-RESPONSE` through a strict
   parser equivalent to D7 (`unsafe_number` + `duplicate_member` fail closed) and
   never hashes on a strict violation.
3. It computes delivered-output commitment as `resultHash` over the MCP `result`
   envelope per §4 (not a separate field).
4. It emits the three §5 outcomes as a verdict axis orthogonal to chain-integrity
   and key-trust, never collapsing `delivery_unproven` into `INVALID`/`TAMPERED`,
   and exits non-zero on `delivery_unproven` by default (§5.2), relaxed only by the
   explicit `--allow-unproven-delivery` opt-in.
5. It reproduces §7 byte-invariance: absent field ⇒ identical bytes to a receipt
   without the feature.

Frozen vectors `DP1_payment_ref_subset` (fixed artifacts → fixed
`x402_payment_ref`), `DP2_delivery_proven`, `DP3_delivery_unproven` remain
pre-scoped but were **NOT added when the code landed**, deliberately. The frozen
corpus `conformance/vectors-v1.json` is untouched by this change, and that is the
point: §7 byte-invariance says an absent field perturbs nothing, so a corpus
that needed editing would have been evidence the claim was false. The subset
math, the three verdicts, and the exit codes are covered by the repo test suite
(§ implementation map at the top). Adding `DP*` vectors is a separate,
additive `.candidate` → promotion cycle — worth doing when a SECOND
implementation appears and needs a shared executable target, which is the point
at which a cross-language vector earns its place.

---

## 9. Standing gap (per the strategic vision)

**The v0 empirical gap is CLOSED.** The registry ships at v3 with two `VERIFIED`
rows (`exact` / `eip155:84532` via Coinbase CDP and via x402.org), each promoted
against a live capture, and the feature is implemented and production-eligible
for those two tuples. Everything else still fails closed.

**The gap that replaces it: coverage of two tuples that differ in one
dimension.** Both VERIFIED rows are `exact` on base-sepolia; only the
facilitator differs. Chirindo can attest delivery for those and nothing else —
not base mainnet, not a non-`exact` scheme, not a third facilitator. Every
uncovered tuple is a consumer who must either go without a receipt or build
their own mapping, and per §3.4.1 rule 3 an operator CANNOT unblock themselves
by editing a row: promotion requires a capture. That is correct and it is also a
scaling bottleneck, because promotion cost is per-tuple and manual — v3 cost a
second full capture to establish a mapping that turned out identical. What this
points toward is a reproducible capture harness whose output feeds a row
directly — a promotion pipeline rather than a promotion ceremony.

**Three narrower open items, carried forward:**
- **`settlement` always-vs-sometimes is UNESTABLISHED.** Presence is now
  observed twice, across two facilitators — which is still an observation, not a
  rule. Until a run establishes whether a successful settle ALWAYS carries
  `transaction`, `settlement` stays optional (§3.2) and a verifier cannot treat
  its absence as anomalous.
- **The commitment does not distinguish the facilitator.** The facilitator is a
  registry dimension but not one of the six §3.2 subset keys, so the two
  VERIFIED rows produce byte-identical `x402_payment_ref` values for the same
  exchange. The row makes a commitment *comparable*; it is not itself committed
  to. A verifier reproducing a preimage therefore learns which mapping was
  needed, not which facilitator settled — fine while the mappings agree, a
  question to reopen the first time two rows for one scheme+network do not.
- **The registry lives in two places** — this document and
  `src/vendor/recorder/x402-registry.ts` — kept in agreement by review, not by a
  check. A second implementation reads the prose; the runtime reads the code. A
  drift test (or generating one from the other) is the obvious hardening.

The deeper, standing gap remains §6 item 3: until the consumer counter-signs the
received-output hash, "delivery proven" is an operator-side attestation, and the
receiver-side signature is the next piece of infrastructure this points toward.

---

## Appendix A — Referenced decisions and files

- **D1** — one JCS path (`src/vendor/recorder/canonicalize.ts`, vendored
  `canonicalize`, RFC 8785).
- **D2** — `entry_hash` sig-stripped (`contentOf`), malleability-insensitive.
- **D7** — `strictJsonParse` strict-ingest gate (`src/vendor/recorder/strict-json.ts`).
- Signed-preimage assembly — `src/vendor/recorder/chain.ts` `Chain.append()`.
- Hash primitives — `src/vendor/recorder/hash.ts` (`sha256Hex`, `argsHash`,
  `resultHash`, `paymentRef`, `*FromJsonString`).
- Payment-ref subset + registry gate — `src/vendor/recorder/payment-ref.ts`
  (`buildPaymentRefSubset`, `paymentRefFromArtifacts`,
  `paymentRefFromJsonStrings`, `PaymentRefError`),
  `src/vendor/recorder/x402-registry.ts` (`X402_REGISTRY_VERSION`,
  `X402_REGISTRY`, `findRegistryRow`).
- Capture that authorized the v1 promotion — `docs/spec/delivery-proof-capture.md`;
  raw artifacts at `x402-capture-rig/capture/` (outside this repository).
- Record schema — `src/vendor/recorder/record.ts` (`RecordContent`,
  `ToolCallEvent`/`McpCallEvent` `result_hash?`).
- Verifier verdicts — `src/vendor/recorder/cli/verify.ts` (`VerifyResult`,
  `TamperReason`, `InvalidReason`, `ResolvedKey`).
- Frozen corpus — `conformance/vectors-v1.json`; report
  `conformance/VERIFICATION-REPORT.md`.
- x402 delivery gap — https://github.com/x402-foundation/x402/issues/2332
  (post-settlement accountability), /2291 (fulfillment obligations / x402-signals),
  /2357 (independently-verifiable receipts in PAYMENT-RESPONSE)
