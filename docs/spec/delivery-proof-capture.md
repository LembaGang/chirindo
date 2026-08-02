# Delivery-Proof Capture Checklist — base-sepolia / Coinbase CDP `exact`

> **STATUS: EXECUTED 2026-08-02.** The capture ran end-to-end: 402 → 200 →
> settled through the Coinbase CDP facilitator
> (`api.cdp.coinbase.com/platform/v2/x402`) on base-sepolia, with the resulting
> transaction resolving on the sepolia explorer (Status Success, 0.001 USDC
> transferred). The (`exact`, `eip155:84532`, CDP) registry row was promoted
> PROVISIONAL → VERIFIED at registry v1 — see `delivery-proof.md` §3.4.2b.
>
> **§7 below records what was actually observed**, including the four places
> where this document's hypotheses were WRONG. Where a hypothesis and an
> observation disagree, the observation wins and this document says so rather
> than being quietly rewritten — that is the honesty contract in §-Honesty.
>
> Raw artifacts: `x402-capture-rig/capture/` (OUTSIDE this repository, never
> copied in — they contain wallet addresses, an EIP-3009 signature, and a
> transaction hash). Referenced by path only.

**Purpose.** Run ONE real x402 payment on base-sepolia against the Coinbase CDP
facilitator and capture exactly the artifacts needed to promote the §3.4 registry
row for (`exact`, `base-sepolia`, CDP) from **PROVISIONAL → VERIFIED** per
`docs/spec/delivery-proof.md` §3.4.3. After this capture, promotion is mechanical:
fill six field names + their source artifact, flip provenance to *observed*.

**Honesty contract for this document.** No field name below is asserted as fact.
Anything drawn from protocol knowledge rather than live observation is tagged
**`hypothesis — confirm`**. Header/endpoint names carry the same tag. The entire
point of the capture is to replace every such tag with an observed value. If a
tagged name turns out wrong when you look at real output, the observed value wins —
record it and move on; do not force reality to match this document.

---

## 0. The x402 flow, and where each artifact lives

The exchange is a 402-retry handshake. Three artifacts matter; each appears at a
distinct point. (Flow shape is protocol knowledge — **`hypothesis — confirm`** the
exact header/body names against what you actually see on the wire.)

```
  1. Client → Server:   GET /<paid-resource>            (no payment)
  2. Server → Client:   HTTP 402 Payment Required
                         body: { x402Version, accepts:[ PaymentRequirements ] , ... }   ← ARTIFACT A
  3. Client builds + signs a PaymentPayload, base64-encodes it
  4. Client → Server:   GET /<paid-resource>
                         header: X-PAYMENT: <base64(PaymentPayload)>                     ← ARTIFACT B
  5. Server → Facilitator (CDP): verify + settle the payment on base-sepolia
  6. Server → Client:   HTTP 200 + the resource
                         header: X-PAYMENT-RESPONSE: <base64(SettleResponse)>            ← ARTIFACT C
```

- **Artifact A — `PaymentRequirements`.** The `accepts[]` entry in the **402
  response body** (step 2). Hypothesized to be the source of `scheme`, `network`,
  `asset`, `resource`, and a required amount. **`hypothesis — confirm`**.
- **Artifact B — `PaymentPayload`.** The base64 value of the **`X-PAYMENT` request
  header** (step 4), decoded to JSON. Hypothesized to carry the signed
  authorization `value` (the actually-authorized amount). **`hypothesis — confirm`**
  the header name and the payload shape.
- **Artifact C — `SettleResponse`.** The base64 value of the **`X-PAYMENT-RESPONSE`
  response header** (step 6), decoded to JSON. Hypothesized to carry the on-chain
  settlement identifier (tx hash) and `network`. **`hypothesis — confirm`** the
  header name and the settle-response shape.

> **OBSERVED (§7.1 findings 1 + 2) — the flow sketch above is WRONG in two
> places.** On x402 v2: (a) the `PaymentRequirements` arrive in the
> **`PAYMENT-REQUIRED` response header**, and the 402 body is `{}` — Artifact A
> is NOT in the body; (b) the request/response headers are
> **`PAYMENT-SIGNATURE`** and **`PAYMENT-RESPONSE`**, not `X-PAYMENT` /
> `X-PAYMENT-RESPONSE` (those are v1). Read §1.1–§1.3 below with that
> correction applied; they are left unedited as the hypotheses they were.
>
> Resolution of the structural caveat: the six subset values span TWO artifacts,
> not three — five from A, `settlement` from C. B supplied only corroboration.

You capture all three because the spec's §3.4.2 structural caveat is unresolved:
the six subset values are hypothesized to span all three artifacts, and part of the
job is confirming **which artifact is authoritative for each key**.

---

## 1. Exactly what to capture, and how to dump it VERBATIM

Capture **raw bytes / raw JSON**, never a pretty-printed summary, never a
screenshot, never a hand-transcription. The whole feature is byte-recomputability;
a reformatted capture defeats the purpose. Rules:

- Preserve the exact bytes: keep original key order, whitespace, string encoding.
  Write each artifact to a file with a tool that does not reformat (e.g. redirect
  the raw response, or `JSON.stringify` the *decoded* value with no re-key-ordering
  only as a SECONDARY convenience file — keep the raw one too).
- For the two base64 headers, capture BOTH the raw base64 string **and** the
  decoded JSON. The base64 is the ground truth; the decode is for reading.

### 1.1 Artifact A — `PaymentRequirements` (from the 402 body)

- **Where:** body of the HTTP 402 response in step 2.
- **Dump:** save the full raw 402 response body to `capture/402-body.raw.json`
  exactly as received (do not re-serialize). If your client only exposes a parsed
  object, additionally save `JSON.stringify(body)` to `capture/402-body.json`, but
  note it may have lost original byte order — the raw file is authoritative.
- **What you need out of it:** the single `accepts[]` entry your client actually
  paid against (there may be more than one offered — record WHICH index you paid).

### 1.2 Artifact B — `PaymentPayload` (from the `X-PAYMENT` request header)

- **Where:** the `X-PAYMENT` request header your client sent in step 4.
  **`hypothesis — confirm`** the header is literally named `X-PAYMENT`.
- **Dump:**
  - `capture/x-payment.b64.txt` — the raw base64 header value, verbatim.
  - `capture/x-payment.decoded.json` — `base64-decode` → the JSON. Save the decoded
    bytes exactly; do not reformat.
- **How to get it if your client hides it:** log the outgoing request header, or
  intercept with a local proxy (see §3.4). Do not reconstruct it by hand.

### 1.3 Artifact C — `SettleResponse` (from the `X-PAYMENT-RESPONSE` header)

- **Where:** the `X-PAYMENT-RESPONSE` response header on the successful 200 in
  step 6. **`hypothesis — confirm`** the header is literally named
  `X-PAYMENT-RESPONSE`.
- **Dump:**
  - `capture/x-payment-response.b64.txt` — raw base64 header value, verbatim.
  - `capture/x-payment-response.decoded.json` — decoded JSON, exact bytes.
- **Also capture the settlement independently:** whatever tx hash / settlement id
  you find here, confirm it resolves on the base-sepolia block explorer
  (basescan sepolia). That cross-check is what proves the field you picked for
  `settlement` is really the on-chain identifier and not an internal id.

---

## 2. Confirm/refute each of the six subset keys

For each key: the hypothesized source, and the concrete thing to look for. **Do not
record a field name you did not see in a raw artifact.** If you can't find it, mark
the cell `UNSPECIFIED` and the row stays PROVISIONAL — that is a valid, honest
outcome.

| # | subset key   | hypothesized artifact + field | how to CONFIRM (what to look for) |
|---|--------------|-------------------------------|-----------------------------------|
| 1 | `scheme`     | A `PaymentRequirements.scheme` = `"exact"` — **`hypothesis — confirm`** | find the literal string `"exact"` in Artifact A; note the key that holds it |
| 2 | `network`    | A/C `network` = `"base-sepolia"` — **`hypothesis — confirm`** | find `"base-sepolia"` (or whatever the network id literally is) in A and C; confirm A and C agree on it |
| 3 | `asset`      | A `PaymentRequirements.asset` (token contract) — **`hypothesis — confirm`** | find the base-sepolia test-USDC contract address in A; confirm it equals the token you actually paid in |
| 4 | `amount`     | **UNRESOLVED (priority):** A `maxAmountRequired` **vs** B `payload.authorization.value` — **`hypothesis — confirm`** | see §2.1 |
| 5 | `resource`   | A `PaymentRequirements.resource` — **`hypothesis — confirm`** | find the URL/id of the resource you called in A |
| 6 | `settlement` | **UNRESOLVED (priority):** C settle-response tx field (name hypothesized `transaction`) — **`hypothesis — confirm`** | see §2.2 |

> **OBSERVED ANSWERS: §7.2.** Rows 1, 2, 5 and 6 held with corrections (network
> is CAIP-2 `eip155:84532`, not `base-sepolia`; `resource` is a top-level object
> and the subset takes its `url`); row 3 held; row 4's hypothesized key
> `maxAmountRequired` was REFUTED — the observed key is `amount`. Both `amount`
> priorities in §2.1 and the `settlement` name in §2.2 are resolved in §7.1/§7.2.

### 2.1 PRIORITY confirmation #1 — `amount` source (which artifact is authoritative)

The spec must commit to ONE authoritative source so two implementations cannot
diverge. Capture BOTH candidates and compare:

- In Artifact A, find the required-amount field (hypothesized `maxAmountRequired` —
  **`hypothesis — confirm`** the exact key name).
- In Artifact B, find the signed authorization value (hypothesized
  `payload.authorization.value` — **`hypothesis — confirm`** the exact path).
- Record BOTH raw values and BOTH exact key paths. Note whether they are equal for
  this `exact`-scheme call (expected equal, but the spec still must pick one).
- **Deliverable:** the two key paths, their two values, and your recommendation for
  which is authoritative — with the reason (e.g. "the signed `value` is what the
  chain actually settled, so it is authoritative over the merely-requested max").
  The spec author makes the final call; you supply the evidence.
- Whichever is chosen, confirm it is expressible as a **base-unit decimal string**
  (§3.1 rule 4). Record whether the observed value is already a string or a number
  in the raw JSON — if it's a JSON number and exceeds 2^53-1, that is a real
  `strict-json` interaction to flag.

### 2.2 PRIORITY confirmation #2 — `settlement` field name

- In Artifact C, find the field carrying the on-chain transaction identifier. The
  hypothesized name is `transaction` — **`hypothesis — confirm`**; it could be
  `txHash`, `transactionHash`, `hash`, or something else entirely. Record the exact
  observed key.
- Confirm the value is a real base-sepolia tx hash by looking it up on the sepolia
  block explorer. If the settle response also carries a non-tx settlement id,
  record both and note which is the on-chain one.
- Record whether the field is ALWAYS present on a successful settle or only
  sometimes (affects §3.2's "optional `settlement`" rule). If you only do one call
  you can't fully answer "always"; note that limitation honestly.

---

## 3. Minimal test setup

The smallest real settle that produces all three artifacts. Everything here is
testnet; §4 forbids anything live.

### 3.1 Wallet
- A **throwaway** EVM wallet created solely for this capture (fresh private key).
  Not the Chirindo signing identity, not any wallet holding real value. See §4.
- Fund it with base-sepolia ETH (for gas, if the flow needs client-side gas) from a
  base-sepolia faucet. **`hypothesis — confirm`** whether the `exact`/EIP-3009 flow
  needs client gas at all (gasless settlement is possible — confirm against the
  actual call).

> **OBSERVED (§7.1 findings 5 + 6).** Two corrections to this setup: (a) the
> client needs NO base-sepolia ETH — the facilitator submits the transaction and
> pays the gas, the client only signs an EIP-3009 authorization; (b) the payer
> and `payTo` MUST be different addresses — CDP rejects a self-send with
> `error: "self_send_not_allowed"`, so a single-wallet setup cannot complete the
> capture.

### 3.2 Test funds
- **base-sepolia test USDC** from the **Circle faucet** (the official Circle testnet
  USDC faucet for Base Sepolia). Request the minimum that covers one call.
- Confirm the token contract address the faucet gives you — that address is what you
  must see in Artifact A's `asset` (§2 row 3). **`hypothesis — confirm`** it matches.

### 3.3 Facilitator + a paid endpoint
- **Facilitator:** the Coinbase CDP x402 facilitator for base-sepolia. **`hypothesis
  — confirm`** the exact endpoint base URL and whether it needs a CDP API key/JWT —
  do not hardcode a guessed URL; get it from current CDP x402 docs at capture time.
- **Paid endpoint (smallest possible):** the cheapest available x402-gated resource
  that returns a real 402 → settles on payment. Options, in order of preference:
  1. An official x402 demo/example server pointed at base-sepolia + CDP facilitator.
  2. A tiny local Express server using the `x402-express` (or equivalent) middleware
     configured for base-sepolia + CDP, serving one trivial route (e.g. returns
     `{"ok":true}`) priced at the minimum. This is the most controllable and lets
     you log headers directly (§3.4).
- **`hypothesis — confirm`** exact package names/versions at capture time from the
  x402 repo; do not trust names from memory.

### 3.4 How to actually see the headers
- If you run the local server (option 2), log the inbound `X-PAYMENT` header and the
  outbound `X-PAYMENT-RESPONSE` header verbatim, and dump the 402 body before the
  middleware serializes it.
- Otherwise put a logging proxy between client and server (e.g. mitmproxy) and
  capture the raw headers + bodies. Avoid any proxy that reformats JSON.
- The client can be the official x402 client/fetch wrapper. Confirm it exposes (or
  can be made to log) the `X-PAYMENT` header it generates.

### 3.5 The call
- One GET to the paid route with the x402 client. Expect: 402 → auto-retry with
  `X-PAYMENT` → 200 + `X-PAYMENT-RESPONSE`. Capture A, B, C as in §1. Done — one
  successful settle is enough to fill the six field names.

---

## 4. DO NOT

- **DO NOT use the live Chirindo signing key** for anything in this exercise. This
  capture involves a payment wallet, which is unrelated to and must never be the
  receipt-signing identity. Keep them categorically separate.
- **DO NOT use real funds or mainnet.** base-sepolia + Circle-faucet test USDC only.
  If any step appears to touch Base mainnet or a real-value asset, stop.
- **DO NOT commit captured output containing wallet addresses or tx-identifying data
  into the repo without review.** The raw artifacts contain the throwaway wallet
  address (`payer`/`from`), the `payTo` address, a tx hash, and possibly a
  signature. These go into `capture/` which MUST be gitignored (or kept entirely
  outside the repo) until redacted and reviewed. Treat `capture/` like the existing
  live-proof scaffolding that is already gitignored — never let raw receipts/keys
  land in git.
- **DO NOT paste unredacted raw artifacts into chat.** Redact per §5 first.
- **DO NOT hand-transcribe or pretty-print field names into the promotion.** Only
  values you can point to in a raw captured file count as *observed*.

---

## 5. What to paste back for promotion

Two things: (a) the observed field map, and (b) the redacted raw artifacts backing
it. Without (b), (a) is just another set of unconfirmed names — the raw files are
what let the spec author verify the mapping independently.

### 5.1 The observed field map (fill every cell from a raw artifact)

```
scheme:     observed key = __________  in artifact [A/B/C]  value = "exact"?  __
network:    observed key = __________  in artifact [A/B/C]  value = __________
asset:      observed key = __________  in artifact [A/B/C]  value = <token addr>
amount:     CHOSEN source = [A.<key> | B.<path>]  both values: A=____ B=____
            recommendation + reason: __________
            raw JSON type of chosen value: [string | number]  exceeds 2^53-1? __
resource:   observed key = __________  in artifact [A/B/C]  value = __________
settlement: observed key = __________  in artifact [C]      value = <tx hash>
            always present on success? [yes | unknown-one-sample]
```

For every row: if you could not find it in a raw artifact, write `UNSPECIFIED` —
do not fill a guess. Any `UNSPECIFIED` keeps the row PROVISIONAL.

### 5.2 The redacted raw artifacts

Paste the raw JSON of each artifact (A: 402 body; B: decoded `X-PAYMENT`; C: decoded
`X-PAYMENT-RESPONSE`), with sensitive values replaced by clearly-marked
placeholders and NOTHING ELSE altered (preserve keys, order, structure):

- wallet / payer / `from` address → `"<PAYER_REDACTED>"`
- `payTo` / recipient address → `"<PAYTO_REDACTED>"`
- signature / authorization signature → `"<SIG_REDACTED>"`
- nonce → `"<NONCE_REDACTED>"`
- tx hash / settlement id → `"<TX_REDACTED>"` **but also** tell me its length and
  0x-prefix so the shape is known (e.g. "0x + 64 hex")

Keep un-redacted (they are non-sensitive and are the actual mapping evidence):
`scheme`, `network`, `asset` (public token contract), the amount value(s),
`resource`, and every KEY NAME at every level. The key names are the deliverable;
redaction only touches values that identify a wallet or a specific settlement.

### 5.3 One-line provenance statement

End with: *"Captured against live base-sepolia / CDP facilitator on <date>; every
field name above was read from a raw artifact file, not documentation."* That
statement is what flips the §3.4 row provenance from `documentation — NOT observed`
to `observed` and authorizes promotion to `VERIFIED` at a new registry version.

---

## Appendix — mapping this capture to §3.4.3 promotion steps

| §3.4.3 step | satisfied by | done |
|-------------|--------------|------|
| 1. capture real exchange end-to-end | §1 artifacts A, B, C (raw) | ✅ 2026-08-02 |
| 2. confirm field name + source artifact per key | §2 table + §2.1/§2.2 priorities → §5.1 map | ✅ §7.2 |
| 3. flip provenance to observed, resolve UNSPECIFIED, new registry version | §5.3 statement + spec edit | ✅ registry v1, `delivery-proof.md` §3.4.2b |
| 4. only then emit in production + build `DP*` vectors | post-promotion, from the §5.2 raw capture | ✅ emission live; `DP*` vectors deliberately deferred (`delivery-proof.md` §8) |

---

## 7. OBSERVED RESULTS (2026-08-02)

Everything in this section was read from a raw artifact file. Nothing here is
recalled or inferred. Wallet addresses, the EIP-3009 signature, and the
transaction hash are NOT reproduced — only key names, value types, and
non-sensitive values, per §5.2.

### 7.1 Seven findings, against this document's hypotheses

| # | finding | this document hypothesized | observed | where |
|---|---------|----------------------------|----------|-------|
| 1 | **Wire header names.** x402 v2 uses `PAYMENT-SIGNATURE` (request) and `PAYMENT-RESPONSE` (response). The `X-PAYMENT*` names are v1 and survive only as a read-side fallback. | `X-PAYMENT` / `X-PAYMENT-RESPONSE` (§0, §1.2, §1.3) | **REFUTED** | `observed-header-names.json`, `exchange-log.jsonl` |
| 2 | **`PaymentRequirements` travel in a HEADER, not the body.** Artifact A is the base64 `PAYMENT-REQUIRED` *response header*. The 402 body was literally `{}` — 2 bytes. | 402 response BODY carries `{ x402Version, accepts:[…] }` (§0 step 2, §1.1) | **REFUTED** | `402-body.raw.json` (2 bytes), `exchange-1.response-headers.raw.txt` |
| 3 | **The amount key is `amount`.** `maxAmountRequired` does not appear anywhere on the wire. | `maxAmountRequired` (§2 row 4, §2.1) | **REFUTED** | Artifact A, `accepts[0].amount` |
| 4 | **`amount` is a base-unit decimal STRING** (`"1000"` = 0.001 USDC at 6 decimals), in A and in B's signed authorization alike. This VALIDATES spec decision (a) / §3.1 rule 4, and means the D7 strict-parse interaction is clean: a string is never an `unsafe_number`. | open question (§2.1: "record whether string or number") | **CONFIRMED as string** | A `accepts[0].amount`; B `payload.authorization.value` |
| 5 | **CDP rejects self-send.** Paying oneself fails with `error: "self_send_not_allowed"`, returned in a `PAYMENT-REQUIRED` header on the retried 402. Payer and `payTo` MUST differ. §3.1's implicit "the wallet can pay itself" setup is FALSIFIED — the capture only succeeded once `payTo` was a different address. | not anticipated (§3.1/§3.3 assume one wallet) | **NEW CONSTRAINT** | `exchange-2.response-headers.raw.txt` (first run) |
| 6 | **The client needs ZERO gas ETH.** The facilitator's own wallet submits the transaction and pays gas; the client only signs an EIP-3009 authorization. §3.1's "fund it with base-sepolia ETH (for gas)" was unnecessary. | open question (§3.1: "confirm whether the flow needs client gas at all") | **CONFIRMED gasless for the client** | on-chain: the submitting address is the facilitator's, not the payer's |
| 7 | **The rig's A/C cross-check read `INCOMPLETE`, and was RIGHT to.** Its error was `"no accepts[] captured from the 402 body"` — correct behavior, wrong-place lookup: it reads the 402 BODY for `accepts[]`, but per finding 2 the requirements moved to the `PAYMENT-REQUIRED` header. The check is not broken; its A-source is. See §7.3 for the proposed fix. | §1.1 tells the rig to read the body | **rig lookup site is stale** | `ac-cross-check.json` |

### 7.2 The observed field map (§5.1 filled in)

```
scheme:     observed key = accepts[i].scheme   in artifact A   value = "exact"    ✔
network:    observed key = accepts[i].network  in artifact A   value = "eip155:84532" (CAIP-2)
                                                               C .network agrees
asset:      observed key = accepts[i].asset    in artifact A   value = base-sepolia USDC contract
                                                               (extra:{name:"USDC",version:"2"})
                                                               C carries NO asset field — NOT COMPARABLE;
                                                               the on-chain token matched A
amount:     CHOSEN source = A accepts[i].amount   both values: A="1000"  B="1000" (agree)
            recommendation + reason: A is authoritative — it is the requirement the payment was
              constructed against and it exists before settlement; B corroborates, it is not a
              second source. `maxAmountRequired` does not exist on the wire.
            raw JSON type of chosen value: string   exceeds 2^53-1? n/a (string; §3.1 rule 4 holds)
resource:   observed key = resource.url        in artifact A   value = the called URL
                                               NOTE: `resource` is a TOP-LEVEL object
                                               {url, description, mimeType}, NOT a member of
                                               the accepts entry. The subset takes `.url`.
settlement: observed key = transaction         in artifact C   value = 0x + 64 hex
            resolved on the sepolia explorer, Status Success — it is the on-chain identifier,
            not an internal id.
            always present on success? UNKNOWN — ONE SAMPLE. Recorded honestly; `settlement`
            therefore stays OPTIONAL in the spec (§3.2). One observation does not license a
            stronger rule.
```

`accepts[i]` denotes the offer actually paid. The captured 402 offered exactly
one (`i = 0`), so this capture does NOT establish anything about multi-offer
selection — the implementation requires the index explicitly rather than
defaulting to 0.

### 7.3 Rig-fix PROPOSAL (finding 7) — not applied here

The A/C cross-check should read Artifact A from the **`PAYMENT-REQUIRED`
response header** (base64-decode, then `accepts[]`), with the 402 body retained
only as a fallback for a v1-shaped server. Today it reads the body alone and so
reports `INCOMPLETE` on a perfectly good v2 capture.

This is recorded as a PROPOSAL, deliberately not applied: the capture rig lives
outside this repository, and silently changing the instrument that produced the
evidence — after the evidence has been used to promote a registry row — would
make the promotion unreproducible. The rig is changed by its owner, on the
record, and the next capture re-runs against the changed rig.

Note the failure was fail-safe in the right direction: the check refused to
report agreement it had not established, rather than defaulting to "looks fine".
