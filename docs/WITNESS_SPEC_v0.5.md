# Chirindo Witness, wire spec v0.5 (public edition, 7 Oct 2026)

> **The served spec is authoritative.** `GET https://api.headlessoracle.com/v1/witness/spec` returns the machine-readable contract (JSON, `"name": "Headless Oracle checkpoint witness"`, `"version": "witness-spec/0.5"`). Sections 2, 3, 4 and 6 below render that document; every quoted rule is its text, verbatim. This edition was rendered from the worker source that serves it (headless-oracle-v5 at `c19824b`, run locally), not fetched from production. If the two ever differ, the served spec wins.
>
> Sections 1 and 5 are not part of the served document: they are this client's side of the contract (how chirindo builds a checkpoint and verifies receipts), unchanged from [v0.4](WITNESS_SPEC_v0.4.md). The subsection "How chirindo sends the account key" in section 2 describes this client's handling of the v0.5 account key; it is not part of the served document either.

Wire contract between the Headless Oracle witness service and the chirindo client (@headlessoracle/chirindo). Changes from v0.4, all additive: an optional account key for the Evidence plans (`Authorization: Bearer ho_live_...`, check 1.5) with its own per-key daily quota and rate limit; the anonymous daily cap applies to anonymous POSTs only; the anonymous-cap 503 and the account 429 `quota_exceeded` carry an `upgrade` object; every 4xx carries `docs`, a link to the spec. Nothing in a receipt, in GET, or in client verification changed.

## Purpose
An operator sends signed chain checkpoints to the witness, which records each one and signs a receipt saying when it saw it. The witness attests only "at time T, I received this checkpoint, validly signed by the key with this thumbprint". It does not attest who owns the key, nor that the records are true.

Base URL: `https://api.headlessoracle.com`. https://headlessoracle.com serves the same paths.

> *Editorial correction to this public edition, 9 Oct 2026:* the line above previously read "https://headlessoracle.com serves the same paths once its route for /v1/witness/\* is deployed." Both hosts served the witness paths when checked on 9 Oct 2026 (an anonymous checkpoint POST accepted on each, and `GET /v1/witness/spec` byte-identical on both). This changes nothing a verifier checks.

## 1. The checkpoint (unchanged, produced by chirindo's vendored recorder)
`SignedCheckpoint` from `src/vendor/recorder/record.ts`: `{ v, type:"checkpoint", session_id, count, last_entry_hash, ts, kid, sig }`, signed exactly as `Chain.checkpoint()` in `src/vendor/recorder/chain.ts` does. The served spec states it as:

> { v, type:"checkpoint", session_id, count, last_entry_hash, ts, kid, sig }: Ed25519 over the RFC 8785 (JCS) bytes of the checkpoint without sig; sig is base64url without padding (64 bytes, 86 chars), never hex; kid is the bare RFC 7638 thumbprint of the Ed25519 public key. The legacy "ed25519/..." kid scheme is not accepted.

## 2. POST `/v1/witness/checkpoints`
Request: `Content-Type: application/json`, body at most 4096 bytes:
```
{ "checkpoint": <SignedCheckpoint>, "public_key_jwk": { "kty":"OKP", "crv":"Ed25519", "x":"<base64url raw 32-byte key>" } }
```
Checks, in ascending `order` (each item is one entry of `submit.checks`: its `order`, its `error` code, then its `rule`):

- order 1, `bad_request`: Content-Type starts with application/json, and the body (read as bytes) is at most 4096 bytes and is a JSON object with exactly the members checkpoint and public_key_jwk.
- order 1.5, `invalid_key`: Only when an Authorization header is sent (see accounts): it matches ^Bearer ho_live_[0-9a-f]{64}$ and names an active Evidence plan key. Failures: 401 invalid_key (malformed or unknown key), 402 payment_required (the key is not active), 403 witness_plan_required (the key is not an Evidence plan key), 503 witness_unavailable (the key store could not answer). Without the header this check is skipped.
- order 2, `bad_checkpoint_shape`: checkpoint is an object with exactly the members v, type, session_id, count, last_entry_hash, ts, kid, sig.
- order 3, `bad_checkpoint_field`: v === "evidence.action/1" and type === "checkpoint"; count is a JSON number with Number.isSafeInteger(count) && count >= 1; last_entry_hash matches ^sha256:[0-9a-f]{64}$; ts matches ^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$ and Date.parse(ts) is finite; session_id is a string of 1 to 128 chars; kid matches ^[A-Za-z0-9_-]{43}$; sig matches ^[A-Za-z0-9_-]{86}$.
- order 4, `bad_jwk`: public_key_jwk is an object with exactly the members kty, crv and x (any other member is rejected), kty is "OKP", crv is "Ed25519", and x matches ^[A-Za-z0-9_-]{43}$, decodes to 32 bytes and re-encodes to the same string.
- order 5, `kid_mismatch`: base64url-nopad(SHA-256(UTF-8 of {"crv":"Ed25519","kty":"OKP","x":"\<x>"})) equals checkpoint.kid.
- order 6, `bad_signature`: Strict RFC 8032 Ed25519 verification of the 64 bytes obtained by base64url-decoding checkpoint.sig (not hex), over the UTF-8 JCS bytes of the checkpoint without sig. For this flat object JCS equals JSON.stringify with keys sorted and no whitespace.

Checks run in order and fail closed on the first failure: 400 for every check except the key check (order 1.5), whose codes its rule lists. The body's error member is the code; other members may be present. Every 4xx carries docs, a link to this spec.

A checkpoint's identity is (kid, session_id, count, last_entry_hash); ts and sig are not part of it.

Responses:

- **200**: The identity was already stored; the body is the stored receipt. Its checkpoint_ts and checkpoint_sha256 may differ from the request when the same head was checkpointed twice.
- **201**: A new checkpoint was stored; the body is its new receipt.
- **400**: A check failed; error names it.
- **401**: { "error": "invalid_key" }: an Authorization header was sent and is malformed or names no key.
- **402**: { "error": "payment_required" }: the key is not active (for example, its subscription was cancelled).
- **403**: { "error": "witness_plan_required" }: the key is not an Evidence plan key.
- **429**: { "error": "RATE_LIMITED" } with Retry-After, or, for an account, { "error": "quota_exceeded", "upgrade": {...} } with Retry-After set to the seconds until 00:00 UTC.
- **503**: { "error": "witness_unavailable" }: the store or key store is unavailable, or the anonymous daily cap is reached. When the cap is the reason, the body also carries upgrade (see upgrade). No receipt is ever returned for a checkpoint that was not stored.

**upgrade.** Sent with 503 witness_unavailable when the anonymous daily cap is reached, and with 429 quota_exceeded: { plans: [{ plan, name, amount_usd, currency, billing, checkpoints_per_utc_day }] for custody_90d and custody_1y, checkout: { method, url, headers, body, then }, pricing }. checkout is the exact request that starts a purchase; nothing is bought without a person paying at the returned url.

**fork.** fork is "true" when, at insert time, a row with the same (kid, session_id, count) and a different last_entry_hash already exists. Two concurrent first submissions with different hashes can both get "false", so verifiers detect forks from the receipts, not from the flag.

Rows are never updated or deleted.

**Rate limit.** Best effort (counted per Cloudflare location, so it can over-admit): about 60 requests per minute per client address, applied separately to POST and to GET of checkpoints, taken from CF-Connecting-IP only (not X-Original-IP): an IPv4 address as is, an IPv6 address by its /64 prefix. A request without CF-Connecting-IP is counted under the single key "none". Requests with an Authorization header are limited instead at about 600 per minute per address (counted before the body is read) and about 600 per minute per account (after the key is checked), and carry X-RateLimit-Limit: 600. Fails open on a limiter error.

**Daily cap.** Best effort: concurrent requests can exceed it slightly. Once 2,000 (a launch limit; raised later) new anonymous witness rows have been stored in the current UTC day, an anonymous POST that would store a new row returns 503 witness_unavailable for the rest of that day. A POST with an Evidence plan key counts against that key's own quota instead (see accounts). The cap counts and blocks new rows only: a repeat POST of an already-stored checkpoint still returns 200 with the stored receipt.

### Accounts (new in v0.5)

Optional Authorization: Bearer \<key>, the key issued with the Evidence plans (https://headlessoracle.com/pricing). Without it the POST is anonymous and shares the anonymous daily cap.

Quotas:
- `evidence_starter`: Up to 1,000 new checkpoints per UTC day.
- `evidence`: Up to 3,000 new checkpoints per UTC day.

Only a POST that stores a new row counts; a repeat POST of an already-stored checkpoint is free. Best effort: concurrent requests can exceed a quota slightly. Over the quota a POST that would store a new row returns 429 quota_exceeded, with Retry-After set to the seconds until 00:00 UTC.

Account rows do not count against the anonymous daily cap, and that cap being reached does not block an account.

Errors:
- **401** invalid_key: the header is not Bearer ho_live_ followed by 64 lowercase hex characters, or names no key. Never answered from the anonymous pool instead.
- **402** payment_required: the key is not active.
- **403** witness_plan_required: the key exists but is not an Evidence plan key.
- **429** quota_exceeded: this key's daily quota is used; or RATE_LIMITED.
- **503** witness_unavailable: the key store could not answer, or the store is unavailable.

Receipts are identical for both pools: the same fields, signed the same way. Nothing in a receipt says which pool stored it.

Rate limit: About 600 requests per minute per client address and per account.

### How chirindo sends the account key (client side, not in the served spec)

- `chirindo proxy` and `chirindo checkpoint` (the two commands that POST checkpoints) take `--witness-account-key-file <path>`, a file holding the key (surrounding whitespace is trimmed), or else the environment variable `CHIRINDO_WITNESS_ACCOUNT_KEY`. The file flag wins; the variable is read only when the flag is absent, and only when `--witness` is given. The key itself is never accepted as a command-line value. `chirindo verify` takes no account key: it only reads, and GET is public.
- The key must match `^ho_live_[0-9a-f]{64}$`; anything else is a usage error (exit 2) before any request is made.
- The key is sent as `Authorization: Bearer <key>` on `POST /v1/witness/checkpoints` only, never on `GET /v1/witness/checkpoints` or `GET /v5/keys`, and with redirects refused, so it is never re-sent to another host.
- The key is never written to the sidecar or printed. 401 `invalid_key`, 402 `payment_required`, 403 `witness_plan_required`, 429 `quota_exceeded` / `RATE_LIMITED` and 503 `witness_unavailable` are recorded in the sidecar as `witness_error` (the code only), never as a receipt; the proxy permits the tool call exactly as for any witness failure. For `quota_exceeded`, and for a 503 that carries `upgrade`, the client prints at most one stderr line naming the reply's `upgrade.pricing` URL (else `upgrade.checkout.url`), accepted only as a plain https URL. It does not retry; `Retry-After` is not acted on.

## 3. GET `/v1/witness/checkpoints?kid=<thumbprint>&session_id=<id>[&after=<count>:<last_entry_hash>]`
Response: `200 { "kid", "session_id", "receipts": [...], "next_after"?: "<count>:<last_entry_hash>" }`.
- At most 500 receipts ordered by count, then last_entry_hash, strictly after the (count, last_entry_hash) pair in after (default: from the start).
- WHERE kid=? AND session_id=? AND (count, last_entry_hash) > (?, ?) ORDER BY count, last_entry_hash LIMIT 501 (SQLite row-value comparison, so the index bounds the scan; the 501st row only signals that next_after is needed).
- next_after is the pair of the last receipt returned, present only when more exist; clients MUST follow it.
- An unknown (kid, session_id) pair returns 200 with an empty list.
- A missing parameter, a kid not matching ^[A-Za-z0-9_-]{43}$, a session_id outside 1 to 128 chars, or a malformed after returns 400 bad_request. A well-formed after is the decimal count (a safe integer >= 0), a colon, then a full last_entry_hash: ^\\d+:sha256:[0-9a-f]{64}$. If the store is unavailable it returns 503 witness_unavailable. 429: RATE_LIMITED with Retry-After.
- Public, no auth, CORS \*.

Clients paging GET must treat 429 as an error to retry later, never as an empty or complete list (v0.4 section 2; chirindo reports UNVERIFIABLE).

## 4. The witness receipt (signed by Headless Oracle)
Type `witness.checkpoint/1`. Fields, in the order the spec lists them, then `signature`; every value is a string (`all_values_are_strings: true`):

| field | note |
|---|---|
| `type` | "witness.checkpoint/1"; distinguishes this receipt from market-state receipts. |
| `witness` | "headlessoracle.com" |
| `received_at` | ISO-8601 UTC in Date.toISOString() form: when the witness stored the checkpoint. |
| `kid` | The checkpoint's thumbprint. |
| `session_id` | The checkpoint's session_id. |
| `count` | The checkpoint's count as a decimal string. |
| `last_entry_hash` | The checkpoint's last_entry_hash. |
| `checkpoint_ts` | The checkpoint's ts. |
| `checkpoint_sha256` | sha256:\<lowercase hex SHA-256 over the UTF-8 JCS bytes of the full signed checkpoint, sig included> |
| `fork` | "true" or "false", set on a best-effort basis at issue time. It is not the detection mechanism; comparing receipts is. |
| `public_key_id` | The id of the Headless Oracle signing key, currently key_2026_v1. |
| `signature` | Lowercase hex, 128 chars. |

**Signing.** All fields except signature, keys sorted, JSON.stringify with no whitespace, UTF-8, Ed25519, hex. For a flat object whose values are all strings these bytes are identical to RFC 8785 JCS, so a verifier may use either.

**Public key.** Take public_key (hex, 32 raw bytes) of the keys[] entry in GET https://api.headlessoracle.com/v5/keys whose key_id equals public_key_id, and pin it.

## 5. Client verification (unchanged from v0.4)
`chirindo verify` is unchanged by v0.5: receipts from both pools are identical and verify the same way. See [WITNESS_SPEC v0.4, section 5](WITNESS_SPEC_v0.4.md#5-client-verification).

## 6. Honest limits

A witness receipt is Headless Oracle's signed statement that at received_at it was shown a checkpoint signed by the key with that thumbprint; it is only as reliable as Headless Oracle and its signing key. It does not prove who controls the key, that the records are true, or that they were written at the times they carry.

What it adds to the chain alone: A cut-off tail, or a rewrite by the key holder (edit, delete or reorder, then re-sign and re-link), of any history up to the last witnessed checkpoint, made after that checkpoint was witnessed, is detected when the chain is compared with the witness's receipts. Edits, reordering, and deletions other than cutting off the tail, made by anyone without the signing key, are already detected by the chain and its signatures, with no witness. Cutting off the tail is not detected by the chain alone, whoever does it.

The witness store is a database with a fixed size ceiling and rows are never deleted. If it fills, new checkpoints are refused with 503 until capacity is added; checkpoints already stored stay readable.

What it does not detect:
- Records after the last witnessed checkpoint, which can be cut off or rewritten undetectably.
- A history rewritten before it was first witnessed (compare received_at with the records' ts: that gap is the exposure window).
- A session the operator never presents, because the verifier looks up only the session_id of the chain it was given, and a rewrite under a new session_id or a new key starts with no receipts.
- Unwitnessed periods: a failed checkpoint never blocks a tool call, a killed process writes no final checkpoint, and because the witness accepts checkpoints from anyone without an account, anyone can use up the rate limit or the daily cap and leave other operators' checkpoints unwitnessed until it resets.
- A wrong witness: nothing here lets a verifier detect Headless Oracle omitting receipts from a query, signing a false received_at, losing stored rows, or the theft of its signing key; receipts are not kept in a public append-only log with consistency proofs.

Two honest cases verify TAMPERED:
- A chain file exported before its session ended verifies TAMPERED once later checkpoints are witnessed, because it looks truncated; verify the complete session file.
- Two chains written under the same key and session_id (for example a reused --session-id with a new chain file) are a fork to the witness and verify TAMPERED.

Verifying against a sidecar file trusts the operator who supplied it. Only querying the witness is independent of the operator.

Receipts are individually signed but the list is not: a mirror, proxy or modified client can drop receipts, hiding a cut-off tail or rewrite after the last receipt it returns. Pinning the witness key does not detect a dropped receipt; query https://api.headlessoracle.com directly.

After a key rotation /v5/keys lists only the new key; receipts signed under an earlier key verify only against a copy pinned before rotation.

The witness is operated by Headless Oracle, which also publishes the gate software. It is independent of the operator, not of Headless Oracle. Anyone who knows a (kid, session_id) pair can read that session's checkpoint counts and times. No arguments, results or records are ever sent to the witness.
