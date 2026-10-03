# Chirindo Witness, wire spec v0.4 (3 Oct 2026)

Wire contract between the Headless Oracle witness service and the chirindo client (@headlessoracle/chirindo). Changes from v0.3: GET paging uses a row-value cursor (section 3), the daily cap is best effort (section 2), rate limits apply to POST and to GET of checkpoints (section 2), and the storage ceiling is stated (section 6).

## Purpose
A hash chain signed by the operator lets anyone detect edits, reordering, and deletions other than cutting off the tail, made by someone who does not hold the signing key. It cannot detect (a) the tail being cut off, by anyone, because a verifier given only the file has no expected length (a trailing checkpoint in the same file can be removed with the tail), or (b) the key holder rewriting the history and re-signing it. A witness narrows both. The operator sends signed checkpoints to an independent party, which records each one and signs a receipt saying when it saw it. A verifier who later compares the chain with the witness's receipts detects a cut-off tail, or a rewrite, of any history up to the last witnessed checkpoint, made after that checkpoint was witnessed. The witness attests only "at time T, I received this checkpoint, validly signed by the key with this thumbprint". It does not attest who owns the key, nor that the records are true.

## 1. The checkpoint (unchanged, produced by chirindo's vendored recorder)
`SignedCheckpoint` from `src/vendor/recorder/record.ts`: `{ v, type:"checkpoint", session_id, count, last_entry_hash, ts, kid, sig }`, signed exactly as `Chain.checkpoint()` in `src/vendor/recorder/chain.ts` does (Ed25519 over JCS RFC 8785 bytes of the content without `sig`, `sig` encoded as `sign.ts` encodes it). `kid` is the bare RFC 7638 thumbprint of the Ed25519 public key (`identity.ts makeKid`). The legacy `ed25519/...` kid scheme is NOT accepted by the witness.

## 2. POST /v1/witness/checkpoints
Base URL: `https://api.headlessoracle.com`.
Request: `Content-Type: application/json`, body at most 4096 bytes:
```
{ "checkpoint": <SignedCheckpoint>, "public_key_jwk": { "kty":"OKP", "crv":"Ed25519", "x":"<base64url raw 32-byte key>" } }
```
Server checks, in order, failing closed with 400 on the first failure. The body's `error` member is the code; other members, such as a `docs` link, may be present.
1. The request's Content-Type starts with `application/json`, and the body (read as bytes) is at most 4096 bytes and is a JSON object with exactly the members `checkpoint` and `public_key_jwk`; else `bad_request`.
2. `checkpoint` is an object with exactly the members v, type, session_id, count, last_entry_hash, ts, kid, sig; else `bad_checkpoint_shape`.
3. Each field is valid, else `bad_checkpoint_field`:
   - `v === "evidence.action/1"` and `type === "checkpoint"`;
   - `count` is a JSON number with `Number.isSafeInteger(count) && count >= 1`;
   - `last_entry_hash` matches `^sha256:[0-9a-f]{64}$`;
   - `ts` matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$` and Date.parse(ts) is finite;
   - `session_id` is a string of 1 to 128 chars;
   - `kid` matches `^[A-Za-z0-9_-]{43}$`;
   - `sig` matches `^[A-Za-z0-9_-]{86}$`.
4. `public_key_jwk` is an object with exactly the members kty, crv and x (any other member is rejected), kty is "OKP" and crv is "Ed25519", and `x` matches `^[A-Za-z0-9_-]{43}$`, decodes to 32 bytes and re-encodes to the same string; else `bad_jwk`.
5. base64url-nopad(SHA-256(UTF-8 of `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`)) equals checkpoint.kid; else `kid_mismatch`.
6. Strict RFC 8032 Ed25519 verification of the 64 bytes obtained by base64url-decoding checkpoint.sig (NOT hex), over the UTF-8 JCS bytes of the checkpoint without sig, succeeds; else `bad_signature`. For this flat object JCS equals JSON.stringify with keys sorted and no whitespace.

A checkpoint's identity is (kid, session_id, count, last_entry_hash); ts and sig are not part of it. INSERT OR IGNORE on that unique key:
- If no row was inserted, return 200 with the stored receipt. Its checkpoint_ts and checkpoint_sha256 may differ from the request, when the same head was checkpointed twice.
- Otherwise return 201 with the new receipt.

`fork` is "true" when, at insert time, a row with the same (kid, session_id, count) and a different last_entry_hash already exists. Two concurrent first submissions with different hashes can both get "false", which is why verifiers detect forks from the receipts (section 5), not from the flag. Rows are never updated or deleted.

If the witness store is unavailable the server returns 503 `{ "error": "witness_unavailable" }` and never a receipt for a checkpoint it did not store.

Rate limit (best effort, counted per Cloudflare location, so it can over-admit): about 60 requests per minute per client address, applied separately to POST and to GET of checkpoints, taken from CF-Connecting-IP only (not X-Original-IP): an IPv4 address as is, an IPv6 address by its /64 prefix. A request without CF-Connecting-IP is counted under the single key `none`. Fails open on a limiter error. Exceeding it returns 429 `{ "error": "RATE_LIMITED" }` with Retry-After. Clients paging GET must treat 429 as an error to retry later, never as an empty or complete list.

Daily cap (best effort: concurrent requests can exceed it slightly): once 2,000 (a launch limit; it will be raised) new witness rows have been stored in the current UTC day, a POST that would store a new row returns 503 `{ "error": "witness_unavailable" }` for the rest of that day. The cap counts and blocks new rows only: a repeat POST of an already-stored checkpoint still returns 200 with the stored receipt.

## 3. GET /v1/witness/checkpoints?kid=<thumbprint>&session_id=<id>[&after=<count>:<last_entry_hash>]
`GET /v1/witness/checkpoints?kid=<thumbprint>&session_id=<id>[&after=<count>:<last_entry_hash>]` returns 200 `{ "kid", "session_id", "receipts": [...], "next_after"?: "<count>:<last_entry_hash>" }`.
- It returns at most 500 receipts ordered by count, then last_entry_hash, strictly after the (count, last_entry_hash) pair in `after` (default: from the start).
- `next_after` is the pair of the last receipt returned, present only when more exist; clients MUST follow it.
- An unknown pair returns 200 with an empty list.
- A missing parameter, a kid not matching `^[A-Za-z0-9_-]{43}$`, a session_id outside 1 to 128 chars, or a malformed `after` returns 400 `bad_request`. A well-formed `after` is the decimal count (a safe integer >= 0), a colon, then a full last_entry_hash: `^\d+:sha256:[0-9a-f]{64}$`.
- If the witness store is unavailable it returns 503 `{ "error": "witness_unavailable" }`.
- Public, no auth, CORS `*`.

## 4. The witness receipt (signed by Headless Oracle)
```
{ "type":"witness.checkpoint/1", "witness":"headlessoracle.com", "received_at":"<ISO-8601 UTC, Date.toISOString() form>",
  "kid":"<thumbprint>", "session_id":"...", "count":"<decimal string>", "last_entry_hash":"sha256:...",
  "checkpoint_ts":"<checkpoint.ts>", "checkpoint_sha256":"sha256:<lowercase hex SHA-256 over the UTF-8 JCS bytes of the full signed checkpoint, sig included>",
  "fork":"true"|"false", "public_key_id":"<signing key id, currently key_2026_v1>", "signature":"<lowercase hex, 128 chars>" }
```
Every value is a string. The witness signs all fields except `signature`, keys sorted, JSON.stringify with no whitespace, UTF-8, Ed25519, hex. For a flat object whose values are all strings these bytes are identical to RFC 8785 JCS, so a verifier may use either.

`type` distinguishes it from market-state receipts.

To get the public key, a verifier takes `public_key` (hex, 32 raw bytes) of the `keys[]` entry in `GET https://api.headlessoracle.com/v5/keys` whose `key_id` equals `public_key_id`, and pins it (section 5).

`fork` is set on a best-effort basis at issue time. It is not the detection mechanism; section 5 is.

A machine-readable copy of sections 2 to 4 and section 6 is served at `GET /v1/witness/spec` (JSON).

## 5. Client verification
`chirindo verify <chain> --key <identity.json> (--witness <base-url> | --witness-file <sidecar>) [--witness-key <hex|jwk-file>] [--witness-key-id <id>] [--witness-name <name>]`

Giving both `--witness` and `--witness-file` is a usage error (exit 2). The gate-key options are unchanged: `--jwks [<url>]` may be used instead of `--key`, since it selects only the gate key; the kit and the tests always pass `--key`.
1. Run the existing verifier first. If it is not VALID, print its line unchanged and exit as today. A VALID line carrying DELIVERY UNPROVEN counts as VALID here.
2. Take kid = records[0].kid and session_id = records[0].session_id.
3. Collect receipts:
   - with `--witness`: `GET <base-url>/v1/witness/checkpoints?kid=..&session_id=..`, following `next_after` until absent. https is required, except http for loopback hosts.
   - with `--witness-file`: every non-null `witness_receipt` in the sidecar.

   3a. If receipts or /v5/keys cannot be fetched or parsed, or the sidecar is missing or malformed, the result is UNVERIFIABLE ("witness receipts unavailable: <reason>"), exit 1.
4. The witness key is the 32-byte Ed25519 key given by `--witness-key`. Its key id is `--witness-key-id` if given, else the JWK file's `kid` if present, else `key_2026_v1`. With `--witness-file`, `--witness-key` is required (exit 2 without it). With `--witness` and no `--witness-key`, the verifier fetches `<base-url>/v5/keys`, takes the `keys[]` entry whose `key_id` equals the receipts' `public_key_id` (its key id is that `key_id`), prints "witness key <hex> fetched from <url>, NOT pinned", and exits 1 even if every check passes.
5. A receipt whose `public_key_id` differs from the witness key's id makes the result UNVERIFIABLE ("witness key mismatch at count N"), exit 1; this is checked before the signature. Otherwise, a receipt whose signature does not verify, whose kid or session_id differs from step 2, whose `type` is not `witness.checkpoint/1`, or whose `witness` differs from `--witness-name` (default `headlessoracle.com`), makes the result TAMPERED ("witness receipt at count N invalid").
6. Check every receipt:
   - the chain must have at least `count` records;
   - the entry hash of record count-1 must equal `last_entry_hash`;
   - two receipts with the same count and different last_entry_hash, or any receipt with fork "true", is a fork.

   Check receipts in ascending count order. Any shortfall, mismatch or fork gives TAMPERED, with a line naming the lowest failing count.
7. Pass: the existing VALID line, then "WITNESSED through count N, received_at T, witness key <hex>", then "M records after the last witnessed checkpoint are not witness-protected". In `--witness-file` mode, append "(sidecar supplied by the operator)". Exit with the existing verifier's code (0 for plain VALID).
8. No receipts: "NO WITNESS: chain VALID, no witness receipts for kid K session S", exit 1.

## 6. Honest limits

A witness receipt is Headless Oracle's signed statement that at received_at it was shown a checkpoint signed by the key with that thumbprint; it is only as reliable as Headless Oracle and its signing key. It does not prove who controls the key, that the records are true, or that they were written at the times they carry.

What it adds to the chain alone: a cut-off tail, or a rewrite by the key holder (edit, delete or reorder, then re-sign and re-link), of any history up to the last witnessed checkpoint, made after that checkpoint was witnessed, is detected when the chain is compared with the witness's receipts. Edits, reordering, and deletions other than cutting off the tail, made by anyone without the signing key, are already detected by the chain and its signatures, with no witness. Cutting off the tail is not detected by the chain alone, whoever does it.

The witness store is a database with a fixed size ceiling and rows are never deleted. If it fills, new checkpoints are refused with 503 until capacity is added; checkpoints already stored stay readable.

What it does not detect:
- records after the last witnessed checkpoint, which can be cut off or rewritten undetectably;
- a history rewritten before it was first witnessed (compare received_at with the records' ts: that gap is the exposure window);
- a session the operator never presents, because the verifier looks up only the session_id of the chain it was given, and a rewrite under a new session_id or a new key starts with no receipts;
- unwitnessed periods: a failed checkpoint never blocks a tool call, a killed process writes no final checkpoint, and because the witness accepts checkpoints from anyone without an account, anyone can use up the rate limit or the daily cap and leave other operators' checkpoints unwitnessed until it resets;
- a wrong witness: nothing here lets a verifier detect Headless Oracle omitting receipts from a query, signing a false received_at, losing stored rows, or the theft of its signing key; receipts are not kept in a public append-only log with consistency proofs.

Two honest cases verify TAMPERED:
- A chain file exported before its session ended verifies TAMPERED once later checkpoints are witnessed, because it looks truncated; verify the complete session file.
- Two chains written under the same key and session_id (for example a reused `--session-id` with a new chain file) are a fork to the witness and verify TAMPERED.

Verifying against a sidecar file trusts the operator who supplied it. Only querying the witness is independent of the operator.

Receipts are individually signed but the list is not: a mirror, proxy or modified client can drop receipts, hiding a cut-off tail or rewrite after the last receipt it returns. Pinning the witness key does not detect a dropped receipt; query https://api.headlessoracle.com directly.

After a key rotation /v5/keys lists only the new key; receipts signed under an earlier key verify only against a copy pinned before rotation.

The witness is operated by Headless Oracle, which also publishes the gate software. It is independent of the operator, not of Headless Oracle. Anyone who knows a (kid, session_id) pair can read that session's checkpoint counts and times. No arguments, results or records are ever sent to the witness.
