# Chirindo

**A fail-closed cryptographic gate for the MCP tool-call boundary — the
watchtower for your AI agents. By Headless Oracle.**

> Chirindo — Shona for "watchtower."

A stdio MCP proxy that intercepts `tools/call` requests from a real MCP
client (Claude Desktop, Cursor), evaluates a policy, and either forwards
the call to the real downstream server (ALLOW) or returns a tool-failure
response WITHOUT forwarding (DENY) — emitting a signed receipt in
either case.

Chirindo emits **calibrated evidence**: a verifying party can prove that
the gate fired for a given call and that the chain is recomputable from
the signed records. The receipts do **not** prove an action was "safe" —
only that the gate's decision is captured, signed, and tamper-evident
(not tamper-proof: an edit, a reorder, or a deletion other than cutting off
the tail breaks the hash chain and is caught by `recorder verify`; cutting
off the tail, and a rewrite by the key holder, are caught only against
witnessed checkpoints, see [Witness](#witness)).
The receipt format and signing reuse the existing
[`recorder`](src/vendor/recorder) engine — no reimplementation of JCS, hashing,
or Ed25519.

Chirindo is an **operator-run** gate that signs its receipts
**operator-side**. Anyone holding a receipt can recompute it against the
gate's **published** key, so a receipt is a recomputable, tamper-evident
record of what this operator's gate decided — not a neutral third party's
attestation, and not proof that the underlying action was "safe."

## Posture: fail-closed (the opposite of the recorder)

The recorder is observe-only: it never blocks the agent, even when its
own signer crashes. The gate is the inverse: when it cannot evaluate
policy, **it denies**. When it cannot write a receipt for an action that
already ran, it withholds the result from the client (the action's
side effect already happened; we cannot un-do it, but we can prevent the
agent from acting on an un-receipted result).

| Failure mode | Recorder | Gate |
|---|---|---|
| Signer throws | log + permit | DENY |
| Policy missing / invalid | n/a | DENY |
| Receipt write fails | log + permit | DENY result back to client |
| Witness unreachable or receipt invalid | n/a | log + permit (availability; the session is then protected by the chain alone) |

## Architecture

```
MCP client (Claude Desktop)
        │
        ▼ stdio (JSON-RPC 2.0, newline-delimited)
   chirindo proxy   ◀── policy.json (deny rules)
        │
        ▼ stdio
  downstream MCP server (the real one)
```

The client launches `chirindo proxy` as its MCP server. The proxy spawns
the real downstream MCP server as a child process. Every JSON-RPC frame
in either direction passes through the proxy. `tools/call` requests are
evaluated against the loaded policy:

- **ALLOW** → forward to downstream; on the response, write an ALLOW
  receipt and pass the response back to the client.
- **DENY** → synthesize a tool-execution-error response
  (`{result: {content:[...], isError: true}}`) per
  [MCP spec § Error Handling](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#error-handling),
  send it to the client, write a DENY receipt. The downstream NEVER
  sees the call.
- **FAIL-CLOSED** → if the policy can't be loaded or the evaluator
  throws, DENY the call.

All other frames (`initialize`, `tools/list`, responses,
notifications) pass through unmodified.

## The signed receipt

Each intercepted `tools/call` produces a single line appended to a
per-session JSONL chain file. The receipt is an `evidence.action/1`
record from the recorder schema, with the `gate` block populated. The
example below is real signer output from a throwaway key, verbatim — it
verifies with `chirindo verify`:

```json
{
  "v": "evidence.action/1",
  "seq": 0,
  "session_id": "11111111-2222-4333-8444-555555555555",
  "ts": "2026-07-08T09:00:00.000Z",
  "agent": {
    "vendor": "chirindo",
    "version": "0.0.1"
  },
  "event": {
    "type": "mcp_call",
    "outcome": "executed",
    "server": "everything",
    "tool_name": "echo",
    "args_hash": "sha256:cbbbdcd27692344de5dbab3abcaba413fb0f45307267de7081401576df1cb176",
    "decision": "allow",
    "decision_source": "config",
    "result_hash": "sha256:493466351f6341d054cec14e973f001dc7d66e5bb4a4177d42014725b2f7cb6b"
  },
  "request_commitment": "sha256:55e4964e7b22557513889732c7998697d40eaeb3cf4996686a638ce9d64c8ccf",
  "gate": {
    "request_commitment": "sha256:55e4964e7b22557513889732c7998697d40eaeb3cf4996686a638ce9d64c8ccf",
    "gate_receipt": "sha256:6cbf1406bf3a0c6a2d6a123697ea72c990f2f8e0f50fdbfc5c568109d1e654dc",
    "gate_family": "permit",
    "result": "act"
  },
  "jwks_uri": "https://gate.example.com/.well-known/jwks.json",
  "key_thumbprint": "DEHVOBA-vd8KledaxgxgPHkpGS4TES9CTQcMTVHcwYo",
  "iss": "https://gate.example.com",
  "prev_hash": "sha256:5a8534e71ecae904f1a9b2945b77bcc9bc3035b08c3968d0fe1ce199189cc345",
  "kid": "DEHVOBA-vd8KledaxgxgPHkpGS4TES9CTQcMTVHcwYo",
  "sig": "E_BIbjouxmMZClFqU2sVw8xkhZDhI8o4ZKjYmTJzHby0nBxJTvSs1-Gu7EZyrQS0E1etqpe9wekeHxzOVjgvCw"
}
```

Field notes:

- **`v`** is `evidence.action/1`. A v1 receipt binds the signer *inside*
  the signed bytes with two fields: **`key_thumbprint`** — the RFC 7638
  JWK thumbprint of the gate's signing key, which the verifier recomputes
  from the resolved key and checks *before* the signature, so a key
  substituted at the `jwks_uri` can't pass by verifying under itself — and
  **`iss`**, the issuer identity, defaulting to the origin of `jwks_uri`
  (the operator's own domain, never Headless Oracle). For a v1 receipt
  `kid == key_thumbprint`: one key identity, reconcilable from the receipt
  alone.
- **`event`**: this is an ALLOW receipt (`outcome: "executed"`,
  `decision: "allow"`, `gate.result: "act"`). A DENY receipt instead reads
  `denied` / `deny` / `halt` and omits `result_hash` — there was no
  downstream response to hash. `args_hash` and `result_hash` are RFC 8785
  JCS + SHA-256 over the argument and result values (recomputable by any
  verifier, not `JSON.stringify`).
- **`gate.request_commitment`** MUST equal the top-level
  `request_commitment` (the continuity invariant); **`gate.gate_receipt`**
  is the receipt's own `entry_hash`: the receipt anchors to its own chain,
  and an outside time for it comes from a witnessed checkpoint whose
  `count` covers that entry (see
  [Showing a gate ran before an action](#showing-a-gate-ran-before-an-action)).
- **`jwks_uri`** (optional) names where this receipt's signing key is
  published; it is inside the signed bytes, so the operator commits to it.

The chain verifies via the recorder's verify engine — same hash chain,
same signature scheme, same canonical bytes — which is exactly what
`chirindo verify` runs. Cross-tool interop is the point: the gate's
output is evidence the recorder's verifier already understands.

## Commands

```
chirindo init   [--dir <path>]
chirindo proxy  --policy <file> --server-label <name>
                [--dir <path>] [--chain <file>] [--session-id <id>]
                [--checkpoint-every <N>] [--witness <base-url>]
                [--witness-key <hex|jwk-file>] [--witness-name <name>]
                [--witness-account-key-file <path>]
                -- <downstream-command> [<args>...]
chirindo checkpoint <chain-file> [--dir <path>] [--witness <base-url>]
                [--witness-key <hex|jwk-file>] [--witness-name <name>]
                [--witness-account-key-file <path>]
chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]
                [--expect-thumbprint <tp>]... [--trust-file <file>]
                [--max-skew-ms <ms>]
                [--witness <base-url> | --witness-file <sidecar>]
                [--witness-key <hex|jwk-file>] [--witness-key-id <id>]
                [--witness-name <name>]
```

Defaults: `--dir = ./.gate/`, identity at `<dir>/identity.json`, chain
at `<dir>/sessions/<session-id>.jsonl`.

**verify key resolution (precedence, highest first):** `--key <file>` >
`--jwks <url>` > the receipt's own `jwks_uri` > `$RECORDER_JWKS_URL` >
the published default. Fallback happens **only when the higher source is
absent** — a receipt whose `jwks_uri` is present but unreachable is
`UNVERIFIABLE`, never silently re-resolved to a default key. There is no
implicit local-identity default; pass `--key` for the offline path.

**Hardened fetch.** Every `jwks_uri` fetch is `https://` + port 443 only,
rejects IP-literal hosts and any hostname that resolves to a
private/loopback/link-local address (checked after DNS, so a rebind can't
slip through), follows at most one same-origin redirect, caps the body at
64 KiB, times out at 5 s, and requires a JSON content-type. A receipt that
names an `http://` `jwks_uri` is malformed → `INVALID`.

### Policy file format

```json
{
  "deny": [
    { "tool": "delete", "reason": "destructive: blocked by policy" },
    { "tool": "shell_exec", "server": "everything" }
  ]
}
```

A rule matches if `tool` matches the call's `name`, AND `server` (if
present) matches the proxy's `--server-label`. Anything not matched by
a deny rule is allowed. The shipped `policy.json` is `{"deny": []}` —
records everything, blocks nothing, **observe-only by default**.
Enforcement is opt-in (see step 6 below). **Fail-closed**: an
unreadable or malformed policy file still denies all calls.

## Witness

A hash chain signed by the operator lets anyone detect edits, reordering,
and deletions other than cutting off the tail, made by someone who does not
hold the signing key. It cannot detect the tail being cut off (a verifier
given only the file has no expected length), nor the key holder rewriting
history and re-signing it. A **witness** narrows both: the gate sends signed
checkpoints `{count, last_entry_hash, ...}` to an independent party, which
records each one and signs a receipt saying when it saw it. The wire
contract is [WITNESS_SPEC v0.5](docs/WITNESS_SPEC_v0.5.md), a public edition
of the spec the witness serves at https://api.headlessoracle.com/v1/witness/spec
(the served spec is authoritative; v0.5 adds optional accounts to
[v0.4](docs/WITNESS_SPEC_v0.4.md) and changes nothing a verifier checks).
Both `https://api.headlessoracle.com` and `https://headlessoracle.com` serve
the witness paths (checked 9 Oct 2026, below); the spec names
`https://api.headlessoracle.com` as the base URL.

**What has been exercised, and what has not.** This client is tested against
a local stub of the spec (`test/witness-stub.ts`), and was run by hand on
7 Oct 2026 against the witness's own source served locally (`wrangler dev`):
anonymous and account-key checkpoints, `verify --witness` with a pinned key,
402 `payment_required`, 403 `witness_plan_required`, the anonymous-cap 503 and
the account 429 `quota_exceeded`.

On 9 Oct 2026 the 0.5.0 client code (packed from this repository and
installed in a clean directory) was run against production, anonymously,
with no account key:

- Two one-receipt chains were made with `chirindo proxy` around the mock MCP
  server in `examples/observe-only-agent/`. `chirindo checkpoint` sent one
  to `https://api.headlessoracle.com` and the other to
  `https://headlessoracle.com`; each POST was accepted and returned a signed
  receipt (`witness.checkpoint/1`, `public_key_id` `key_2026_v1`), written
  to the sidecar.
- The witness key was taken from `GET /v5/keys` (both hosts returned the
  same key) and pinned. `chirindo verify --key ... --witness <host>
  --witness-key <pinned>` read `VALID` and `WITNESSED through count 1` for
  both chains against both hosts, each host returning the receipt the other
  host stored, so the two hosts read one store.
- One byte of a chain changed (one hex digit of `event.args_hash`): verify
  read `TAMPERED — entry 0: request_commitment mismatch`, exit 1. That edit
  is caught by the chain itself; the run did not exercise a witness-only
  detection (a cut-off tail or a re-signed rewrite) against production.
  With a wrong pinned witness key, verify read `TAMPERED — witness receipt
  at count 1 invalid`, exit 1.
- `GET /v1/witness/checkpoints?kid=...&session_id=...` returned the stored
  receipt on both hosts.

Not exercised against production: account keys, the 402 paid path, the
403 and 401 key refusals, the anonymous daily cap (503) and the account
quota (429), rate limits, fork receipts, multi-page `next_after` reads,
checkpoints from a long-running proxy (`--checkpoint-every`, the shutdown
checkpoint), and a key rotation.

```
# checkpoint the head of a chain, optionally witnessed
chirindo checkpoint <chain> --witness https://api.headlessoracle.com

# or let the proxy do it: every N receipts, and once more on clean shutdown
chirindo proxy ... --checkpoint-every 50 --witness https://api.headlessoracle.com -- <cmd>

# verify the chain against the witness (pin the witness key: hex or JWK file)
chirindo verify <chain> --key <identity.json> \
  --witness https://api.headlessoracle.com --witness-key <hex>
```

- Checkpoints are written to the sidecar `<chain>.witness.ndjson`, one line
  `{checkpoint, witness_receipt, witness_error}` each, **never** into the
  chain file (a checkpoint inside the live chain would make every later
  receipt write fail). `chirindo checkpoint` refuses (exit 1, nothing
  written) unless the chain verifies VALID under the identity's key, that key
  signed the chain, and its kid is an RFC 7638 thumbprint (not a legacy
  `ed25519/...` kid).
- A witness failure on the proxy is one sidecar line with `witness_error`
  and one stderr line; the tool call is never delayed, altered or denied
  (see the fail-closed table). On clean shutdown the proxy checkpoints the
  head and waits at most 5 s for the witness before exiting. **A killed
  process writes no final checkpoint**: everything after its last witnessed
  checkpoint is protected by the chain alone.
- **What is sent to the witness:** the checkpoint's `kid`, `session_id`,
  `count`, `last_entry_hash`, `ts`, `sig`, the constant `v` and `type`
  fields, and the gate's public key; plus, as with any HTTPS request, the
  sender's IP address. Never arguments, results or records.
- A `--session-id` longer than 128 characters cannot be witnessed.
- `verify --witness <url>` queries the witness (following `next_after`
  pages); `verify --witness-file <sidecar> --witness-key <key>` reads the
  receipts from the sidecar, offline. **`--witness-file` trusts the sidecar
  the operator supplied; only querying the witness is independent of the
  operator.** Output on success is the usual VALID lines, then
  `WITNESSED through count N, received_at T, witness key <hex>` and
  `M records after the last witnessed checkpoint are not witness-protected`.
  A cut-off tail, a rewrite, or a fork reads `TAMPERED` naming the lowest
  failing count; no receipts reads `NO WITNESS: ...` (exit 1); a witness key
  fetched from `/v5/keys` instead of pinned is named and exits 1.
  `--witness-name` sets the expected receipt `witness` member (default
  `headlessoracle.com`).

Receipt signature verification needs no Headless Oracle service when you
verify with `--key`, with `--jwks <your URL>`, or through the receipt's own
`jwks_uri`. Without `--key` or a `--jwks` URL, a receipt with no `jwks_uri`,
and with `$RECORDER_JWKS_URL` unset, is checked against keys fetched from
https://headlessoracle.com/.well-known/jwks.json; pinning a thumbprint
(`--expect-thumbprint`) removes the need to trust that fetch. Evidence from
Headless Oracle's witness relies on Headless Oracle, and only for truncation
and rewrite detection.

A runnable demonstration against a local stub witness (not Headless
Oracle's) is in [`examples/e015-4-kit/`](examples/e015-4-kit/).

### Witness accounts (v0.5, optional)

Without an account, checkpoints go to a pool shared by everyone. An Evidence
plan key gives the operator its own daily quota:

```
# from a file (preferred; whitespace around the key is trimmed)
chirindo proxy ... --witness https://api.headlessoracle.com \
  --witness-account-key-file ~/.config/chirindo/witness.key -- <cmd>

# or from the environment
CHIRINDO_WITNESS_ACCOUNT_KEY=ho_live_... chirindo checkpoint <chain> \
  --witness https://api.headlessoracle.com
```

- **Precedence:** `--witness-account-key-file` wins; `CHIRINDO_WITNESS_ACCOUNT_KEY`
  is read only when the flag is absent, and only when `--witness` is given.
  The key is never accepted as a command-line value (`--witness-account-key`
  is refused), so it does not land in shell history or process listings.
  `--witness-key` is unrelated: it is the witness's *public* key.
- The key must be `ho_live_` followed by 64 lowercase hex characters; anything
  else exits 2 before any request is made, with a message that never echoes it.
- It is sent as `Authorization: Bearer <key>` on the checkpoint POST only.
  Reading receipts (`GET /v1/witness/checkpoints`, `GET /v5/keys`) is public
  and never carries it. Redirects are refused, so it is never re-sent to
  another host. It is never written to the sidecar or printed.
- A refused key (401 `invalid_key`, 402 `payment_required`, 403
  `witness_plan_required`) or a used-up quota (429 `quota_exceeded`) is a
  witness failure like any other: one sidecar line with `witness_error`, and
  on the proxy the tool call is permitted unchanged. A 401 is never answered
  from the anonymous pool instead. When the reply carries the spec's `upgrade`
  object (429 `quota_exceeded`, or the anonymous-cap 503), chirindo prints at
  most one stderr line naming its pricing URL; it does not retry.

Limits, as the spec states them (all best effort):

| | anonymous (no key) | Evidence plan key |
|---|---|---|
| new checkpoints per UTC day | 2,000 shared by all anonymous callers (a launch limit), then 503 `witness_unavailable` | `evidence_starter` 1,000, `evidence` 3,000, then 429 `quota_exceeded` with `Retry-After` to 00:00 UTC |
| requests per minute | about 60 per client address, POST and GET counted separately | about 600 per client address and about 600 per account |

Only a POST that stores a new checkpoint counts; repeating an already-stored
checkpoint is free. Account checkpoints do not count against the anonymous
cap, and that cap being reached does not block an account, so an account key
closes the "anyone can use up the daily cap" gap below for that operator (not
the rate limit per address). Receipts are identical for both pools; nothing in
a receipt says which pool stored it. Prices are not in this README: the
witness returns them in its `upgrade` object and at
https://headlessoracle.com/v5/pricing.

### Honest limits

A witness receipt is Headless Oracle's signed statement that at
`received_at` it was shown a checkpoint signed by the key with that
thumbprint; it is only as reliable as Headless Oracle and its signing key.
It does not prove who controls the key, that the records are true, or that
they were written at the times they carry.

**What it adds to the chain alone:** a cut-off tail, or a rewrite by the key
holder (edit, delete or reorder, then re-sign and re-link), of any history
up to the last witnessed checkpoint, made after that checkpoint was
witnessed, is detected when the chain is compared with the witness's
receipts. Edits, reordering, and deletions other than cutting off the tail,
made by anyone without the signing key, are already detected by the chain
and its signatures, with no witness. Cutting off the tail is not detected by
the chain alone, whoever does it.

**What it does not detect:**

- records after the last witnessed checkpoint, which can be cut off or
  rewritten undetectably;
- a history rewritten before it was first witnessed (compare `received_at`
  with the records' `ts`: that gap is the exposure window);
- a session the operator never presents, because the verifier looks up only
  the `session_id` of the chain it was given, and a rewrite under a new
  `session_id` or a new key starts with no receipts;
- unwitnessed periods: a failed checkpoint never blocks a tool call, a
  killed process writes no final checkpoint, and because the witness accepts
  checkpoints from anyone without an account, anyone can use up the rate
  limit or the daily cap and leave other operators' checkpoints unwitnessed
  until it resets;
- a wrong witness: nothing here lets a verifier detect Headless Oracle
  omitting receipts from a query, signing a false `received_at`, losing
  stored rows, or the theft of its signing key; receipts are not kept in a
  public append-only log with consistency proofs.

**Two honest cases verify TAMPERED:**

- A chain file exported before its session ended verifies TAMPERED once
  later checkpoints are witnessed, because it looks truncated; verify the
  complete session file.
- Two chains written under the same key and `session_id` (for example a
  reused `--session-id` with a new chain file) are a fork to the witness and
  verify TAMPERED.

Verifying against a sidecar file trusts the operator who supplied it. Only
querying the witness is independent of the operator.

Receipts are individually signed but the list is not: a mirror, proxy or
modified client can drop receipts, hiding a cut-off tail or rewrite after
the last receipt it returns. Pinning the witness key does not detect a
dropped receipt; query https://api.headlessoracle.com directly.

After a key rotation `/v5/keys` lists only the new key; receipts signed
under an earlier key verify only against a copy pinned before rotation.

The witness is operated by Headless Oracle, which also publishes the gate
software. It is independent of the operator, not of Headless Oracle. Anyone
who knows a (`kid`, `session_id`) pair can read that session's checkpoint
counts and times. No arguments, results or records are ever sent to the
witness.

### Showing a gate ran before an action

A receipt's `gate_receipt` (in its `gate` object) is its own `entry_hash`.
Outside evidence about it says these things and no more:

1. **A witness receipt.** A witnessed checkpoint whose `count` covers the
   gate receipt's entry is the witness's signed statement that it received
   that checkpoint at `received_at`, on the witness's clock. It says nothing
   about whether the gate's contents are true or whether the action was
   authorized.
2. **The transaction itself.** Where the action is an on-chain transaction,
   the strongest ordering evidence is to carry the gate receipt's
   `entry_hash` in the transaction itself, so the blockchain orders them
   without trusting any clock.
3. **Refusals.** A witness also records refusals (DENY receipts, once a
   checkpoint covers them), which leave nothing on-chain.

The served spec's `honest_limits` member
(https://api.headlessoracle.com/v1/witness/spec) states what a witness
receipt does and does not attest.

## Getting started

The goal of this section: take you from "I use Cursor or Claude Code
with my own MCP server" to "Chirindo is observing it, and I can
independently verify a receipt." Six steps, all done locally except
the verify hop which contacts a public JWKS endpoint.

### 1. Install

<!-- INSTALL: TBD at publish — clone-and-run vs npm install. Until the
     install mechanism lands, assume you have a local checkout of
     Chirindo built (`npm install && npm run build`) and a working
     absolute path to its `dist/cli.js`. The steps below write that
     path as `<ABSOLUTE-PATH-TO-CHIRINDO>`. -->

For now: `git clone` Chirindo, `npm install && npm run build`. Note the
absolute path to the repo — the next step uses it.

Generate the gate's signing identity:

```
node <ABSOLUTE-PATH-TO-CHIRINDO>/dist/cli.js init --dir <ABSOLUTE-PATH-TO-CHIRINDO>/.gate
# -> initialized chirindo at <abs path>
#    kid:          <rfc7638-thumbprint>
```

### 2. Configure your client

Copy the template that matches your MCP client into the right place:

- **Cursor**: `config-examples/cursor-mcp.json` → `<your-project>/.cursor/mcp.json` (or `~/.cursor/mcp.json`)
- **Claude Desktop**: `config-examples/claude_desktop_config.json` → `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

Then edit two things — see [`config-examples/README.md`](config-examples/README.md):

1. Replace every `<ABSOLUTE-PATH-TO-CHIRINDO>` with the absolute path to
   your Chirindo checkout.
2. Replace the line after `"--"` with **your real downstream MCP
   server's command** (the template ships with
   `npx -y @your-org/your-mcp-server` as a deliberately-invalid
   placeholder so a forgotten edit fails loudly). The documented
   default is `npx`-form on every platform; a `node` + absolute-path
   fallback is documented for clients whose `PATH` does not include
   `npx`.

Restart your client. You should see `my-server-gated` in its MCP
indicator. Chirindo is now wrapping your server.

### 3. Run

Use your agent as you normally would — anything that calls a tool on
your downstream server is being observed.

### 4. Observe

Each MCP session writes a chain file:

```
ls <ABSOLUTE-PATH-TO-CHIRINDO>/.gate/sessions/
```

One JSONL line per `tools/call`. Each line is a signed receipt covering
the request and its outcome. Inspect one:

```
head -n 1 <ABSOLUTE-PATH-TO-CHIRINDO>/.gate/sessions/<session-id>.jsonl
```

You'll see `event.type:"mcp_call"`, `event.decision:"allow"`,
`gate.result:"act"`, and an Ed25519 signature in `sig`.

### 5. Verify (the payoff)

```
node <ABSOLUTE-PATH-TO-CHIRINDO>/dist/cli.js verify \
  <ABSOLUTE-PATH-TO-CHIRINDO>/.gate/sessions/<session-id>.jsonl \
  --jwks
```

The bare `--jwks` form resolves the gate's public key from the
recorder's published JWKS document over HTTPS, then verifies every
record's signature and the hash-chain linkage. Expected output:

```
VALID — N entries, chain intact, all signatures verified, session <id>
verified under key <thumbprint> resolved from <source> (<origin>)
```

The second line is not decoration. It names **which** key verified the
chain and **where** that key came from (`flag`, `receipt-jwks`, `env`,
or `default`). Read it carefully, because:

> **Without a pin, `VALID` means the chain is *internally consistent
> under the key that was presented* — NOT that it was signed by Headless
> Oracle or anyone in particular.** A self-describing receipt tells the
> verifier where to fetch a key; on its own that only proves the chain
> agrees with *that* key.

To assert **who** signed, pin the key's RFC 7638 thumbprint:

```
chirindo verify <chain> --jwks --expect-thumbprint <tp>
# or a JSON trust file: --trust-file trusted-keys.json
#   ["<tp1>", "<tp2>"]   |   { "thumbprints": ["<tp1>"] }
```

`--expect-thumbprint` is repeatable. If the resolved key's thumbprint is
not in your pinned set, verification is `INVALID — untrusted_key` (exit
1) even when every signature checks out — the chain is consistent, but
not with a key you trust. The key binding is enforced *before* the
signature: every v1 receipt carries the signer's thumbprint in its
signed bytes, and the verifier compares the thumbprint of the key it
resolved to that committed value first, so a substituted key at the
`jwks_uri` cannot pass by verifying under itself.

You just verified, against a public key over the internet, what your
gate recorded — no trust in this repo, no trust in the binary you ran,
no trust in the client you used. The receipts **prove the gate fired
for each call and that the chain is recomputable from the signed
records**. They do **not** prove the action was "safe," only that the
decision is captured, signed, and **tamper-evident** (not tamper-proof:
an edit, a reorder, or a deletion other than cutting off the tail breaks
the hash chain and is caught by `chirindo verify`; cutting off the tail,
and a rewrite by the key holder, are caught only against witnessed
checkpoints, see [Witness](#witness)).

Offline alternative (no network): `--key <ABSOLUTE-PATH-TO-CHIRINDO>/.gate/identity.json`.

### 6. Enforce (opt-in)

Enforcement is one line in `policy.json`. Add a deny rule for a tool
on your downstream server that you'd rather never have happen:

```json
{
  "deny": [
    { "tool": "shell_exec", "reason": "blocked by policy" }
  ]
}
```

Restart your client. Ask the agent to call `shell_exec`. The downstream
**never receives the call**; the agent sees `isError: true`; a DENY
receipt with `event.decision:"deny"` and `gate.result:"halt"` is
appended to the chain. Run `chirindo verify` again — still VALID.

That's the observe→enforce transition: same gate, same receipts, one
extra line in `policy.json`.

## Honesty about what `isError: true` does and doesn't do

MCP's spec describes tool execution errors this way:
> Tool Execution Errors contain actionable feedback that language models
> can use to self-correct and retry with adjusted parameters.

So `isError: true` blocks the *action* (we never forward to the
downstream) but does NOT block the *agent* — the LLM may retry. Each
retry is independently evaluated by the gate and will be denied again
if it matches policy. The destructive side-effect is prevented; the
agent's attempt count is not capped. Productization may want a stronger
"this conversation cannot perform this action" mechanism than per-call
denial (e.g. a session-scoped lockout, or a protocol-error escalation
after N denials).

## What the harness proves and what it does NOT

### Proves (from the test suite)

- The proxy correctly parses and mediates newline-delimited JSON-RPC
  per [MCP stdio transport spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio).
- On DENY, the downstream server **never receives the call** — proven by
  the in-memory test asserting a flag set on the fake downstream's
  data handler stays false, AND by the spawn test asserting the fake
  server's "DESTRUCTIVE delete tool ran" stderr line never appears.
- ALLOW + DENY + FAIL-CLOSED each emit a receipt with `gate` populated
  per the schema, including the continuity invariant
  `gate.request_commitment == record.request_commitment`.
- The recorder's `verify` accepts every produced chain unchanged, and
  catches a tampered receipt with the legible `request_commitment
  mismatch` reason.
- The OS-pipe path works (spawn integration test).
- `chirindo verify` (CLI e2e test) reports VALID on a fresh chain,
  TAMPERED on a mutated chain, and exit 2 on conflicting `--key` +
  `--jwks` — same vocabulary the recorder uses, because it is the
  recorder's verify engine wired into the chirindo binary.
- The strict-ingest gate fails closed at the JSON parse boundary: an
  integer token outside the IEEE-754 safe range (`unsafe_number`) or a
  repeated object member at any depth (`duplicate_member`) is rejected
  *before* it is hashed, so a non-recomputable input can never enter a
  receipt or pass verification. The gate sits on both the receipt-writing
  hash path and `chirindo verify`'s chain parse
  (`strict-json.test.ts`, `conformance-strict-parse.test.ts`).

### Also verified (beyond the unit suite)

- **Conformance corpus, three-way and enforced.** The canonicalization
  (RFC 8785 / JCS) and RFC 7638 key-binding vectors are verified
  byte-for-byte across three implementations — Chirindo's own, an
  independent RFC 8785 library (`@truestamp/canonify`), and the external
  vector author — and the strict-ingest reject vectors fail closed with
  the expected reason. The binary enforces the *same* canonicalization
  and strict-ingest the vectors check; it is not a separate reference
  implementation. (Harness: `conformance/verify-harness/`.) This is
  deliberately **not** the claim that a published package "passes a
  conformance suite". That claim requires a re-verification run against
  the published artifact, and no such run has been made. Published
  versions and their dates are listed on npm
  (https://www.npmjs.com/package/@headlessoracle/chirindo?activeTab=versions).
  From 0.5.1 on, each release is published from its tag, and the release
  notes record a file-by-file comparison of the published tarball with that
  tag. Everything above was verified against the source tree, not against
  the tarball the registry serves.
- **Live fetch/verify, end-to-end.** The verify path was exercised by
  hand against the live published JWKS over HTTPS, and all three verdicts
  behaved as specified: a well-formed chain resolved its key and returned
  `VALID`; a receipt whose committed `key_thumbprint` was altered returned
  `INVALID (key_binding_mismatch)`, rejected *before* the signature check;
  and a chain signed by a key the JWKS does not publish returned
  `UNVERIFIABLE (issuer_key_unresolvable)` with no silent fallback to a
  default key.

### Does NOT prove

- **The real client honors `isError: true` as a block in the agent
  loop** — for clients other than the ones already tested. Cursor's
  agent halts cleanly on a deny-shaped result (proven live, see
  `SPIKE_RESULT.md`); whether Claude Desktop and other MCP clients
  surface it the same way to the LLM must be confirmed per client.
- **COSE output mode.** Receipts are currently JSON/Ed25519/base64url.
  A COSE_Sign1 variant is the productization step for ecosystem
  interop.
- **Argument-level policy.** The current policy matches on tool name
  (+ optional server label) only. Production needs argument matchers
  (e.g. "deny `shell_exec` whose `command` starts with `rm`").
- **Per-action UI** — the proxy emits stderr logs and writes JSONL;
  Claude Desktop / Cursor will not surface "this action was gated" in
  any operator-visible way without further integration.

## License

Apache-2.0. See `LICENSE`.
