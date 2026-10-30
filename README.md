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
notifications) pass through unmodified, with these exceptions. A
`tools/call` is recognised by its method alone, whatever its `id` or
`jsonrpc` members say, and these client lines are refused, never
forwarded:

- a `tools/call` with no `id`: a DENY receipt and no reply (a message
  without an id is a notification);
- a `tools/call` whose `id` is `null`, or is not a string or an integer:
  a DENY receipt and a JSON-RPC error `-32600` with `id: null`;
- a JSON-RPC batch (a JSON array): a DENY receipt for each `tools/call`
  in it and one `-32600` error (MCP removed batching in its 2025-06-18
  revision);
- a line that is not JSON (`-32700`), or that has a carriage return
  inside it (`-32600`);
- a message that names a member twice in one object, or whose top-level
  members include `jsonrpc`, `id`, `method` or `params` in another case
  (`"Method"`, or `"paramſ"` with U+017F), or that has two members
  differing only in case at the top level or in `params`; and a
  `tools/call` whose `params` holds `name`, `arguments` or `_meta` in
  another case: `-32600` with the request's id. A decoder that matches
  member names without regard to case, as Go's `encoding/json` does for a
  struct, could read these differently from the gate;
- a message with a member named `__proto__` at the top level or in
  `params`: `-32600` with the request's id, and a DENY receipt when the
  method of the message or of that member can be read as a `tools/call`.
  `JSON.parse` keeps `__proto__` as an inert data member, so the gate
  reads no method or name from it; but a downstream that copies the
  message into a fresh object (`Object.assign({}, msg)`, a `for...in`
  loop) sets that object's prototype from the member, so a method and
  `params` carried inside it read as the message's own;
- a message whose `method` is not a string (an array such as
  `["tools/call"]`, an object, a number, `true`, `false` or `null`), or is
  `tools/call` only after trimming white space or folding case
  (`"TOOLS/CALL"`, `"tools/call "`), or holds a control or format
  character: `-32600` with the request's id, and a DENY receipt when it
  can be read as a `tools/call`. A downstream that trims or folds the
  method, or that turns a method that is not a string into text
  (`String(method)`, or a lookup in a table of handlers keyed by method),
  could otherwise run a call the gate never checked;
- a `tools/call` with an integer outside JavaScript's safe range (beyond
  2^53 - 1), or a number too large for a double (such as `1e400`),
  anywhere in it: `-32600` with the request's id. The gate forwards an
  allowed call re-encoded from its parsed value, which would change such
  a number (`1e400` would become `null`);
- a `tools/call` nested more than 128 levels deep, too deep to
  canonicalize for a receipt: `-32600` with the request's id, and a DENY
  receipt whose `args_hash` is over the empty object. The gate computes a
  call's `args_hash` and `request_commitment` before forwarding it, so a
  call it could not record never reaches the downstream; a call at or
  within the limit runs as before;
- a `tools/call` with the `id` of a `tools/call` still waiting for its
  result: `-32600` with the request's id;
- a `tools/call` whose `params` is not an object, or whose `params.name`
  is not a non-empty string: `-32602` with the request's id; its DENY
  receipt names the tool `""`;
- a `tools/call` whose `params.name` begins or ends with white space, or
  holds a control or format character (Unicode categories Cc and Cf, such
  as NUL or a zero-width space) anywhere: `-32602` with the request's id.
  A downstream that trims names, or drops such characters, could read the
  name of a tool that a deny rule names;
- unless the proxy runs with `--allow-nonstandard-tool-names`, a
  `tools/call` whose `params.name` is outside MCP's rule for tool names:
  `-32602` with the request's id. MCP's
  [tools page](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
  (revision 2026-07-28, "Tool Names") says tool names SHOULD be 1 to 128
  characters long, and "The following SHOULD be the only allowed
  characters": ASCII letters, digits, underscore (`_`), hyphen (`-`) and
  dot (`.`). A downstream may normalize a name outside that rule into
  the name of a tool a deny rule names (NFKC turns the fullwidth
  `ｍｏｃｋ＿ｓｗａｐ` into `mock_swap`; invisible and combining characters
  can be dropped). With the flag such names are forwarded, deny rules
  compare them without regard to case only, and the proxy prints a
  warning to stderr at start.

"The request's id" is the message's `id` when the message is a request
(it has a `method` member, in any case), has one member named exactly
`id`, and that id is a string or an integer within JavaScript's safe
range; otherwise the error has `id: null`. A client's response to a
request from the server is answered with `id: null`, since its id is the
server's.

Each refusal writes one line to stderr. Every refused line that is a
`tools/call`, or that a downstream could read as one (matching member
names without regard to case, trimming, folding the case of or dropping
control and format characters from the method, reading a method that is
not a string as text, or reading a `__proto__` member as the message's
own members), gets one DENY receipt (a batch, one per such element);
lines that are not JSON or have a carriage return inside get none, nor
does a `tools/call` whose arguments hold a number too large for a
double, which no receipt can hash (its stderr line says so). A
`tools/call` refused for nesting too deep gets a DENY receipt over the
empty object. A refusal's DENY receipt reads like a policy denial
(`decision: "deny"`, `decision_source: "config"`): the reason is in the
stderr line only. Member names inside `params.arguments` and
`params._meta` are not checked for case or for a `__proto__` member; the
receipt's `args_hash` covers the arguments as the gate parsed them,
which is what it forwards.

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
- **`agent`** names the gate software that wrote the receipt: `vendor` is
  `chirindo` and, from 0.5.3, `version` is the version of the package that
  wrote it. Receipts written by 0.5.2 and earlier, like the example above,
  carry `"version": "0.0.1"` whatever the package version was.
- **`event`**: this is an ALLOW receipt (`outcome: "executed"`,
  `decision: "allow"`, `gate.result: "act"`). A DENY receipt instead reads
  `denied` / `deny` / `halt` and omits `result_hash` — there was no
  downstream response to hash. `args_hash` and `result_hash` are RFC 8785
  JCS + SHA-256 over the argument and result values (recomputable by any
  verifier, not `JSON.stringify`).
- **`gate.request_commitment`** MUST equal the top-level
  `request_commitment` (the continuity invariant); **`gate.gate_receipt`**
  is the hash of the receipt computed while `gate_receipt` still held the
  placeholder `"self"`; it is not the receipt's entry hash. The entry hash
  is computed from the signed record without `sig`,
  `"sha256:" + hex(SHA-256(JCS(record without "sig")))` (the value the next
  record's `prev_hash` carries), and that computed value is what ordering
  evidence should carry. An outside time for the receipt comes from a
  witnessed checkpoint whose `count` covers that entry (see
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
                [--allow-nonstandard-tool-names]
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

A rule matches if `tool` is the call's `name` without regard to case,
AND `server` (if present) is the proxy's `--server-label` exactly.
Without regard to case means under Unicode case folding and under the
full case mappings of upper and lower case: a rule for `delete_file`
also matches `DELETE_FILE`, `Delete_File` and `delete_ﬁle` (with the
ligature U+FB01), which a downstream that looks tools up without
regard to case could run as `delete_file`. Up to 0.5.2 the match was
exact. By default a name outside MCP's rule for tool names is refused
before any rule is applied (see the refusals above). Anything not matched by
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

A receipt's `gate_receipt` (in its `gate` object) is the hash of the receipt
computed while `gate_receipt` still held the placeholder `"self"`; it is not
the receipt's entry hash. The entry hash is computed from the signed record
without `sig`, `"sha256:" + hex(SHA-256(JCS(record without "sig")))`, and that
computed value is what ordering evidence should carry. Outside evidence about
a receipt says these things and no more:

1. **A witness receipt.** A witnessed checkpoint whose `count` covers the
   gate receipt's entry is the witness's signed statement that it received
   that checkpoint at `received_at`, on the witness's clock. It says nothing
   about whether the gate's contents are true or whether the action was
   authorized.
2. **The transaction itself.** Where the action is an on-chain transaction,
   the strongest ordering evidence is to carry the gate receipt's entry
   hash, computed as above, in the transaction itself, so the blockchain
   orders them without trusting any clock.
3. **Refusals.** A witness also records refusals (DENY receipts, once a
   checkpoint covers them), which leave nothing on-chain.

The served spec's `honest_limits` member
(https://api.headlessoracle.com/v1/witness/spec) states what a witness
receipt does and does not attest.

A worked example of all three, run against production with an offline
checker, is in [`examples/ordering-evidence/`](examples/ordering-evidence/).

## Chirindo trial recorder

The trial recorder lets a merchant's checkout service record each agent cart
as a signed, hash-chained entry and have the witness countersign checkpoints
of that chain. It is the recording and witnessing half of the gate, with
nothing blocked: `record()` is synchronous, never throws and returns a plain
object; every call that makes no entry is recorded in `gaps.ndjson`, or, if
that file cannot be written, in one stderr line; the recorder never fails
your checkout.

### What it does not show

These are limits of the evidence an entry can support, copied verbatim from
the evidence verifier (`examples/evidence-bundle/lib/limits.mjs`):

- **L1.** A gate entry is the operator's own signed statement of what its gate saw and decided. The bundle does not show that a decision was wise, that the agent read the instruction correctly, or that any member's contents are true.
- **L3.** The witness receipt is Headless Oracle's signed statement that at received_at it was shown a checkpoint signed by the key with that thumbprint; it is only as reliable as Headless Oracle and its signing key. The witness is operated by Headless Oracle, which also publishes the gate software: it is independent of an operator other than Headless Oracle, not of Headless Oracle.
- **L5.** This version checks instructions only in the minimal profile of Annex A. Verifiable Intent and AP2 members are carried with their digests and marked PRESENT, not verified.
- **L7.** Times on the principal's, the issuer's, the operator's and Headless Oracle's clocks are those parties' statements, and the block timestamp is set by the block producer within the chain's rules. Only the orderings that need no clock rest on signatures and hashes alone.
- **L24.** v0.10. For a card payment, the payment proof is the card network's authorization record, which the issuer holds; this bundle neither carries nor verifies it. What this verdict shows is whether the decision and the order the gate recorded were witnessed before the charge's authorization time as stated, and whether that order matches the stated charge: the stated charge and its time are the statements of the person running the verifier, taken from the processor's records.
- **L25.** v0.10. The committed order is the agent's statement at decision time, as the gate recorded it: its merchant, items, prices, refundability, dates and places are what the agent's call named. The bundle does not show that the merchant fulfilled that order, that the charge was for it beyond the fields compared, or that an item's attributes are true.

### What it records, and where

Each `record()` that passes its checks writes one entry. Its tool name is
`record_agent_cart`, its decision `allow`, and its arguments are exactly
`{ "order": <order> }`, plus `"agent_context": <agent_context>` when given:
the place where spec v0.10 section 4.3, "The committed order", reads the
order. Entries are the format the proxy writes, so
`chirindo verify <chain> --key <dir>/identity.json` reads them unchanged.
The chain holds only hashes; the arguments are kept beside it, one file per
entry, because the evidence format needs them.

Under the data directory (`chirindo init --dir <dir>` creates its identity;
the recorder never creates keys):

| path | holds |
|---|---|
| `chains/<session_id>.jsonl` | this process's chain |
| `chains/<session_id>.jsonl.witness.ndjson` | its witness sidecar |
| `chains/<session_id>.lock` | the process id, while the recorder runs |
| `args/<session_id>/<floor(count/1000)>/<count>-<32 hex>.json` | retained arguments `{ args_hash, order_ref_sha256, call_seq, arguments }` |
| `gaps.ndjson` | one line per call that made no entry |
| `witness-timing.ndjson` | one line per witness POST and per `awaitWitness` |

The 32 hex characters are the start of `args_hash` after `sha256:`; no file
name holds a colon. Directories are created 0700 and files 0600 where the OS
honours modes. Each recorder process writes its own chain under
`<dir>/chains/`, so finding an order means looking across all of them.

`record({ order_ref, order, agent_context?, call_seq? })` returns
`{ ok: true, entry_hash, args_hash, count, session_id }`, or
`{ ok: false, reason, paths, session_id }`, where `paths` holds RFC 6901
pointers of the members that decided it. Member names that are plain
identifiers (`[A-Za-z0-9_-]`, at most 64) are written into `paths` as they
are, any other name as `~invalid-key`; values never are. The input is
checked, then copied once into a snapshot that every later check and the
write use. The checks run in this order, and the first failure decides:

| reason | when |
|---|---|
| `invalid-input` | not a plain object of JSON values within 256 KB (integers within the safe range) |
| `refused-field` | a member outside the allow-list below, at any depth |
| `invalid-order`, `invalid-input` | a screened free-text field is longer than 256 characters: an item's `name`, `location` or `category` (`invalid-order`), or `agent_name` (`invalid-input`); checked before it is screened |
| `refused-value` | a free-text field holds a card-number-like or e-mail-like token (below) |
| `invalid-input` | `order_ref` is not 1 to 256 printable ASCII characters, `call_seq` not a non-negative integer, or an `agent_context` value is outside its format |
| `invalid-order` | the order is not the committed order of spec section 4.3 |
| `write-failed` | the retained file or the entry could not be written (a retained file is removed when its entry could not be, and a part-written line is cut from the chain), or the chain is broken (below) |
| `internal` | anything else, including a call after `close()` |

If a part-written line cannot be cut from the chain, the chain is broken:
one gap line with reason `chain-broken` says so, and every later `record()`
in that process is refused with `write-failed`. That chain's file then ends
in the part-written line, so `chirindo verify` rejects it.

Allowed members: `order_ref`, `order`, `agent_context`, `call_seq`. In
`agent_context`: `channel` (`acp`, `ucp`, `ap2`, `mcp`,
`stripe-approval-hook` or `other`); `platform_signature` (`header_name`,
`value`, optional `key_id` and `alg`, each at most 4,096 characters);
`payment_token_limits` (`currency`, three upper-case letters;
`max_amount_minor`, a decimal string with no sign and no leading zero;
optional `expires_at`, an RFC 3339 UTC time naming a real instant, so
`2026-02-30T00:00:00Z` and `24:00:00` are refused); `agent_name` (at most 256
characters); `mandate` (`format` `ap2`, `vi` or `other`; `value` at most
65,536 characters). In the order, the members of spec section 4.3, with an
item `name` of at most 256 characters.

Screening reads only the free-text fields: an item's `name`, `location` and
`category`, and `agent_context.agent_name`. A card-number-like token is 13 to
19 contiguous digits, or digit groups of 3 to 6 digits joined by one kind of
separator throughout (single spaces or single hyphens), 13 to 19 digits in
all, whose first digit is 2 to 6 and which passes the Luhn check, standing
alone (not touching a letter or digit). In an item's `name`, `location` and
`category` an e-mail-like token (`local@domain.tld`) is refused too.
Identifiers, references, SKUs, amounts, dates and the other `agent_context`
fields are your own values and are never screened. Screening is a guard
against a mistake, not a data-protection control: do not put personal data
in an order.

### When to call it

Each time your code creates or changes the agent's cart, and once more just
before your code calls your payment processor. Inside a payment platform's
approval hook, pass the cart only, and keep any witness wait inside that
hook's own time limit.

Pass `call_seq`, a counter your code increments for every call, so that the
numbers that never arrived can be found: `call_seq` is kept with each entry
(in its retained file) and with each failure (in its gap line). Your counter
restarts when your process restarts, so the numbers repeat across restarts.

`awaitWitness(entry_hash, maxMs)` resolves, never rejects, with
`{ ok: true, received_at, covering_count }` once a verified witness receipt
covers the entry, or `{ ok: false, reason }` with `timeout` (at `maxMs`,
capped at 3,500), `no-witness`, `unknown-entry` (not one of this process's
last 10,000 entries), `stopped`, `closed` or `internal`. At most one witness POST is in
flight; a new head waits while one is, and the later checkpoint covers the
heads in between. So the record made just before the charge can wait up to
one witness round trip more than its own POST: allow for that in your wait
limit. On `quota_exceeded`, `payment_required`, `invalid_key` or
`witness_plan_required` the recorder stops sending until 00:00 UTC or a
restart, and says so once in the log.

`close(timeoutMs)` (default 5,000) sends a final checkpoint of the head
unless it is already witnessed or in flight, and waits at most that long; a
POST still unanswered is recorded as `witness_timeout`, and a head never
sent because sending was stopped as `witness_stopped`.

After a restart, the recorder looks at up to 10 earlier chains in the data
directory, signed by this identity, that no running recorder holds and that
have not changed for 10 minutes, and sends one checkpoint for each head that
no receipt covers; after each of its own POSTs, one such head goes before
its next own head. It reads only a chain's first line and last complete
line (a torn last line is ignored): it does not verify the lines between.
Such a checkpoint's receipt carries a late `received_at`, and shows that the
head existed by then; it does not show that the chain verifies. A stale lock
left by a crashed process can make that session look live if its process
id has been reused; such a chain is then skipped.

### What reaches the witness

Each checkpoint POST carries the checkpoint members `v`, `type`,
`session_id`, `count`, `last_entry_hash`, `ts`, `kid` and `sig`, and the
gate's public key; the account key, when one is configured, as
`Authorization: Bearer` on that POST only; and, as with any HTTPS request,
your server's IP address. Never an order, an argument or an entry. The
timing file holds counts, hashes, times and outcomes only, never a key, a
signature or an error body.

### Gaps

Every `record()` that makes no entry appends a line to `gaps.ndjson`:
`{ ts, session_id, order_ref_sha256, call_seq, reason, paths }`. Some
failures the recorder never sees: your own timeout, the recorder
unreachable, your process restarting. Count your own failed calls and report
each with `reportGap({ order_ref, call_seq?, reason })` (or `POST /gap`),
where `reason` is `caller-timeout`, `unreachable` or `other`. If a gap line
cannot be written, the call still returns, and one stderr line says so.

### Erasure

```
chirindo trial-erase --dir <dir> --args-hash <sha256:hex>
chirindo trial-erase --dir <dir> --order-ref <order_ref>
```

Removes every retained file for that `args_hash`, or for that order
reference (matched by its SHA-256), and prints one JSON line per file, then
`{"removed_count": N}`. It never touches a chain, a sidecar, `gaps.ndjson`
or `witness-timing.ndjson`, and empty retained-file directories may remain.
After erasure:

- the chain still shows that an entry existed, and its hashes;
- a hash of short or guessable content can itself identify that content;
- a gap line still holds the SHA-256 of an order reference and its
  `call_seq`;
- the witness's receipts (count, session id, head hash, times) are kept by
  Headless Oracle;
- the evidence format can no longer be completed for that record.

A retained file whose entry was never appended (the process stopped between
the two writes) is an orphan: no entry names its hash, so it is evidence of
nothing.

### The loopback endpoint

```
chirindo trial-recorder --dir <dir> --server-label <name> [--port 7419] \
  [--host 127.0.0.1|::1] [--token-file <file>] [--jwks-uri <https-url>] \
  [--witness <base-url> --witness-key <hex|jwk-file> --witness-name <name>] \
  [--witness-account-key-file <path>]
```

It prints `{"listening":"http://127.0.0.1:<port>"}` once bound and serves
`POST /record`, `POST /await` (`{ "entry_hash", "max_ms" }`), `POST /gap`
and `GET /health`. Call `http://127.0.0.1:<port>`, not `localhost`: the
`Host` header must name the bound address and port. Each POST needs
`Content-Type: application/json`; bodies are capped at 256 KB and a
duplicate member is refused. A reply is 200 only when its `ok` is true; a
refused input is 422, an `awaitWitness` timeout 504, and a failure on the
recorder's side 503, each with the result object. **Without `--token-file`,
any process on this host can call it**; with one, each POST needs
`Authorization: Bearer <token>`. `GET /health` needs no token and shows the
session id.

### In your service

The trial recorder is not yet in a published npm release:
`@headlessoracle/chirindo` 0.5.3 does not include it. Until a release,
install it from a build of this repository or from a tarball made with
`npm pack`.

Create one recorder per process. The package is ESM only:

```js
import { createTrialRecorder } from "@headlessoracle/chirindo/trial-recorder";

const recorder = createTrialRecorder({
  dir: "/var/lib/chirindo",
  serverLabel: "checkout",
  witness: { baseUrl: "https://api.headlessoracle.com", name: "headlessoracle.com", pinnedKey: "<hex>" },
});
const r = recorder.record({ order_ref: "R-1001", order, call_seq: n++ });
// ... on shutdown
await recorder.close();
```

From CommonJS, load it with
`const { createTrialRecorder } = await import("@headlessoracle/chirindo/trial-recorder")`.
`createTrialRecorder` throws on invalid options or a missing identity;
nothing after it throws. The package now has an `exports` map, so deep
imports such as `@headlessoracle/chirindo/dist/...` no longer resolve; only
`@headlessoracle/chirindo/trial-recorder`,
`@headlessoracle/chirindo/purchase-check` and
`@headlessoracle/chirindo/package.json` do. The `chirindo` command is
unchanged.

## Purchase check (before you charge)

The purchase check is for a payment provider whose agents buy for its customers. Before minting a credential or charging, the provider's code sends the instruction it signed for its customer and the order to Chirindo. Chirindo answers allow or deny with the reasons, and writes each decision it makes on a well-formed request as a signed, hash-chained receipt before it answers.

The purchase check is not yet in a published npm release: `@headlessoracle/chirindo` 0.5.3 does not include it. Until a release, install it from a build of this repository, or from a tarball made with `npm pack`.

### What it claims, and its limits

> Before you charge, Chirindo checks each purchase against the instruction you signed for your customer, refuses one outside it, and keeps a signed, chained record of each decision it makes and its reason.

That claim holds only with these five limits:

- **Limit 1.** It checks only purchases the provider sends through it. A purchase made around it is not checked, and a deny binds only if the provider obeys it. A repeat allow is not a second purchase.
- **Limit 2.** The instruction is signed by the provider, stating what its customer approved. Chirindo does not see or verify the customer's approval. The provider also holds the gate key. The record is the provider's own signed, chained record, with checkpoints sent to Headless Oracle's witness.
- **Limit 4.** Spend is not summed across purchases. Each purchase is checked against the cap and uses are counted, so an instruction allows up to max_uses purchases, each up to the cap. Counts are shared only within one directory and one process.
- **Limit 5.** The order is what the caller states. The cap is judged on its stated total, and Chirindo does not see the charge. Only an after-the-fact comparison with the charge shows a mismatch (L24).
- **Limit 6.** These leave no receipt: input refused at step 1, record-failed, and a repeat (it returns the earlier receipt). `evaluatePurchase` is a dry run, not a record.

The full list:

1. It checks only purchases the provider sends through it. A purchase made around it is not checked, and a deny binds only if the provider obeys it. A repeat allow is not a second purchase.
2. The instruction is signed by the provider, stating what its customer approved. Chirindo does not see or verify the customer's approval. The provider also holds the gate key. The record is the provider's own signed, chained record, with checkpoints sent to Headless Oracle's witness.
3. The description is carried and signed over, not checked. The v0.1 mappers set no item or category limits.
4. Spend is not summed across purchases. Each purchase is checked against the cap and uses are counted, so an instruction allows up to max_uses purchases, each up to the cap. Counts are shared only within one directory and one process.
   - Start-up re-reads every chain in `purchase-chains/` to rebuild the counts, so start-up time grows with history.
5. The order is what the caller states. The cap is judged on its stated total, and Chirindo does not see the charge. Only an after-the-fact comparison with the charge shows a mismatch (L24).
6. These leave no receipt: input refused at step 1, record-failed, and a repeat (it returns the earlier receipt). `evaluatePurchase` is a dry run, not a record.
7. Today's evidence-bundle verifier does not read `check`. In a bundle a deny shows only as a record that cites no instruction; its reason is read from the receipt itself. A verifier that reads it is planned.
8. The witness is Headless Oracle's own, not independent (L3).
9. The MCP gate does not check purchases (v0.2).
10. A later evidence bundle judges the instruction's time window at the charge's authorization time, as the processor states it, not at the time of the check. A charge authorized after valid_until shows as outside the instruction, even when the check allowed it in time.

### The API

The package is ESM only. Create one check per data directory and process:

```js
import { createPurchaseCheck } from "@headlessoracle/chirindo/purchase-check";

const pc = createPurchaseCheck({ dir: "/var/lib/chirindo" }); // after `chirindo init --dir /var/lib/chirindo`
const r = pc.check({ instruction: instructionJsonText, order });
if (r.decision === "allow") {
  // charge: r.receipt is the signed receipt of this decision, already written
}
// ... on shutdown
await pc.close();
```

**`createPurchaseCheck({ dir, serverLabel?, jwksUri?, witness?, now? })`**
- It loads the identity `chirindo init` made, and refuses a kid that is not the RFC 7638 thumbprint of its key.
- It takes an exclusive lock on the directory.
- It verifies every chain in `<dir>/purchase-chains/`.
- It throws on invalid options, a held or stale lock, or a chain that does not verify. Nothing after it throws.

**`check({ instruction, order })`** is synchronous and never throws.
- `instruction` is the instruction's JSON text, so that a duplicate member can be detected. It is an Annex A.3 `signed-instruction-ed25519/0.3` instruction with card limits only.
- `order` is the committed order of spec 4.3.
- It returns `{ decision, reasons, exceeded, card_limits, instruction_sha256, at, receipt, repeat }`.
- An allow is returned only after its receipt is written. Any failure to write gives deny `record-failed`: alone on what would have been an allow, after the deny's own reasons on a deny.
- An identical order checked again under the same instruction, merchant and order reference returns the earlier allow, with `repeat: true`. It writes nothing and uses nothing.

**The receipt.** It is an ordinary chirindo receipt, so `chirindo verify` reads it. It has `tool_name` "check" and a top-level `check` member holding the decision, its reasons and the order's digest. On an allow, `event.outcome` is "executed", which on a purchase-check receipt means "the check allowed". The arguments of each receipt are kept in `<dir>/purchase-args/`.

**`evaluatePurchase(instruction, order, { kid, at, usesSoFar })`** is the same judge as a dry run. It writes nothing and consumes no use. Its answer is neither a decision nor a record, and a provider must not charge on it.

**`signInstruction(body, privateKey)`** signs an instruction body with the provider's Ed25519 key, as principal.

### The HTTP form

```
chirindo purchase-check --dir <dir> --token-file <file> [--port 7420] \
  [--host 127.0.0.1|::1] [--server-label <name>] [--jwks-uri <https-url>] \
  [--witness <base-url> --witness-key <hex|jwk-file> --witness-name <name>]
```

It prints `{"listening":"http://127.0.0.1:<port>"}` once bound, and serves `POST /v1/check` with the body `{ "instruction": "<JSON text>", "order": { ... } }`.

**Requests:**
- The token is required: each request needs `Authorization: Bearer <token>`.
- Call `http://127.0.0.1:<port>`, not `localhost`: the `Host` header must name the bound address and port.
- The body needs `Content-Type: application/json`. It is capped at 256 KB, read as UTF-8 that must be valid, and parsed strictly.
- No CORS header is sent.

**Status codes:**

| Code | Meaning |
|---|---|
| 200 | A decided answer: an allow, a deny with a receipt, or a repeat. |
| 422 | A refused input, with no receipt. |
| 503 | `record-failed`. |
| 400 | Invalid UTF-8 or JSON. |
| 401 | No token, or a wrong one. |
| 403 | The Host header is wrong. |
| 404 | Any path other than `/v1/check`. |
| 405 | Any method other than POST. |
| 413 | The body is over 256 KB. |
| 415 | The body is not `application/json`. |

The CLI and the library cannot run on one directory at once, because of the lock.

### A stale lock

If a process holding the directory ends without closing (a crash, a kill), `<dir>/purchase-chains/.lock` remains. The next start refuses and names the lock's pid and path. Check that no process holds the directory, then remove that file. The lock is never removed automatically.

### Reasons

Every reason matches exactly one pattern of the frozen vocabulary of `purchase-check/0.1`, published in [docs/purchase-check-reasons.md](docs/purchase-check-reasons.md) and exported as `PURCHASE_REASON_PATTERNS`. A change to the vocabulary is a new `check.v`.

### Mappers

The mappers follow each provider's public documentation as read on 30 Oct 2026; no provider has reviewed or endorsed them.

They build an instruction body from a provider's own approval object. The provider then signs it as principal, with `signInstruction`. The functions:
- `mapCrossmintOrderIntent` takes an order intent.
- `mapBasisTheoryAllowance` takes an allowance.
- `mapPravaMandate` takes a mandate together with the session that set it up.

Each takes `{ principalKey, agentKids, maxUses, approvedAt, iat? }`.

**What a mapper sets:**
- An amount becomes minor units by a fixed currency table (`CURRENCY_EXPONENTS`). An unknown currency refuses. Precision finer than the minor unit is floored, so the cap is never above what was approved.
- A merchant becomes the origin of its URL (`merchantIdOf`), and the provider must build `order.merchant_id` with the same function.
- Times become Z instants.

**What a mapper refuses:** each refusal is a `MapperError` with a stable code. Among them: an unknown currency, a URL with userinfo or a scheme other than http or https, a time that does not parse, and a Prava session with more than one merchant entry.

**For Prava:** `valid_until` is the earlier of the mandate's `validUntil` and the approval time plus the session's `effective_until_minutes` (default 15). For a recurring mandate, that can make an instruction valid for minutes, narrower than the mandate itself. A caller may sign a fresh instruction for each charge.

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
