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
(not tamper-proof: any actor with the chain file can rewrite history,
but a mutation breaks the hash chain and is caught by `recorder verify`).
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
  is the receipt's own `entry_hash`, self-anchored for the spike.
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
                -- <downstream-command> [<args>...]
chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]
                [--expect-thumbprint <tp>]... [--trust-file <file>]
                [--max-skew-ms <ms>]
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
#    kid: ed25519/...
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
any actor with the chain file can rewrite history, but a mutation
breaks the hash chain and is caught by `chirindo verify`).

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
  conformance suite" — that waits for the 0.3.0 publish and a
  re-verification from the published artifact.
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
