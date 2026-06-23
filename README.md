# mcp-gate-spike

**Fail-closed cryptographic gate at the MCP `tools/call` boundary.** A stdio
MCP proxy that intercepts `tools/call` requests from a real MCP client
(Claude Desktop, Cursor), evaluates a policy, and either forwards the
call to the real downstream server (ALLOW) or returns a tool-failure
response WITHOUT forwarding (DENY) — emitting a signed receipt in
either case.

This is a **spike**. Its purpose is to de-risk the single greenfield
unknown on the critical path: can a stdio MCP proxy emit signed
recomputable receipts AND have a real MCP client honor its DENY as a
block? The receipt format and signing reuse the existing
[`recorder`](../recorder) engine — no reimplementation of JCS, hashing,
or Ed25519.

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
   mcp-gate proxy   ◀── policy.json (deny rules)
        │
        ▼ stdio
  downstream MCP server (the real one)
```

The client launches `mcp-gate proxy` as its MCP server. The proxy spawns
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
per-session JSONL chain file. The receipt is a regular
`evidence.action/0` record from the recorder schema, with the `gate`
block populated:

```jsonc
{
  "v": "evidence.action/0",
  "seq": 0,
  "session_id": "<uuid>",
  "ts": "...",
  "agent": {"vendor": "mcp-gate-spike", "version": "0.0.0"},
  "event": {
    "type": "mcp_call",
    "outcome": "denied",                     // or "executed" on ALLOW
    "server": "<server-label>",
    "tool_name": "delete",
    "args_hash": "sha256:...",               // SHA-256 of JSON-stringified arguments
    "result_hash": "sha256:...",             // present only on ALLOW
    "decision": "deny",                      // or "allow"
    "decision_source": "config"
  },
  "request_commitment": "sha256:<a>",        // SHA-256 over JCS(request_descriptor)
  "gate": {
    "request_commitment": "sha256:<a>",      // MUST equal record.request_commitment
    "gate_receipt": "sha256:<self entry_hash>",  // self-anchored for the spike
    "gate_family": "permit",
    "result": "halt"                         // "act" on ALLOW
  },
  "prev_hash": "sha256:...",
  "kid": "ed25519/<fingerprint>",
  "sig": "<base64url Ed25519>"
}
```

The chain verifies via `recorder verify` (no code change to the
recorder) — same hash chain, same signature scheme, same canonical
bytes. Cross-tool interop is the point: the gate's output is evidence
the recorder's verifier already understands.

## Usage

```
mcp-gate init [--dir <path>]
mcp-gate proxy --policy <file> --server-label <name>
               [--dir <path>] [--chain <file>] [--session-id <id>]
               -- <downstream-command> [<args>...]
```

Defaults: `--dir = ./.gate/`, identity at `<dir>/identity.json`, chain
at `<dir>/sessions/<session-id>.jsonl`.

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
a deny rule is allowed. **Fail-closed**: a missing, unreadable, or
malformed policy file denies all calls.

## Running locally (no MCP client required)

```
# In the recorder dir, first time:
cd ../recorder && npm install && npm run build

# In this dir:
cd ../mcp-gate-spike && npm install
npm test           # 7 tests, all green
```

The test suite exercises every branch the brief lists:

- `test/proxy-allow.test.ts` — ALLOW round-trip, ALLOW receipt verifies.
- `test/proxy-deny.test.ts` — DENY blocks the call, downstream never sees
  it, isError returned, DENY receipt verifies.
- `test/proxy-failclosed.test.ts` — null policy and thrown policy both
  produce DENY.
- `test/tamper.test.ts` — mutating a recorded receipt is caught by
  `recorder verify` as `request_commitment mismatch`.
- `test/proxy-spawn.test.ts` — same ALLOW + DENY, but with the
  downstream spawned as a real OS subprocess via the production
  `spawnRealDownstream` path.

## Verifying against a REAL MCP client (the headline question)

The spike's headline question is: **does a real MCP client honor a
proxy-returned `isError: true` response as a block?** The harness above
proves the proxy implements the contract correctly; the real-client
question can only be answered by running it against Claude Desktop or
Cursor. This requires hand-on-keyboard.

### Setup (one-time)

```
# From the spike root:
mkdir -p .gate
node /abs/path/to/mcp-gate-spike/dist/cli.js init --dir .gate
# -> initialized mcp-gate at <abs path>
#    kid: ed25519/...

# Build first:
npm run build

# Create policy.json:
echo '{"deny":[{"tool":"delete","reason":"blocked by policy"}]}' > policy.json
```

### Claude Desktop configuration

Add to `claude_desktop_config.json` (its location:
`~/Library/Application Support/Claude/claude_desktop_config.json` on
macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "everything-gated": {
      "command": "node",
      "args": [
        "C:/abs/path/to/mcp-gate-spike/dist/cli.js",
        "proxy",
        "--policy", "C:/abs/path/to/mcp-gate-spike/policy.json",
        "--server-label", "everything",
        "--dir", "C:/abs/path/to/mcp-gate-spike/.gate",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-everything"
      ]
    }
  }
}
```

Restart Claude Desktop. The `everything-gated` server should appear in
the MCP indicator.

### Cursor configuration

Cursor's MCP config lives at `<project>/.cursor/mcp.json` (or
`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "everything-gated": {
      "command": "node",
      "args": [
        "C:/abs/path/to/mcp-gate-spike/dist/cli.js",
        "proxy",
        "--policy", "C:/abs/path/to/mcp-gate-spike/policy.json",
        "--server-label", "everything",
        "--dir", "C:/abs/path/to/mcp-gate-spike/.gate",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-everything"
      ]
    }
  }
}
```

### Note on `npx` as the downstream command (Windows)

The stock form above — `npx -y @modelcontextprotocol/server-everything`
as the passthrough — is the **primary** configuration on every
platform. On Windows it now works without any client-side massaging
because `spawnRealDownstream` defaults to `shell: true` on `win32`,
which is the only way Node will resolve a `.cmd` shim (`npx.cmd`,
`yarn.cmd`, `pnpm.cmd`, `tsx.cmd`) since the CVE-2024-27980 hardening.
On Linux and macOS `npx` is a real script with a shebang, so the same
config string also runs directly.

**Fallback**: if `npx` is unavailable in your client's `PATH` (Cursor
and Claude Desktop launch their MCP servers from a process tree whose
`PATH` is *not* always your shell's `PATH` — Cursor in particular has
been observed missing the npm global bin on Windows), pass the
downstream's installed entry point directly with Node, bypassing
shim resolution:

```jsonc
// substitute the absolute path your `npm install` produced under
// `node_modules/@modelcontextprotocol/server-everything/dist/index.js`
"--",
"node", "C:/abs/path/to/mcp-gate-spike/node_modules/@modelcontextprotocol/server-everything/dist/index.js"
```

This is a workaround for client-PATH problems, not a workaround for
shim resolution — that's fixed in the proxy itself.

### Decisive runs

After the client is configured:

1. **ALLOW**: ask the agent to call a non-denied tool (e.g. the
   `everything` server's `echo` tool). Expect: the agent receives the
   real result; an ALLOW receipt appears in
   `.gate/sessions/<session>.jsonl`; `node /abs/path/to/recorder/dist/cli.js verify .gate/sessions/<session>.jsonl --key .gate/identity.json` says VALID.

2. **DENY** (the headline): ask the agent to call the `delete` tool.
   Expect: the agent sees the tool as failed (`isError: true`); the
   action is NOT performed by the downstream; a DENY receipt is
   written; verify says VALID. **Confirm by inspection** that the
   downstream server's stderr / log does NOT show the deletion.

3. **FAIL-CLOSED**: corrupt or remove `policy.json` while the proxy is
   running, then ask the agent to call any tool. Expect: every call
   denied; receipts written with `gate.result: "halt"`.

4. **TAMPER**: with the proxy stopped, edit a receipt in the chain
   file (change a `tool_name` or `args_hash`). Run
   `recorder verify .gate/sessions/<session>.jsonl --key .gate/identity.json`.
   Expect: `TAMPERED — entry K: request_commitment mismatch`, exit 1.

**Report back**: which of (2)'s behaviors the real client exhibits — does
the LLM treat `isError: true` as the action having failed, does it
retry with different args, does the user see the failure clearly? This
is the single most important finding from the spike, and only a real
client can produce it.

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

### Proves (from the 7 green tests)

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

### Does NOT prove (hand-on-keyboard required)

- **The real client honors `isError: true` as a block in the agent
  loop.** The local harness shows the proxy returns the correct bytes;
  whether Claude Desktop or Cursor surfaces it to the LLM as a failed
  call and what the LLM does next can only be observed against the
  real client.
- **Cross-machine receipt verifiability.** The verifier still resolves
  `kid` only via a locally-pinned identity file. A JWKS resolver via
  `.well-known/` is the next foundational step (carried over from the
  recorder MVP gap).
- **COSE output mode.** Receipts are currently JSON/Ed25519/base64url.
  A COSE_Sign1 variant is the productization step for ecosystem
  interop.
- **Argument-level policy.** The spike's policy matches on tool name
  (+ optional server label) only. Production needs argument matchers
  (e.g. "deny `shell_exec` whose `command` starts with `rm`").
- **Per-action UI** — the spike emits stderr logs and writes JSONL;
  Claude Desktop / Cursor will not surface "this action was gated" in
  any operator-visible way without further integration.

## License

Apache-2.0. See `LICENSE`.
