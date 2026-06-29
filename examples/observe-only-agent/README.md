# Observe-only MCP agent + Chirindo (end-to-end example)

A complete, runnable example showing how to wire **Chirindo** in front of
a stdio MCP server as an **observe-only sidecar**: every consequential
tool call still executes against the downstream as before, and each one
emits a signed, hash-chained receipt you can independently verify.

This example uses the published [`@headlessoracle/chirindo`][npm] package
from npm — no local Chirindo checkout required. If `npm install` in this
directory succeeds, you have everything you need.

[npm]: https://www.npmjs.com/package/@headlessoracle/chirindo

---

## What's in this directory

| File | Role |
|---|---|
| `package.json` | Pins `@headlessoracle/chirindo`. Defines the three npm scripts you'll run. |
| `downstream-mcp-server.mjs` | A minimal stdio MCP server exposing three tools: `get_quote` (safe), `mock_swap`, `mock_send` (both "consequential" — in production they'd move money). |
| `policy.json` | `{ "deny": [] }` — observe-only. No tool calls are blocked; every call is recorded. |
| `harness.mjs` | Drives the gate as if it were Claude Desktop / Cursor: spawns `chirindo proxy`, talks MCP to it, calls `mock_swap`, closes the session. |
| `verify-latest.mjs` | Convenience: verifies the newest chain file against the live JWKS. |
| `cursor-mcp.json` | Drop-in Cursor config template (replace `<ABSOLUTE-PATH-TO-EXAMPLE>`). |
| `claude_desktop_config.json` | Same shape, for Claude Desktop. |
| `sample-chain/sample.jsonl` | A pre-recorded chain signed by a key already published on Headless Oracle's live JWKS — used in §5 below to demonstrate the `--jwks` verify path returning `VALID` end-to-end. |

---

## 1. Install

```
npm install
```

Pulls `@headlessoracle/chirindo` (and its single non-dev dependency,
`canonicalize`, for RFC 8785 JCS) from npm. The CLI lands at
`node_modules/.bin/chirindo`.

## 2. Initialize the gate's signing identity

```
npm run init
```

Generates a fresh Ed25519 keypair under `./.gate/`. Output:

```
initialized chirindo at <abs>/examples/observe-only-agent/.gate
  kid:          ed25519/<id>
  identity:     <abs>/.../identity.json
  private key:  <abs>/.../private-key.pem
```

`.gate/` is gitignored. The private key never leaves your machine.

## 3. Run the example agent

```
npm run harness
```

This spawns `chirindo proxy` with `downstream-mcp-server.mjs` as the
mediated child, then drives MCP over the proxy:

1. `initialize` → handshake
2. `tools/list` → returns `get_quote`, `mock_swap`, `mock_send`
3. `tools/call mock_swap` with `{ pair: "ETH/USDC", amount_in: 0.25, slippage_bps: 50 }`
4. close stdin → proxy shuts down

Real output (captured from this directory):

```
[chirindo] boot: cwd=<abs>/examples/observe-only-agent dir=<abs>/.gate chain=<abs>/.gate/sessions/<session-id>.jsonl
[chirindo] proxy up: server-label='observe-only-example' session=<session-id> chain=<abs>/.gate/sessions/<session-id>.jsonl
[harness] downstream exposes tools: get_quote, mock_swap, mock_send
[proxy] ALLOW tool='mock_swap' forwarded id=3
[downstream] CONSEQUENTIAL mock_swap executed: pair='ETH/USDC' amount_in=0.25
[harness] mock_swap response: swap submitted (mock): 0.25 of ETH/USDC — tx 0xMOCK<hex>
[harness] session_id=<session-id>
[harness] chain file: <abs>/.gate/sessions/<session-id>.jsonl
[chirindo] proxy exiting (1 receipts written)
```

The `CONSEQUENTIAL mock_swap executed` line comes from the downstream
itself — proof the proxy is **observing**, not blocking. Switching to
enforcement is one rule in `policy.json` (see §6).

## 4. Inspect the receipt

```
ls .gate/sessions/
cat .gate/sessions/<session-id>.jsonl
```

One JSONL line per `tools/call`. Pretty-printed, an `ALLOW` receipt for
the `mock_swap` call looks like this (this is the actual `sample.jsonl`
shipped in `sample-chain/`):

```json
{
  "v": "evidence.action/0",
  "seq": 0,
  "session_id": "jwks-demo-00000000-0000-0000-0000-000000000001",
  "ts": "2026-06-29T13:32:06.545Z",
  "agent": { "vendor": "chirindo", "version": "0.0.1" },
  "event": {
    "type": "mcp_call",
    "outcome": "executed",
    "server": "observe-only-example",
    "tool_name": "mock_swap",
    "args_hash": "sha256:7abf24ca72b407e2510f88c812b28f00845a4700f1263024cd0408a57732a659",
    "decision": "allow",
    "decision_source": "config",
    "result_hash": "sha256:39b5f73204e256bc13f077545967661ae1688a66125173723131989c7dc7aa2b"
  },
  "request_commitment": "sha256:cd50d3db0fb418c1db8883064759c6d795320b904260a063209ee7f2de0730a3",
  "gate": {
    "request_commitment": "sha256:cd50d3db0fb418c1db8883064759c6d795320b904260a063209ee7f2de0730a3",
    "gate_receipt": "sha256:d23e6d4737bb2a85ebcb6e7a55e10b8db001d8b1c7190df764039bde15c64927",
    "gate_family": "permit",
    "result": "act"
  },
  "prev_hash": "sha256:0f5ca40c5b98d9e883f8ec82a1cd68a018cd2515b92cbc3ba61e2e335668bb10",
  "kid": "ed25519/nQgjxdLXI3wJ",
  "sig": "FeKs3gJlCb1lGjJEl1b2LY4wMrFb5qpP2lZn0llbi4WO0VXaUPsF-6_zjRVo0xHrCwdg6BGxB9LzV6XitbzoBA"
}
```

Notes on the shape:
- `args_hash` is SHA-256 over **RFC 8785 JCS** of the tool arguments —
  meaning a verifier given the same arguments value derives byte-identical
  bytes regardless of key order, whitespace, or number formatting.
- `request_commitment` is mirrored into `gate.request_commitment` — the
  *continuity invariant*. The gate's decision is bound to the exact
  request it saw.
- `gate.gate_receipt` is self-anchored: the receipt's own `entry_hash`,
  recomputable by the verifier.
- `prev_hash` chains this entry to the previous one (or a deterministic
  genesis derived from `session_id` for `seq:0`).
- `sig` is Ed25519 over the canonical JCS bytes.

## 5. Verify the chain — `VALID` against the live JWKS

The interesting verification is the **public, network-resolved** one:
fetch the gate's public key from
`https://headlessoracle.com/.well-known/jwks.json` over HTTPS, then
verify every signature and chain link.

A chain verifies against the live JWKS only if its `kid` is on that
JWKS. The shipped `sample-chain/sample.jsonl` is signed by
`ed25519/nQgjxdLXI3wJ`, which is published — so the JWKS path returns
`VALID` for it without any setup on your part. Run:

```
node node_modules/@headlessoracle/chirindo/dist/cli.js verify \
  sample-chain/sample.jsonl --jwks
```

Real output (captured 2026-06-29):

```
VALID — 1 entries, chain intact, all signatures verified, session jwks-demo-00000000-0000-0000-0000-000000000001
```

This is the payoff. **Without trusting this repo, the example code, the
binary you ran, or the network path between you and the downstream MCP
server**, a third party with only the chain file and an internet
connection has confirmed:

- Every entry is signed by a key the JWKS publishes.
- The chain's hash linkage is intact end-to-end.
- The `gate.request_commitment` matches the entry's `request_commitment`
  (the gate saw and decided exactly the request that's in the receipt).

### Your own chain: offline verify

The chain produced by **your** `npm run harness` run is signed by the
freshly-generated key under `./.gate/identity.json`. That key isn't on
Headless Oracle's JWKS — and shouldn't be, until *you* publish it (see
the main repo's `docs/JWKS-OPS.md` for how a gate's key gets onto a
hosted JWKS, including the add-and-retain invariant). For now, verify
your own chain **offline** against your local public key:

```
npm run verify
```

That script wraps:

```
node node_modules/@headlessoracle/chirindo/dist/cli.js verify \
  .gate/sessions/<newest>.jsonl --key .gate/identity.json
```

Real output (captured running this example with a freshly-init'd
`.gate/`):

```
VALID — 1 entries, chain intact, all signatures verified, session 00000000-0000-0000-0000-000000000001
```

Same engine, same vocabulary; just a different public-key source.

### What the receipts prove (and don't)

**Prove**:
- The gate fired for each `tools/call` that produced a line.
- The chain is recomputable from the signed records: given any prefix,
  the next entry's `prev_hash` is the previous entry's canonical hash.
- The signing key matches the `kid` published in the verifier's key
  source (live JWKS or local identity.json).

**Tamper-evident, not tamper-proof**: any actor with the chain file can
rewrite history, but a mutation breaks the hash chain and is caught by
`chirindo verify` (which will print `TAMPERED — <reason>` and exit 1).

**Do NOT prove**: that an action was "safe," "correct," or "approved by
a human" — only that the decision was captured, signed, and tamper-
evident. The gate's `decision: "allow"` here just means policy.json had
no matching deny rule; an `ALLOW` receipt is *evidence the gate evaluated
this call*, not a stamp of safety.

## 6. Wire it into a real MCP client (Cursor / Claude Desktop)

The harness is a stand-in for a real MCP client. For the actual product
experience, drop the gate in front of the downstream by editing your
client's MCP server config. Templates ship in this directory.

### Cursor

Copy `cursor-mcp.json` to `<your-project>/.cursor/mcp.json` (or
`~/.cursor/mcp.json` for a user-global config). Replace every
`<ABSOLUTE-PATH-TO-EXAMPLE>` with the absolute path to this example
directory.

### Claude Desktop

Copy `claude_desktop_config.json` to:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Same substitution.

### What's in the template

```json
{
  "mcpServers": {
    "observe-only-example-gated": {
      "command": "npx",
      "args": [
        "-y", "@headlessoracle/chirindo", "proxy",
        "--policy",       "<ABSOLUTE-PATH-TO-EXAMPLE>/policy.json",
        "--server-label", "observe-only-example",
        "--dir",          "<ABSOLUTE-PATH-TO-EXAMPLE>/.gate",
        "--",
        "node", "<ABSOLUTE-PATH-TO-EXAMPLE>/downstream-mcp-server.mjs"
      ]
    }
  }
}
```

`npx -y @headlessoracle/chirindo` is the same launch path that worked in
this README — what the agent invokes is exactly what you tested. After
saving the config and restarting your client, `observe-only-example-gated`
appears as an MCP server. Any `tools/call` it routes will produce a new
line in `<example>/.gate/sessions/<session-id>.jsonl`.

## 7. Enforcement is one rule away

To convert observe-only into a real gate, edit `policy.json`:

```json
{
  "deny": [
    { "tool": "mock_send", "reason": "blocked: requires human signoff" }
  ]
}
```

Restart your MCP client (or re-run the harness). Now if the agent calls
`mock_send`, the downstream **never sees the call** — the proxy
synthesizes a tool-execution-error response (`isError: true`), and the
chain gets a `DENY` receipt with `event.decision: "deny"`,
`event.outcome: "denied"`, and `gate.result: "halt"`. `chirindo verify`
still returns `VALID` — the same shape, signed, chain-linked.

That's the entire observe → enforce transition. Same gate, same
receipts, one extra line.

---

## Gap (per the standing instruction)

The example demonstrates the JWKS verification path using a chain
**signed by a key already on the published JWKS**. A real integrator's
own gate cannot get an `--jwks VALID` until their public key is
published (manually, today, via the v5 Worker per
`docs/JWKS-OPS.md`). The publication step is a human-in-the-loop edit
of a different repo — that's the next thing to automate before this
example scales to a self-serve adopter flow. A hosted "bring your own
JWKS" path (point `RECORDER_JWKS_URL` at *your* domain) is the
agent-consumable answer; today it works at the protocol level (the env
var is honored end-to-end) but there's no tooling to help an integrator
stand up that endpoint.
