# Observe-only MCP agent + Chirindo (end-to-end example)

A complete, runnable example showing how to wire **Chirindo** in front of
a stdio MCP server as an **observe-only sidecar**. Every consequential
tool call still executes against the downstream as before; each one
emits a signed, hash-chained receipt you can independently verify.

This iteration of the example demonstrates **self-describing receipts**:
the gate stamps the URL of its own published JWKS into every receipt's
signed bytes, so a stranger holding only the chain file can fetch the
gate's public key from a location *the adopter controls* and verify —
with Headless Oracle **not in the trust path**.

> Build dependency: this example references the in-repo `dist/cli.js`
> directly (`node ../../dist/cli.js ...`) — `jwks_uri`, `--jwks-uri`,
> and `export-jwks` are post-0.1.0 features that aren't in the
> published `@headlessoracle/chirindo@0.1.0` yet. After a tagged release
> ships them, the example will swap to a normal `npm install
> @headlessoracle/chirindo@^x.y.z` dep.

---

## What's in this directory

| File | Role |
|---|---|
| `package.json` | Defines the npm scripts you'll run. No dependencies — the example shells out to `../../dist/cli.js`. |
| `downstream-mcp-server.mjs` | A minimal stdio MCP server exposing three tools: `get_quote` (safe), `mock_swap`, `mock_send` (both "consequential" — in production they'd move money). |
| `policy.json` | `{ "deny": [] }` — observe-only. No tool calls are blocked; every call is recorded. |
| `harness.mjs` | Drives the gate as if it were Claude Desktop / Cursor: spawns `chirindo proxy`, talks MCP to it, calls `mock_swap`, closes the session. Honors `JWKS_URI` env var to stamp self-describing receipts. |
| `verify-latest.mjs` | Verifies the newest chain file. With `jwks_uri` stamped, the bare `chirindo verify` form resolves automatically. |
| `prove-self-describing.mjs` | Demonstrates the self-describing path on the adopter's OWN chain, with the JWKS pre-seeded in-process (a stand-in for the network fetch — same crypto path). |
| `cursor-mcp.json` | Drop-in Cursor config template (replace `<ABSOLUTE-PATH-TO-EXAMPLE>`). |
| `claude_desktop_config.json` | Same shape, for Claude Desktop. |
| `sample-chain/sample.jsonl` | A pre-recorded chain signed by a key already published on Headless Oracle's live JWKS — used in §5 to demonstrate the legacy fallback path returning `VALID`. |

---

## 1. Build the parent repo

```
( cd ../.. && npm install && npm run build )
```

This example shells out to `../../dist/cli.js` rather than installing
Chirindo as an npm dep (see the build-dependency note above). There's
no `npm install` step inside the example directory.

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

## 3. Export your JWKS

```
npm run export-jwks
```

Writes `./jwks.json` containing the gate's public key as a JWK with the
correct `kid`, `kty:OKP`, `crv:Ed25519`, `use:sig`, `alg:EdDSA` — the
exact shape Headless Oracle's own JWKS uses (the formats are
interchangeable from the verifier's perspective). Real output:

```
exported chirindo JWKS
  kid:  ed25519/<id>
  file: <abs>/.../jwks.json

Host this file at an https:// URL you control, then pass that URL
to 'chirindo proxy --jwks-uri <url>' so every receipt names where
verifiers should fetch its signing key.
```

**Hosting**: upload `jwks.json` anywhere that serves it over HTTPS — your
domain, GitHub Pages, S3 + CloudFront, an existing nginx config, an
edge worker, anywhere. Chirindo provides the file; you provide the URL.
The published URL is what goes into `--jwks-uri` in step 4.

## 4. Run the example with self-describing receipts

Point the harness at the URL you hosted `jwks.json` at in step 3:

```
JWKS_URI=https://your-domain.example/path/jwks.json npm run harness
```

The proxy launches with `--jwks-uri <url>` and stamps that URL into
every receipt's `jwks_uri` field — **inside the signed bytes**, so any
post-sign mutation breaks the signature. A stranger holding only the
resulting chain file now sees, in the first record, where to fetch the
public key. Real output (with `JWKS_URI=https://adopter.example/.well-known/jwks.json`):

```
[chirindo] boot: cwd=<abs>/examples/observe-only-agent dir=<abs>/.gate chain=<abs>/.gate/sessions/<sid>.jsonl
[chirindo] proxy up: server-label='observe-only-example' session=<sid> chain=<abs>/.gate/sessions/<sid>.jsonl jwks_uri=https://adopter.example/.well-known/jwks.json
[harness] downstream exposes tools: get_quote, mock_swap, mock_send
[proxy] ALLOW tool='mock_swap' forwarded id=3
[downstream] CONSEQUENTIAL mock_swap executed: pair='ETH/USDC' amount_in=0.25
[harness] mock_swap response: swap submitted (mock): 0.25 of ETH/USDC — tx 0xMOCK<hex>
[chirindo] proxy exiting (1 receipts written)
```

## 5. Verify — the legacy HO-hosted demo (pre-jwks_uri receipts)

A receipt without `jwks_uri` falls back to the verifier's configured
JWKS URL (the existing `--jwks` flag and its `$RECORDER_JWKS_URL` /
default). The shipped `sample-chain/sample.jsonl` is signed by a key
that's *already* on Headless Oracle's published JWKS, so it verifies
end-to-end with no setup:

```
node ../../dist/cli.js verify sample-chain/sample.jsonl --jwks
```

Real output (captured against the live HO JWKS):

```
VALID — 1 entries, chain intact, all signatures verified, session jwks-demo-00000000-0000-0000-0000-000000000001
```

This is the v0.1.0 demo from the previous iteration. It still works
because the record has no `jwks_uri` and the verifier falls back to
HO's URL. The interesting demo today is §6.

## 6. Verify your OWN chain via the embedded jwks_uri — the new payoff

```
npm run prove-self-describing
```

What it does: reads your harness chain, extracts `jwks_uri` from the
first record (the URL you set in step 4), pre-seeds the in-process JWKS
cache with the contents of `./jwks.json` as if it had just been fetched
from that URL, then calls the production verification path. Real
output (captured 2026-06-29):

```
proving self-describing verification:
  chain:    <abs>/.gate/sessions/self-describing-demo-000.jsonl
  jwks_uri: https://adopter.example/.well-known/jwks.json  (from inside signed bytes)
  kid:      ed25519/ZP8V_XzL2rAk
  JWKS:     <abs>/jwks.json (pre-seeded as if fetched from jwks_uri)

VALID — 1 entries, chain intact, all signatures verified, session self-describing-demo-000
```

The cryptographic verification path (signature, chain linkage, JCS
recompute) is the production code path. The cache seam short-circuits
*only* the HTTPS GET. In production the verifier issues that GET to
your hosted URL and receives the same JWKS bytes. Once you've hosted
`jwks.json` at a real URL, the equivalent command is just:

```
chirindo verify .gate/sessions/<session>.jsonl
```

— with no flag. The verifier reads `jwks_uri` from inside the signed
bytes, fetches over HTTPS, finds the JWK matching `kid`, verifies.
Headless Oracle is never consulted.

### What this proves (calibrated)

- The gate fired for each `tools/call` and produced a signed receipt.
- The chain is recomputable from the signed records.
- The signature matches the key at the **signer's own published
  location**, with **Headless Oracle not in the trust path**.

**Tamper-evident, not tamper-proof**: any actor with the chain file can
rewrite history, but a mutation breaks the hash chain and is caught by
`chirindo verify`. The `jwks_uri` field is inside the signed bytes:
rewriting it to point at an attacker-controlled JWKS does NOT bypass
the signature — the signature is over the original bytes, so the
verifier reports `TAMPERED — signature invalid` (covered by the
`tampering jwks_uri after signing trips the signature check` test in
the suite).

**Do NOT prove**: that an action was "safe," "correct," or "approved by
a human" — only that the decision was captured, signed, and tamper-
evident. The gate's `decision: "allow"` here just means `policy.json`
had no matching deny rule.

## 7. Wire it into a real MCP client (Cursor / Claude Desktop)

Drop-in templates in `cursor-mcp.json` / `claude_desktop_config.json`.
Replace `<ABSOLUTE-PATH-TO-EXAMPLE>` and add `--jwks-uri` to the args
array if you want self-describing receipts:

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
        "--jwks-uri",     "https://your-domain.example/path/jwks.json",
        "--",
        "node", "<ABSOLUTE-PATH-TO-EXAMPLE>/downstream-mcp-server.mjs"
      ]
    }
  }
}
```

Restart the client. Any `tools/call` it routes produces a new line in
`<example>/.gate/sessions/<session-id>.jsonl` with `jwks_uri` stamped.

## 8. Enforcement is one rule away

Same as before: edit `policy.json`:

```json
{
  "deny": [
    { "tool": "mock_send", "reason": "blocked: requires human signoff" }
  ]
}
```

The downstream never sees a `mock_send` call; the chain gets a `DENY`
receipt with `event.decision: "deny"` and `gate.result: "halt"`.
`chirindo verify` still returns `VALID`.

---

## Gap (per the standing instruction)

The example uses an HTTPS URL the adopter promises to host, but
**publishes nothing on its own**. A self-serve hosting story would
shrink the time-to-first-verify further: e.g. a `chirindo serve-jwks
--port 443 --cert ...` to stand up a minimal Workers-style endpoint
from the gate dir directly, or first-class integration with common
hosts (GitHub Pages, R2 + Workers, S3 + CloudFront) that takes
`jwks.json` and a domain and gives back the live URL. Today the
adopter is on the hook for that last hop — they can do it in any
number of ways, but Chirindo doesn't carry them.

Closely related: agents discovering an MCP gate's `jwks_uri` ahead of
time (e.g. via a `.well-known/agent-attestation` document at the
gate's domain) would let a verifying agent decide whether to trust a
new tool call BEFORE seeing the receipt — the agent-consumable
direction of the same problem. Out of scope for this iteration, but
worth naming.
