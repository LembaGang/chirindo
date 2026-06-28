# JWKS Operations

Runbook for rotating chirindo's receipt-signing key and publishing the
resulting JWKS. Bridges two repositories — read the architecture section
once before following the steps.

---

## Architecture (why this lives in two repos)

Chirindo signs receipts with an Ed25519 keypair stored locally in `.gate/`
(gitignored). Cross-machine verification works because the public key is
published in JWK form at:

    https://headlessoracle.com/.well-known/jwks.json

That endpoint is **not** a static file in this repo. It is served by the
**headless-oracle-v5 Cloudflare Worker** at `C:\Users\User\headless-oracle-v5`.
The handler lives in `src/index.ts`, in the route block beginning with:

    if (url.pathname === '/.well-known/jwks.json') {

The `keys` array inside that handler holds:
1. The oracle's own receipt-signing key (computed from
   `env.ED25519_PUBLIC_KEY`, kid = RFC 7638 thumbprint).
2. One literal `OKP` JWK per chirindo verification key, with kid in the
   recorder's `ed25519/<id>` form.

**Editing a file in this repo will not affect the served JWKS.** All
publication changes happen in the v5 Worker source, then `wrangler deploy`.

---

## When to rotate

- Suspected compromise of `.gate/private-key.pem` (workstation theft,
  accidental commit, malware exposure).
- Scheduled rotation (no fixed cadence yet; revisit at v1.0).
- Onboarding a new signing environment (e.g. server-side gate instance
  with its own keypair). The new environment gets its own key; the
  existing key stays in the JWKS.

---

## Invariant — add-and-retain, never replace

Receipts must remain verifiable forever. A receipt signed with key `K`
verifies if and only if `K`'s JWK is in the served JWKS at verify time.

Therefore: **never remove a key that has signed any receipt.** Rotation
adds the new key alongside the old; the old key stays in the JWKS
indefinitely. Dropping a key invalidates every receipt it signed.

The only justification for removing a key is cryptographic compromise
(the private key has demonstrably leaked and an attacker is forging
receipts). In that case the right answer is usually still "leave the
JWK in place and republish the affected receipts to a new chain with a
new key" — silent removal corrupts honest verifiers' history.

---

## Procedure

### 1. Back up the current `.gate/`

Never delete the existing key — move it aside.

    cd C:\Users\User\mcp-gate-spike
    Move-Item .gate ".gate.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

The `.gitignore` rule `.gate.backup-*/` keeps the backup directory out
of git automatically. Verify with `git status --ignored`.

### 2. Generate the new keypair

    node dist/cli.js init

`chirindo init` refuses to overwrite an existing `.gate/`, so step 1 is
mandatory. Output prints the new kid (`ed25519/<id>`). Capture it.

### 3. Materialize the new key as a JWK literal

The values you need:
- `kid`: the new `ed25519/<id>` from step 2 (verbatim, includes the
  `ed25519/` prefix).
- `x`: the `public_key_b64url` field of `.gate/identity.json` (verbatim).
- `kty`, `crv`, `use`, `alg`, `key_ops`: fixed — see the existing entries
  in the v5 Worker source for the canonical shape.

### 4. Edit the v5 Worker

Open `C:\Users\User\headless-oracle-v5\src\index.ts`. Find the route
block for `/.well-known/jwks.json` (search for the literal pathname
string — line numbers shift). Inside `jwks.keys = [ ... ]`, append a new
object literal **after** the existing chirindo entries:

```ts
}, {
  // Chirindo MCP-gate recorder's signing key (rotated in YYYY-MM-DD).
  // kid format is the recorder's `ed25519/<id>` — NOT an RFC 7638
  // thumbprint; do not recompute via ed25519JwkThumbprint.
  kty:     'OKP',
  crv:     'Ed25519',
  x:       '<new-x-from-step-3>',
  kid:     'ed25519/<new-id-from-step-2>',
  use:     'sig',
  alg:     'EdDSA',
  key_ops: ['verify'],
}],
```

Update the comment at the top of the route block ("Two-key set" →
"Three-key set" or whatever the new count is) so future readers know
what to expect.

### 5. Deploy the v5 Worker

    cd C:\Users\User\headless-oracle-v5
    npm run deploy

This runs `wrangler deploy`. Single-environment Worker — no `--env` flag.
Wait for the `Current Version ID: ...` line and exit 0. The Worker is
bound to `headlessoracle.com/.well-known/*` (see `wrangler.toml`
`routes`), so a successful deploy puts the new JWKS at the canonical URL
within seconds.

### 6. Verify origin has the new doc (bypass CDN cache)

    curl -s 'https://headlessoracle.com/.well-known/jwks.json?cb=POSTDEPLOY' | jq '.keys[].kid'

A unique query string forces Cloudflare to bypass its edge cache and
fetch from origin. You should see all expected kids — the oracle key,
every retained chirindo key, and the new one.

If the new kid is missing here:
- The deploy did not land. Check the deploy output for errors.
- The wrong file got edited. Confirm `git diff src/index.ts` in the v5
  repo shows the new JWK literal.
- The route is being intercepted by another Cloudflare layer (Page
  Rule, Transform Rule, or a different Worker). Check the dashboard's
  Workers Routes view for `headlessoracle.com/.well-known/*`.

### 7. End-to-end smoke test against the live endpoint

Generate one fresh receipt under the new key and verify it cross-machine:

    cd C:\Users\User\mcp-gate-spike
    # produce a receipt — easiest path is to run the proxy + send one
    # tool call, or write a one-shot script that calls appendReceipt()
    node dist/cli.js verify <chain-file> --jwks https://headlessoracle.com/.well-known/jwks.json

Expected: `VALID — N entries, chain intact, all signatures verified`,
exit 0. Anything else means publication didn't fully land — diagnose
before declaring the rotation done.

For the strongest signal (proves a stranger can verify, not just you),
re-run the verify from a fresh temp directory after `npm install
@headlessoracle/chirindo`. See the launch transcript for the exact
shape, or just trust the local verify — same engine, same outcome.

### 8. Commit the v5 change

The deploy reads the working tree, not git, so committing is decoupled
from deploying. Commit anyway so the change is recoverable and the v5
log explains why the JWKS grew:

    cd C:\Users\User\headless-oracle-v5
    git add src/index.ts
    git commit -m "jwks: rotate chirindo signing key (add ed25519/<new-id>, retain prior)"

---

## Rollback

If a deploy breaks the JWKS endpoint (returns 5xx, malformed JSON, drops
a key) — restore the previous Worker version via the Cloudflare
dashboard: Workers → headless-oracle-v5 → Deployments → previous version
→ "Rollback to this version." This is faster and lower-risk than
re-deploying a fix and waiting for it to propagate.

After rollback, fix the source, re-deploy, re-verify with step 6.

**Do not roll back receipt-signing keys.** A chirindo private key once
generated and used must never be re-used after rotation. If the rotation
itself was a mistake (you generated a new key but didn't want to switch
yet), keep using the old key for new receipts and leave the new key
unused in `.gate.backup-*/`. The JWKS can hold both.

---

## What stays in this repo

- The receipt-signing keypair (`.gate/`, gitignored, never published).
- The verifier code (`src/vendor/recorder/jwks.ts`) — how chirindo
  consumes the JWKS, not how it's published.
- This runbook.

## What lives in the v5 repo

- The `/.well-known/jwks.json` route handler.
- The deploy mechanism (`wrangler.toml`, `npm run deploy`).
- The Cloudflare account / zone bindings.

## What lives only in operator memory (avoid)

Anything else. If a step is in this runbook, it's reproducible. If a
step is missing from this runbook because "you just know," the runbook
is wrong — patch it the next time you find the gap.
