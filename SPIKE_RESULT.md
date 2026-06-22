# mcp-gate-spike — Result

## What was proven

End-to-end, against a real MCP client (Cursor) speaking stdio to the gate,
which spawned `@modelcontextprotocol/server-everything` as the downstream:

- **Intercept.** The gate sits transparently between client and server.
  `initialize`, `tools/list`, and notifications pass through untouched;
  every `tools/call` is evaluated against policy before the downstream sees
  it.
- **Allow path.** `echo` was permitted, forwarded, and the downstream
  result returned to the agent. A signed receipt was appended to
  `.gate/sessions/<session-id>.jsonl` capturing `args_hash`, `result_hash`,
  `decision:allow`, and `gate.result:act`. `recorder verify` reports
  **VALID**.
- **Deny path.** `get-env` was blocked at the gate; the downstream was
  never invoked. The agent received a synthesized `isError:true` tool
  result. A signed receipt was appended with `outcome:denied`,
  `decision:deny`, `gate.result:halt`. `recorder verify` reports **VALID**.
- **Chain integrity.** Both receipts cross-verify with the unmodified
  `recorder verify` command — the gate produces evidence that is
  indistinguishable in structure from records emitted by the recorder
  library itself.

## Behavioural finding — agent stops cleanly on deny

The deny-shaped tool result (`isError:true` + a human-readable reason) is
sufficient for the client agent to **halt the action and not retry**. No
loop, no re-prompt, no fallback path. This validates the choice to model
deny as a normal tool-result error rather than a transport-level failure:
agents already know how to surrender on `isError:true`, so the gate
inherits that behaviour for free.

This matters more than the cryptographic surface for adoption. A gate that
makes agents loop or escalate is a gate operators will turn off.

## Fail-closed surface (confirmed live)

The boot-time chain-dir probe and the receipt-write fail-closed path were
both exercised during integration (the latter via the
`.gate/sessions/` directory not existing on first Cursor launch). The
proxy denied with a clear reason rather than letting an un-receipted
action through, and the stderr diagnostic identified the exact failing
path. After the probe was added, the boot self-check creates the directory
and a clean run follows.

## Open productization items

These were intentionally out of scope for the spike. Each is a discrete
follow-up:

- **`npx`-on-Windows spawn fix.** The `spawn(..., { shell: true })`
  fallback used by `spawnRealDownstream` works around the Node CVE that
  broke spawning `.cmd`/`.bat` shims, but `shell:true` shell-interpolates
  arguments. Production needs argv-safe spawning for shims on Windows.
- **JWKS resolver.** `gate.gate_receipt` currently self-references the
  record's own entry hash (placeholder). Production must resolve a real
  pre-action attestation bundle via a published JWKS, so a verifier can
  walk from the receipt back to the gate's signed pre-action commitment.
- **JCS over `arguments`.** `args_hash` is currently
  `sha256(JSON.stringify(arguments))`. `JSON.stringify` is not canonical
  (key order, whitespace, number formatting), so two semantically
  identical calls can hash differently. Move to RFC 8785 (JCS) — the
  recorder library already uses JCS for record canonicalisation, so the
  primitive is in hand.
- **COSE output mode.** Receipts today are JCS-canonical JSON with a
  detached Ed25519 signature in `sig`. For cross-ecosystem verification
  (and to align with the broader attestation stack), add a COSE_Sign1
  output mode alongside the existing JSON form.
- **Argument-level policy.** The spike's policy language is
  `{deny: [{tool, server?}]}` — tool-name match only. Real deployments
  need matchers over `arguments` (path prefixes, host allow-lists,
  capability scopes, principal/role bindings) and a richer decision
  vocabulary than `allow`/`deny`.

## Standing gap

The chain sink is local-filesystem-only. A host that sandboxes the gate
into a read-only or per-invocation ephemeral working directory will
correctly fail closed on every call — visible at boot via the probe — but
the gate cannot recover. Productization needs a pluggable chain sink
(local file, daemon socket, signed remote append-only log) so the
evidence path is not coupled to the host's filesystem assumptions.
