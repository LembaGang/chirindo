This kit uses a local stub witness ("witness":"stub.invalid", throwaway key from a fixed seed), NOT Headless Oracle's witness.
received_at values come from a fixed test clock and are not real times.

# E015.4 evidence kit

A self-contained demonstration, for an auditor or insurer, of what Chirindo's
signed receipt log detects on its own and what it detects once checkpoints of
it are witnessed by an independent party. It produces real files and runs the
open verifier (`chirindo verify`) against them; the results are in
[`RESULTS.md`](RESULTS.md).

This is evidence for E015.4 "Config: Log integrity protection" (AIUC-1).
It does not make a vendor compliant with or certified under AIUC-1, and the
gaps listed below are part of the evidence.

## Rerun it

From the repository root, with Node 20 or later (Windows or Linux):

```
npm install
npx tsx examples/e015-4-kit/run.mjs
```

The script prints `all 12 outcomes match the expected table` and rewrites
`RESULTS.md`, or exits 1 and names each outcome that differs. RESULTS.md is
byte-identical on every run (fixed keys, session id, stub clock, one call at
a time); the chain files in work/ carry real record timestamps and differ
between runs, and received_at from the stub clock is not comparable with
them. Scratch files are written to `work/`
(ignored by git; it holds the throwaway private key).

## What it does

1. Creates a throwaway gate identity from a fixed seed (32 bytes of 0x01) and
   a throwaway witness key from another (32 bytes of 0x02).
2. Starts a stub witness on 127.0.0.1 that implements the witness wire
   protocol ([WITNESS_SPEC v0.4](../../docs/WITNESS_SPEC_v0.4.md) sections
   2 to 4). It differs from the real
   service in two stated ways: it signs as `stub.invalid`, and it accepts
   small-order public keys, which the real witness rejects.
3. Runs `chirindo proxy --checkpoint-every 2 --witness ...` in front of a
   stub MCP server and sends 7 tool calls (5 allowed `echo`, 2 `delete`
   denied by policy). After every 2nd receipt the gate signs a checkpoint
   over the head of its chain and the witness countersigns it; on clean
   shutdown the gate checkpoints the final head. Witnessed counts: 2, 4, 6, 7.
4. Writes six copies of the session's chain and verifies each one twice:
   with `--key` only, and again against the witness receipts in the sidecar
   (`--witness-file`, offline: the stub has been shut down by then).

## What each case shows

| Copy | What was done | Chain alone | With witnessed checkpoints |
|---|---|---|---|
| intact | nothing | VALID | VALID, witnessed through count 7 |
| edited | one record's `args_hash` changed, not re-signed | TAMPERED at that entry | TAMPERED |
| deleted | one middle record removed | TAMPERED (sequence gap) | TAMPERED |
| reordered | two adjacent records swapped | TAMPERED (sequence gap) | TAMPERED |
| truncated | the last 2 records cut off | **VALID** | TAMPERED (a witnessed count is beyond the chain) |
| resigned | the key holder rewrote one record's arguments and re-signed and re-linked the whole chain | **VALID** | TAMPERED (last_entry_hash mismatch at the first witnessed count after the rewrite) |

The first four rows are what a signed hash chain gives you with no third
party: anyone without the signing key who edits or reorders records, or
deletes one other than at the tail, is caught. The last two rows are what it cannot catch: a chain whose tail was
cut off, and a history rewritten by whoever holds the key, both still verify
VALID. Only the comparison with witnessed checkpoints catches them, and only
for history up to the last witnessed checkpoint, rewritten after that
checkpoint was witnessed.

--witness-file trusts the sidecar the operator supplied; only querying the
witness is independent of the operator. A real check queries the witness
service (`chirindo verify <chain> --key <identity.json> --witness <url>
--witness-key <pinned key>`), not a file the operator handed over. The full
limits of the witness are in the main README, section
[Witness](../../README.md#witness).

## Mapping to AIUC-1

Cited by code and title as published at standard.aiuc-1.com (read
2026-10-03):

- **D003.3 "Config: Tool call log"** (under D003 "Restrict unsafe tool
  calls"): "may include log entries capturing the originating MCP server,
  tool name, tool version, input parameters, and timestamps per invocation".
- **E015.2 "Config: AI agent logging implementation"**: "may include ...
  structured log entries capturing tool call parameters and their results",
  provenance metadata per execution, and approval/authorization records.
- **E015.4 "Config: Log integrity protection"**: "Log immutability controls -
  for example, ... cryptographic hashing of log entries ...". Under E015's
  supplemental "May include": logs that are "tamper-evident and
  independently verifiable", with "gaps, omissions, and reordering"
  detectable.

How each receipt field maps, and what is missing:

| AIUC-1 item | Chirindo receipt field | Status |
|---|---|---|
| D003.3 originating MCP server | `event.server` | **Gap:** this is the operator's `--server-label` string, not an identity of the MCP server; nothing verifies it names the server actually spawned. |
| D003.3 tool name | `event.tool_name` | Recorded, as sent by the client. |
| D003.3 tool version | none | **Gap:** tool version is not recorded. |
| D003.3 input parameters | `event.args_hash` | **Gap:** inputs are kept only as a hash (SHA-256 over RFC 8785 JCS of the arguments), not the parameters themselves. Someone holding the arguments can prove they match; the log alone does not reveal them. |
| D003.3 timestamps | `ts` | **Gap:** one `ts` per receipt, taken when the receipt is written (after the downstream response for ALLOW, at decision time for DENY), not a request timestamp. |
| D003 "Restrict unsafe tool calls": blocked calls | DENY receipts (`event.decision: "deny"`, `outcome: "denied"`, `gate.result: "halt"`) | Recorded (no alerting); the deny reason text is not in the receipt. |
| E015.2 tool call results | `event.result_hash` | **Gap:** a hash only, and on ALLOW only; DENY receipts have no result. |
| E015.2 agent provenance | `agent` | **Gap:** `agent` is the constant `{vendor:"chirindo", version:"0.0.1"}`; it identifies neither the agent nor the package version (0.4.0). The signing key (`kid` / `key_thumbprint`) identifies the gate instance that signed. |
| E015.2 authorization record | `event.decision`, `event.decision_source: "config"`, `gate.*` | Policy decision recorded; no approver identity (decisions come from the policy file, not a person). |
| E015.4 integrity protection | `prev_hash`, `sig`, `seq`, `request_commitment`; witnessed checkpoints in `<chain>.witness.ndjson` | Demonstrated by this kit, with the limits above: the chain alone does not catch a cut-off tail or a key-holder rewrite; witnessed checkpoints catch them only up to the last witnessed checkpoint. |
