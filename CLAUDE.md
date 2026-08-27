# Chirindo (repo: `mcp-gate-spike`)

Chirindo is the fail-closed cryptographic gate for the MCP tool-call boundary.
"Chirindo" is Shona for "watchtower." Published as `@headlessoracle/chirindo`.

## Where to look first

- `README.md` — user-facing overview
- `SPIKE_RESULT.md` — the original spike write-up
- `.claude/rules/10_decisions.md` — durable architectural decisions
- `.claude/rules/90_active_priorities.md` — what's in flight and top-line verdicts
- `conformance/VERIFICATION-REPORT.md` — status of the external conformance corpus

## Conformance corpus (external Fable-authored vectors)

The promoted, frozen vector set is `conformance/vectors-v1.json`. Verification
runs under `conformance/verify-harness/` (dev-only, `private:true`, not shipped).
See `conformance/VERIFICATION-REPORT.md` for the three-way agreement record.
Findings F2/F3/F4 are CLOSED under red-proofed tests — see that report's
"## v0.4.x re-verification — 2026-08-27" section for the harness results, the
test names, and what that pass did NOT close.
