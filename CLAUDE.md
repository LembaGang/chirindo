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

The candidate vector set is `conformance/vectors-v1.candidate.json` — kept
`.candidate` (not `vectors-v1.json`) until human sign-off. Verification runs
under `conformance/verify-harness/` (dev-only, `private:true`, not shipped).
