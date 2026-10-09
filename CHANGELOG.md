# Changelog

Published versions and their dates are listed on npm
(https://www.npmjs.com/package/@headlessoracle/chirindo?activeTab=versions).
Releases before 0.5.1 have no entry here; their notes are their commit
messages.

## 0.5.1 — 2026-10-09

Docs and package metadata only. No behaviour change: `src/` and `test/` are
unchanged from 0.5.0, and the test suite is unchanged.

- README, Witness: replaces "What has been exercised, and what has not" with
  a dated statement of the 9 Oct 2026 anonymous run of the 0.5.0 client
  code against production (`https://api.headlessoracle.com` and
  `https://headlessoracle.com`), and what that run did not exercise. Drops
  the stale line that `https://headlessoracle.com` does not serve the
  witness paths.
- README, field notes: `gate_receipt` keeps its meaning (the receipt's own
  `entry_hash`); "self-anchored for the spike" is replaced by how it gets an
  outside time. New subsection "Showing a gate ran before an action".
- README, "Also verified": the published-version sentence now points to the
  npm versions list instead of naming a version that goes stale.
- docs/WITNESS_SPEC_v0.5.md: editorial correction of the public edition
  (both hosts serve the witness paths); nothing a verifier checks.
- package.json: `keywords`, `homepage`, `bugs`.
