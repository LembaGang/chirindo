#!/usr/bin/env bash
# Dev-tree advisory REPORT. Informational only — this script must NEVER fail its
# caller, regardless of npm version, findings count, or the shell options the
# caller happens to have set. The runtime gate is the thing that fails builds;
# this one only prints.
#
# It lives in the repo rather than inline in .github/workflows/audit.yml so the
# workflow's canary can execute THIS FILE. A canary that tests a copy of the
# logic proves nothing about the logic that actually runs.
#
# ---------------------------------------------------------------------------
# Why this file exists at all: run 33075038345 (2026-08-27)
#
# The first real Actions run of audit.yml failed with exit 1 in the dev-tree
# step — the step whose own comment says it does not fail the build. The report
# printed in full, then the step died and the job summary was never written.
#
# Root cause was a two-flag conjunction, neither half fatal alone:
#
#   1. GitHub runs a `run:` block with no explicit `shell:` as `bash -e {0}`
#      (documented). So errexit was already ON before line one. The step's own
#      `set -uo pipefail` did NOT clear it — and unlike the canary step in the
#      same file, this step never said `set +e`.
#   2. That same `set -uo pipefail` turned pipefail ON. `npm audit --json` exits
#      1 when it FINDS something (findings present is its success path here),
#      `node` exits 0, and pipefail promotes the pipeline's status to 1.
#
#   SUMMARY="$(npm audit --json | node -e '...')"
#
# A bare assignment takes the status of its command substitution, so the
# assignment returned 1, and errexit killed the step at that line. Proven
# locally, all four combinations, with a marker after the assignment:
#
#   -e off, pipefail off -> exit 0, marker reached
#   -e off, pipefail on  -> exit 0, marker reached   (status set, nothing aborts)
#   -e on,  pipefail off -> exit 0, marker reached   (pipeline takes node's 0)
#   -e on,  pipefail on  -> exit 1, MARKER NEVER REACHED   <-- the failure
#
# It shipped green because the pre-merge local test ran `bash script.sh` — no
# -e — which is precisely the combination that passes. The T8 report had already
# named this as the likeliest divergence; it was named but not tested.
#
# The defence below is deliberately belt-and-braces, because the cost of a
# false failure here is a red build on an informational step, and the cost of
# over-defending is nothing:
#   - clear BOTH inherited flags explicitly, rather than assuming either state;
#   - never let a pipeline's status reach an assignment (`|| true` on each);
#   - `exit 0` unconditionally at the end, so the exit status is stated outright
#     instead of inherited from whatever ran last.
# Note `shell: bash` (if anyone adds it later) supplies `-eo pipefail` from
# GitHub itself — hence clearing the flags here rather than relying on the
# caller's `set` line.
# ---------------------------------------------------------------------------

# Clear both halves of the fatal pair regardless of who set them.
set +e
set +o pipefail

echo "Dev-tree advisories (informational - these do NOT fail the build):"
npm audit || true

# Each stage guarded independently: npm audit's exit 1 (findings present) must
# not reach the assignment even if a future caller re-enables pipefail.
AUDIT_JSON="$(npm audit --json 2>/dev/null || true)"
SUMMARY="$(printf '%s' "${AUDIT_JSON}" | node -e '
  let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
    try{const m=JSON.parse(s).metadata.vulnerabilities;
        console.log(`total ${m.total} | critical ${m.critical}, high ${m.high}, moderate ${m.moderate}, low ${m.low}`);}
    catch{console.log("report unavailable");}
  });' || true)"
[ -n "${SUMMARY}" ] || SUMMARY="report unavailable"

# GITHUB_STEP_SUMMARY is absent when this runs outside Actions (the canary sets
# it to a temp file). Never let an unset variable or an unwritable path fail the
# script - `set -u` may be inherited, so guard the expansion too.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Dependency audit"
    echo ""
    echo "- **Runtime tree (gating):** clean at high+critical, or this job failed above."
    echo "- **Full tree incl. dev (informational):** ${SUMMARY}"
    echo ""
    echo "Dev-only advisories do not fail this build by design; see the workflow comments."
  } >> "${GITHUB_STEP_SUMMARY}" || true
else
  echo "(no GITHUB_STEP_SUMMARY set; summary would read: ${SUMMARY})"
fi

# Stated, not inherited. This is the whole contract of the file.
exit 0
