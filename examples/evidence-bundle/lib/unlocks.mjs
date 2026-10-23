// For each property lib/allowlist.mjs judges beyond the first build's shape
// (JUDGED), the checks of spec table 4-2 and the binding-rule tags of
// lib/built.mjs it needs, and the id of one vector or refusal-case bundle that
// carries it (its tie vector). test/unlocks.mjs runs each tie vector and
// requires an output, not a refusal, in which every need is reached: a check
// need as a row of `checks` with status PASS or FAIL (NOT-EVALUATED only with
// the reason the need names), restricted to `member` when one is named; a tag
// need as its binding in the state (and reason) the need names.

export const UNLOCKS = {
  "role:instruction:signed-instruction-ed25519/0.2": {
    widening: "Wa-01",
    needs: { "M6.instruction": {}, "B-INS.compare": { binding: "B-INS", state: "BOUND", reason: null } },
    tie: "SA-01",
  },
  "profile:instruction:vi-0.1-draft+ap2-0.2": {
    widening: "Wa-02",
    needs: { "B-INS.present": { binding: "B-INS", state: "PRESENT", reason: null } },
    tie: "SA-06",
  },
  "role:action-result": {
    widening: "Wa-03",
    needs: { "M8.result": { member: "result-t" } },
    tie: "SA-09",
  },
  "profile:gate-log:jcs-sha256-chain/0.1": {
    widening: "Wa-04",
    needs: { "M2.log": { member: "log-t" } },
    tie: "S-66",
  },
  "role:gate-receipt+role:issuer-profile": {
    widening: "Wa-05",
    needs: {
      "M7.envelope": { member: "gr-t" },
      "M7.uid": { member: "gr-t" },
      "M7.signature": { member: "gr-t" },
      "M7.signer-key": { member: "gr-t" },
      "M9.issuer-profile": { member: "ip-t" },
      "B-GRC.receipts": { binding: "B-GRC", state: "BOUND", reason: null },
    },
    tie: "S-67",
  },
  "role:checkpoint+role:witness-receipt": {
    widening: "Wa-06",
    needs: { "M3.checkpoint": { member: "cp-a" }, "M3.signature": { member: "cp-a" }, "M3.history": { member: "cp-a" }, "M4.witness-receipt": { member: "wr-a" } },
    tie: "SA-11",
  },
  "role:supporting": {
    widening: "Wa-07",
    needs: { "M1.member": { member: "sup-a" } },
    tie: "SA-12",
  },
  "legacy-shape:jwk-okp-ed25519": {
    widening: "Wa-08",
    needs: { "M9.operator-key": { member: "opkey-a" } },
    tie: "SA-16",
  },
  "jwks-uri": {
    widening: "Wa-09",
    needs: { "M2.log": { member: "log-t" }, "B-KEY.jwks": { binding: "B-KEY", state: "SUPPLIED", reason: null } },
    tie: "SA-13a",
  },
  "log-prefix": {
    widening: "Wa-10",
    needs: { "M2.prefix": { member: "log-a" } },
    tie: "SA-14",
  },
  truncated: {
    widening: "Wa-11",
    needs: { "M3.history": { member: "sidecar-t15" }, "B-CKP.truncated": { binding: "B-CKP", state: "TRUNCATED", reason: null } },
    tie: "SA-15",
  },
};
