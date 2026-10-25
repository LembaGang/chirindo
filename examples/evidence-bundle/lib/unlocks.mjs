// For each property lib/allowlist.mjs judges beyond the first build's shape
// (JUDGED), the checks of spec table 4-2 and the binding-rule tags of
// lib/built.mjs it needs, and the id of one vector or refusal-case bundle that
// carries it (its tie vector). test/unlocks.mjs runs each tie vector and
// requires an output, not a refusal, in which every need is reached: a check
// need as a row of `checks` with status PASS or FAIL (NOT-EVALUATED only with
// the reason the need names), restricted to `member` when one is named; a tag
// need as its binding in the state (and reason) the need names. A tie named
// `unit:<function>` is a unit test of that function in test/unlocks.mjs, for a
// property whose own rows all need a later widening.

export const UNLOCKS = {
  "role:instruction:signed-instruction-ed25519/0.2": {
    widening: "Wa-01",
    needs: { "M6.instruction": {}, "B-INS.compare": { binding: "B-INS", state: "BOUND", reason: null, reached: ["BOUND", "EXCEEDS", "MATCHED", "UNBOUND-OUTSIDE"] } },
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
  "type:0x0+0x1": {
    widening: "Wb-01",
    needs: { "M5.transaction": { member: "tx-a" }, "M5.sender": { member: "tx-a" } },
    tie: "T-18",
  },
  "carrier:calldata": {
    widening: "Wb-02",
    needs: { "B-PAY.carrier": {} },
    tie: "unit:decodedShape",
  },
  "type:0x4": {
    widening: "Wb-03",
    needs: { "M5.transaction": { member: "tx-a" }, "B-PAY.10e-tuples": { binding: "B-PAY", state: "NOT-EVALUATED", reason: "account-has-code" } },
    tie: "T-22",
  },
  "type:0x3": {
    widening: "Wb-04",
    needs: { "M5.support": { notEvaluated: "unsupported-type" } },
    tie: "T-20",
  },
  "call:twaBytes65": {
    widening: "Wb-05",
    needs: { "M5.call": { member: "tx-a" }, "M5.token-domain": {}, "M5.authorization": { member: "tx-a" }, "M5.token-logs": { member: "rc-a" }, "M5.validity-window": {} },
    tie: "T-25",
  },
  "call:rule2-unread": {
    widening: "Wb-06",
    needs: { "B-PAY.rule2": { binding: "B-PAY", state: "UNSUPPORTED-PATH", reason: "unsupported-call" } },
    tie: "T-23",
  },
  "call:calldata-path": {
    widening: "Wb-07",
    // T-28 carries no logs: its B-INS is ABSENT once the outflow reading has
    // run; the pair tie S-20 reaches the reading and the comparison with a movement.
    needs: {
      "B-PAY.calldata": { binding: "B-PAY", state: "BOUND", reason: null },
      "B-PAY.outflow": { binding: "B-INS", state: "ABSENT", reason: null, reached: ["EXCEEDS", "NOT-EVALUATED", "BOUND"] },
      "B-INS.compare": { binding: "B-INS", state: "ABSENT", reason: null, reached: ["BOUND", "EXCEEDS", "MATCHED", "UNBOUND-OUTSIDE"] },
    },
    tie: "T-28",
  },
  trailer: {
    widening: "Wb-08",
    needs: { "B-PAY.rule4-sender": { binding: "B-PAY", state: "CARRIED-BY-OTHER", reason: null } },
    tie: "T-29",
  },
  "contract-signer": {
    widening: "Wb-09",
    needs: { "M5.authorization": { member: "tx-a", notEvaluated: "contract-signer" } },
    tie: "T-30",
  },
  "unread-carrier": {
    widening: "Wb-10",
    needs: { "B-PAY.rule6": { binding: "B-PAY", state: "NOT-EVALUATED", reason: "unread-carrier" } },
    tie: "T-31",
  },
  "no-payment": {
    widening: "Wb-11",
    needs: { "B-PAY.no-payment": { binding: "B-PAY", state: "NO-PAYMENT", reason: null } },
    tie: "T-32",
  },
  "role:payment-parent-block": {
    widening: "Wb-12",
    needs: { "M5.parent-block": { member: "parent-t" } },
    tie: "T-06",
  },
  "role:account-proof": {
    widening: "Wb-13",
    needs: { "M5.account-proof": { member: "proof-t" }, "B-PAY.10e-proofs": { binding: "B-PAY", state: "NOT-EVALUATED", reason: "account-has-code" } },
    tie: "S-96",
  },
  "role:payment-block-transactions": {
    widening: "Wb-14",
    needs: { "M5.block-transactions": { member: "btx-t" }, "B-PAY.10e-scan": { binding: "B-PAY", state: "NOT-EVALUATED", reason: "account-has-code" } },
    tie: "S-99",
  },
  "bundle-type:0.10": {
    widening: "W3-01",
    needs: { "M0.bundle": { status: "PASS" } },
    tie: "V-01",
  },
  "card:charge-stated": {
    widening: "W3-02",
    needs: {
      "S3.charge": { status: "PASS" },
      "B-CARD.prereq": { binding: "B-CARD", state: "NOT-EVALUATED", reason: "no-order-committed" },
      "verdict.card": { verdict: { code: "PAYMENT-NOT-VERIFIED", rule: "C3", text: "NOT VERIFIED: the record does not show that the decision was recorded before the charge and matches it" } },
    },
    tie: "V-02",
  },
  "args:order": {
    widening: "W3-03",
    needs: {
      "M8.order": { member: "args-d", status: "PASS" },
      "B-CARD.match": { binding: "B-CARD", state: "BOUND", reason: null },
      "B-CARD.time": { binding: "B-CARD", state: "BOUND", reason: null },
    },
    tie: "V-03",
  },
  "role:instruction:signed-instruction-ed25519/0.3": {
    widening: "W3-04",
    needs: { "M6.instruction": { member: "ins-d", status: "PASS" }, "B-INS.card": { binding: "B-INS", state: "BOUND", reason: null } },
    tie: "V-10",
  },
  // An input: the tie is a case of vectors/pointer-cases.mjs, run through the
  // library entry with a fake fetch.
  pointer: {
    widening: "W3-05",
    needs: { "P1.pointer": { status: "PASS" }, "P2.entry": { status: "PASS" } },
    tie: "V-40",
  },
};

// The pair ties of C4 (6): a vector that carries an evidence property and a
// payment property together, in which the needs of both are reached.
export const PAIRS = [
  ["S-86", "role:gate-receipt+role:issuer-profile", "type:0x3"],
  ["S-20", "role:instruction:signed-instruction-ed25519/0.2", "call:calldata-path"],
  ["S-63", "role:instruction:signed-instruction-ed25519/0.2", "trailer"],
];
