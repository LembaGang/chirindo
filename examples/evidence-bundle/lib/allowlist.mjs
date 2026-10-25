// The shape this build judges. A bundle outside it is refused (exit 2, no
// verdict) unless a check that runs before the property FAILs; see README.md,
// "The shape this build judges". Items 1 and 2 read only the declared roles
// and profiles and run right after M0 and M1; items 3 to 13 read the decoded
// members and run after M2 to M9. Each function returns the code of the first
// property outside the shape, or null. An item whose input does not exist does
// not apply.
//
// JUDGED lists every property judged beyond the first build's shape, by the
// name its widening gives it; lib/unlocks.mjs names the checks each one needs,
// and test/unlocks.mjs fails when a judged property's checks are not built or
// not reached. A property not in JUDGED is refused exactly as before.

import { isPlainObject } from "../../ordering-evidence-h4/lib/formats.mjs";
import { LEGACY_KID_RE, ROLES } from "./table.mjs";
import { eip3009Readable, unreadByRule2 } from "./tx.mjs";

export const JUDGED = [
  // Wa-01: Annex A instructions (M6, B-INS on the EIP-3009 path).
  "role:instruction:signed-instruction-ed25519/0.2",
  // Wa-02: Verifiable Intent and AP2 instructions, carried as PRESENT.
  "profile:instruction:vi-0.1-draft+ap2-0.2",
  // Wa-03: action results (M8.result).
  "role:action-result",
  // Wa-04: logs that follow Annex B's chain rules.
  "profile:gate-log:jcs-sha256-chain/0.1",
  // Wa-05: gate receipts read through issuer profiles (M7, M9, B-GRC).
  "role:gate-receipt+role:issuer-profile",
  // Wa-06: checkpoints and witness receipts as members of their own.
  "role:checkpoint+role:witness-receipt",
  // Wa-07: supporting members (M1.member only).
  "role:supporting",
  // Wa-08: an operator key as one JWK outside the legacy shape; item 3 then
  // limits only logs of evidence.action/0 records.
  "legacy-shape:jwk-okp-ed25519",
  // Wa-09: records that name a jwks_uri (B-KEY offline).
  "jwks-uri",
  // Wa-10: two carried logs of one kid and session (M2.prefix).
  "log-prefix",
  // Wa-11: a checkpoint or witness receipt beyond the carried log (TRUNCATED).
  "truncated",
  // Wb-01: legacy (EIP-155) and type 0x1 transactions (M5.transaction, M5.sender).
  "type:0x0+0x1",
  // Wb-02: H as raw bytes in the calldata outside the nonce word (rules 3, 7).
  "carrier:calldata",
  // Wb-03: EIP-7702 transactions (rule 10e's tuple recovery).
  "type:0x4",
  // Wb-04: blob transactions (UNSUPPORTED-PATH unsupported-type); 0x7e stays refused.
  "type:0x3",
  // Wb-05: transferWithAuthorization in the bytes-signature form with a
  // 65-byte signature, on the EIP-3009 path.
  "call:twaBytes65",
  // Wb-06: the calls rule 2 does not read (UNSUPPORTED-PATH unsupported-call),
  // to any address.
  "call:rule2-unread",
  // Wb-07: any other call, on the calldata path (rules 5, 10c, 10d; the
  // outflow reading; B-INS on that path).
  "call:calldata-path",
  // Wb-08: bytes after a recognised call's arguments (rule 4's carrier in
  // bytes the sender alone signed; rules 10a and 10b; the flag trailer).
  "trailer",
  // Wb-09: an authorization that does not recover to its from
  // (M5.authorization NOT-EVALUATED contract-signer; B-PAY likewise; L23).
  "contract-signer",
  // Wb-10: H found only where it does not bind (rule 6: NOT-EVALUATED
  // unread-carrier), and a binding match with one that does not bind beside it.
  "unread-carrier",
  // Wb-11: an authorization that moves nothing out of its payer (NO-PAYMENT).
  "no-payment",
  // Wb-12: the payment block's parent (M5.parent-block).
  "role:payment-parent-block",
  // Wb-13: account proofs (M5.account-proof; rule 10e reading carried proofs).
  "role:account-proof",
  // Wb-14: the payment block's raw transactions (M5.block-transactions; rule
  // 10e's scan of the earlier entries).
  "role:payment-block-transactions",
  // W3-01: bundles of type evidence-bundle/0.10 (M0 reads 0.10 and 0.9).
  "bundle-type:0.10",
  // W3-02: a disputed charge stated for a card subject (S3.charge, B-CARD
  // rule 1, rules C1 and C3); an order in the cited arguments stays refused.
  "card:charge-stated",
  // W3-03: an order committed in the cited arguments (M8.order, B-CARD rules
  // 2 to 4, rules C2, C5 and C6, L25).
  "args:order",
  // W3-04: instructions of profile 0.3 (Annex A.3, M6; B-INS for a card
  // subject, card_limits; rule C4; L12 and L13).
  "role:instruction:signed-instruction-ed25519/0.3",
  // W3-05: the Agent Evidence Pointer in place of a bundle path (P1.pointer,
  // P2.entry; lib/pointer.mjs).
  "pointer",
];
// Inputs and views (the stated charge, the pointer, the exhibit and the
// export) are judged by name too: the code that reads one refuses it until its
// widening adds it here.
export const judged = (p) => JUDGED.includes(p);

const JUDGED_ROLES = ["gate-log", "action-arguments", "witness-sidecar", "operator-key", "witness-key", "payment-transaction", "payment-receipt", "payment-block"];
const JUDGED_PROFILE = {
  "gate-log": ["chirindo-evidence.action/1"],
  "action-arguments": ["jcs-json"],
  "witness-sidecar": ["chirindo-witness-sidecar/1"],
  // jwk-okp-ed25519 only in the legacy shape, which item 3 limits.
  "operator-key": ["jwks", "jwk-okp-ed25519"],
  "witness-key": ["ho-v5-keys"],
  "payment-transaction": ["eth-rpc-json"],
  "payment-receipt": ["eth-rpc-json"],
  "payment-block": ["eth-rpc-json"],
};
// The roles and profiles each judged property adds to items 1 and 2.
const WIDENED = {
  "role:instruction:signed-instruction-ed25519/0.2": [["instruction", ["signed-instruction-ed25519/0.2"]]],
  "profile:instruction:vi-0.1-draft+ap2-0.2": [["instruction", ["vi-0.1-draft", "ap2-0.2"]]],
  "role:instruction:signed-instruction-ed25519/0.3": [["instruction", ["signed-instruction-ed25519/0.3"]]],
  "role:action-result": [["action-result", ["jcs-json"]]],
  "profile:gate-log:jcs-sha256-chain/0.1": [["gate-log", ["jcs-sha256-chain/0.1"]]],
  "role:gate-receipt+role:issuer-profile": [
    ["gate-receipt", ["eip712-gate-receipt/0.1"]],
    ["issuer-profile", ["chirindo-h4-issuer-profile/2", "chirindo-h4-issuer-profile/1"]],
  ],
  "role:checkpoint+role:witness-receipt": [
    ["checkpoint", ["witness-spec-0.5-checkpoint"]],
    ["witness-receipt", ["witness.checkpoint/1"]],
  ],
  "role:supporting": [["supporting", ["opaque"]]],
  "role:payment-parent-block": [["payment-parent-block", ["eth-rpc-json"]]],
  "role:account-proof": [["account-proof", ["eth-proof-json"]]],
  "role:payment-block-transactions": [["payment-block-transactions", ["eth-raw-transactions"]]],
};
const JUDGED_CALL_TARGET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
// The transaction types each judged property adds to item 8.
const TYPES = { "type:0x0+0x1": ["0x0", "0x1"], "type:0x4": ["0x4"], "type:0x3": ["0x3"] };
const judgedTypes = () => ["0x2", ...JUDGED.flatMap((p) => TYPES[p] ?? [])];

function rolesAndProfiles() {
  const roles = [...JUDGED_ROLES];
  const profiles = Object.fromEntries(Object.entries(JUDGED_PROFILE).map(([r, ps]) => [r, [...ps]]));
  for (const p of JUDGED)
    for (const [role, ps] of WIDENED[p] ?? []) {
      if (!roles.includes(role)) roles.push(role);
      profiles[role] = [...(profiles[role] ?? []), ...ps];
    }
  return { roles, profiles };
}

export function declaredShape(members) {
  const { roles, profiles } = rolesAndProfiles();
  for (const role of ROLES) if (!roles.includes(role) && members.some((m) => m.role === role)) return `role:${role}`;
  for (const role of roles) for (const m of members.filter((x) => x.role === role)) if (!profiles[role].includes(m.profile)) return `profile:${role}`;
  return null;
}

// `s` is what the decoded members show: the logs, the checkpoints and
// receipts, the subject, the payment as M5 read it, and the search of B-PAY
// rule 3 for the cited hash (null when the cited record does not exist).
export function decodedShape(s) {
  const { doc, logs, checkpoints, receipts, pay, search, citedArgs, insMembers = [] } = s;
  const members = doc.members;
  const subject = doc.subject;
  // 3. legacy-shape
  const legacyLog = logs.some((l) => l.records.some((r) => r.v === "evidence.action/0" || LEGACY_KID_RE.test(String(r.kid))));
  const jwkKey = members.some((m) => m.role === "operator-key" && m.profile === "jwk-okp-ed25519");
  if (legacyLog || (jwkKey && !judged("legacy-shape:jwk-okp-ed25519"))) {
    const ops = members.filter((m) => m.role === "operator-key");
    const ok =
      logs.length === 1 &&
      logs[0].records.length > 0 &&
      logs[0].records.every((r) => r.v === "evidence.action/0" && LEGACY_KID_RE.test(String(r.kid))) &&
      ops.length === 1 &&
      ops[0].profile === "jwk-okp-ed25519" &&
      !members.some((m) => m.role === "witness-sidecar") &&
      subject.kind === "evm-payment" &&
      subject.carried_as === "none";
    if (!ok) return "legacy-shape";
  }
  // 4. jwks-uri
  if (!judged("jwks-uri") && logs.some((l) => l.records.some((r) => Object.keys(r).includes("jwks_uri")))) return "jwks-uri";
  // 5. log-prefix
  const keys = logs.map((l) => `${l.records[0]?.kid}\u0000${l.records[0]?.session_id}`);
  if (!judged("log-prefix") && new Set(keys).size !== keys.length) return "log-prefix";
  // 6. truncated
  const countOf = (kid, sid) => logs.find((l) => l.records[0]?.kid === kid && l.records[0]?.session_id === sid)?.records.length;
  for (const c of [...checkpoints.map((x) => ({ kid: x.cp.kid, sid: x.cp.session_id, count: x.cp.count })), ...receipts.map((x) => ({ kid: x.r.kid, sid: x.r.session_id, count: Number(x.r.count) }))]) {
    const n = countOf(c.kid, c.sid);
    if (!judged("truncated") && n !== undefined && c.count > n) return "truncated";
  }
  // args:order: a card subject whose cited record's arguments commit to an order.
  if (subject.kind === "card-payment" && isPlainObject(citedArgs) && Object.keys(citedArgs).includes("order") && !judged("args:order")) return "args:order";
  if (subject.kind === "card-payment") return null;
  // An evm-payment subject with a profile 0.3 instruction for card orders only
  // (no chain_id, asset, max_amount or payees): the spec gives step 5 no
  // outcome for it, so this build refuses it rather than name a new code.
  if (insMembers.some((i) => i.m6 === "PASS" && i.profile === "signed-instruction-ed25519/0.3" && !Object.keys(i.value.constraints).includes("chain_id"))) return "instruction:card-only";
  // 7. chain
  if (subject.chain_id !== "eip155:84532") return "chain";
  // 8. type
  if (!judgedTypes().includes(pay.type)) return "type";
  // 9. call
  const toTarget = String(pay.to).toLowerCase() === JUDGED_CALL_TARGET;
  const callJudged =
    pay.call &&
    ((toTarget && (pay.call.kind === "twa9" || (judged("call:twaBytes65") && eip3009Readable(pay.call)))) || (judged("call:rule2-unread") && unreadByRule2(pay.call)) || (judged("call:calldata-path") && pay.call.kind === "other"));
  if (!callJudged) return "call";
  // Items 10, 11 and 13 read the authorization of a call on the EIP-3009 path,
  // and do not apply to any other call.
  const eipCall = eip3009Readable(pay.call);
  // 10. trailer
  if (eipCall && pay.call.trailerHex !== "0x" && !judged("trailer")) return "trailer";
  // 11. contract-signer
  if (eipCall && pay.authStatus === "contract-signer" && !judged("contract-signer")) return "contract-signer";
  // 12. unread-carrier
  const carriers = judged("carrier:calldata") ? ["eip3009-nonce", "calldata", null] : ["eip3009-nonce", null];
  if (search && (!carriers.includes(search.carrier) || (search.nonBinding.length > 0 && !judged("unread-carrier")))) return "unread-carrier";
  // 13. no-payment
  const a = pay.call.auth;
  if (eipCall && (!(a.value > 0n) || a.to === a.from) && !judged("no-payment")) return "no-payment";
  return null;
}
