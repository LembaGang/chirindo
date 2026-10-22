// The shape this build judges. A bundle outside it is refused (exit 2, no
// verdict) unless a check that runs before the property FAILs; see README.md,
// "The shape this build judges". Items 1 and 2 read only the declared roles
// and profiles and run right after M0 and M1; items 3 to 13 read the decoded
// members and run after M2 to M9. Each function returns the code of the first
// property outside the shape, or null. An item whose input does not exist does
// not apply.

import { LEGACY_KID_RE, ROLES } from "./table.mjs";

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
const JUDGED_CALL_TARGET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

export function declaredShape(members) {
  for (const role of ROLES) if (!JUDGED_ROLES.includes(role) && members.some((m) => m.role === role)) return `role:${role}`;
  for (const role of JUDGED_ROLES) for (const m of members.filter((x) => x.role === role)) if (!JUDGED_PROFILE[role].includes(m.profile)) return `profile:${role}`;
  return null;
}

// `s` is what the decoded members show: the logs, the checkpoints and
// receipts, the subject, the payment as M5 read it, and the search of B-PAY
// rule 3 for the cited hash (null when the cited record does not exist).
export function decodedShape(s) {
  const { doc, logs, checkpoints, receipts, pay, search } = s;
  const members = doc.members;
  const subject = doc.subject;
  // 3. legacy-shape
  const legacyLog = logs.some((l) => l.records.some((r) => r.v === "evidence.action/0" || LEGACY_KID_RE.test(String(r.kid))));
  const jwkKey = members.some((m) => m.role === "operator-key" && m.profile === "jwk-okp-ed25519");
  if (legacyLog || jwkKey) {
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
  if (logs.some((l) => l.records.some((r) => Object.keys(r).includes("jwks_uri")))) return "jwks-uri";
  // 5. log-prefix
  const keys = logs.map((l) => `${l.records[0]?.kid}\u0000${l.records[0]?.session_id}`);
  if (new Set(keys).size !== keys.length) return "log-prefix";
  // 6. truncated
  const countOf = (kid, sid) => logs.find((l) => l.records[0]?.kid === kid && l.records[0]?.session_id === sid)?.records.length;
  for (const c of [...checkpoints.map((x) => ({ kid: x.cp.kid, sid: x.cp.session_id, count: x.cp.count })), ...receipts.map((x) => ({ kid: x.r.kid, sid: x.r.session_id, count: Number(x.r.count) }))]) {
    const n = countOf(c.kid, c.sid);
    if (n !== undefined && c.count > n) return "truncated";
  }
  if (subject.kind === "card-payment") return null;
  // 7. chain
  if (subject.chain_id !== "eip155:84532") return "chain";
  // 8. type
  if (pay.type !== "0x2") return "type";
  // 9. call
  if (!pay.call || pay.call.kind !== "twa9" || String(pay.to).toLowerCase() !== JUDGED_CALL_TARGET) return "call";
  // 10. trailer
  if (pay.call.trailerHex !== "0x") return "trailer";
  // 11. contract-signer
  if (pay.authStatus === "contract-signer") return "contract-signer";
  // 12. unread-carrier
  if (search && (!(search.carrier === "eip3009-nonce" || search.carrier === null) || search.nonBinding.length > 0)) return "unread-carrier";
  // 13. no-payment
  const a = pay.call.auth;
  if (!(a.value > 0n) || a.to === a.from) return "no-payment";
  return null;
}
