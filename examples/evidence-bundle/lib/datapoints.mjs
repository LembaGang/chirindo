// The data-point export (spec 4.10): a flat JSON object,
// evidence-bundle-datapoints/0.10, for chargeback platforms' argument
// engines, serialised by RFC 8785 (JCS) with a line feed after it. It is a
// view: every member is defined from the verdict JSON alone, none from the
// bundle or a stated input. A member that does not apply to the subject is
// null, and every boolean is three-valued: null never means true.

import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { built } from "./built.mjs";
import { readVerdict } from "./exhibit.mjs";

export const DATAPOINTS_TYPE = "evidence-bundle-datapoints/0.10";

built("datapoints.export");
// The export of one verdict JSON's bytes, as an object.
export function datapointsOf(bytes) {
  const o = readVerdict(bytes);
  const state = (id) => o.bindings.find((b) => b.id === id)?.state ?? null;
  const p2 = o.checks.find((c) => c.id === "P2.entry");
  const wit = state("B-WIT");
  const ins = state("B-INS");
  const cardCharge = o.card !== null && o.stated.charge !== null;
  const m = o.card?.matches ?? null;
  const refs = m ? [m.merchant_order_id, m.checkout_ref] : [];
  const cited = o.instructions.find((i) => i.cited) ?? null;
  return {
    agent_evidence_format: DATAPOINTS_TYPE,
    agent_evidence_verdict: o.verdict.code,
    agent_evidence_verdict_text: o.verdict.text,
    agent_evidence_verdict_rule: o.verdict.rule,
    agent_evidence_verdict_reason: o.verdict.reason,
    agent_evidence_mode: o.mode,
    agent_evidence_checked_at: o.checked_at,
    agent_evidence_bundle_sha256: o.bundle_sha256,
    // The one member computed over the verdict JSON as a whole.
    agent_evidence_verdict_sha256: "sha256:" + createHash("sha256").update(bytes).digest("hex"),
    agent_evidence_uri: o.pointer?.uri ?? null,
    agent_evidence_entry: o.pointer?.stated_entry ?? null,
    agent_evidence_entry_cited: p2?.status === "PASS" ? true : p2?.status === "FAIL" ? false : null,
    agent_evidence_pointer_status: o.pointer?.status ?? null,
    agent_decision: o.decision.value,
    // Confirmed only when B-WIT is BOUND, the one state that confirms the
    // receipt's time (spec 4.3, B-CARD rule 3; 4.10); null otherwise.
    agent_decision_before_auth: cardCharge && wit === "BOUND" ? o.card.before_authorization : null,
    agent_order_matches_charge: !cardCharge || o.card.order === null ? null : Object.values(m).includes(false) ? false : m.amount === true && m.currency === true && refs.includes(true) ? true : null,
    agent_order_reference_matched: !cardCharge ? null : refs.includes(false) ? false : refs.includes(true) ? true : null,
    agent_charge_id: o.stated.charge?.id ?? null,
    agent_authorization_time: o.card?.authorized_at ?? null,
    agent_witness_time: o.card?.witness_received_at ?? null,
    agent_witness_state: wit,
    agent_witness_time_as_supplied: wit === "SUPPLIED" || wit === "TRUNCATED" ? true : wit === "BOUND" ? false : null,
    agent_log_state: state("B-LOG"),
    agent_key_state: state("B-KEY"),
    agent_card_binding_state: state("B-CARD"),
    agent_instruction_state: ins,
    agent_instruction_scope_ok: ins === "BOUND" || ins === "MATCHED" ? true : ins === "EXCEEDS" || ins === "UNBOUND-OUTSIDE" ? false : null,
    agent_instruction_exceeded: cited ? cited.exceeded.join(",") : null,
    agent_gate_receipt_state: state("B-GRC"),
    agent_gaps: o.verdict.gaps.map((g) => `${g.binding}:${g.state}`).join(","),
    agent_limits: o.limits.map((l) => l.id).join(","),
    agent_verifier: `${o.verifier.name} ${o.verifier.version}`,
    agent_verifier_commit: o.verifier.commit,
  };
}

// The export's bytes: JCS and a line feed.
export const datapointBytes = (bytes) => Buffer.from(canonicalize(datapointsOf(bytes)) + "\n", "utf8");
