// The data-point export (W3-08; spec 4.10): make-datapoints.mjs on the
// verdict JSON of every card vector and of the pointer cases. Each export is
// read back from the command's stdout; its members are asserted as 4.10
// defines them from the verdict, and the values Appendix V names ([spec]).

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import canonicalize from "canonicalize";
import { FOLDER } from "../vectors/make-vectors.mjs";
import { cardVerdicts, pointerVerdicts, sha256 } from "../vectors/view-cases.mjs";

// Spec 4.10's members, in its table's order.
const MEMBERS = [
  "agent_evidence_format", "agent_evidence_verdict", "agent_evidence_verdict_text", "agent_evidence_verdict_rule", "agent_evidence_verdict_reason",
  "agent_evidence_mode", "agent_evidence_checked_at", "agent_evidence_bundle_sha256", "agent_evidence_verdict_sha256", "agent_evidence_uri",
  "agent_evidence_entry", "agent_evidence_entry_cited", "agent_evidence_pointer_status", "agent_decision", "agent_decision_before_auth",
  "agent_order_matches_charge", "agent_order_reference_matched", "agent_charge_id", "agent_authorization_time", "agent_witness_time",
  "agent_witness_state", "agent_witness_time_as_supplied", "agent_log_state", "agent_key_state", "agent_card_binding_state",
  "agent_instruction_state", "agent_instruction_scope_ok", "agent_instruction_exceeded", "agent_gate_receipt_state", "agent_gaps",
  "agent_limits", "agent_verifier", "agent_verifier_commit",
];
const BOOLEANS = ["agent_evidence_entry_cited", "agent_decision_before_auth", "agent_order_matches_charge", "agent_order_reference_matched", "agent_witness_time_as_supplied", "agent_instruction_scope_ok"];

let dir;
const card = [];
const pointer = [];
const exp = new Map();
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-datapoints-"));
  card.push(...(await cardVerdicts(dir)));
  pointer.push(...(await pointerVerdicts()));
  for (const c of [...card, ...pointer]) exp.set(c.id, make(c.id, c.bytes));
});
after(() => rmSync(dir, { recursive: true, force: true }));

function make(name, bytes, args = null) {
  const vp = path.join(dir, `${name}.verdict.json`);
  writeFileSync(vp, bytes);
  const r = spawnSync(process.execPath, [path.join(FOLDER, "make-datapoints.mjs"), ...(args ?? [vp])], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, value: r.status === 0 ? JSON.parse(r.stdout) : null };
}
const of = (id) => {
  const r = exp.get(id);
  assert.ok(r, `${id} has an export`);
  assert.equal(r.status, 0, `${id}: ${r.stderr}`);
  return r.value;
};
const verdictOf = (id) => [...card, ...pointer].find((c) => c.id === id);

test("V-60: V-10's export: every member of 4.10, each with its defined value [spec, v0.10 4.10]", () => {
  const d = of("V-10");
  const v = verdictOf("V-10");
  assert.deepEqual(Object.keys(d).sort(), [...MEMBERS].sort());
  assert.equal(d.agent_evidence_format, "evidence-bundle-datapoints/0.10");
  assert.equal(d.agent_evidence_verdict, "PAYMENT-NOT-VERIFIED");
  assert.equal(d.agent_evidence_verdict_rule, "C3");
  assert.equal(d.agent_evidence_verdict_reason, "offline-witness-data");
  assert.equal(d.agent_evidence_verdict_text, v.output.verdict.text);
  assert.equal(d.agent_evidence_mode, "offline");
  assert.equal(d.agent_evidence_checked_at, v.output.checked_at);
  assert.equal(d.agent_evidence_bundle_sha256, v.output.bundle_sha256);
  assert.equal(d.agent_evidence_verdict_sha256, "sha256:" + sha256(v.bytes));
  for (const k of ["agent_evidence_uri", "agent_evidence_entry", "agent_evidence_entry_cited", "agent_evidence_pointer_status"]) assert.equal(d[k], null, `${k}: no pointer given`);
  assert.equal(d.agent_decision, "allow");
  assert.equal(d.agent_decision_before_auth, null, "B-WIT SUPPLIED: the time rule is unconfirmed");
  assert.equal(d.agent_order_matches_charge, true);
  assert.equal(d.agent_order_reference_matched, true);
  assert.equal(d.agent_charge_id, "TEST-ch-we4-1");
  assert.equal(d.agent_authorization_time, "2026-11-02T10:05:00Z");
  assert.equal(d.agent_witness_time, "2026-11-02T10:00:02.000Z");
  assert.equal(d.agent_witness_state, "SUPPLIED");
  assert.equal(d.agent_witness_time_as_supplied, true);
  assert.equal(d.agent_log_state, "BOUND");
  assert.equal(d.agent_key_state, "KEY-ONLY");
  assert.equal(d.agent_card_binding_state, "BOUND");
  assert.equal(d.agent_instruction_state, "BOUND");
  assert.equal(d.agent_instruction_scope_ok, true);
  assert.equal(d.agent_instruction_exceeded, "");
  assert.equal(d.agent_gate_receipt_state, "ABSENT");
  assert.equal(d.agent_gaps, v.output.verdict.gaps.map((g) => `${g.binding}:${g.state}`).join(","));
  assert.equal(d.agent_limits, "L1,L2,L3,L4,L6,L7,L8,L9,L12,L13,L14,L17,L24,L25");
  assert.equal(d.agent_verifier, `${v.output.verifier.name} 0.10.0`);
  assert.equal(d.agent_verifier_commit, v.output.verifier.commit);
});

test("V-61: every card vector's export has exactly 4.10's members, each a string, a boolean or null, the booleans true, false or null, in snake_case [spec, v0.10 4.10]", () => {
  assert.ok(card.length >= 25, `${card.length} card verdicts`);
  for (const c of card) {
    const d = of(c.id);
    assert.deepEqual(Object.keys(d).sort(), [...MEMBERS].sort(), c.id);
    for (const [k, x] of Object.entries(d)) {
      assert.match(k, /^[a-z]+(_[a-z0-9]+)*$/);
      assert.ok(x === null || typeof x === "string" || typeof x === "boolean", `${c.id} ${k}: ${JSON.stringify(x)}`);
      if (BOOLEANS.includes(k)) assert.ok(x === null || typeof x === "boolean", `${c.id} ${k}`);
      else assert.ok(typeof x !== "boolean", `${c.id} ${k} is not a boolean member`);
    }
  }
});

test("V-62: agent_decision_before_auth is null for every test-key vector, whose B-WIT is never BOUND [spec, v0.10 4.10]", () => {
  for (const c of card) {
    const d = of(c.id);
    assert.notEqual(d.agent_witness_state, "BOUND", c.id);
    assert.equal(d.agent_decision_before_auth, null, c.id);
  }
});

test("V-63: agent_order_matches_charge is null for V-19 (no reference compared), true for V-10, false for V-14 [spec, v0.10 4.10]", () => {
  assert.equal(of("V-19").agent_order_matches_charge, null);
  assert.equal(of("V-10").agent_order_matches_charge, true);
  assert.equal(of("V-14").agent_order_matches_charge, false);
  assert.equal(of("V-19").agent_order_reference_matched, null);
  assert.equal(of("V-14").agent_order_reference_matched, true, "V-14 differs in its amount only");
});

test("V-64: with no charge stated (V-05, V-18), every member about the charge is null [spec, v0.10 4.10]", () => {
  for (const id of ["V-05", "V-18"]) {
    const d = of(id);
    for (const k of ["agent_decision_before_auth", "agent_order_matches_charge", "agent_order_reference_matched", "agent_charge_id"]) assert.equal(d[k], null, `${id} ${k}`);
    assert.equal(d.agent_evidence_verdict_reason, "card-subject", id);
  }
});

test("V-65: the instruction's scope: V-11 exceeds refundable_only (false), V-28 is not judged (null), V-04 cites none (exceeded null) [spec, v0.10 4.10]", () => {
  assert.equal(of("V-11").agent_instruction_scope_ok, false);
  assert.equal(of("V-11").agent_instruction_exceeded, "refundable_only");
  assert.equal(of("V-28").agent_instruction_state, "NOT-EVALUATED");
  assert.equal(of("V-28").agent_instruction_scope_ok, null);
  assert.equal(of("V-04").agent_instruction_exceeded, null);
});

test("V-66: B-WIT TRUNCATED (V-31) is as supplied; a FAILS vector (V-21) keeps the members it defines [spec, v0.10 4.10]", () => {
  assert.equal(of("V-31").agent_witness_state, "TRUNCATED");
  assert.equal(of("V-31").agent_witness_time_as_supplied, true);
  assert.equal(of("V-21").agent_evidence_verdict, "FAILS");
  assert.equal(of("V-21").agent_evidence_verdict_rule, "C1");
});

test("V-67: the pointer cases' exports carry the pointer: V-40 cites the stated entry (true), V-43 does not (false), an unfetchable pointer leaves it null with a null bundle_sha256 [spec, v0.10 4.10]", () => {
  assert.ok(pointer.length >= 10);
  for (const c of pointer) {
    const d = of(c.id);
    assert.deepEqual(Object.keys(d).sort(), [...MEMBERS].sort(), c.id);
    assert.equal(d.agent_evidence_uri, c.output.pointer.uri, c.id);
    assert.equal(d.agent_evidence_entry, c.output.pointer.stated_entry, c.id);
    assert.equal(d.agent_evidence_pointer_status, c.output.pointer.status, c.id);
  }
  assert.equal(of("V-40").agent_evidence_entry_cited, true);
  assert.equal(of("V-43").agent_evidence_entry_cited, false);
  const un = pointer.filter((c) => c.output.pointer.status === "unfetchable");
  assert.ok(un.length >= 5);
  for (const c of un) {
    assert.equal(of(c.id).agent_evidence_entry_cited, null, c.id);
    assert.equal(of(c.id).agent_evidence_bundle_sha256, null, c.id);
    assert.equal(of(c.id).agent_evidence_verdict_reason, "pointer-unfetchable", c.id);
  }
});

test("V-68: the export is its JCS bytes and one line feed, and the same verdict JSON gives the same bytes [spec, v0.10 4.10]", () => {
  for (const c of card) {
    const r = exp.get(c.id);
    assert.equal(r.stdout, canonicalize(JSON.parse(r.stdout)) + "\n", c.id);
    assert.equal(make(`${c.id}-again`, c.bytes).stdout, r.stdout, c.id);
  }
});

test("V-69: make-datapoints.mjs: no file, two files, an option, an unreadable file and a file that is not a 0.10 verdict exit 2 with nothing on stdout [derived]", () => {
  const v10 = verdictOf("V-10");
  const vp = path.join(dir, "v69.verdict.json");
  writeFileSync(vp, v10.bytes);
  for (const args of [[], [vp, vp], ["--out", vp], [path.join(dir, "missing.json")]]) {
    const r = make("v69", v10.bytes, args);
    assert.equal(r.status, 2, JSON.stringify(args));
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /^usage error: /);
  }
  for (const bytes of [Buffer.from("not json"), Buffer.from(JSON.stringify({ ...v10.output, type: "evidence-bundle-verdict/0.9" }))]) {
    const r = make("v69b", bytes);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /^usage error: .*verdict/);
  }
});
