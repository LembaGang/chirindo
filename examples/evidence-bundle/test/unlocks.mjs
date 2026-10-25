// The ties between what the allow-list judges and what the verifier builds
// (lib/allowlist.mjs JUDGED, lib/unlocks.mjs UNLOCKS, lib/built.mjs BUILT):
// every judged property has an entry and every entry is judged; every need of
// every entry is built; and each entry's tie vector gives an output, not a
// refusal, in which each need is reached. The red proof shows that an entry
// whose need is not built is reported. A property whose own rows all need a
// later widening is tied by a unit test of decodedShape on WE-1's decoded state.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { decodedShape, JUDGED } from "../lib/allowlist.mjs";
import { loadPins } from "../lib/cli.mjs";
import { PAIRS, UNLOCKS } from "../lib/unlocks.mjs";
// Loaded here so that its BUILT tags are registered before the needs are checked.
import { verifyPointer } from "../lib/pointer.mjs";
import { BUILT, verifyBundle } from "../lib/verify.mjs";
import { bundleBytes } from "../lib/we1.mjs";
import { A, FOLDER, runCli, runVector, T, VECTORS, we1 } from "../vectors/make-vectors.mjs";
import { ONLINE_CASES } from "../vectors/online-cases.mjs";
import { POINTER_CASES } from "../vectors/pointer-cases.mjs";
import { CASES } from "../vectors/refusal-cases.mjs";
import { drawnStrings, readPdf, shownForm, vectorById, verdictOf } from "../vectors/view-cases.mjs";

// The views' writers, loaded before the needs are checked so that their BUILT
// tags are registered; a writer that does not exist yet registers none, and
// its tie then fails on its needs.
const exhibitLib = await import("../lib/exhibit.mjs").catch(() => null);
await import("../lib/datapoints.mjs").catch(() => null);
await import("../lib/pages.mjs").catch(() => null);

// Spec 4.10's members, which the export holds exactly.
const DATAPOINT_MEMBERS = "agent_evidence_format agent_evidence_verdict agent_evidence_verdict_text agent_evidence_verdict_rule agent_evidence_verdict_reason agent_evidence_mode agent_evidence_checked_at agent_evidence_bundle_sha256 agent_evidence_verdict_sha256 agent_evidence_uri agent_evidence_entry agent_evidence_entry_cited agent_evidence_pointer_status agent_decision agent_decision_before_auth agent_order_matches_charge agent_order_reference_matched agent_charge_id agent_authorization_time agent_witness_time agent_witness_state agent_witness_time_as_supplied agent_log_state agent_key_state agent_card_binding_state agent_instruction_state agent_instruction_scope_ok agent_instruction_exceeded agent_gate_receipt_state agent_gaps agent_limits agent_verifier agent_verifier_commit".split(" ");

let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-unlocks-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

// Each need an entry names that BUILT lacks, as [property, need].
export const missingNeeds = (unlocks, built) => Object.entries(unlocks).flatMap(([p, e]) => Object.keys(e.needs).filter((n) => !built.has(n)).map((n) => [p, n]));

// A view's tie gives { view: { <need's view>: true or false } } in place of a verdict.
const VIEW_TIES = {
  // W3-07: the exhibit of V-10's verdict, made twice by the command line.
  "V-50": async () => {
    const { bytes } = await verdictOf(vectorById("V-10"), dir);
    const vp = path.join(dir, "tie-v50.verdict.json");
    writeFileSync(vp, bytes);
    const make = (n) => {
      const out = path.join(dir, `tie-v50-${n}.pdf`);
      const r = spawnSync(process.execPath, [path.join(FOLDER, "make-exhibit.mjs"), vp, "--page", "letter", "--out", out], { encoding: "utf8" });
      return { r, file: r.status === 0 && existsSync(out) ? readFileSync(out) : null };
    };
    const a = make(1);
    if (!a.file) return { status: a.r.status ?? 1, stderr: a.r.stderr, output: null };
    const b = make(2);
    const pdf = readPdf(a.file);
    const { shown, literal } = drawnStrings(pdf);
    const w = exhibitLib.makeExhibit(bytes, { page: "letter" });
    return {
      status: 0,
      stderr: "",
      output: {
        view: {
          written: pdf.header === "%PDF-1.7" && [...pdf.text.matchAll(/\/Type \/Page\b(?!s)/g)].length === 1,
          "same-bytes": Boolean(b.file && a.file.equals(b.file)),
          strings: literal === 0 && JSON.stringify(shown) === JSON.stringify(w.lines.map(shownForm)),
        },
      },
    };
  },
  // W3-08: the export of V-10's verdict: every member of 4.10, and the
  // members a run without a pointer leaves null.
  "V-60": async () => {
    const { bytes, output } = await verdictOf(vectorById("V-10"), dir);
    const vp = path.join(dir, "tie-v60.verdict.json");
    writeFileSync(vp, bytes);
    const r = spawnSync(process.execPath, [path.join(FOLDER, "make-datapoints.mjs"), vp], { encoding: "utf8" });
    if (r.status !== 0) return { status: r.status ?? 1, stderr: r.stderr, output: null };
    const d = JSON.parse(r.stdout);
    const members =
      JSON.stringify(Object.keys(d).sort()) === JSON.stringify([...DATAPOINT_MEMBERS].sort()) &&
      d.agent_evidence_verdict === output.verdict.code &&
      d.agent_evidence_uri === null &&
      d.agent_decision_before_auth === null &&
      d.agent_order_matches_charge === true;
    return { status: 0, stderr: "", output: { view: { members } } };
  },
  // W3-09: pages/we-4-1.json, its seven members, and the sha256 of the
  // bundle file and of the exhibit it names equal to the files'.
  "V-70": async () => {
    const f = path.join(FOLDER, "pages", "we-4-1.json");
    if (!existsSync(f)) return { status: 2, stderr: "pages/we-4-1.json is absent", output: null };
    const p = JSON.parse(readFileSync(f, "utf8"));
    const seven = ["id", "limit", "bundle", "stated", "offline_verdict", "datapoints", "exhibit"];
    const sha = (rel) => createHash("sha256").update(readFileSync(path.join(FOLDER, rel))).digest("hex");
    const page = JSON.stringify(Object.keys(p).filter((k) => k !== "online")) === JSON.stringify(seven) && p.bundle.sha256 === sha(p.bundle.path) && p.exhibit.sha256 === sha(p.exhibit.path);
    return { status: 0, stderr: "", output: { view: { page } } };
  },
};

async function runTie(id) {
  if (VIEW_TIES[id]) return VIEW_TIES[id]();
  const v = VECTORS.find((x) => x.id === id);
  if (v) return runVector(v, dir);
  // An online case runs through the library entry, its reads answered by a fake (W3-10).
  const oc = ONLINE_CASES.find((x) => x.id === id);
  if (oc) {
    const r = await oc.run(verifyBundle);
    return { status: r.kind === "verdict" ? 0 : 2, stderr: r.kind === "refused" ? `not supported in this build: ${r.code}` : "", output: r.output ?? null };
  }
  // A pointer case runs through the library entry, its fetch a fake (W3-05).
  const pc = POINTER_CASES.find((x) => x.id === id);
  if (pc) {
    const r = await pc.run(verifyPointer);
    return { status: r.kind === "verdict" ? 0 : 2, stderr: r.kind === "refused" ? `not supported in this build: ${r.code}` : "", output: r.output ?? null };
  }
  const c = CASES.find((x) => x.id === id);
  assert.ok(c, `tie vector ${id} is neither a vector nor a refusal case`);
  const { doc, args } = await c.build();
  return runCli(dir, `tie-${id}`, doc, args);
}

test("every judged property has an UNLOCKS entry, and every entry is judged", () => {
  assert.deepEqual(JUDGED.filter((p) => !(p in UNLOCKS)), []);
  assert.deepEqual(Object.keys(UNLOCKS).filter((p) => !JUDGED.includes(p)), []);
});

// Asserts that output `o` reaches each need of an entry: a check need as a
// row with status PASS or FAIL (NOT-EVALUATED only with the reason the need
// names); a tag need as its binding in the state the need names, or, in a
// pair tie, one of the states the need lists as reached (`reached`).
function assertReached(o, needs, { pair = false } = {}) {
  for (const [need, w] of Object.entries(needs)) {
    // A view need: the property of the view its tie made (W3-07 to W3-09).
    if (w.view) {
      assert.equal(o.view?.[w.view], true, `${need}: the view is ${w.view}`);
      continue;
    }
    // A verdict need: the verdict's code, rule and text (W3-02: a card rule and its card text).
    if (w.verdict) {
      for (const [k, val] of Object.entries(w.verdict)) assert.equal(o.verdict[k], val, `${need}: verdict ${k}`);
      continue;
    }
    if (w.binding) {
      const b = o.bindings.find((x) => x.id === w.binding);
      if (pair && w.reached) assert.ok(w.reached.includes(b.state), `${need}: ${w.binding} state ${b.state}`);
      else {
        assert.equal(b.state, w.state, `${need}: ${w.binding} state`);
        if ("reason" in w) assert.equal(b.reason, w.reason, `${need}: ${w.binding} reason`);
      }
    } else {
      const rows = o.checks.filter((c) => c.id === need && (!w.member || c.member === w.member));
      assert.ok(rows.length > 0, `${need} is listed${w.member ? ` for ${w.member}` : ""}`);
      for (const c of rows) {
        // A need may name the one status that reaches it (W3-01: M0.bundle PASS on a 0.10 bundle).
        if (w.status) assert.equal(c.status, w.status, `${need} on ${c.member}: ${c.status}`);
        else if (c.status === "NOT-EVALUATED") assert.equal(c.reason, w.notEvaluated, `${need} on ${c.member}: NOT-EVALUATED only with the reason the entry names`);
        else assert.ok(["PASS", "FAIL"].includes(c.status), `${need} on ${c.member}: ${c.status}`);
      }
    }
  }
}

for (const [p, e] of Object.entries(UNLOCKS)) {
  test(`${p} (${e.widening}): every need is built, and ${e.tie} reaches each`, async () => {
    assert.deepEqual(missingNeeds({ [p]: e }, BUILT), [], "every need is in BUILT");
    // A unit tie is the test of that function below.
    if (e.tie.startsWith("unit:")) return;
    const r = await runTie(e.tie);
    assert.equal(r.status, 0, `${e.tie} gives an output, not a refusal: ${r.stderr}`);
    assertReached(r.output, e.needs);
  });
}

for (const [id, p1, p2] of PAIRS) {
  test(`pair ${id}: ${p1} (${UNLOCKS[p1]?.widening}) with ${p2} (${UNLOCKS[p2]?.widening}): the needs of both are reached`, async () => {
    assert.ok(UNLOCKS[p1] && UNLOCKS[p2], "both properties have entries");
    assert.ok(JUDGED.includes(p1) && JUDGED.includes(p2), "both properties are judged");
    const r = await runTie(id);
    assert.equal(r.status, 0, `${id} gives an output, not a refusal: ${r.stderr}`);
    assertReached(r.output, UNLOCKS[p1].needs, { pair: true });
    assertReached(r.output, UNLOCKS[p2].needs, { pair: true });
  });
}

test("carrier:calldata (Wb-02) and unread-carrier (Wb-10): WE-1's decoded state with the carrier calldata is judged, and with a match that does not bind", async () => {
  let s = null;
  await verifyBundle(bundleBytes(we1()), { authorizer: A.toLowerCase(), tx: T }, loadPins(), { onDecoded: (x) => (s = x) });
  assert.ok(s && s.search, "WE-1's decoded state, with its search");
  assert.equal(decodedShape(s), null, "WE-1 as it is");
  assert.equal(decodedShape({ ...s, search: { ...s.search, carrier: "calldata", nonBinding: [] } }), null, "the carrier calldata, no match that does not bind");
  // Refused from Wb-02 until Wb-10 judged a match that does not bind.
  assert.equal(decodedShape({ ...s, search: { ...s.search, carrier: "calldata", nonBinding: [{ field: "input", form: "hex-text", offset: 300 }] } }), null, "one match that does not bind");
});

// An input property is refused by name until it is judged, as a shape is.
for (const [property, option] of [
  ["card:charge-stated", "--charge-amount"],
  ["pointer", "--evidence-uri"],
])
  test(`an input not judged is refused by name: ${property}`, () => {
    if (JUDGED.includes(property)) return;
    const r = runCli(dir, `input-${property.replace(/\W/g, "-")}`, we1(), [option, "x"]);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.equal(r.stderr, `not supported in this build: ${property}\n`);
  });

test("red proof: an entry that needs a check this build does not have is reported", () => {
  assert.deepEqual(missingNeeds(UNLOCKS, BUILT), []);
  const copy = { ...UNLOCKS, "chain:eip155:8453": { widening: "none", needs: { "O5.token-domain-call": {} }, tie: "none" } };
  assert.deepEqual(missingNeeds(copy, BUILT), [["chain:eip155:8453", "O5.token-domain-call"]]);
  assert.ok(!BUILT.has("O5.token-domain-call"));
});
