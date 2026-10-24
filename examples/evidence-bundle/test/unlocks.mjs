// The ties between what the allow-list judges and what the verifier builds
// (lib/allowlist.mjs JUDGED, lib/unlocks.mjs UNLOCKS, lib/built.mjs BUILT):
// every judged property has an entry and every entry is judged; every need of
// every entry is built; and each entry's tie vector gives an output, not a
// refusal, in which each need is reached. The red proof shows that an entry
// whose need is not built is reported. A property whose own rows all need a
// later widening is tied by a unit test of decodedShape on WE-1's decoded state.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { decodedShape, JUDGED } from "../lib/allowlist.mjs";
import { loadPins } from "../lib/cli.mjs";
import { PAIRS, UNLOCKS } from "../lib/unlocks.mjs";
import { BUILT, verifyBundle } from "../lib/verify.mjs";
import { bundleBytes } from "../lib/we1.mjs";
import { A, runCli, runVector, T, VECTORS, we1 } from "../vectors/make-vectors.mjs";
import { CASES } from "../vectors/refusal-cases.mjs";

let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-unlocks-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

// Each need an entry names that BUILT lacks, as [property, need].
export const missingNeeds = (unlocks, built) => Object.entries(unlocks).flatMap(([p, e]) => Object.keys(e.needs).filter((n) => !built.has(n)).map((n) => [p, n]));

async function runTie(id) {
  const v = VECTORS.find((x) => x.id === id);
  if (v) return runVector(v, dir);
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
        if (c.status === "NOT-EVALUATED") assert.equal(c.reason, w.notEvaluated, `${need} on ${c.member}: NOT-EVALUATED only with the reason the entry names`);
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

test("red proof: an entry that needs a check this build does not have is reported", () => {
  assert.deepEqual(missingNeeds(UNLOCKS, BUILT), []);
  const copy = { ...UNLOCKS, "chain:eip155:8453": { widening: "none", needs: { "O5.token-domain-call": {} }, tie: "none" } };
  assert.deepEqual(missingNeeds(copy, BUILT), [["chain:eip155:8453", "O5.token-domain-call"]]);
  assert.ok(!BUILT.has("O5.token-domain-call"));
});
