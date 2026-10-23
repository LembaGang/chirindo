// The ties between what the allow-list judges and what the verifier builds
// (lib/allowlist.mjs JUDGED, lib/unlocks.mjs UNLOCKS, lib/built.mjs BUILT):
// every judged property has an entry and every entry is judged; every need of
// every entry is built; and each entry's tie vector gives an output, not a
// refusal, in which each need is reached. The red proof shows that an entry
// whose need is not built is reported.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { JUDGED } from "../lib/allowlist.mjs";
import { UNLOCKS } from "../lib/unlocks.mjs";
import { BUILT } from "../lib/verify.mjs";
import { runCli, runVector, VECTORS } from "../vectors/make-vectors.mjs";
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

for (const [p, e] of Object.entries(UNLOCKS)) {
  test(`${p} (${e.widening}): every need is built, and ${e.tie} reaches each`, async () => {
    assert.deepEqual(missingNeeds({ [p]: e }, BUILT), [], "every need is in BUILT");
    const r = await runTie(e.tie);
    assert.equal(r.status, 0, `${e.tie} gives an output, not a refusal: ${r.stderr}`);
    const o = r.output;
    for (const [need, w] of Object.entries(e.needs)) {
      if (w.binding) {
        const b = o.bindings.find((x) => x.id === w.binding);
        assert.equal(b.state, w.state, `${need}: ${w.binding} state`);
        if ("reason" in w) assert.equal(b.reason, w.reason, `${need}: ${w.binding} reason`);
      } else {
        const rows = o.checks.filter((c) => c.id === need && (!w.member || c.member === w.member));
        assert.ok(rows.length > 0, `${need} is listed${w.member ? ` for ${w.member}` : ""}`);
        for (const c of rows) {
          if (c.status === "NOT-EVALUATED") assert.equal(c.reason, w.notEvaluated, `${need} on ${c.member}: NOT-EVALUATED only with the reason the entry names`);
          else assert.ok(["PASS", "FAIL"].includes(c.status), `${need} on ${c.member}: ${c.status}`);
        }
      }
    }
  });
}

test("red proof: an entry that needs a check this build does not have is reported", () => {
  assert.deepEqual(missingNeeds(UNLOCKS, BUILT), []);
  const copy = { ...UNLOCKS, "chain:eip155:8453": { widening: "none", needs: { "O5.token-domain-call": {} }, tie: "none" } };
  assert.deepEqual(missingNeeds(copy, BUILT), [["chain:eip155:8453", "O5.token-domain-call"]]);
  assert.ok(!BUILT.has("O5.token-domain-call"));
});
