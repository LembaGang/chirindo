// The output against the schema of spec D.3 (schema/, the exact text of its
// code block), with a validator for the keywords that schema uses. The
// validator is shown to reject what it must, so that a pass means something.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { validate } from "../lib/schema-check.mjs";
import { FOLDER, runVector, VECTORS } from "../vectors/make-vectors.mjs";

const file = path.join(FOLDER, "schema", "evidence-bundle-verdict-0.11.schema.json");
// 0.10 stays as published (spec v0.10 rev3 D.3); a 0.10 validator rejects a 0.11 output.
const file010 = path.join(FOLDER, "schema", "evidence-bundle-verdict-0.10.schema.json");
const schema = JSON.parse(readFileSync(file, "utf8"));
let dir;
const outputs = [];
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-schema-"));
  for (const v of VECTORS) {
    const r = await runVector(v, dir);
    if (r.status === 0) outputs.push([v.id, r.output]);
  }
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("the schema file is the code block of spec v0.11 D.3", () => {
  const b = readFileSync(file);
  assert.equal(b.length, 12099);
  assert.equal(createHash("sha256").update(b).digest("hex"), "847a12b2d806b5a349e501241b0d190edfad836da9285b24f98ddf7d7e4811b7");
});

test("the 0.10 schema file is unchanged: the code block of spec v0.10 rev3 D.3", () => {
  const b = readFileSync(file010);
  assert.equal(b.length, 12065);
  assert.equal(createHash("sha256").update(b).digest("hex"), "64bd63bed5f41b1151419f50552d145966b49cab3d1b9455cc53aa4a5908ddfd");
});

test("the 0.10 schema rejects a check row that carries state, which is why the type moved to 0.11", () => {
  const schema010 = JSON.parse(readFileSync(file010, "utf8"));
  const withState = outputs.map(([, o]) => o).find((o) => o.checks.some((c) => Object.keys(c).includes("state")));
  assert.ok(withState, "a vector output carries a check row with state");
  const o = structuredClone(withState);
  o.type = "evidence-bundle-verdict/0.10";
  assert.ok(validate(schema010, o).length > 0);
  for (const c of o.checks) delete c.state;
  assert.deepEqual(validate(schema010, o), [], "the same output without state is valid 0.10");
});

test("the output of every vector validates", () => {
  assert.ok(outputs.length >= 20);
  for (const [id, o] of outputs) assert.deepEqual(validate(schema, o), [], id);
});

test("the validator rejects what the schema forbids", () => {
  const o = structuredClone(outputs[0][1]);
  const bad = (edit) => {
    const x = structuredClone(o);
    edit(x);
    return validate(schema, x).length > 0;
  };
  assert.ok(bad((x) => (x.extra = 1)), "an extra member");
  assert.ok(bad((x) => delete x.limits), "a missing member");
  assert.ok(bad((x) => (x.verdict.code = "PASSES")), "a value outside an enum");
  assert.ok(bad((x) => (x.type = "evidence-bundle-verdict/0.8")), "another const");
  assert.ok(bad((x) => (x.stated.authorizer = "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673")), "an address not lowercase ($ref and pattern)");
  assert.ok(bad((x) => (x.decision.record.seq = -1)), "below a minimum");
  assert.ok(bad((x) => (x.checks[0].status = 1)), "another type");
  assert.ok(bad((x) => (x.bindings[0].state = "PASS")), "a state outside $defs");
  assert.ok(bad((x) => (x.checks[0].state = "MATCHED")), "a check state other than PRESENT");
  assert.ok(validate({ type: "object", oneOf: [] }, {}).length > 0, "a keyword the validator does not know");
});
