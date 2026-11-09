// B-448, Lead ruling 2026-11-09 option A (spec v0.11 D.3): a member whose
// content the verifier does not read says so in the verdict, machine-readably.
// The M1.member row (status PASS) of every `supporting` member and of every
// vi-0.1-draft or ap2-0.2 instruction carries state "PRESENT"; every other
// M1.member row carries no `state`. The sweep runs every vector and asserts it
// met each kind of member at least once, so it cannot pass on a set that lacks them.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { OUTPUT_TYPE } from "../lib/table.mjs";
import { project, runVector, VECTORS } from "../vectors/make-vectors.mjs";

const UNREAD_PROFILES = new Set(["vi-0.1-draft", "ap2-0.2"]);
const unread = (m) => m.role === "supporting" || (m.role === "instruction" && UNREAD_PROFILES.has(m.profile));
const kindOf = (m) => (m.role === "supporting" ? "supporting" : m.role === "instruction" ? m.profile : "other");

let dir;
const runs = [];
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-present-"));
  for (const v of VECTORS) {
    const r = await runVector(v, dir);
    if (r.status === 0) runs.push([v.id, r]);
  }
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("the output type is evidence-bundle-verdict/0.11", () => {
  assert.equal(OUTPUT_TYPE, "evidence-bundle-verdict/0.11");
  assert.ok(runs.length >= 20);
  for (const [id, r] of runs) assert.equal(r.output.type, "evidence-bundle-verdict/0.11", id);
});

test("an M1.member PASS row carries state PRESENT exactly for supporting, vi-0.1-draft and ap2-0.2 members", () => {
  const seen = new Map();
  for (const [id, r] of runs) {
    const members = new Map(r.built.doc.members.map((m) => [m.id, m]));
    for (const c of r.output.checks) {
      if (c.id !== "M1.member" || c.status !== "PASS") continue;
      const m = members.get(c.member);
      assert.ok(m, `${id}: ${c.member} is a member of the bundle`);
      const k = kindOf(m);
      seen.set(k, (seen.get(k) ?? 0) + 1);
      if (unread(m)) assert.equal(c.state, "PRESENT", `${id}: ${c.member} (${m.role}, ${m.profile})`);
      else assert.equal(Object.keys(c).includes("state"), false, `${id}: ${c.member} (${m.role}, ${m.profile}) has no state`);
    }
  }
  for (const k of ["supporting", "vi-0.1-draft", "ap2-0.2", "signed-instruction-ed25519/0.2", "signed-instruction-ed25519/0.3", "other"])
    assert.ok((seen.get(k) ?? 0) > 0, `the vectors meet at least one ${k} M1.member row`);
});

test("no other check row carries a state", () => {
  for (const [id, r] of runs)
    for (const c of r.output.checks) if (c.id !== "M1.member") assert.equal(Object.keys(c).includes("state"), false, `${id}: ${c.id}`);
});

test("the D.5 projection carries a check's state, and only where the output has one", () => {
  const sa12 = runs.find(([id]) => id === "SA-12");
  assert.ok(sa12, "SA-12 (WE-1 with an opaque supporting member) ran");
  const p = project(sa12[1].output);
  const sup = p.checks.find((c) => c.id === "M1.member" && c.member === "sup-a");
  assert.deepEqual(sup, { id: "M1.member", member: "sup-a", status: "PASS", reason: null, state: "PRESENT" });
  const other = p.checks.find((c) => c.id === "M1.member" && c.member !== "sup-a");
  assert.equal(Object.keys(other).includes("state"), false);
});
