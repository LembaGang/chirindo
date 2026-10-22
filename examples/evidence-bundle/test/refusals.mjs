// The shape this build judges (README.md, "The shape this build judges"): one
// test per class it refuses, each asserting exit 2, the one stderr line
// "not supported in this build: <code>" and an empty stdout; and one test per
// FAILS twin, asserting the verdict FAILS with the named check. Each refused
// bundle is also run through the library entry, to show that every check that
// ran before the refusal passed or was not evaluated, and that the payment's
// checks named below passed, so that the refusal and not a FAIL is what the
// test sees.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { loadPins, parseArgs } from "../lib/cli.mjs";
import { verifyBundle } from "../lib/verify.mjs";
import { bundleBytes } from "../lib/we1.mjs";
import { runCli } from "../vectors/make-vectors.mjs";
import { CASES } from "../vectors/refusal-cases.mjs";

const M5_STEPS_0_TO_4 = ["M5.chain", "M5.receipt", "M5.block", "M5.support", "M5.transaction", "M5.sender", "M5.block-hash", "M5.call"];
const M5_ALL = [...M5_STEPS_0_TO_4, "M5.token-domain", "M5.authorization", "M5.token-logs", "M5.validity-window"];
const MUST_PASS = {
  "T-11": ["M2.log", "M9.operator-key"],
  "T-12": ["M9.operator-key", ...M5_ALL],
  "T-13": ["M2.log", "M9.operator-key"],
  "T-14": ["M2.log", "M2.prefix"],
  "T-15": ["M3.checkpoint", "M3.signature", "M3.history"],
  "T-16": M5_STEPS_0_TO_4,
  "T-17": ["M5.chain", "M5.receipt", "M5.block"],
  "T-18": M5_ALL,
  "T-19": M5_ALL,
  "T-20": ["M5.chain", "M5.receipt", "M5.block"],
  "T-22": M5_ALL,
  "T-23": M5_STEPS_0_TO_4,
  "T-24": M5_STEPS_0_TO_4,
  "T-25": M5_ALL,
  "T-26": M5_STEPS_0_TO_4,
  "T-27": M5_STEPS_0_TO_4,
  "T-28": M5_STEPS_0_TO_4,
  "T-29": M5_ALL,
  "T-30": M5_ALL.filter((id) => id !== "M5.authorization"),
  "T-31": M5_ALL,
  "T-32": M5_ALL,
};

let dir;
let pins;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-refusals-"));
  pins = loadPins();
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("the table has 45 rows: T-01 to T-36 and nine FAIL twins", () => {
  assert.equal(CASES.length, 45);
  const ids = CASES.map((c) => c.id);
  for (let k = 1; k <= 36; k++) assert.ok(ids.includes(`T-${String(k).padStart(2, "0")}`), `T-${k}`);
  for (const t of ["T-11F", "T-12F", "T-13F", "T-14F", "T-15F", "T-18F", "T-19F", "T-22F", "T-25F"]) assert.ok(ids.includes(t), t);
});

for (const c of CASES) {
  test(`${c.id}: ${c.code ? `exit 2, ${c.code}` : `FAILS, ${c.fails}`}`, async () => {
    const { doc, args } = await c.build();
    const r = runCli(dir, c.id, doc, args);
    const o = parseArgs(["bundle.json", ...args]);
    const lib = await verifyBundle(bundleBytes(doc), { authorizer: o.authorizer, tx: o.tx }, pins);
    if (c.code) {
      assert.equal(r.status, 2, r.stderr);
      assert.equal(r.stdout, "");
      assert.equal(r.stderr, `not supported in this build: ${c.code}\n`);
      assert.equal(lib.kind, "refused");
      assert.ok(!lib.checks.some((x) => x.status === "FAIL"), "no check that ran before the refusal FAILed");
      for (const id of MUST_PASS[c.id] ?? []) {
        const rows = lib.checks.filter((x) => x.id === id);
        assert.ok(rows.length > 0, `${id} ran`);
        for (const row of rows) assert.equal(row.status, row.id === "M2.log" && row.member === "log-l" ? "NOT-EVALUATED" : "PASS", `${id} on ${row.member}: ${row.detail}`);
      }
      if (c.id === "T-30") assert.equal(lib.checks.find((x) => x.id === "M5.authorization").reason, "contract-signer");
    } else {
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.output.verdict.code, "FAILS");
      const failed = [...r.output.checks.filter((x) => x.status === "FAIL").map((x) => x.id), ...r.output.bindings.filter((b) => b.state === "FAIL").map((b) => b.id)];
      assert.ok(failed.includes(c.fails), `${c.fails} FAILs (FAILs: ${failed.join(", ")})`);
    }
  });
}
