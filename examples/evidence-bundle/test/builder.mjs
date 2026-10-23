// build-we1.mjs's digest refusal: on a copy of its eleven sources under
// --root it writes the bytes of the default build, and with one byte of one
// source changed it exits 2, names the file, and writes nothing. Exit 1 (an
// internal error) has no test: no input is known to reach it.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { buildWe1 } from "../build-we1.mjs";
import { bundleBytes, REPO_ROOT, SOURCES } from "../lib/we1.mjs";

const BUILDER = path.join(REPO_ROOT, "examples", "evidence-bundle", "build-we1.mjs");
const RECEIPT = "examples/ordering-evidence/case-a/rpc/receipt.sealed.json";
let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-builder-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

function copySources(root) {
  for (const rel of Object.keys(SOURCES)) {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    copyFileSync(path.join(REPO_ROOT, rel), path.join(root, rel));
  }
}
const build = (root, out) => spawnSync(process.execPath, [BUILDER, "--root", root, "--out", out], { encoding: "utf8" });

test("a copy of the eleven sources under --root gives the default build's bytes", () => {
  const root = path.join(dir, "same");
  copySources(root);
  assert.equal(Object.keys(SOURCES).length, 11);
  const out = path.join(root, "we1.json");
  const r = build(root, out);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(readFileSync(out).equals(bundleBytes(buildWe1())));
});

test("one changed byte of a source: exit 2, the file named, nothing written", () => {
  const root = path.join(dir, "changed");
  copySources(root);
  const p = path.join(root, RECEIPT);
  const b = readFileSync(p);
  b[100] ^= 1;
  writeFileSync(p, b);
  const out = path.join(root, "we1.json");
  const r = build(root, out);
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
  assert.ok(r.stderr.startsWith(`refused: ${RECEIPT} does not have its committed sha256`), r.stderr);
  assert.equal(r.stderr.trim().split("\n").length, 1);
  assert.ok(!existsSync(out));
});
