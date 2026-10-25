// W3-05: the Agent Evidence Pointer (spec section 3 and 4.2, P1.pointer and
// P2.entry; D.1; D.4), through the library entry with a fake fetch
// (vectors/pointer-cases.mjs) and, for its usage errors, through the CLI.
// lib/pointer.mjs is imported in each test, so that each test stands alone.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { verifyBundle } from "../lib/verify.mjs";
// make-vectors.mjs first: it and rows-a3.mjs import each other, and
// make-vectors.mjs reads rows-a3.mjs's rows as it loads.
import { runCli } from "../vectors/make-vectors.mjs";
import { cardPins } from "../vectors/rows-a3.mjs";
import { POINTER_CASES, STATED, URI, we4Bundle } from "../vectors/pointer-cases.mjs";

let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-pointer-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const run = async (id) => {
  const { verifyPointer } = await import("../lib/pointer.mjs");
  return POINTER_CASES.find((c) => c.id === id).run(verifyPointer);
};
const check = (o, id) => o.checks.find((c) => c.id === id);
// V-10's verdict, the bundle read from its bytes with no pointer.
const v10 = async () => (await verifyBundle(we4Bundle().bytes, STATED, cardPins())).output.verdict;

test("V-40: the entry stated and no digest: P1.pointer PASS fetched, P2.entry PASS, V-10's verdict [spec, v0.10 lines 233, 1302]", async () => {
  const r = await run("V-40");
  const o = r.output;
  assert.equal(r.kind, "verdict");
  assert.deepEqual([check(o, "P1.pointer").status, o.pointer.status], ["PASS", "fetched"]);
  assert.equal(check(o, "P2.entry").status, "PASS");
  assert.deepEqual(o.verdict, await v10());
  assert.deepEqual(o.pointer, { uri: URI, stated_entry: r.bundle.entry, stated_sha256: null, fetched_sha256: r.bundle.sha256, status: "fetched", detail: o.pointer.detail });
  assert.equal(o.bundle_sha256, r.bundle.sha256);
});

test("V-40: one GET, no credentials, redirects not followed by fetch; P1 and P2 listed after the stated inputs, before M0 [derived]", async () => {
  const r = await run("V-40");
  assert.equal(r.fetch.calls.length, 1);
  const init = r.fetch.calls[0].init;
  assert.deepEqual([init.method, init.redirect, init.credentials], ["GET", "manual", "omit"]);
  assert.deepEqual([...new Headers(init.headers ?? {}).keys()], []);
  const ids = r.output.checks.map((c) => c.id);
  assert.deepEqual(ids.slice(0, 4), ["S3.charge", "P1.pointer", "P2.entry", "M0.bundle"]);
  assert.equal(check(r.output, "P2.entry").member, "log-d");
});

test("V-41: with its digest stated: match, written lowercase [spec, v0.10 lines 233, 1153, 1302]", async () => {
  const r = await run("V-41");
  const o = r.output;
  assert.deepEqual([check(o, "P1.pointer").status, o.pointer.status], ["PASS", "match"]);
  assert.equal(o.pointer.stated_sha256, r.bundle.sha256);
  assert.equal(o.pointer.fetched_sha256, r.bundle.sha256);
  assert.deepEqual(o.verdict, await v10());
});

test("V-42: another digest stated: P1.pointer FAIL, mismatch, both digests, FAILS, nothing else runs [spec, v0.10 lines 233, 696, 1302]", async () => {
  const o = (await run("V-42")).output;
  assert.deepEqual([check(o, "P1.pointer").status, o.pointer.status], ["FAIL", "mismatch"]);
  assert.notEqual(o.pointer.stated_sha256, o.pointer.fetched_sha256);
  assert.ok(o.pointer.stated_sha256 && o.pointer.fetched_sha256);
  assert.equal(o.bundle_sha256, o.pointer.fetched_sha256);
  assert.deepEqual([o.verdict.code, o.verdict.rule], ["FAILS", "V1"]);
  assert.equal(check(o, "M0.bundle"), undefined);
  for (const b of o.bindings) assert.deepEqual([b.state, b.reason], ["NOT-EVALUATED", "prerequisite-failed:P1.pointer"], b.id);
});

test("V-43: a bundle that cites another entry: P2.entry FAIL, FAILS, its detail naming the cited entry [spec, v0.10 lines 233, 642, 1302]", async () => {
  const r = await run("V-43");
  const o = r.output;
  assert.equal(check(o, "P1.pointer").status, "PASS");
  const p2 = check(o, "P2.entry");
  assert.equal(p2.status, "FAIL");
  assert.ok(p2.detail.includes(we4Bundle((await import("../vectors/rows-a3.mjs")).WE4_ORDER_2).entry), p2.detail);
  assert.deepEqual([o.verdict.code, o.verdict.rule], ["FAILS", "C1"]);
});

test("V-44: served with Content-Encoding gzip: the digest of the bundle file, match [spec, v0.10 lines 233, 1302]", async () => {
  const r = await run("V-44");
  assert.deepEqual([check(r.output, "P1.pointer").status, r.output.pointer.status, r.output.pointer.fetched_sha256], ["PASS", "match", r.bundle.sha256]);
});

for (const [id, why] of [
  ["V-45a", /404/],
  ["V-45b", /https/],
  ["V-45c", /redirect/],
  ["V-45d", /67,108,864|67108864/],
  ["V-45e", /60 s/],
])
  test(`${id}: ${POINTER_CASES.find((c) => c.id === id).what}: PAYMENT-NOT-VERIFIED pointer-unfetchable, bundle_sha256 null [spec, v0.10 lines 233, 548, 696, 1302]`, async () => {
    const r = await run(id);
    const o = r.output;
    const p1 = check(o, "P1.pointer");
    assert.deepEqual([p1.status, p1.reason, o.pointer.status], ["NOT-EVALUATED", "pointer-unfetchable", "unfetchable"]);
    assert.match(p1.detail, why);
    assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "pointer-unfetchable"]);
    assert.equal(o.bundle_sha256, null);
    assert.equal(o.pointer.fetched_sha256, null);
    for (const b of o.bindings) assert.deepEqual([b.state, b.reason], ["NOT-EVALUATED", "prerequisite-failed:P1.pointer"], b.id);
    if (id === "V-45e") assert.deepEqual(r.delays, [60000]);
    if (id === "V-45c") assert.equal(r.fetch.calls.length, 6);
  });

// The CLI's usage errors (spec 4.2): exit 2, one line on stderr, nothing on stdout.
const ENTRY = "sha256:" + "ab".repeat(32);
for (const [id, what, args, noBundle] of [
  ["V-46a", "an http URI", ["--evidence-uri", "http://evidence.test-merchant.example/b.json", "--evidence-entry", ENTRY], true],
  ["V-46b", "a URI with user information", ["--evidence-uri", "https://user:pw@evidence.test-merchant.example/b.json", "--evidence-entry", ENTRY], true],
  ["V-46c", "an entry of another form", ["--evidence-uri", URI, "--evidence-entry", "sha256:" + "ab".repeat(31)], true],
  ["V-46d", "an entry without a URI", ["--evidence-entry", ENTRY], true],
  ["V-46e", "a bundle path with the pointer", ["--evidence-uri", URI, "--evidence-entry", ENTRY], false],
])
  test(`${id}: through the CLI, ${what}: a usage error whose reason is not "unknown option" [spec, v0.10 lines 233, 1302]`, () => {
    const r = runCli(dir, id, we4Bundle().doc, args, { noBundle });
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /^usage error: /);
    assert.doesNotMatch(r.stderr, /unknown option/);
    assert.equal(r.stderr.split("\n").length, 2);
  });
