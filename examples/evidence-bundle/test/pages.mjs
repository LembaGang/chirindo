// The page-ready JSON files of the card worked examples (W3-09 and W3-10;
// pages/<id>.json): each holds the example's stated limit, its bundle file,
// the stated inputs and the pins named, the offline verdict, the data-point
// export and the exhibit, and, once the live step has run, the online verdict.
// Each page is checked against itself: the bundle file's bytes, a fresh
// offline run of that bundle with the page's own stated inputs, the export
// and the exhibit made again from the page's verdict.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { FOLDER } from "../vectors/make-vectors.mjs";
import { sha256 } from "../vectors/view-cases.mjs";
import { datapointsOf } from "../lib/datapoints.mjs";
import { makeExhibit } from "../lib/exhibit.mjs";

const PAGES = path.join(FOLDER, "pages");
const SEVEN = ["id", "limit", "bundle", "stated", "offline_verdict", "datapoints", "exhibit"];
// The examples' stated limits, spec section 7, WE-4 (line 926) and WE-5 (line 943).
const LIMITS = {
  "we-4": "in WE-4, Headless Oracle is the gate's operator (it runs the gate and holds the operator key) and the witness, and the customer, the merchant and the charge are test parties the example makes. The example demonstrates the format and the checks, not independence between those parties (L14, L3). The card data is test data only: no card number, expiry, security code, network token or last four digits appears in the bundle, in the stated inputs, on the page or on the exhibit, because B-CARD reads none of them; the charge id and every merchant and item value are labelled test values (`TEST`, and the domain `test-merchant.example`, under the `.example` name reserved for examples).",
  "we-5": "Headless Oracle is the gate's operator and the witness; the traveller, the hotel and the charge are test parties; test card data only.",
};

const pageFiles = () => readdirSync(PAGES).filter((f) => /^we-[45]-[12]\.json$/.test(f)).sort();
const read = (f) => JSON.parse(readFileSync(path.join(PAGES, f), "utf8"));
// The verdict JSON's bytes as check-bundle.mjs writes them.
const verdictBytes = (o) => Buffer.from(JSON.stringify(o, null, 2) + "\n", "utf8");
const withoutClock = (o) => ({ ...o, checked_at: null });
const fileAt = (rel) => path.join(FOLDER, rel);

// The page's bundle run offline again with the page's stated inputs.
function rerun(p) {
  const args = p.stated.args.map((a) => (a.startsWith("pages/") ? fileAt(a) : a));
  const r = spawnSync(process.execPath, [path.join(FOLDER, "check-bundle.mjs"), fileAt(p.bundle.path), ...args], { encoding: "utf8" });
  assert.equal(r.status, 0, `${p.id}: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

test("V-70: pages/we-4-1.json exists, with its seven members (and online, once the live step has run) [derived]", () => {
  assert.ok(pageFiles().includes("we-4-1.json"), "pages/we-4-1.json");
  const p = read("we-4-1.json");
  assert.deepEqual(Object.keys(p).filter((k) => k !== "online"), SEVEN);
  assert.ok(Object.keys(p).length === 7 || Object.keys(p).at(-1) === "online");
});

test("V-70: each page's bundle member names its committed bundle file, with that file's sha256 and size; the offline verdict reads that file [derived]", () => {
  for (const f of pageFiles()) {
    const p = read(f);
    assert.equal(`${p.id}.json`, f);
    assert.deepEqual(Object.keys(p.bundle), ["path", "sha256", "size"]);
    assert.match(p.bundle.path, /^pages\/[a-z0-9-]+\.bundle\.json$/);
    const b = readFileSync(fileAt(p.bundle.path));
    assert.equal(p.bundle.sha256, sha256(b), f);
    assert.equal(p.bundle.size, b.length, f);
    assert.ok(p.offline_verdict.bundle_sha256.endsWith(sha256(b)), `${f}: the verdict's bundle_sha256`);
  }
});

test("V-70: each page's limit is its example's stated limit (spec section 7), and its stated inputs name the pins it was run with [derived]", () => {
  for (const f of pageFiles()) {
    const p = read(f);
    assert.equal(p.limit, LIMITS[p.id.slice(0, 4)], f);
    assert.deepEqual(Object.keys(p.stated), ["args", "pins"]);
    const i = p.stated.args.indexOf("--pins");
    assert.ok(i >= 0, `${f}: --pins`);
    assert.equal(p.stated.pins, `${p.stated.args[i + 1]}/pins.json`);
    assert.ok(existsSync(fileAt(p.stated.pins)), `${f}: ${p.stated.pins} is committed`);
  }
});

test("V-70: each page's offline verdict is what the verifier gives for its bundle and stated inputs now, apart from checked_at [derived]", () => {
  for (const f of pageFiles()) {
    const p = read(f);
    assert.equal(p.offline_verdict.mode, "offline");
    assert.deepEqual(withoutClock(rerun(p)), withoutClock(p.offline_verdict), f);
  }
});

test("V-70: each page's datapoints are the export of its offline verdict, and its exhibit's sha256 and size are the committed exhibit's, which the generator makes again byte for byte [derived]", () => {
  for (const f of pageFiles()) {
    const p = read(f);
    const vb = verdictBytes(p.offline_verdict);
    assert.deepEqual(p.datapoints, datapointsOf(vb), f);
    assert.deepEqual(Object.keys(p.exhibit), ["page", "path", "sha256", "size"]);
    assert.equal(p.exhibit.page, "letter");
    const pdf = readFileSync(fileAt(p.exhibit.path));
    assert.equal(p.exhibit.sha256, sha256(pdf), f);
    assert.equal(p.exhibit.size, pdf.length, f);
    assert.ok(makeExhibit(vb, { page: "letter" }).bytes.equals(pdf), `${f}: regenerated byte-equal`);
  }
});

test("V-70: no page states an online verdict it did not get from its own bundle: online is absent, null with a reason, or a verdict whose bundle_sha256 is the page's bundle's [derived; ruling A3-8]", () => {
  for (const f of pageFiles()) {
    const p = read(f);
    if (!("online" in p)) continue;
    if (p.online.verdict === null) assert.equal(typeof p.online.reason, "string", f);
    else {
      assert.equal(p.online.verdict.mode, "online", f);
      assert.equal(p.online.verdict.bundle_sha256, p.offline_verdict.bundle_sha256, f);
    }
  }
});
