#!/usr/bin/env node
// The offline vectors this folder can build from the repository's own bytes:
// WE-1 and its variants. Each vector is a recipe (a base bundle and a change),
// built at run time, never stored as bundle bytes.
//
//   node vectors/make-vectors.mjs --write [<file>]
//
// writes the vector file (default vectors/evidence-bundle-0.9.json): for each
// vector its recipe, its arguments and the verifier's output projected as
// spec D.5's last paragraph lists. The file is a regression snapshot of this
// verifier's own output, not an independent check.

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildWe1 } from "../build-we1.mjs";
import { bundleBytes, member, readSource, WE1_AUTHORIZER, WE1_TX } from "../lib/we1.mjs";
import { ROWS_STEP0, ROWS_WA01, ROWS_WA02, ROWS_WA03, ROWS_WA04, ROWS_WA05, ROWS_WA06, ROWS_WA07, ROWS_WA08, ROWS_WA09, ROWS_WA10, ROWS_WA11 } from "./rows-a2.mjs";
import { ROWS_B0, ROWS_WB04, ROWS_WB06, ROWS_WB07, ROWS_WB08, ROWS_WB09, ROWS_WB10, ROWS_WB11, ROWS_WB12, ROWS_WB13, ROWS_WB14 } from "./rows-a2b.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FOLDER = path.resolve(HERE, "..");
export const CREATED_AT = "2026-10-22T00:00:00Z";
const ASSEMBLED_BY = "examples/evidence-bundle/vectors/make-vectors.mjs";
export const VECTOR_FILE = path.join(HERE, "evidence-bundle-0.9.json");

export const A = WE1_AUTHORIZER;
export const T = WE1_TX;
export const F = "0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf";
export const T11 = "0x7806295f38acab4997d1108264edd821e650faddc5b785ac22c098b86388c267";
export const PAY_CONTRACT = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

const CASE_B = "examples/ordering-evidence/case-b/";
const JSONL = "application/x-ndjson";
const RAW_TIME = "2026-10-09T14:50:23Z";

export function we1() {
  const d = buildWe1();
  d.created_at = CREATED_AT;
  d.assembled_by = ASSEMBLED_BY;
  return d;
}
export const byId = (doc, id) => doc.members.find((m) => m.id === id);
export const textOf = (m) => Buffer.from(m.bytes_b64, "base64").toString("utf8");
export function setBytes(doc, id, bytes, extra = {}) {
  const i = doc.members.findIndex((m) => m.id === id);
  const old = doc.members[i];
  doc.members[i] = member({ id, role: old.role, profile: old.profile, bytes, source: old.source, fetched_at: old.fetched_at, capture: old.capture, media_type: old.media_type, ...extra });
}

// The line of this file that holds `marker`, for a capture of
// reconstructed-from <file:line>.
function lineOf(marker) {
  const lines = readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n");
  const k = lines.findIndex((l) => l.includes(marker) && !l.includes("lineOf("));
  return `examples/evidence-bundle/vectors/make-vectors.mjs:${k + 1}`;
}

export const caseB = () => [
  member({ id: "log-b", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: readSource(CASE_B + "ordering-evidence-case-b-1.jsonl"), source: CASE_B + "ordering-evidence-case-b-1.jsonl", fetched_at: RAW_TIME, capture: "raw-response", media_type: JSONL }),
  member({ id: "sidecar-b", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: readSource(CASE_B + "ordering-evidence-case-b-1.jsonl.witness.ndjson"), source: CASE_B + "ordering-evidence-case-b-1.jsonl.witness.ndjson", fetched_at: RAW_TIME, capture: "raw-response", media_type: JSONL }),
];

// The legacy-v0 fixture's log and its key as a JWK (vector R-15).
export function legacyMembers() {
  const ident = JSON.parse(readSource("test/fixtures/legacy-v0/identity.json").toString("utf8"));
  const jwk = Buffer.from(JSON.stringify({ kty: "OKP", crv: "Ed25519", x: ident.public_key_b64url }), "utf8");
  return [
    member({ id: "log-l", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: readSource("test/fixtures/legacy-v0/chain.jsonl"), source: "test/fixtures/legacy-v0/chain.jsonl", fetched_at: RAW_TIME, capture: "raw-response", media_type: JSONL }),
    member({ id: "opkey-l", role: "operator-key", profile: "jwk-okp-ed25519", bytes: jwk, source: "test/fixtures/legacy-v0/identity.json", fetched_at: RAW_TIME, capture: "reconstructed-from test/fixtures/legacy-v0/identity.json:4", media_type: "application/json" }),
  ];
}

export function r15() {
  const doc = we1();
  doc.members = [...legacyMembers(), ...doc.members.filter((m) => ["tx-a", "rc-a", "blk-a"].includes(m.id))];
  doc.subject.cites = { log: "log-l", seq: 0 };
  doc.subject.carried_as = "none";
  return doc;
}

// Uppercase the first letter among an address's hex digits, at the n-th
// (0-based) occurrence of `"<name>": "<address>"` in a member's text.
function flipAddress(doc, id, name, addr, n) {
  const text = textOf(byId(doc, id));
  const needle = `"${name}": "${addr}"`;
  let at = -1;
  for (let k = 0; k <= n; k++) at = text.indexOf(needle, at + 1);
  if (at < 0) throw new Error(`no occurrence ${n} of ${needle} in ${id}`);
  const start = at + needle.length - 1 - 40;
  const hex = text.slice(start, start + 40);
  const j = [...hex].findIndex((c) => /[a-f]/.test(c));
  const changed = hex.slice(0, j) + hex[j].toUpperCase() + hex.slice(j + 1);
  setBytes(doc, id, Buffer.from(text.slice(0, start) + changed + text.slice(start + 40), "utf8"));
  return "0x" + changed;
}

export const ADDRESS_FLIPS = [
  ["tx-a", "from", F, 0],
  ["tx-a", "to", PAY_CONTRACT, 0],
  ["rc-a", "from", F, 0],
  ["rc-a", "to", PAY_CONTRACT, 0],
  ["rc-a", "address", PAY_CONTRACT, 0],
  ["rc-a", "address", PAY_CONTRACT, 1],
];

const stated = ["--authorizer", A, "--tx", T];

// Each vector: id, description, recipe { base, change }, args (with a <pins>
// placeholder), build() -> { doc, pins?, changed?, argv? }. A vector whose
// stated inputs are known only once it is built (a synthetic payment's hash)
// returns them as argv; the file then records them.
export const VECTORS = [
  { id: "R-01", description: "WE-1, offline, with its stated account and transaction", recipe: { base: "WE-1", change: "none" }, args: stated, build: () => ({ doc: we1() }) },
  { id: "R-02", description: "WE-1 with only the transaction stated", recipe: { base: "WE-1", change: "none" }, args: ["--tx", T], build: () => ({ doc: we1() }) },
  { id: "R-03", description: "WE-1 with the facilitator stated as the account", recipe: { base: "WE-1", change: "none" }, args: ["--authorizer", F, "--tx", T], build: () => ({ doc: we1() }) },
  { id: "R-04", description: "WE-1 with another transaction of the same block stated", recipe: { base: "WE-1", change: "none" }, args: ["--authorizer", A, "--tx", T11], build: () => ({ doc: we1() }) },
  { id: "R-05", description: "WE-1 with the stated transaction in upper case", recipe: { base: "WE-1", change: "none" }, args: ["--authorizer", A, "--tx", "0x" + T.slice(2).toUpperCase()], build: () => ({ doc: we1() }) },
  { id: "R-06", description: "WE-1 with only the account stated", recipe: { base: "WE-1", change: "none" }, args: ["--authorizer", A], build: () => ({ doc: we1() }) },
  ...[
    ["R-07a", "--authorizer given twice", ["--authorizer", A, "--authorizer", A, "--tx", T]],
    ["R-07b", "--tx given twice", ["--authorizer", A, "--tx", T, "--tx", T]],
    ["R-07c", "--authorizer with every hex digit in upper case", ["--authorizer", "0xE65E3DE1493171DCF0A706A3F407D7DDB38C5673", "--tx", T]],
    ["R-07d", "--authorizer with one letter's case changed from its EIP-55 form", ["--authorizer", "0xe65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", T]],
    ["R-07e", "--authorizer of 39 hex digits", ["--authorizer", "0xe65e3de1493171dcf0a706a3f407d7ddb38c567", "--tx", T]],
    ["R-07f", "--tx that is not 64 hex digits", ["--authorizer", A, "--tx", "0x30ca1568"]],
    ["R-07g", "--online", ["--online", "--authorizer", A, "--tx", T]],
    ["R-07h", "--rpc", ["--rpc", "https://sepolia.base.org", "--authorizer", A, "--tx", T]],
    ["R-07i", "an unknown option", ["--show-parties", "--authorizer", A, "--tx", T]],
    ["R-07j", "no bundle path", ["--authorizer", A, "--tx", T], { noBundle: true }],
    ["R-07k", "a bundle path that does not exist", ["--authorizer", A, "--tx", T], { missingBundle: true }],
  ].map(([id, description, args, o = {}]) => ({ id, description: `usage error: ${description}`, recipe: { base: "WE-1", change: o.noBundle ? "no bundle path given" : o.missingBundle ? "the bundle path names no file" : "none" }, args, usage: true, ...o, build: () => ({ doc: we1() }) })),
  {
    id: "R-08",
    description: "WE-1 whose subject names expected_authorizer",
    recipe: { base: "WE-1", change: 'subject.expected_authorizer = "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673"' },
    args: stated,
    build: () => {
      const doc = we1();
      doc.subject.expected_authorizer = "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673";
      return { doc };
    },
  },
  ...["none", "calldata"].map((c, k) => ({
    id: `R-09${"ab"[k]}`,
    description: `WE-1 claiming carried_as ${c}`,
    recipe: { base: "WE-1", change: `subject.carried_as = "${c}"` },
    args: stated,
    build: () => {
      const doc = we1();
      doc.subject.carried_as = c;
      return { doc };
    },
  })),
  ...[
    ["R-10", "none"],
    ["R-11", "eip3009-nonce"],
  ].map(([id, c]) => ({
    id,
    description: `Case B's DENY record cited by Case A's payment, claim ${c}`,
    recipe: { base: "WE-1", change: `log-a and sidecar-a replaced by Case B's log-b and sidecar-b; subject.cites = {log: log-b, seq: 0}; subject.carried_as = "${c}"` },
    args: stated,
    build: () => {
      const doc = we1();
      const [lb, sb] = caseB();
      doc.members.splice(0, 1, lb);
      doc.members.splice(doc.members.findIndex((m) => m.id === "sidecar-a"), 1, sb);
      doc.subject.cites = { log: "log-b", seq: 0 };
      doc.subject.carried_as = c;
      return { doc };
    },
  })),
  {
    id: "R-12",
    description: "both logs carried, Case B's record cited",
    recipe: { base: "WE-1", change: 'log-b and sidecar-b added; subject.cites = {log: log-b, seq: 0}; subject.carried_as = "none"' },
    args: stated,
    build: () => {
      const doc = we1();
      doc.members.push(...caseB());
      doc.subject.cites = { log: "log-b", seq: 0 };
      doc.subject.carried_as = "none";
      return { doc };
    },
  },
  {
    id: "R-13",
    description: "WE-1 under pins whose 84532 token list is empty",
    recipe: { base: "WE-1", change: "none; --pins names a copy of pins/pins.json with tokens[84532] empty" },
    args: [...stated, "--pins", "<pins>"],
    build: () => {
      const pins = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8"));
      pins.tokens["84532"] = [];
      return { doc: we1(), pins };
    },
  },
  {
    id: "R-14",
    description: "WE-1 whose witness receipt names a key id neither pinned nor carried",
    recipe: { base: "WE-1", change: 'sidecar-a line 1: witness_receipt.public_key_id = "key_2099_unpinned"' },
    args: stated,
    build: () => {
      const doc = we1();
      const text = textOf(byId(doc, "sidecar-a"));
      const nl = text.endsWith("\n") ? "\n" : "";
      const line = JSON.parse(text.trim());
      line.witness_receipt.public_key_id = "key_2099_unpinned"; // R-14 receipt key id
      setBytes(doc, "sidecar-a", Buffer.from(JSON.stringify(line) + nl, "utf8"), { capture: `reconstructed-from ${lineOf("R-14 receipt key id")}` });
      return { doc };
    },
  },
  {
    id: "R-15",
    description: "the legacy-v0 fixture's log, cited, with its key as a JWK",
    recipe: { base: "WE-1", change: 'members log-l (test/fixtures/legacy-v0/chain.jsonl), opkey-l (a jwk-okp-ed25519 JWK of identity.json:4), tx-a, rc-a, blk-a; subject.cites = {log: log-l, seq: 0}; subject.carried_as = "none"' },
    args: stated,
    build: () => ({ doc: r15() }),
  },
  {
    id: "R-16",
    description: "a card subject citing Case A's record",
    recipe: { base: "WE-1", change: 'members log-a, args-a, sidecar-a, opkey-a, wkey; subject = {kind: card-payment, reference: "WE-1 card variant", cites: {log: log-a, seq: 0}}' },
    args: [],
    build: () => {
      const doc = we1();
      doc.members = doc.members.filter((m) => ["log-a", "args-a", "sidecar-a", "opkey-a", "wkey"].includes(m.id));
      doc.subject = { kind: "card-payment", reference: "WE-1 card variant", cites: { log: "log-a", seq: 0 } };
      return { doc };
    },
  },
  ...ADDRESS_FLIPS.map(([id, name, addr, n], k) => ({
    id: `R-17${"abcdef"[k]}`,
    description: `WE-1 with the first letter of ${id} ${name}${n ? ` (occurrence ${n + 1})` : ""} in upper case`,
    recipe: { base: "WE-1", change: `${id}: the first letter of "${name}" occurrence ${n + 1} in upper case, digest recomputed` },
    args: stated,
    build: () => {
      const doc = we1();
      const changed = flipAddress(doc, id, name, addr, n);
      return { doc, changed };
    },
  })),
  {
    id: "R-18",
    description: "WE-1 with args-a spelled 2.5e-1 for 0.25",
    recipe: { base: "WE-1", change: 'args-a bytes = {"amount_in":2.5e-1,"pair":"ETH/USDC","slippage_bps":50}, digest recomputed' },
    args: stated,
    build: () => {
      const doc = we1();
      setBytes(doc, "args-a", Buffer.from('{"amount_in":2.5e-1,"pair":"ETH/USDC","slippage_bps":50}', "utf8"));
      return { doc };
    },
  },
  ...ROWS_STEP0,
  ...ROWS_WA01,
  ...ROWS_WA02,
  ...ROWS_WA03,
  ...ROWS_WA04,
  ...ROWS_WA05,
  ...ROWS_WA06,
  ...ROWS_WA07,
  ...ROWS_WA08,
  ...ROWS_WA09,
  ...ROWS_WA10,
  ...ROWS_WA11,
  ...ROWS_B0,
  ...ROWS_WB04,
  ...ROWS_WB06,
  ...ROWS_WB07,
  ...ROWS_WB08,
  ...ROWS_WB09,
  ...ROWS_WB10,
  ...ROWS_WB11,
  ...ROWS_WB12,
  ...ROWS_WB13,
  ...ROWS_WB14,
];

// Runs check-bundle.mjs on a bundle document (or on none) with arguments.
export function runCli(dir, name, doc, args, { pins, noBundle, missingBundle } = {}) {
  const bundlePath = path.join(dir, `${name}.json`);
  if (doc) writeFileSync(bundlePath, bundleBytes(doc));
  let pinsDir = null;
  if (pins) {
    pinsDir = path.join(dir, `${name}-pins`);
    mkdirSync(pinsDir, { recursive: true });
    writeFileSync(path.join(pinsDir, "pins.json"), JSON.stringify(pins, null, 2) + "\n");
  }
  const argv = args.map((a) => (a === "<pins>" ? pinsDir : a));
  const pre = noBundle ? [] : [missingBundle ? path.join(dir, "does-not-exist.json") : bundlePath];
  const r = spawnSync(process.execPath, [path.join(FOLDER, "check-bundle.mjs"), ...pre, ...argv], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, output: r.status === 0 ? JSON.parse(r.stdout) : null };
}

// Builds a vector into dir and runs check-bundle.mjs on it.
export async function runVector(v, dir) {
  const built = await v.build();
  const args = built.argv ?? v.args;
  return { ...runCli(dir, v.id, built.doc, args, { pins: built.pins, noBundle: v.noBundle, missingBundle: v.missingBundle }), built, args };
}

// Spec D.5, last paragraph: what every implementation must reproduce.
export function project(o) {
  return {
    verdict: { code: o.verdict.code, rule: o.verdict.rule, reason: o.verdict.reason },
    checks: o.checks.map((c) => ({ id: c.id, member: c.member, status: c.status, reason: c.reason })),
    bindings: o.bindings.map((b) => ({ id: b.id, state: b.state, reason: b.reason, carrier: b.carrier, signed_by: b.signed_by })),
    decision: o.decision,
    gate_receipts: o["gate_receipts"].map((g) => ({ member: g.member, uid: g.uid, log: g.log, seq: g.seq, at_or_before_cited: g.at_or_before_cited, cited: g.cited, state: g.state, reason: g.reason, flags: g.flags })),
    hash_search: o.hash_search,
    movements: o.payment.movements,
    flags: o.flags.map((f) => f.code),
    stated: o.stated,
    endpoints: o.endpoints.filter((e) => e.answered).map((e) => ({ url: e.url, registrable_domain: e.registrable_domain })),
    limits: o.limits.map((l) => l.id),
  };
}

export function expectedOf(r) {
  if (r.status !== 0) {
    const line = r.stderr.trim();
    return { exit: r.status, stdout_empty: r.stdout === "", stderr: line.startsWith("not supported in this build:") ? line : "usage error" };
  }
  return { exit: 0, projection: project(r.output) };
}

export async function makeFile() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "eb-vectors-"));
  try {
    const vectors = [];
    for (const v of VECTORS) {
      const r = await runVector(v, dir);
      vectors.push({ id: v.id, description: v.description, recipe: v.recipe, args: r.args, mode: "offline", expected: expectedOf(r) });
    }
    return {
      format: "evidence-bundle-vectors/0.9",
      note: "Offline vectors built from the repository's own bytes. Each recipe is applied at run time by vectors/make-vectors.mjs; no bundle bytes are stored here. The expected values are a snapshot of this verifier's own output, projected as spec D.5's last paragraph lists (detail fields, checked_at, verifier and bundle_sha256 left out).",
      vectors,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export const fileBytes = (f) => Buffer.from(JSON.stringify(f, null, 2) + "\n", "utf8");

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  if (args[0] !== "--write" || args.length > 2) {
    process.stderr.write("usage: node vectors/make-vectors.mjs --write [<file>]\n");
    process.exitCode = 2;
  } else writeFileSync(args[1] ?? VECTOR_FILE, fileBytes(await makeFile()));
}
