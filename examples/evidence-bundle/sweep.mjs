#!/usr/bin/env node
// The WE-1 sweep of spec 4.8.3, run offline with WE-1's stated account and
// transaction, through the verifier's library entry (no child process per
// change):
//
//   node sweep.mjs [--out <file>]
//
// Step 1: every byte of every member's decoded bytes, changed by XOR 1, by
// each other JSON whitespace byte for a whitespace byte, and by the other case
// for an ASCII letter, with bytes_b64 and sha256 recomputed. Step 2: every
// byte of the bundle document outside the bytes_b64 values, changed the same
// ways, nothing recomputed. Step 3: step 1's changes with the manifest digest
// left as it was. Step 4: each change after which the verdict is not FAILS is
// classed same-values, listed or UNEXPECTED (lib/coverage.mjs). It prints the
// counts per step, per class and per member, then its elapsed time, and writes
// every change of steps 1 and 2 whose verdict was not FAILS to --out (default
// we1/sweep-positions.json).

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildWe1 } from "./build-we1.mjs";
import { loadPins } from "./lib/cli.mjs";
import { okpThumbprint } from "../ordering-evidence-h4/lib/formats.mjs";
import { classify, ROLE_KEY } from "./lib/coverage.mjs";
import { verifyBundle } from "./lib/verify.mjs";
import { bundleBytes, WE1_AUTHORIZER, WE1_TX } from "./lib/we1.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_OUT = path.join(HERE, "we1", "sweep-positions.json");
const WS = [0x20, 0x09, 0x0a, 0x0d];
const isLetter = (c) => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
const sha256 = (b) => "sha256:" + createHash("sha256").update(b).digest("hex");

export function variants(c) {
  const out = new Set([c ^ 1]);
  if (WS.includes(c)) for (const w of WS) if (w !== c) out.add(w);
  if (isLetter(c)) out.add(c ^ 0x20);
  return [...out];
}

// The byte ranges of the bundle document that are bytes_b64 values.
function b64Ranges(text) {
  const ranges = [];
  const re = /"bytes_b64": "([^"]*)"/g;
  let m;
  while ((m = re.exec(text))) {
    const start = m.index + m[0].indexOf(': "') + 3;
    ranges.push([start, start + m[1].length]);
  }
  return ranges;
}

export async function sweep({ log = () => {} } = {}) {
  const t0 = Date.now();
  const pins = loadPins();
  const stated = { authorizer: WE1_AUTHORIZER.toLowerCase(), tx: WE1_TX };
  const doc = buildWe1();
  const baseBytes = bundleBytes(doc);
  const outcome = async (bytes) => {
    try {
      const r = await verifyBundle(bytes, stated, pins);
      if (r.kind === "refused") return "exit-2";
      return r.output.verdict.code;
    } catch {
      return "exit-1";
    }
  };
  const base = await outcome(baseBytes);
  if (base === "FAILS" || base.startsWith("exit")) throw new Error(`WE-1 itself gives ${base}`);
  // What the conditions of table 4-8 read for WE-1: the logs M5.token-logs
  // reads, the payment's index, the JWKS entry of the log's kid, the key ids
  // the receipts use, the kids with a carried operator key.
  const resolvedKeyIds = pins.witness_keys.keys.map((k) => k.key_id);
  const carriedKids = JSON.parse(Buffer.from(doc.members.find((m) => m.id === "opkey-a").bytes_b64, "base64")).keys.map((k) => okpThumbprint(k.x));
  const ctxOf = () => ({ readLogs: [0, 1], txIndex: 10, usedKeyIndexes: [0], resolvedKeyIds, carriedKids });
  const counts = { step1: {}, step2: {}, step3: {} };
  const perMember = {};
  const bump = (step, cls, member) => {
    counts[step][cls] = (counts[step][cls] ?? 0) + 1;
    perMember[member] ??= {};
    perMember[member][`${step}:${cls}`] = (perMember[member][`${step}:${cls}`] ?? 0) + 1;
  };
  const positions = [];

  // Steps 1 and 3.
  for (let k = 0; k < doc.members.length; k++) {
    const m = doc.members[k];
    const orig = Buffer.from(m.bytes_b64, "base64");
    for (let off = 0; off < orig.length; off++) {
      for (const nb of variants(orig[off])) {
        const next = Buffer.from(orig);
        next[off] = nb;
        const changed = { ...m, bytes_b64: next.toString("base64"), sha256: sha256(next) };
        const d1 = { ...doc, members: doc.members.map((x, i) => (i === k ? changed : x)) };
        const v1 = await outcome(bundleBytes(d1));
        if (v1 === "FAILS") bump("step1", "FAILS", m.id);
        else {
          const cls = v1.startsWith("exit") ? "UNEXPECTED" : classify({ key: ROLE_KEY(m), origBytes: orig, nextBytes: next, ctx: ctxOf() });
          bump("step1", cls, m.id);
          positions.push({ step: 1, member: m.id, offset: off, original: orig[off], new: nb, class: cls });
        }
        const d3 = { ...doc, members: doc.members.map((x, i) => (i === k ? { ...changed, sha256: m.sha256 } : x)) };
        const v3 = await outcome(bundleBytes(d3));
        bump("step3", v3 === "FAILS" ? "FAILS" : "not-FAILS", m.id);
      }
    }
    log(`step 1 and 3: ${m.id} done (${orig.length} bytes)`);
  }

  // Step 2.
  const text = baseBytes.toString("latin1");
  const skip = b64Ranges(text);
  const inB64 = (i) => skip.some(([a, b]) => i >= a && i < b);
  for (let off = 0; off < baseBytes.length; off++) {
    if (inB64(off)) continue;
    for (const nb of variants(baseBytes[off])) {
      const next = Buffer.from(baseBytes);
      next[off] = nb;
      const v2 = await outcome(next);
      if (v2 === "FAILS") bump("step2", "FAILS", "bundle");
      else {
        const cls = v2.startsWith("exit") ? "UNEXPECTED" : classify({ key: "bundle", origBytes: baseBytes, nextBytes: next, ctx: {} });
        bump("step2", cls, "bundle");
        positions.push({ step: 2, member: "bundle", offset: off, original: baseBytes[off], new: nb, class: cls });
      }
    }
  }
  log("step 2: bundle document done");
  return { counts, perMember, positions, baseVerdict: base, elapsedMs: Date.now() - t0 };
}

export function positionsFile(r) {
  const head = {
    format: "evidence-bundle-sweep-positions/0.9",
    note: "The WE-1 sweep of spec 4.8.3 (sweep.mjs): every change of steps 1 and 2 after which the offline verdict, with WE-1's stated account and transaction, was not FAILS, with its class. A snapshot of this verifier's own output.",
    columns: ["step", "member", "offset", "original", "new", "class"],
    column_notes: "step 1 changes a member's decoded bytes (offset into them, digest recomputed); step 2 changes the bundle document as build-we1.mjs writes it (member \"bundle\", offset into the document). original and new are byte values.",
  };
  const rows = r.positions.map((p) => "    " + JSON.stringify([p.step, p.member, p.offset, p.original, p.new, p.class]));
  const text = JSON.stringify(head, null, 2).slice(0, -2) + ',\n  "positions": [\n' + rows.join(",\n") + "\n  ]\n}\n";
  return Buffer.from(text, "utf8");
}

export function summary(r) {
  const out = [];
  for (const step of ["step1", "step2", "step3"]) out.push(`${step}: ` + Object.entries(r.counts[step]).map(([k, v]) => `${k} ${v}`).join(", "));
  for (const [m, c] of Object.entries(r.perMember)) out.push(`member ${m}: ` + Object.entries(c).map(([k, v]) => `${k} ${v}`).join(", "));
  out.push(`elapsed ${(r.elapsedMs / 1000).toFixed(1)} s`);
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  const out = args[0] === "--out" && args[1] ? args[1] : args.length === 0 ? DEFAULT_OUT : null;
  if (!out) {
    process.stderr.write("usage: node sweep.mjs [--out <file>]\n");
    process.exitCode = 2;
  } else {
    const r = await sweep({ log: (s) => process.stdout.write(s + "\n") });
    writeFileSync(out, positionsFile(r));
    for (const l of summary(r)) process.stdout.write(l + "\n");
  }
}
