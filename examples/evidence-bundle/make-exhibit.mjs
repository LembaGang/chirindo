#!/usr/bin/env node
// The exhibit PDF of one verdict JSON (spec 4.9; lib/exhibit.mjs).
//
//   node make-exhibit.mjs <verdict.json> --page letter|a4 --out <file.pdf>
//
// Exit 0: the exhibit written, nothing on stdout. Exit 2: a usage error, a
// font file that is not the pinned one, or a file that is not an
// evidence-bundle-verdict/0.10 verdict; one line on stderr and no file.
// Exit 3: "exhibit not written: <why>" when every limit does not fit one page
// at 6 points; no file. Exit 1: an internal error.
//
// Test-only options, for the tests of this folder: --test-page-height <points>
// makes the page shorter, and --test-font <file> reads another font file
// (refused unless it is the pinned font).

import { readFileSync, writeFileSync } from "node:fs";
import { judged } from "./lib/allowlist.mjs";
import { ExhibitError, makeExhibit, PAGES } from "./lib/exhibit.mjs";

class UsageError extends Error {}

function parseArgs(argv) {
  const o = { verdict: null, page: null, out: null, pageHeight: null, font: undefined };
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      if (o.verdict !== null) throw new UsageError(`a second verdict file: ${a}`);
      o.verdict = a;
      continue;
    }
    if (!["--page", "--out", "--test-page-height", "--test-font"].includes(a)) throw new UsageError(`unknown option ${a}`);
    if (seen.has(a)) throw new UsageError(`${a} given twice`);
    seen.add(a);
    const v = argv[++i];
    if (v === undefined) throw new UsageError(`${a} needs a value`);
    if (a === "--page") {
      if (!Object.hasOwn(PAGES, v)) throw new UsageError(`--page is ${v}, not letter or a4`);
      o.page = v;
    } else if (a === "--out") o.out = v;
    else if (a === "--test-page-height") {
      if (!/^[1-9][0-9]*$/.test(v)) throw new UsageError("--test-page-height is not a positive whole number of points");
      o.pageHeight = Number(v);
    } else o.font = v;
  }
  if (o.verdict === null) throw new UsageError("no verdict file given");
  if (o.page === null) throw new UsageError("--page letter|a4 is required");
  if (o.out === null) throw new UsageError("--out <file> is required");
  return o;
}

function main() {
  if (!judged("view:exhibit")) {
    process.stderr.write("not supported in this build: view:exhibit\n");
    return 2;
  }
  try {
    const o = parseArgs(process.argv.slice(2));
    let bytes;
    try {
      bytes = readFileSync(o.verdict);
    } catch (e) {
      throw new UsageError(`the verdict file ${o.verdict} cannot be read (${e.code ?? e.message})`);
    }
    const w = makeExhibit(bytes, { page: o.page, pageHeight: o.pageHeight, fontPath: o.font });
    writeFileSync(o.out, w.bytes);
    return 0;
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
    }
    if (e instanceof ExhibitError) {
      if (e.exit === 3) process.stderr.write(`exhibit not written: ${e.message}\n`);
      else if (/^the font/.test(e.message)) process.stderr.write(`font refused: ${e.message}\n`);
      else process.stderr.write(`usage error: ${e.message}\n`);
      return e.exit;
    }
    throw e;
  }
}

try {
  process.exitCode = main();
} catch (e) {
  process.stderr.write(`internal error: ${String(e?.message ?? e).split("\n")[0]}\n`);
  process.exitCode = 1;
}
