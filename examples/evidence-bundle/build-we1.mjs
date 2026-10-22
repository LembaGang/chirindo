#!/usr/bin/env node
// Builds the WE-1 bundle (spec section 7) from the committed Case A files:
//
//   node build-we1.mjs --out <file>
//
// Each source file is checked against its committed sha256 first; a file that
// differs (for example after a checkout that rewrote line ends) makes the
// builder exit 2 naming it, and nothing is written. The bundle's created_at
// is fixed, so every build gives the same bytes.

import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { bundleBytes, bundleDoc, SourceError, we1Members, WE1_SUBJECT } from "./lib/we1.mjs";

export const CREATED_AT = "2026-10-22T00:00:00Z";
export const ASSEMBLED_BY = "examples/evidence-bundle/build-we1.mjs";

export function buildWe1() {
  return bundleDoc({ createdAt: CREATED_AT, assembledBy: ASSEMBLED_BY, subject: structuredClone(WE1_SUBJECT), members: we1Members() });
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--out") {
    process.stderr.write("usage: node build-we1.mjs --out <file>\n");
    return 2;
  }
  let bytes;
  try {
    bytes = bundleBytes(buildWe1());
  } catch (e) {
    if (e instanceof SourceError) {
      process.stderr.write(`refused: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  writeFileSync(args[1], bytes, { flag: "wx" });
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) process.exitCode = main();
