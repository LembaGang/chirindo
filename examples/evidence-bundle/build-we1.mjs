#!/usr/bin/env node
// Builds the WE-1 bundle (spec section 7) from the committed Case A files:
//
//   node build-we1.mjs --out <file> [--root <dir>]
//
// Each source file is checked against its committed sha256 first; a file that
// differs (for example after a checkout that rewrote line ends) makes the
// builder exit 2 naming it, and nothing is written. The bundle's created_at
// is fixed, so every build gives the same bytes. --root names the directory
// the sources are read under, in place of the repository root (the test of
// the digest refusal reads a changed copy).

import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { bundleBytes, bundleDoc, SourceError, we1Members, WE1_SUBJECT } from "./lib/we1.mjs";

export const CREATED_AT = "2026-10-22T00:00:00Z";
export const ASSEMBLED_BY = "examples/evidence-bundle/build-we1.mjs";

export function buildWe1(root) {
  return bundleDoc({ createdAt: CREATED_AT, assembledBy: ASSEMBLED_BY, subject: structuredClone(WE1_SUBJECT), members: we1Members(root) });
}

function main() {
  const args = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!["--out", "--root"].includes(args[i]) || args[i + 1] === undefined || opts[args[i]] !== undefined) opts.bad = true;
    else opts[args[i]] = args[i + 1];
  }
  if (opts.bad || opts["--out"] === undefined) {
    process.stderr.write("usage: node build-we1.mjs --out <file> [--root <dir>]\n");
    return 2;
  }
  let bytes;
  try {
    bytes = bundleBytes(buildWe1(opts["--root"]));
  } catch (e) {
    if (e instanceof SourceError) {
      process.stderr.write(`refused: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  writeFileSync(opts["--out"], bytes, { flag: "wx" });
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) process.exitCode = main();
