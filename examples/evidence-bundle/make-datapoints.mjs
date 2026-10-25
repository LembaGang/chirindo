#!/usr/bin/env node
// The data-point export of one verdict JSON (spec 4.10; lib/datapoints.mjs).
//
//   node make-datapoints.mjs <verdict.json>
//
// Exit 0: the export on stdout, its JCS bytes and a line feed. Exit 2: a
// usage error, or a file that is not an evidence-bundle-verdict/0.10 verdict;
// one line on stderr and nothing on stdout. Exit 1: an internal error.

import { readFileSync } from "node:fs";
import { judged } from "./lib/allowlist.mjs";
import { datapointBytes } from "./lib/datapoints.mjs";
import { ExhibitError } from "./lib/exhibit.mjs";

function main() {
  if (!judged("view:datapoints")) {
    process.stderr.write("not supported in this build: view:datapoints\n");
    return 2;
  }
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0].startsWith("--")) {
    process.stderr.write(`usage error: ${args.length === 0 ? "no verdict file given" : args[0].startsWith("--") ? `unknown option ${args[0]}` : "one verdict file only"}\n`);
    return 2;
  }
  let bytes;
  try {
    bytes = readFileSync(args[0]);
  } catch (e) {
    process.stderr.write(`usage error: the verdict file ${args[0]} cannot be read (${e.code ?? e.message})\n`);
    return 2;
  }
  try {
    process.stdout.write(datapointBytes(bytes));
    return 0;
  } catch (e) {
    if (e instanceof ExhibitError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
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
