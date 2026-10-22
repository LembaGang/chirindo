#!/usr/bin/env node
// Offline verifier for dispute evidence bundles (evidence-bundle/0.9).
//
//   node check-bundle.mjs <bundle.json> [--authorizer <address>] [--tx <hash>] [--pins <dir>]
//
// Exit 0: one verdict object (evidence-bundle-verdict/0.9) on stdout, whatever
// the verdict. Exit 2: a usage error, or a bundle outside the shape this build
// judges ("not supported in this build: <code>"), one line on stderr and
// nothing on stdout. Exit 1: an internal error, likewise. See README.md.

import { readFileSync } from "node:fs";
import { loadPins, parseArgs, UsageError } from "./lib/cli.mjs";
import { verifyBundle } from "./lib/verify.mjs";

async function main() {
  let opts;
  let pins;
  let bytes;
  try {
    opts = parseArgs(process.argv.slice(2));
    pins = loadPins(opts.pinsDir ?? undefined);
    try {
      bytes = readFileSync(opts.bundlePath);
    } catch (e) {
      throw new UsageError(`the bundle ${opts.bundlePath} cannot be read (${e.code ?? e.message})`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  const r = await verifyBundle(bytes, { authorizer: opts.authorizer, tx: opts.tx }, pins);
  if (r.kind === "refused") {
    process.stderr.write(`not supported in this build: ${r.code}\n`);
    return 2;
  }
  process.stdout.write(JSON.stringify(r.output, null, 2) + "\n");
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`internal error: ${String(e?.message ?? e).split("\n")[0]}\n`);
    process.exitCode = 1;
  },
);
