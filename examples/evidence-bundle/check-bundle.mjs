#!/usr/bin/env node
// Offline verifier for dispute evidence bundles (evidence-bundle/0.10, and 0.9).
// Its output is evidence-bundle-verdict/0.10.
//
//   node check-bundle.mjs <bundle.json> [--authorizer <address>] [--tx <hash>] [--pins <dir>]
//   node check-bundle.mjs --evidence-uri <https URL> --evidence-entry sha256:<hex> [--evidence-sha256 sha256:<hex>] [...]
//   node check-bundle.mjs <bundle.json> <the charge options> --online [...]
//
// With the pointer, the bundle is fetched once (lib/pointer.mjs): Node's
// fetch, each redirect followed and checked here. With --online, for a
// card-payment subject only, the witness's list, the witness key list when
// a receipt needs it, and the records' jwks_uri are read (lib/online.mjs).
//
// Exit 0: one verdict object (evidence-bundle-verdict/0.10) on stdout, whatever
// the verdict. Exit 2: a usage error, or a bundle outside the shape this build
// judges ("not supported in this build: <code>"), one line on stderr and
// nothing on stdout. Exit 1: an internal error, likewise. See README.md.

import { readFileSync } from "node:fs";
import { loadPins, NotJudged, parseArgs, subjectKind, UsageError } from "./lib/cli.mjs";
import { fetchPointer } from "./lib/pointer.mjs";
import { verifyBundle } from "./lib/verify.mjs";

async function main() {
  let opts;
  let pins;
  let bytes;
  let pointer = null;
  try {
    opts = parseArgs(process.argv.slice(2));
    pins = loadPins(opts.pinsDir ?? undefined);
    if (opts.pointer) {
      pointer = await fetchPointer(opts.pointer, (url, init) => fetch(url, init));
      bytes = pointer.bytes;
    } else
      try {
        bytes = readFileSync(opts.bundlePath);
      } catch (e) {
        throw new UsageError(`the bundle ${opts.bundlePath} cannot be read (${e.code ?? e.message})`);
      }
    // With the pointer, the subject's kind is known only after the fetch, so the
    // charge rule applies only once the fetched bundle is read.
    const read = !pointer || ["fetched", "match"].includes(pointer.status);
    if (opts.charge && read && subjectKind(bytes) === "evm-payment") throw new UsageError("the charge options are for a card-payment subject only (spec 4.2)");
    // This build's online read is the witness read of a card subject (lib/online.mjs).
    if (opts.online && read && subjectKind(bytes) !== "card-payment") throw new UsageError("--online: this build is offline only for a subject that is not card-payment");
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
    }
    if (e instanceof NotJudged) {
      process.stderr.write(`not supported in this build: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  const online = opts.online ? { fetch: (url, init) => fetch(url, init) } : null;
  const r = await verifyBundle(bytes, { authorizer: opts.authorizer, tx: opts.tx, charge: opts.charge }, pins, { pointer, online });
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
