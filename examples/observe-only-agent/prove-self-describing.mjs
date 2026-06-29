#!/usr/bin/env node
// Prove the self-describing verification path on the adopter's OWN chain.
//
// What this does:
//   1. Read the newest chain file produced by the harness.
//   2. Read the first record's `jwks_uri` (stamped by the proxy when run
//      with --jwks-uri or JWKS_URI env var).
//   3. Pre-seed the in-process JWKS cache so the URL "resolves" to the
//      adopter's own jwks.json — the same bytes a real HTTPS fetch would
//      return. Production fetches from the network; the cryptographic
//      verification path is byte-identical either way.
//   4. Call runVerify against the chain. It reads `jwks_uri`, calls
//      resolveKeyFromJwks (which hits our seeded cache), gets the JWK,
//      verifies signature + chain.
//
// Why the cache seam, not a real HTTPS server: standing up HTTPS locally
// requires a trusted cert chain — too much setup for an example. The
// cryptographic verification path (signature, chain linkage, JCS
// recompute) is the production code path; only the "fetch HTTPS bytes"
// step is short-circuited. The honest framing in the README §5 makes
// that explicit.
//
// In production this script is unnecessary: an adopter hosts jwks.json
// at their chosen HTTPS URL, runs `chirindo verify <chain>` with no
// flag, and the verifier resolves over the network. This script exists
// because the example demo machine does not actually host the JWKS.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Import library API from the in-repo build. The recorder primitives
// (_setJwksCacheEntry, runVerify, formatVerifyResult) aren't yet
// re-exported by a published @headlessoracle/chirindo (it's CLI-only at
// 0.1.0, and these helpers post-date 0.1.0 anyway). file:// is required
// for ESM import() on Windows paths.
const recorderIndex = resolve(__dirname, "..", "..", "dist", "vendor", "recorder", "index.js");
const { _setJwksCacheEntry, runVerify, formatVerifyResult } = await import(
  new URL("file:///" + recorderIndex.replace(/\\/g, "/")).href
);

const sessionsDir = join(__dirname, ".gate", "sessions");
const files = readdirSync(sessionsDir)
  .filter((f) => f.endsWith(".jsonl"))
  .sort();
if (files.length === 0) {
  process.stderr.write(
    `no chain files under ${sessionsDir}.\n` +
      `run \`npm run harness\` first (and \`JWKS_URI=https://your-host/jwks.json npm run harness\` to stamp jwks_uri into the chain).\n`,
  );
  process.exit(1);
}
const chainPath = join(sessionsDir, files[files.length - 1]);
const firstLine = readFileSync(chainPath, "utf8").split("\n").find((l) => l.trim().length > 0);
if (firstLine === undefined) {
  process.stderr.write(`chain file ${chainPath} is empty\n`);
  process.exit(1);
}
const firstRecord = JSON.parse(firstLine);
const jwksUri = firstRecord.jwks_uri;
if (typeof jwksUri !== "string") {
  process.stderr.write(
    `chain file ${chainPath} has no jwks_uri on its first record.\n` +
      `re-run the harness with JWKS_URI set, e.g.:\n` +
      `  JWKS_URI=https://adopter.example/.well-known/jwks.json npm run harness\n`,
  );
  process.exit(1);
}
const kid = firstRecord.kid;

// Load the adopter's own jwks.json (produced by `npm run export-jwks`).
const jwksPath = join(__dirname, "jwks.json");
const adopterJwks = JSON.parse(readFileSync(jwksPath, "utf8"));

// Seed the cache as if we'd just fetched adopter's jwks.json from jwksUri.
// In production the verifier issues an HTTPS GET to jwksUri and receives
// these same bytes back. Cryptographic identity is unchanged.
_setJwksCacheEntry(jwksUri, adopterJwks);

process.stdout.write(`proving self-describing verification:\n`);
process.stdout.write(`  chain:    ${chainPath}\n`);
process.stdout.write(`  jwks_uri: ${jwksUri}  (from inside signed bytes)\n`);
process.stdout.write(`  kid:      ${kid}\n`);
process.stdout.write(`  JWKS:     ${jwksPath} (pre-seeded as if fetched from jwks_uri)\n\n`);

const result = await runVerify({ chainPath, jwksUrl: jwksUri });
const formatted = formatVerifyResult(result);
process.stdout.write(formatted.line + "\n");
process.exit(formatted.exitCode);
