#!/usr/bin/env node
// Verify the most recent session's chain file against the live JWKS.
//
// Equivalent to running, by hand:
//   npx chirindo verify ./.gate/sessions/<id>.jsonl --jwks
//
// The bare `--jwks` form resolves the verifier's public key over HTTPS
// from $RECORDER_JWKS_URL (or the recorder's published default). On
// success, prints VALID and exits 0. On a tampered chain, exits 1. The
// example assumes you've just run `npm run harness`.

import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const sessionsDir = join(__dirname, ".gate", "sessions");
const files = readdirSync(sessionsDir).filter((f) => f.endsWith(".jsonl")).sort();
if (files.length === 0) {
  process.stderr.write(`no chain files under ${sessionsDir}. Did you run \`npm run harness\` yet?\n`);
  process.exit(1);
}
const latest = join(sessionsDir, files[files.length - 1]);

const chirindoPkg = require.resolve("@headlessoracle/chirindo/package.json");
const chirindoCli = join(dirname(chirindoPkg), "dist", "cli.js");

const r = spawnSync(process.execPath, [chirindoCli, "verify", latest, "--jwks"], {
  stdio: "inherit",
});
process.exit(r.status ?? 1);
