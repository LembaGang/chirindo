#!/usr/bin/env node
// Verify the most recent session's chain file OFFLINE against the
// adopter's local identity. This is the no-network path — useful when
// the chain has no `jwks_uri` OR when the adopter wants to confirm
// signature integrity without trusting any external publication.
//
// For the self-describing-receipt path (chain has `jwks_uri`, resolve
// from THAT URL over HTTPS), see `prove-self-describing.mjs`.

import { readdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));

const sessionsDir = join(__dirname, ".gate", "sessions");
const files = readdirSync(sessionsDir).filter((f) => f.endsWith(".jsonl")).sort();
if (files.length === 0) {
  process.stderr.write(`no chain files under ${sessionsDir}. Did you run \`npm run harness\` yet?\n`);
  process.exit(1);
}
const latest = join(sessionsDir, files[files.length - 1]);

const chirindoCli = resolve(__dirname, "..", "..", "dist", "cli.js");
const identity = join(__dirname, ".gate", "identity.json");

const r = spawnSync(
  process.execPath,
  [chirindoCli, "verify", latest, "--key", identity],
  { stdio: "inherit" },
);
process.exit(r.status ?? 1);
