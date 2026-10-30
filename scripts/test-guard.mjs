#!/usr/bin/env node
// The test memory guard (B-432 T2 ruling 2). `npm test` runs this, not vitest
// directly. It reads free memory with os.freemem(), prints the reading and its
// decision, and then either runs vitest or starts nothing:
//
//   3,000,000 KB and above    vitest run, normally (files in parallel)
//   1,000,000 to 2,999,999 KB  vitest run --no-file-parallelism
//   below 1,000,000 KB         exit 2, naming the floor and the apps to close
//
// Arguments after `npm test --` go to vitest unchanged. The machine's rule for
// people and agents running the suite: close apps to reach the floor first
// (never one with unsaved work); the serial mode is the fallback, not the plan.

import { spawn } from "node:child_process";
import { freemem } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

export const FLOOR_KB = 3_000_000;
export const MIN_KB = 1_000_000;
const SERIAL_FLAG = "--no-file-parallelism";

// The decision for a free-memory reading in KB. Pure.
export function decide(freeKb) {
  if (!Number.isFinite(freeKb) || freeKb < MIN_KB) return "refuse";
  return freeKb >= FLOOR_KB ? "parallel" : "serial";
}

// The vitest arguments for a decision; null for refuse. A caller's own
// --no-file-parallelism is not repeated.
export function vitestArgs(decision, args) {
  if (decision === "refuse") return null;
  if (decision === "serial" && !args.includes(SERIAL_FLAG)) return ["run", SERIAL_FLAG, ...args];
  return ["run", ...args];
}

export function message(decision, freeKb) {
  const kb = `${Math.floor(freeKb).toLocaleString("en-US")} KB free`;
  if (decision === "parallel") return `[test-guard] ${kb} (floor ${FLOOR_KB.toLocaleString("en-US")} KB): running vitest normally`;
  if (decision === "serial") {
    return `[test-guard] ${kb}, under the ${FLOOR_KB.toLocaleString("en-US")} KB floor: running vitest with ${SERIAL_FLAG} (close apps to reach the floor; this is the fallback)`;
  }
  return (
    `[test-guard] ${kb}, under ${MIN_KB.toLocaleString("en-US")} KB: vitest NOT started. ` +
    `The floor is ${FLOOR_KB.toLocaleString("en-US")} KB. Close apps first, never one with unsaved work: ` +
    `NordVPN, Phone Link, browsers, Google Drive for desktop (restart it after the run). ` +
    `Never the Claude desktop app or the terminal running this.`
  );
}

// Runs the guard. `deps` is injectable for tests: freeKb, spawnVitest(args) ->
// Promise<exit code>, and log.
export async function main(args, deps = {}) {
  const freeKb = deps.freeKb ?? Math.floor(freemem() / 1024);
  const log = deps.log ?? ((l) => process.stderr.write(l + "\n"));
  const decision = decide(freeKb);
  log(message(decision, freeKb));
  const vargs = vitestArgs(decision, args);
  if (vargs === null) return 2;
  const run = deps.spawnVitest ?? spawnVitest;
  return run(vargs);
}

function spawnVitest(vargs) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const bin = join(root, "node_modules", "vitest", "vitest.mjs");
  return new Promise((done) => {
    const child = spawn(process.execPath, [bin, ...vargs], { stdio: "inherit", cwd: root });
    child.on("error", (e) => {
      process.stderr.write(`[test-guard] cannot start vitest: ${e.message}\n`);
      done(1);
    });
    child.on("exit", (code, signal) => done(code ?? (signal ? 1 : 0)));
  });
}

// Run only when executed, not when imported (the test imports it). Windows
// paths compare without regard to case.
const norm = (p) => (process.platform === "win32" ? resolve(p).toLowerCase() : resolve(p));
if (process.argv[1] && norm(fileURLToPath(import.meta.url)) === norm(process.argv[1])) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
