// The command line of check-bundle.mjs: exit 0 with one verdict object on
// stdout whatever the verdict; exit 2 with one stderr line and nothing on
// stdout for a usage error, for invalid pins and for the options this build
// does not offer.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { buildWe1 } from "../build-we1.mjs";
import { parseArgs, UsageError } from "../lib/cli.mjs";
import { FOLDER, runCli } from "../vectors/make-vectors.mjs";

const A = "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673";
const T = "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3";
let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-cli-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const usage = (r) => {
  assert.equal(r.status, 2, r.stderr);
  assert.equal(r.stdout, "");
  assert.equal(r.stderr.trim().split("\n").length, 1);
};

test("exit 0 and exactly one JSON object on stdout, whatever the verdict", () => {
  const ok = runCli(dir, "ok", buildWe1(), ["--authorizer", A, "--tx", T]);
  assert.equal(ok.status, 0);
  assert.equal(ok.stderr, "");
  assert.ok(ok.stdout.endsWith("}\n"));
  assert.equal(ok.stdout, JSON.stringify(ok.output, null, 2) + "\n");
  const fails = runCli(dir, "fails", buildWe1(), ["--authorizer", A, "--tx", "0x" + "1".repeat(64)]);
  assert.equal(fails.status, 0);
  assert.equal(fails.output.verdict.code, "FAILS");
});

test("usage errors of spec 4.2 and of this build", () => {
  for (const args of [
    ["--authorizer", A, "--authorizer", A],
    ["--tx", T, "--tx", T],
    ["--authorizer", "0xE65E3DE1493171DCF0A706A3F407D7DDB38C5673"],
    ["--authorizer", "0xe65E3dE1493171dCF0A706a3f407d7DdB38C5673"],
    ["--authorizer", "0xe65e3de1493171dcf0a706a3f407d7ddb38c567"],
    ["--authorizer", "e65e3de1493171dcf0a706a3f407d7ddb38c5673"],
    ["--tx", "0x30ca1568"],
    ["--online"],
    ["--rpc", "https://sepolia.base.org"],
    ["--show-parties"],
    ["--pins", dir, "--pins", dir],
    ["--authorizer"],
  ])
    usage(runCli(dir, "u", buildWe1(), args));
  usage(runCli(dir, "u", null, ["--authorizer", A], { noBundle: true }));
  usage(runCli(dir, "u", null, ["--authorizer", A], { missingBundle: true }));
});

test("a bundle path that names a directory is a usage error", () => {
  usage(runCli(dir, "u", null, [dir], { noBundle: true }));
});

test("invalid pins are a usage error: the verifier does not run", () => {
  const pins = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8"));
  usage(runCli(dir, "p0", buildWe1(), ["--pins", path.join(dir, "no-such-dir")]));
  usage(runCli(dir, "p1", buildWe1(), ["--pins", "<pins>"], { pins: { ...pins, format: "other" } }));
  // Spec 4.2: a value in both the permit and the refuse list of one profile.
  usage(runCli(dir, "p2", buildWe1(), ["--pins", "<pins>"], { pins: { ...pins, issuer_profiles: [{ sha256: "0".repeat(64), permit: ["ALLOW"], refuse: ["ALLOW", "DENY"] }] } }));
  usage(runCli(dir, "p3", buildWe1(), ["--pins", "<pins>"], { pins: { ...pins, tokens: { "84532": [{ address: "0xABC", name: "x", version: "1" }] } } }));
  const fine = runCli(dir, "p4", buildWe1(), ["--pins", "<pins>"], { pins: { ...pins, issuer_profiles: [{ sha256: "0".repeat(64), permit: ["ALLOW"], refuse: ["DENY"] }] } });
  assert.equal(fine.status, 0);
});

test("parseArgs reads a stated transaction without regard to case and keeps one bundle path", () => {
  assert.equal(parseArgs(["b", "--tx", "0x" + T.slice(2).toUpperCase()]).tx, T);
  assert.throws(() => parseArgs(["b", "c"]), UsageError);
});
