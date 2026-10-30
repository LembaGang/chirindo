// scripts/release-gate-checks.mjs (B-428 R2, ruling 3): the pack-mode checks
// on what the release ships. Each test builds a consumer's project with a
// package installed under node_modules/@headlessoracle/chirindo, shows the
// check passing on a clean one, then turns it red with one defect at a time.
// The gate itself runs these checks against the package it installed from
// the packed tarball (scripts/release-gate.mjs, EXPORTS, PACKED-PATHS, CR).

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTmpDir, makeTmpDir } from "./helpers.js";
import {
  CR_FILES,
  REQUIRED_EXPORTS,
  crFindings,
  exportFindings,
  forbiddenPaths,
  packedFiles,
  probeExports,
  // @ts-expect-error -- plain .mjs without declarations
} from "../scripts/release-gate-checks.mjs";

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));

const PURCHASE = "@headlessoracle/chirindo/purchase-check";
const TRIAL = "@headlessoracle/chirindo/trial-recorder";
// A PEM header's start, kept apart from "PRIVATE KEY" on every line: the
// repo's pre-push hook refuses a line holding both.
const BEGIN = "-----BEGIN";
const PURCHASE_NAMES = ["createPurchaseCheck", "evaluatePurchase", "signInstruction", "mapCrossmintOrderIntent", "mapBasisTheoryAllowance", "mapPravaMandate"];

interface Fake {
  consumer: string;
  pkg: string;
  put: (rel: string, body: string) => void;
}

// A consumer's project holding a package shaped like the release: an exports
// map with both entry points, ESM modules exporting the documented names, and
// the five files the CR check reads, LF only.
function fake(opts: { purchaseNames?: string[]; exportsMap?: Record<string, unknown> } = {}): Fake {
  const consumer = makeTmpDir("gate-pack-");
  dirs.push(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0", private: true }) + "\n");
  const pkg = join(consumer, "node_modules", "@headlessoracle", "chirindo");
  const put = (rel: string, body: string) => {
    mkdirSync(dirname(join(pkg, rel)), { recursive: true });
    writeFileSync(join(pkg, rel), body);
  };
  const exportsMap = opts.exportsMap ?? {
    "./trial-recorder": { import: "./dist/trial/index.js" },
    "./purchase-check": { import: "./dist/purchase/index.js" },
    "./package.json": "./package.json",
  };
  put("package.json", JSON.stringify({ name: "@headlessoracle/chirindo", version: "0.6.0", type: "module", exports: exportsMap }, null, 2) + "\n");
  put("dist/purchase/index.js", (opts.purchaseNames ?? PURCHASE_NAMES).map((n) => `export function ${n}() {}\n`).join(""));
  put("dist/trial/index.js", "export function createTrialRecorder() {}\n");
  put("dist/cli.js", "#!/usr/bin/env node\nprocess.exitCode = 2;\n");
  put("README.md", "# chirindo\n");
  put("LICENSE", "Apache License\n");
  put("NOTICE", "Chirindo\n");
  return { consumer, pkg, put };
}

describe("release gate pack mode: EXPORTS", () => {
  it("both specifiers import through the exports map with every documented name (the control)", () => {
    expect(REQUIRED_EXPORTS).toEqual({ [PURCHASE]: PURCHASE_NAMES, [TRIAL]: ["createTrialRecorder"] });
    const probe = probeExports(fake().consumer);
    expect(probe[PURCHASE].ok).toBe(true);
    expect(exportFindings(probe)).toEqual([]);
  });

  it("red: a documented name missing from ./purchase-check", () => {
    const f = fake({ purchaseNames: PURCHASE_NAMES.filter((n) => n !== "mapPravaMandate") });
    expect(exportFindings(probeExports(f.consumer))).toEqual([`${PURCHASE} mapPravaMandate (absent)`]);
  });

  it("red: a name present but not a function", () => {
    const f = fake();
    f.put("dist/trial/index.js", "export const createTrialRecorder = 1;\n");
    expect(exportFindings(probeExports(f.consumer))).toEqual([`${TRIAL} createTrialRecorder (number)`]);
  });

  it("red: ./trial-recorder missing from the exports map, though its file is packed", () => {
    const f = fake({ exportsMap: { "./purchase-check": { import: "./dist/purchase/index.js" } } });
    expect(exportFindings(probeExports(f.consumer))).toEqual([`${TRIAL} (import failed: ERR_PACKAGE_PATH_NOT_EXPORTED)`]);
  });

  it("red: the package is not installed in the consumer's project", () => {
    const f = fake();
    rmSync(f.pkg, { recursive: true, force: true });
    const bad = exportFindings(probeExports(f.consumer));
    expect(bad).toHaveLength(2);
    for (const line of bad) expect(line).toMatch(/\(import failed: ERR_MODULE_NOT_FOUND\)$/);
  });

  it("red: a specifier that was never probed", () => {
    expect(exportFindings({ [PURCHASE]: { ok: true, names: Object.fromEntries(PURCHASE_NAMES.map((n) => [n, "function"])) } })).toEqual([`${TRIAL} (not probed)`]);
  });
});

describe("release gate pack mode: PACKED-PATHS", () => {
  it("a clean package has no forbidden path; a dependency's node_modules is not packed (the control)", () => {
    const f = fake();
    f.put("node_modules/dep/test/x.js", `${BEGIN} PRIVATE KEY-----\n`);
    f.put("dist/keys.js", "export const k = '-----BEGIN PUBLIC KEY-----';\n");
    expect(forbiddenPaths(f.pkg)).toEqual([]);
    expect(packedFiles(f.pkg)).not.toContain("node_modules/dep/test/x.js");
  });

  const cases: [string, string, string][] = [
    ["test/a.test.js", "x", "test/a.test.js (under test/)"],
    ["scripts/release-gate.mjs", "x", "scripts/release-gate.mjs (under scripts/)"],
    ["keys/identity.json", "{}", "keys/identity.json (under keys/)"],
    ["dist/test/helpers.js", "x", "dist/test/helpers.js (under test/)"],
    [".env", "A=1", ".env (.env)"],
    ["dist/.env.local", "A=1", "dist/.env.local (.env)"],
    ["dist/key.js", "const k = `" + BEGIN + " PRIVATE KEY-----\nMC4CAQ...`;\n", "dist/key.js (PEM private key header)"],
    ["dist/ssh.txt", `${BEGIN} OPENSSH PRIVATE KEY-----\n`, "dist/ssh.txt (PEM private key header)"],
    ["dist/enc.pem", `${BEGIN} ENCRYPTED PRIVATE KEY-----\n`, "dist/enc.pem (PEM private key header)"],
  ];
  for (const [rel, body, want] of cases) {
    it(`red: ${rel}`, () => {
      const f = fake();
      f.put(rel, body);
      expect(forbiddenPaths(f.pkg)).toEqual([want]);
    });
  }
});

describe("release gate pack mode: CR", () => {
  it("the five files, LF only, pass (the control)", () => {
    expect(CR_FILES).toEqual(["README.md", "LICENSE", "NOTICE", "package.json", "dist/cli.js"]);
    expect(crFindings(fake().pkg)).toEqual([]);
  });

  for (const file of ["README.md", "LICENSE", "NOTICE", "package.json", "dist/cli.js"]) {
    it(`red: a CR in ${file}`, () => {
      const f = fake();
      f.put(file, file === "package.json" ? '{\r\n"name": "@headlessoracle/chirindo"\r\n}\r\n' : "line one\r\nline two\n");
      expect(crFindings(f.pkg)).toEqual([`${file} (${file === "package.json" ? 3 : 1} CR)`]);
    });
  }

  it("red: a missing file fails closed", () => {
    const f = fake();
    rmSync(join(f.pkg, "NOTICE"));
    expect(crFindings(f.pkg)).toEqual(["NOTICE (missing)"]);
  });
});
