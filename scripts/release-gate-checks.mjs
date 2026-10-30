// The pack-mode checks that look at what the release ships (B-428 R2, ruling
// 3): the two package exports as a consumer imports them, packed paths that
// must never ship, and carriage returns in the files a reader or the shell
// sees. They live apart from scripts/release-gate.mjs, which runs when it is
// imported, so that test/release-gate-pack.test.ts can turn each one red
// against a directory it builds, without a build, a pack or an install.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The named exports the README documents for each entry point. A consumer's
// import of either specifier resolves through the package's exports map, so a
// missing entry in that map fails here as surely as a missing name does.
export const REQUIRED_EXPORTS = {
  "@headlessoracle/chirindo/purchase-check": [
    "createPurchaseCheck",
    "evaluatePurchase",
    "signInstruction",
    "mapCrossmintOrderIntent",
    "mapBasisTheoryAllowance",
    "mapPravaMandate",
  ],
  "@headlessoracle/chirindo/trial-recorder": ["createTrialRecorder"],
};

// Files whose bytes reach a reader or a shell as they are: a CR in dist/cli.js
// breaks its #! line on Unix; in the others it is a sign the release worktree
// was not checked out with LF, as every release since 0.5.1 has been.
export const CR_FILES = ["README.md", "LICENSE", "NOTICE", "package.json", "dist/cli.js"];

const FORBIDDEN_DIRS = new Set(["test", "scripts", "keys"]);
// Any PEM private key: PKCS#8 ("PRIVATE KEY"), "ENCRYPTED PRIVATE KEY",
// "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY". Built from two
// parts so that no line of this file holds both the header's start and
// "PRIVATE KEY": the repo's pre-push hook refuses any such line.
const PEM_BEGIN = "-----BEGIN";
const PEM_PRIVATE = new RegExp(`${PEM_BEGIN} [A-Z0-9 ]*PRIVATE KEY-----`);

// Every file under the installed package root, as a /-separated path relative
// to it. A nested node_modules holds dependencies, not packed files.
export function packedFiles(root) {
  const out = [];
  const walk = (rel) => {
    for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
      const p = rel === "" ? e.name : `${rel}/${e.name}`;
      if (e.isDirectory()) {
        if (e.name !== "node_modules") walk(p);
      } else out.push(p);
    }
  };
  walk("");
  return out.sort();
}

// RED WHEN: a packed path sits in a test/, scripts/ or keys/ directory, is a
// .env file, or holds a PEM private key header. Returns one line per finding.
export function forbiddenPaths(root) {
  const bad = [];
  for (const p of packedFiles(root)) {
    const parts = p.split("/");
    const name = parts[parts.length - 1];
    if (parts.slice(0, -1).some((d) => FORBIDDEN_DIRS.has(d))) bad.push(`${p} (under ${parts.find((d) => FORBIDDEN_DIRS.has(d))}/)`);
    if (name === ".env" || name.startsWith(".env.")) bad.push(`${p} (.env)`);
    if (PEM_PRIVATE.test(readFileSync(join(root, p), "latin1"))) bad.push(`${p} (PEM private key header)`);
  }
  return bad;
}

// RED WHEN: one of CR_FILES holds a carriage return, or is missing (fail
// closed: an absent file cannot be shown to be free of them).
export function crFindings(root) {
  const bad = [];
  for (const f of CR_FILES) {
    const p = join(root, f);
    if (!existsSync(p)) bad.push(`${f} (missing)`);
    else {
      const n = readFileSync(p).filter((b) => b === 0x0d).length;
      if (n > 0) bad.push(`${f} (${n} CR)`);
    }
  }
  return bad;
}

// Imports each specifier the way a consumer does: a separate node process
// whose working directory is the consumer's project, so resolution goes
// through that project's node_modules and the package's exports map, not
// through this repository. Returns { [specifier]: { ok: true, names:
// { [name]: typeof } } } or { [specifier]: { ok: false, error } }.
export function probeExports(consumerDir, specifiers = Object.keys(REQUIRED_EXPORTS)) {
  const script = [
    `const specs = ${JSON.stringify(specifiers)};`,
    "const out = {};",
    "for (const s of specs) {",
    "  try { const m = await import(s); out[s] = { ok: true, names: Object.fromEntries(Object.keys(m).map((k) => [k, typeof m[k]])) }; }",
    "  catch (e) { out[s] = { ok: false, error: String(e && e.code ? e.code : e).slice(0, 200) }; }",
    "}",
    "process.stdout.write(JSON.stringify(out));",
  ].join("\n");
  const stdout = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: consumerDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(stdout);
}

// RED WHEN: a specifier does not import, or lacks a required name, or the
// name is not a function. Returns one line per finding.
export function exportFindings(probe) {
  const bad = [];
  for (const [spec, names] of Object.entries(REQUIRED_EXPORTS)) {
    const got = probe[spec];
    if (got === undefined) bad.push(`${spec} (not probed)`);
    else if (got.ok !== true) bad.push(`${spec} (import failed: ${got.error})`);
    else for (const n of names) if (got.names[n] !== "function") bad.push(`${spec} ${n} (${got.names[n] ?? "absent"})`);
  }
  return bad;
}
