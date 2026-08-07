#!/usr/bin/env node
// PROPOSAL — intended landing place: mcp-gate-spike/scripts/release-gate.mjs
//
// Binds the published artifact to the source tree. Every other check in this
// repo runs against the working directory: vitest imports `../src/*.ts`, the
// conformance harness imports `@truestamp/canonify` and reads the vectors
// file. Nothing imports `dist/`, and nothing installs the package. That is how
// HEAD reached ten commits and a whole feature ahead of the `latest` dist-tag
// with every check green.
//
// This gate installs the package the way a consumer does — clean directory,
// --omit=dev, no repo on disk — and runs the CURRENT corpus against it.
//
//   node scripts/release-gate.mjs                      # pre-publish: gate the pack candidate
//   node scripts/release-gate.mjs --from-registry latest   # drift: what consumers actually get
//   node scripts/release-gate.mjs --from-registry 0.3.0 --json
//
// Exit codes (deterministic, agent-consumable):
//   0  every check passed
//   1  at least one check failed — do not publish / drift detected
//   2  harness error (bad flags, npm unavailable, corpus unreadable)

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { createHash, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Derived from the script's own location once this lands in scripts/.
// CHIRINDO_REPO overrides it so the gate can be run out-of-tree (review, CI).
const REPO = process.env.CHIRINDO_REPO ?? resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PKG_NAME = "@headlessoracle/chirindo";

// The capability surface the README and docs/spec claim this version has.
// This list is the deliverable's contract, maintained by hand: when a feature
// is documented, its entry point is added here. Check S below asserts the
// INSTALLED build actually carries it. Without this list the gate can only
// prove the artifact is well-formed, never that it is current — and
// well-formed-but-stale is exactly the failure that occurred.
const REQUIRED_SURFACE = [
  "jcs",
  "jcsBytes",
  "rfc7638Thumbprint",
  "strictJsonParse",
  "StrictJsonParseError",
  // x402 delivery-proof surface — docs/spec/delivery-proof.md, README B.2.
  // ABSENT from published 0.3.0; present in the source tree since f333eb2.
  "paymentRef",
  "paymentRefFromArtifacts",
  "paymentRefFromJsonStrings",
];

// ---------------------------------------------------------------- arg parsing

const argv = process.argv.slice(2);
let source = { mode: "pack" };
let expectVersion = null;
let asJson = false;
let keep = false;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--from-pack") source = { mode: "pack" };
  else if (a === "--from-registry") source = { mode: "registry", spec: argv[++i] };
  else if (a === "--expect-version") expectVersion = argv[++i];
  else if (a === "--json") asJson = true;
  else if (a === "--keep") keep = true;
  else die(2, `unknown flag: ${a}`);
}
if (source.mode === "registry" && !source.spec) die(2, "--from-registry needs a spec");

function die(code, msg) {
  process.stderr.write(`release-gate: ${msg}\n`);
  process.exit(code);
}

// `npm` is a .cmd shim on Windows and needs shell:true; `node` must NOT get it,
// because process.execPath contains a space ("C:\Program Files\nodejs\node.exe")
// and the shell splits it at the space.
function sh(cmd, args, cwd) {
  return execFileSync(cmd, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    shell: process.platform === "win32" && /^(npm|npx)$/.test(cmd),
  });
}

// ------------------------------------------------------------------- staging

const corpus = JSON.parse(readFileSync(join(REPO, "conformance", "vectors-v1.json"), "utf8"));
const declared = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")).version;
// Default the expectation to the source tree in BOTH modes. In registry mode
// that is the point: artifact != source tree IS the drift, and it must be red.
const targetVersion = expectVersion ?? declared;

const work = mkdtempSync(join(tmpdir(), "chirindo-gate-"));
const results = [];
let installed = null; // resolved path to the installed package root
let surface = null; // the imported module namespace

function record(id, ok, detail) {
  results.push({ id, ok, detail });
  if (!asJson) process.stdout.write(`${ok ? "PASS" : "FAIL"}  ${id}  ${detail}\n`);
  return ok;
}

try {
  // --- INSTALL -------------------------------------------------------------
  // RED WHEN: the tarball is malformed, or a package the runtime needs sits in
  // devDependencies and therefore is not installed under --omit=dev.
  let spec;
  if (source.mode === "pack") {
    // Build first: the release itself builds before packing, so the gate must
    // reflect that. NAMED LIMITATION — because this step rebuilds `dist/`, pack
    // mode can never go red on a stale committed `dist/`. Only registry mode
    // observes the bytes that were actually shipped.
    sh("npm", ["run", "build"], REPO);
    const out = JSON.parse(sh("npm", ["pack", "--json", "--pack-destination", work], REPO));
    spec = join(work, out[0].filename);
  } else {
    spec = `${PKG_NAME}@${source.spec}`;
  }

  sh("npm", ["init", "-y"], work);
  sh("npm", ["install", spec, "--omit=dev", "--no-audit", "--no-fund", "--ignore-scripts"], work);
  installed = join(work, "node_modules", ...PKG_NAME.split("/"));
  record("INSTALL", true, `${spec} → clean dir, --omit=dev`);

  // --- VERSION -------------------------------------------------------------
  // RED WHEN: package.json, the tag being cut, and the artifact disagree. This
  // is the three-way identity check; run it in registry mode after publish and
  // it also answers "did the registry serve what we packed".
  const meta = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"));
  record("VERSION", meta.version === targetVersion,
    `artifact=${meta.version} source_tree=${declared}`);

  // --- PROD-GRAPH ----------------------------------------------------------
  // RED WHEN: a dev-only package rides into the production dependency graph.
  // Informational threshold, not a hard rule — but a jump from 2 to 108 is the
  // signature of exactly the defect fixed in this release.
  const prodDeps = Object.keys(meta.dependencies ?? {});
  const treeCount = sh("npm", ["ls", "--omit=dev", "--all", "--parseable"], work)
    .split("\n").filter(Boolean).length - 1;
  record("PROD-GRAPH", treeCount <= 8,
    `direct=[${prodDeps.join(", ")}] transitive_installed=${treeCount}`);

  // --- FILES ---------------------------------------------------------------
  // RED WHEN: the `files` array drops something the runtime needs.
  const need = ["dist/cli.js", "dist/vendor/recorder/index.js", "LICENSE", "NOTICE"];
  const missing = need.filter((f) => !existsSync(join(installed, f)));
  record("FILES", missing.length === 0,
    missing.length ? `missing: ${missing.join(", ")}` : `${need.length}/${need.length} present`);

  // --- BOOT ----------------------------------------------------------------
  // RED WHEN: the shipped bin cannot resolve an import under --omit=dev.
  // A module-not-found here is the failure the vitest suite structurally cannot
  // produce, because `npm ci` always installs dev deps.
  let bootCode = 0;
  let bootErr = "";
  try {
    sh(process.execPath, [join(installed, "dist", "cli.js")], work);
  } catch (e) {
    bootCode = e.status ?? -1;
    bootErr = String(e.stderr ?? "").trim().split("\n")[0] ?? "";
  }
  // 2 is the CLI's documented usage-error code — the bin ran and parsed argv.
  record("BOOT", bootCode === 2, `exit=${bootCode} ${bootErr}`);

  // --- SURFACE -------------------------------------------------------------
  // RED WHEN: the installed build lacks a capability the docs claim. THIS is
  // the check that would have been red every day since 2026-07-10.
  surface = await import(pathToFileURL(join(installed, "dist", "vendor", "recorder", "index.js")).href);
  const absent = REQUIRED_SURFACE.filter((s) => surface[s] === undefined);
  record("SURFACE", absent.length === 0,
    absent.length ? `absent from artifact: ${absent.join(", ")}` : `${REQUIRED_SURFACE.length}/${REQUIRED_SURFACE.length} present`);

  // --- CORPUS/JCS ----------------------------------------------------------
  // RED WHEN: the shipped build canonicalizes differently from the frozen
  // corpus. Runs the CURRENT vectors against the artifact, so a corpus revision
  // the artifact predates shows up here.
  // The *_REJECT entries carry canonical_utf8:null — they document inputs for
  // which no canonical form exists, and V8's `input` is prose, not JSON. They
  // are not feedable here; CORPUS/STRICT is where rejection is asserted.
  const jcsBad = [];
  const positives = corpus.jcs_canonicalization.filter((v) => v.canonical_utf8 !== null);
  for (const v of positives) {
    const got = surface.jcs(v.input);
    const digest = createHash("sha256").update(got, "utf8").digest("hex");
    if (got !== v.canonical_utf8 || digest !== v.sha256) jcsBad.push(v.name);
  }
  record("CORPUS/JCS", jcsBad.length === 0,
    jcsBad.length ? `mismatch: ${jcsBad.join(", ")}`
      : `${positives.length} vectors byte-exact (${corpus.jcs_canonicalization.length - positives.length} REJECT entries deferred to CORPUS/STRICT)`);

  // --- CORPUS/THUMBPRINT ---------------------------------------------------
  // RED WHEN: RFC 7638 key binding drifts — verification would accept a chain
  // bound to a different key.
  // rfc7638Thumbprint takes a Node KeyObject, not a bare JWK — the corpus
  // stores the JWK, so it is imported here.
  const kb = corpus.key_binding;
  const tp = surface.rfc7638Thumbprint(createPublicKey({ key: kb.jwk, format: "jwk" }));
  record("CORPUS/THUMBPRINT", tp === kb.rfc7638_thumbprint,
    `got=${tp} expected=${kb.rfc7638_thumbprint}`);

  // --- CORPUS/STRICT -------------------------------------------------------
  // RED WHEN: the artifact's strict-ingest gate fails OPEN — accepts a vector
  // it must reject, or rejects it for the wrong reason. Fail-open here is the
  // worst outcome in the product, so it is asserted against the artifact, not
  // only against source.
  const strictBad = [];
  for (const v of corpus.strict_parse) {
    let reason = null;
    try {
      surface.strictJsonParse(v.input);
      reason = "<accepted>";
    } catch (e) {
      reason = e instanceof surface.StrictJsonParseError ? e.reason : `<${e.constructor.name}>`;
    }
    if (reason !== v.expected_reason) strictBad.push(`${v.name}: ${reason}`);
  }
  record("CORPUS/STRICT", strictBad.length === 0,
    strictBad.length ? strictBad.join("; ") : `${corpus.strict_parse.length} vectors reject as specified`);

  // --- CLI/E2E -------------------------------------------------------------
  // RED WHEN: the shipped bin cannot complete a real command end-to-end —
  // key generation, file layout, and the export path, through the published
  // artifact rather than through tsx against source.
  let e2e = "";
  try {
    sh(process.execPath, [join(installed, "dist", "cli.js"), "init", "--dir", join(work, ".gate")], work);
    sh(process.execPath, [join(installed, "dist", "cli.js"), "export-jwks", "--dir", join(work, ".gate"), "--out", join(work, "jwks.json")], work);
    const jwks = JSON.parse(readFileSync(join(work, "jwks.json"), "utf8"));
    const identity = JSON.parse(readFileSync(join(work, ".gate", "identity.json"), "utf8"));
    const exported = surface.rfc7638Thumbprint(createPublicKey({ key: jwks.keys[0], format: "jwk" }));
    // identity.json binds the key under `kid`, which init derives via
    // rfc7638Thumbprint. Agreement proves the exported JWKS and the on-disk
    // identity name the same key — the binding a verifier relies on.
    const bound = identity.kid;
    e2e = exported === bound ? `thumbprint agrees: ${exported}` : `MISMATCH exported=${exported} identity=${bound}`;
    record("CLI/E2E", exported === bound, e2e);
  } catch (e) {
    record("CLI/E2E", false, String(e.stderr ?? e.message).trim().split("\n")[0]);
  }
} catch (e) {
  record("HARNESS", false, String(e.stderr ?? e.message).trim().split("\n").slice(0, 3).join(" | "));
  if (!keep) rmSync(work, { recursive: true, force: true });
  if (asJson) process.stdout.write(JSON.stringify({ ok: false, error: "harness", results }, null, 2) + "\n");
  process.exit(2);
}

if (!keep) rmSync(work, { recursive: true, force: true });

const failed = results.filter((r) => !r.ok);
if (asJson) {
  process.stdout.write(JSON.stringify({
    ok: failed.length === 0,
    package: PKG_NAME,
    source: source.mode === "pack" ? "pack-candidate" : `registry:${source.spec}`,
    source_tree_version: declared,
    failed: failed.map((r) => r.id),
    results,
  }, null, 2) + "\n");
} else {
  process.stdout.write(`\n${failed.length === 0 ? "GATE PASS" : `GATE FAIL (${failed.map((r) => r.id).join(", ")})`}\n`);
}
process.exit(failed.length === 0 ? 0 : 1);
