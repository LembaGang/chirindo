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
//   node scripts/release-gate.mjs --require-ci <sha>   # pre-publish: CI on the tagged commit
//
// --require-ci <sha> runs only the CI gate (B-329, B-330). It checks that
// `git ls-remote origin refs/tags/v<version>^{}` is <sha> (version from
// --expect-version, else package.json), then reads GitHub's check runs for
// <sha> every --poll-seconds (default 30) until --deadline-seconds (default
// 1200): at most ceil(deadline / poll) requests, 40 by default, under the 60
// an hour GitHub allows an address without a token. With GITHUB_TOKEN set,
// each request carries it as a bearer token; the token is never printed. It
// passes only when each of CI_EXPECTED has at least one run and every run
// listed is "completed" with conclusion "success". A run that completes any
// other way fails at once, and so does an HTTP 401, 403 or 429 from GitHub
// (rate limit or refused token: run the gate again later, or set
// GITHUB_TOKEN). No runs, a missing name, a run still going or any other
// answer at the deadline fails. Each poll prints its UTC time and its rows.
//
// --from-file <json> replays a fixture ({"tag_ref": <sha or null>,
// "responses": [<check-runs response>, ...]}, poll n reads response n, the
// last one repeating) with no network at all. With --github-api
// http://127.0.0.1:<port> (tests only: a loopback address is the only one it
// takes) the fixture gives only tag_ref, and the check runs are read over
// HTTP from that address. --no-tag-check reads the check runs without
// checking the tag; such a run never passes.
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

// The check runs --require-ci waits for: the job ids in .github/workflows/
// (ci.yml build-test-conformance, audit.yml audit, gitleaks.yml scan). No job
// sets `name:`, so GitHub names each check run after its job. A tag push adds
// a second check suite, so a released commit has two runs of each; both count.
const CI_EXPECTED = ["build-test-conformance", "audit", "scan"];

// ---------------------------------------------------------------- arg parsing

const argv = process.argv.slice(2);
let source = { mode: "pack" };
let expectVersion = null;
let asJson = false;
let keep = false;
let requireCi = null;
let fromFile = null;
let deadlineSeconds = 1200;
let pollSeconds = 30;
let noTagCheck = false;
let githubApi = null;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--from-pack") source = { mode: "pack" };
  else if (a === "--from-registry") source = { mode: "registry", spec: argv[++i] };
  else if (a === "--expect-version") expectVersion = argv[++i];
  else if (a === "--json") asJson = true;
  else if (a === "--keep") keep = true;
  else if (a === "--require-ci") requireCi = argv[++i] ?? "";
  else if (a === "--from-file") fromFile = argv[++i] ?? "";
  else if (a === "--deadline-seconds") deadlineSeconds = seconds(a, argv[++i]);
  else if (a === "--poll-seconds") pollSeconds = seconds(a, argv[++i]);
  else if (a === "--no-tag-check") noTagCheck = true;
  else if (a === "--github-api") githubApi = argv[++i] ?? "";
  else die(2, `unknown flag: ${a}`);
}
if (source.mode === "registry" && !source.spec) die(2, "--from-registry needs a spec");
if (requireCi !== null && !/^[0-9a-f]{40}$/.test(requireCi)) {
  die(2, "--require-ci needs the full 40-character lowercase commit sha");
}
if (fromFile !== null && requireCi === null) die(2, "--from-file works only with --require-ci");
if (fromFile === "") die(2, "--from-file needs a path");
if (noTagCheck && requireCi === null) die(2, "--no-tag-check works only with --require-ci");
if (githubApi !== null) {
  if (fromFile === null) die(2, "--github-api is for tests and works only with --require-ci and --from-file");
  if (!/^http:\/\/(127\.0\.0\.1|localhost):[0-9]{1,5}$/.test(githubApi)) {
    die(2, "--github-api takes only http://127.0.0.1:<port> or http://localhost:<port>");
  }
}

function seconds(flag, value) {
  const n = Number(value);
  if (value === undefined || !Number.isFinite(n) || n <= 0) die(2, `${flag} needs a positive number of seconds`);
  return n;
}

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

// ------------------------------------------------------------------ dispatch
//
// The exit code is the verdict, so after the arguments are read the gate never
// ends with process.exit(): it sets process.exitCode and returns, and Node
// exits once nothing is left to run. On Windows, process.exit() after two
// --require-ci polls tripped a libuv assertion in Node 24 ("Assertion failed:
// !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76") and
// exited 0xC0000409 after printing GATE PASS. Nothing keeps the process
// running once the verdict is printed: each request asks for connection: close
// and reads its whole body, its timer is cleared, and each wait between two
// polls is over before the next poll. die() above runs only while the
// arguments are read, before any request.
process.exitCode = requireCi !== null ? await runRequireCi() : await runPackGate();

// ---------------------------------------------------------------- pack gate

async function runPackGate() {
  // ----------------------------------------------------------------- staging

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

    // --- AGENT-VERSION -------------------------------------------------------
    // RED WHEN: receipts from the shipped build would name another version than
    // the artifact's own package.json. Up to 0.5.2 every receipt said "0.0.1";
    // from 0.5.3 dist/version.js reads ../package.json when it loads, and this
    // check runs that read in the installed layout, not under tsx against src/.
    const receiptModule = await import(pathToFileURL(join(installed, "dist", "receipt.js")).href);
    const agentVersion = receiptModule.GATE_AGENT?.version;
    record("AGENT-VERSION", agentVersion === meta.version,
      `receipt agent.version=${agentVersion} artifact=${meta.version}`);

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
    return 2;
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
  return failed.length === 0 ? 0 : 1;
}

// ------------------------------------------------------------ --require-ci

async function runRequireCi() {
  const sha = requireCi;
  const expected = CI_EXPECTED;
  const results = [];
  const polls = [];
  // GITHUB_TOKEN, when set, goes out only in the authorization header. Every
  // line this gate prints passes through redact() as well, so the token
  // cannot reach the output even if an answer or an error message held it.
  const token = process.env.GITHUB_TOKEN ?? "";
  const redact = (text) => (token === "" ? text : text.split(token).join("<GITHUB_TOKEN>"));
  const out = (line) => { if (!asJson) process.stdout.write(redact(line) + "\n"); };
  const rec = (id, ok, detail) => {
    results.push({ id, ok, detail });
    out(`${ok ? "PASS" : "FAIL"}  ${id}  ${detail}`);
    return ok;
  };
  // Exit 2 for a harness error; otherwise 0 only when every check passed.
  const finish = (harnessError, tagRef) => {
    const failed = results.filter((r) => !r.ok).map((r) => r.id);
    const code = harnessError ? 2 : failed.length === 0 ? 0 : 1;
    if (asJson) {
      process.stdout.write(redact(JSON.stringify({
        ok: code === 0, mode: "require-ci", sha, expected, tag_ref: tagRef ?? null,
        failed, results, polls,
      }, null, 2)) + "\n");
    } else if (code !== 2) {
      out(`\n${code === 0 ? "GATE PASS" : `GATE FAIL (${failed.join(", ")})`}`);
    }
    return code;
  };
  const harness = (msg) => {
    process.stderr.write(`release-gate: ${redact(msg)}\n`);
    return finish(true);
  };

  let fixture = null;
  if (fromFile !== null) {
    try {
      fixture = JSON.parse(readFileSync(fromFile, "utf8"));
    } catch (e) {
      return harness(`--from-file ${fromFile}: ${e.message}`);
    }
    const tagOk = fixture !== null && typeof fixture === "object" &&
      (fixture.tag_ref === null || typeof fixture.tag_ref === "string");
    const replay = githubApi === null;
    const responsesOk = replay
      ? Array.isArray(fixture?.responses) && fixture.responses.length > 0
      : fixture?.responses === undefined;
    if (!tagOk || !responsesOk) {
      return harness(replay
        ? `--from-file ${fromFile}: need {"tag_ref": <sha or null>, "responses": [<check-runs response>, ...]}`
        : `--from-file ${fromFile}: with --github-api, need {"tag_ref": <sha or null>} and no responses`);
    }
  }
  const network = fixture === null || githubApi !== null;
  if (network && token !== "" && !/^[\x21-\x7e]+$/.test(token)) {
    return harness("GITHUB_TOKEN holds a character an HTTP header cannot carry (the token is not printed)");
  }

  // The tag must be on origin and peel to <sha> before anything is polled.
  let peeled = null;
  if (noTagCheck) {
    rec("TAG", false, "not checked (--no-tag-check): this run reads the check runs and cannot pass");
  } else {
    let version = expectVersion;
    if (version === null || version === undefined) {
      try {
        version = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")).version;
      } catch (e) {
        return harness(`cannot read package.json: ${e.message}`);
      }
    }
    const tagName = `refs/tags/v${version}^{}`;
    if (fixture !== null) {
      peeled = fixture.tag_ref;
    } else {
      let lsRemote;
      try {
        lsRemote = execFileSync("git", ["ls-remote", "origin", tagName], {
          cwd: REPO, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (e) {
        return harness(`git ls-remote origin ${tagName} failed: ${String(e.stderr ?? e.message).trim()}`);
      }
      for (const line of lsRemote.split("\n")) {
        const [hash, ref] = line.trim().split(/\s+/);
        if (ref === tagName) peeled = hash;
      }
    }
    const seen = peeled ?? "(absent: tag not pushed, or not an annotated tag)";
    if (!rec("TAG", peeled === sha, `origin ${tagName} = ${seen}; expected ${sha}`)) {
      return finish(false, peeled);
    }
  }

  const path = `/repos/LembaGang/chirindo/commits/${sha}/check-runs?per_page=100&filter=latest`;
  const url = `${githubApi ?? "https://api.github.com"}${path}`;
  // Whole milliseconds, so that 0.9 / 0.3 is 3 polls, not 4.
  const pollMs = Math.round(pollSeconds * 1000);
  const deadlineMs = Math.round(deadlineSeconds * 1000);
  const maxPolls = Math.max(1, Math.ceil(deadlineMs / Math.max(1, pollMs)));
  out(`check runs: ${fixture !== null && githubApi === null ? `fixture ${fromFile}` : url}`);
  out(`expected: ${expected.join(", ")}; poll every ${pollSeconds} s, at most ${maxPolls} poll(s) (deadline ${deadlineSeconds} s)`);
  if (network) {
    out(`auth: ${token !== ""
      ? "GITHUB_TOKEN, sent as a bearer token (not printed)"
      : "none (GitHub allows 60 requests an hour per address without a token)"}`);
  }
  const start = Date.now();
  let lastWait = "no poll answered";
  for (let n = 1; ; n++) {
    const at = new Date().toISOString();
    let body = null;
    let source;
    let refused = null; // an HTTP answer that waiting will not change
    if (!network) {
      const i = Math.min(n, fixture.responses.length) - 1;
      body = fixture.responses[i];
      source = `fixture response ${i + 1} of ${fixture.responses.length}`;
    } else {
      try {
        // connection: close, so that no socket is left open once the answer
        // is read, and a timer of the gate's own, cleared once the body is
        // read, rather than AbortSignal.timeout's, which outlives the request.
        const headers = {
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "chirindo-release-gate",
          connection: "close",
        };
        if (token !== "") headers.authorization = `Bearer ${token}`;
        const controller = new AbortController();
        const timer = setTimeout(
          () => controller.abort(new DOMException("The operation was aborted due to timeout", "TimeoutError")),
          15_000,
        );
        let res;
        let text;
        try {
          res = await fetch(url, { headers, signal: controller.signal });
          text = await res.text();
        } finally {
          clearTimeout(timer);
        }
        const remaining = res.headers.get("x-ratelimit-remaining");
        const reset = Number(res.headers.get("x-ratelimit-reset"));
        const resetAt = Number.isFinite(reset) && reset > 0 ? new Date(reset * 1000).toISOString() : null;
        const retryAfter = res.headers.get("retry-after");
        source = `HTTP ${res.status}, rate limit remaining ${remaining ?? "?"}` +
          (resetAt !== null ? ` (resets ${resetAt})` : "") +
          (retryAfter !== null ? `, retry-after ${retryAfter} s` : "");
        if (res.status === 200) {
          try {
            body = JSON.parse(text);
          } catch {
            source += ", body is not JSON";
          }
        } else {
          // GitHub's error text names the caller's IP address; it is masked.
          source += `, ${text.replace(/\s+/g, " ").replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, "<address>").slice(0, 200)}`;
          if (res.status === 401 || res.status === 403 || res.status === 429) {
            const when = resetAt !== null ? `after ${resetAt}` : retryAfter !== null ? `after ${retryAfter} s` : "later";
            refused = `GitHub answered HTTP ${res.status} on poll ${n}` +
              (remaining !== null ? ` (rate limit remaining ${remaining})` : "") + ": " +
              (token !== ""
                ? `the request with GITHUB_TOKEN was refused; check the token, or run the gate again ${when}`
                : `run the gate again ${when}, or set GITHUB_TOKEN to a GitHub token so its requests are authenticated`);
          }
        }
      } catch (e) {
        source = `request failed: ${e.message}`;
      }
    }
    const verdict = body === null ? null : judgeCheckRuns(body, sha, expected);
    polls.push({ poll: n, at, source: redact(source), verdict: verdict?.verdict ?? "no-data", rows: verdict?.rows ?? [] });
    out(`poll ${n} at ${at}: ${source}${verdict?.rows ? `, ${verdict.rows.length} run(s)` : ""}`);
    for (const r of verdict?.rows ?? []) {
      out(`  ${r.name.padEnd(24)} ${String(r.status).padEnd(12)} ${String(r.conclusion).padEnd(16)} ${r.completed_at ?? "-"}  suite ${r.suite ?? "-"}`);
    }
    if (refused !== null) {
      rec("CI", false, refused);
      return finish(false, peeled);
    }
    if (verdict?.verdict === "error") return harness(verdict.reason);
    if (verdict?.verdict === "pass") {
      rec("CI", true, verdict.reason);
      return finish(false, peeled);
    }
    if (verdict?.verdict === "fail") {
      rec("CI", false, verdict.reason);
      return finish(false, peeled);
    }
    lastWait = verdict?.reason ?? source;
    out(`  waiting: ${lastWait}`);
    if (n >= maxPolls || Date.now() - start >= deadlineMs) {
      rec("CI", false, `not complete at the deadline (${deadlineSeconds} s, ${n} poll(s)): ${lastWait}`);
      return finish(false, peeled);
    }
    const wait = start + n * pollMs - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
}

// One check-runs response -> pass, fail (now, whatever later polls say),
// pending (poll again), or error (a response the gate cannot judge).
function judgeCheckRuns(body, sha, expected) {
  if (body === null || typeof body !== "object" || !Array.isArray(body.check_runs) ||
      typeof body.total_count !== "number") {
    return { verdict: "error", reason: "the response is not a check-runs list ({total_count, check_runs})" };
  }
  const rows = body.check_runs.map((r) => ({
    name: typeof r?.name === "string" ? r.name : "(no name)",
    status: r?.status ?? null,
    conclusion: r?.conclusion ?? null,
    completed_at: r?.completed_at ?? null,
    head_sha: r?.head_sha,
    suite: r?.check_suite?.id ?? null,
  }));
  if (body.total_count !== rows.length) {
    return { verdict: "error", rows, reason: `total_count ${body.total_count} but ${rows.length} run(s) in the response` };
  }
  const otherCommit = rows.filter((r) => r.head_sha !== undefined && r.head_sha !== sha);
  if (otherCommit.length > 0) {
    return { verdict: "fail", rows, reason: `run(s) for another commit: ${otherCommit.map((r) => `${r.name} ${r.head_sha}`).join(", ")}` };
  }
  const failed = rows.filter((r) => r.status === "completed" && r.conclusion !== "success");
  if (failed.length > 0) {
    return { verdict: "fail", rows, reason: failed.map((r) => `${r.name} completed with ${r.conclusion}`).join("; ") };
  }
  const missing = expected.filter((name) => !rows.some((r) => r.name === name));
  const running = rows.filter((r) => r.status !== "completed");
  if (rows.length > 0 && missing.length === 0 && running.length === 0) {
    const count = (name) => rows.filter((r) => r.name === name).length;
    return {
      verdict: "pass", rows,
      reason: `${rows.length} run(s), every one completed with success: ${expected.map((n) => `${n} x${count(n)}`).join(", ")}`,
    };
  }
  const why = [];
  if (rows.length === 0) why.push("no check runs");
  if (missing.length > 0) why.push(`missing ${missing.join(", ")}`);
  if (running.length > 0) why.push(running.map((r) => `${r.name} ${r.status}`).join(", "));
  return { verdict: "pending", rows, reason: why.join("; ") };
}
