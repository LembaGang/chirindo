// The gate against a local fixture server, polling twice (B-329). Run it with
// node; it needs nothing but Node 20 or later.
//
//   node test/fixtures/release-gate/two-polls.mjs [path/to/release-gate.mjs]
//
// On Windows, Node 24.13.0, the gate as first written for 0.5.3 printed GATE
// PASS after two polls and then exited 0xC0000409 ("Assertion failed:
// !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76"),
// inside process.exit(). This runs the gate twice against a server on
// 127.0.0.1 that answers two requests: first a 502 (in the second run, 200
// with no check runs), then 200 with the 52136e8 shape (check-runs-52136e8.json,
// next to this file). It runs the gate under test/fixtures/exit-probe.mjs and
// prints, for each run, the gate's output, its exit code, the requests the
// server answered and what the probe saw as the gate exited. It ends with
// REPRO PASS (exit code 0) when each run exits 0 after GATE PASS, made two
// requests, wrote nothing to stderr, never called process.exit() after a
// fetch, and left nothing open but its stdio pipes; else with REPRO FAIL (exit
// code 1). It sends no token.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const GATE = resolve(process.argv[2] ?? join(HERE, "..", "..", "..", "scripts", "release-gate.mjs"));
const PROBE = join(HERE, "..", "exit-probe.mjs");
const SHA = "52136e8881434201e5a98dde4c569dc0e8a359c5";
const SHAPE = JSON.parse(readFileSync(join(HERE, "check-runs-52136e8.json"), "utf8")).responses[0];

const CASES = [
  { name: "a 502, then 200 with the 52136e8 shape", answers: [{ status: 502, body: { message: "Server Error" } }, { status: 200, body: SHAPE }] },
  { name: "200 with no check runs, then 200 with the 52136e8 shape", answers: [{ status: 200, body: { total_count: 0, check_runs: [] } }, { status: 200, body: SHAPE }] },
];

// Serves answers[n] to the n-th request, the last one repeating.
function listen(answers) {
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    const a = answers[Math.min(requests, answers.length) - 1];
    req.resume();
    res.writeHead(a.status, { "content-type": "application/json" });
    res.end(JSON.stringify(a.body));
  });
  return new Promise((ok) =>
    server.listen(0, "127.0.0.1", () =>
      ok({
        base: `http://127.0.0.1:${server.address().port}`,
        requests: () => requests,
        close: () => new Promise((done) => server.close(() => done())),
      }),
    ),
  );
}

function runGate(args, probeDir) {
  return new Promise((ok, fail) => {
    const env = { ...process.env, EXIT_PROBE_DIR: probeDir };
    delete env.GITHUB_TOKEN;
    delete env.NODE_USE_ENV_PROXY;
    const child = spawn(process.execPath, ["--import", pathToFileURL(PROBE).href, GATE, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d) => (stderr += d.toString("utf8")));
    const timer = setTimeout(() => child.kill(), 25_000);
    child.on("error", fail);
    child.on("close", (status, signal) => {
      clearTimeout(timer);
      ok({ status, signal, stdout, stderr });
    });
  });
}

const work = mkdtempSync(join(tmpdir(), "chirindo-two-polls-"));
const failures = [];
try {
  const fixture = join(work, "fixture.json");
  writeFileSync(fixture, JSON.stringify({ tag_ref: SHA }), "utf8");
  console.log(`gate: ${GATE}`);
  console.log(`node: ${process.version} on ${process.platform}`);
  for (const [i, c] of CASES.entries()) {
    const probeDir = mkdtempSync(join(work, "probe-"));
    const server = await listen(c.answers);
    let r;
    try {
      r = await runGate(
        [
          "--require-ci", SHA,
          "--expect-version", "0.5.2",
          "--from-file", fixture,
          "--github-api", server.base,
          "--deadline-seconds", "2",
          "--poll-seconds", "0.25",
        ],
        probeDir,
      );
    } finally {
      await server.close();
    }
    const last = r.stdout.trimEnd().split("\n").pop() ?? "";
    const files = readdirSync(probeDir).filter((f) => f.startsWith("exit-probe-"));
    const probe = files.length === 1 ? JSON.parse(readFileSync(join(probeDir, files[0]), "utf8")) : null;
    const open = probe === null ? null : probe.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap");
    console.log("");
    console.log(`case ${i + 1} of ${CASES.length}: ${c.name}`);
    console.log("--- gate stdout");
    process.stdout.write(r.stdout);
    console.log("--- gate stderr");
    process.stdout.write(r.stderr === "" ? "(empty)\n" : r.stderr);
    const hex = r.status === null ? "none" : `0x${r.status.toString(16)}`;
    console.log(`EXIT ${r.status ?? `signal ${r.signal}`} (${hex}) requests=${server.requests()}`);
    console.log(`last line: ${last}`);
    console.log(
      probe === null
        ? `exit probe: ${files.length} file(s), expected 1`
        : `exit probe: fetches ${probe.fetches}, process.exit() after a fetch ${probe.exitAfterFetch}, ` +
            `open at exit besides stdio pipes: ${open.length === 0 ? "none" : open.join(", ")}`,
    );
    const why = [];
    if (r.status !== 0) why.push(`exit ${r.status ?? r.signal}`);
    if (last !== "GATE PASS") why.push(`last line "${last}"`);
    if (server.requests() !== 2) why.push(`${server.requests()} request(s)`);
    if (r.stderr !== "") why.push("stderr not empty");
    if (probe === null) why.push("no exit probe");
    else {
      if (probe.exitAfterFetch !== 0) why.push(`process.exit() after a fetch ${probe.exitAfterFetch}`);
      if (open.length !== 0) why.push(`open at exit: ${open.join(", ")}`);
    }
    if (why.length > 0) failures.push(`case ${i + 1}: ${why.join("; ")}`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
console.log("");
if (failures.length === 0) {
  console.log(`REPRO PASS: ${CASES.length} of ${CASES.length} two-poll runs exit 0 after GATE PASS and leave nothing open`);
  process.exitCode = 0;
} else {
  console.log(`REPRO FAIL: ${failures.join(" | ")}`);
  process.exitCode = 1;
}
