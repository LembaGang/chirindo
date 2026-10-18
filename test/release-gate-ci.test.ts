// scripts/release-gate.mjs --require-ci (B-329, B-330): the pre-publish CI
// gate. The rule: a pass needs at least one check run for each expected job
// and every run listed "completed" with "success"; any other completion fails
// at once, and so does an HTTP 401, 403 or 429 from GitHub; no runs, a missing
// job or a run still going at the deadline fails. It polls every 30 s for
// 1200 s by default, at most ceil(deadline / poll) requests, and sends
// GITHUB_TOKEN, when set, as a bearer token without printing it.
//
// Most tests replay fixtures (--from-file, no network). The HTTP tests serve
// check runs from a server on 127.0.0.1 (--github-api), so the request the
// gate makes, its headers and its handling of each status are exercised over
// a real socket. Nothing here reaches GitHub.
//
// The exit code is the contract: a script reads it, and the founder's publish
// line publishes only on 0. So the tests below also check that the exit code
// is the one the last GATE line names, over one poll and several, and that the
// gate ends on its own after its requests (test/fixtures/exit-probe.mjs): on
// Windows, process.exit() after two polls crashed Node 24 with 0xC0000409
// after GATE PASS had been printed.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTmpDir, makeTmpDir } from "./helpers.js";

const ROOT = resolve(import.meta.dirname, "..");
const GATE = join(ROOT, "scripts", "release-gate.mjs");
const SHAPE_52136E8 = join(ROOT, "test", "fixtures", "release-gate", "check-runs-52136e8.json");
const SHA = "52136e8881434201e5a98dde4c569dc0e8a359c5";
const FAKE_TOKEN = "fake-gate-test-value";
const EXIT_PROBE = join(ROOT, "test", "fixtures", "exit-probe.mjs");

interface Fixture {
  tag_ref: string | null;
  responses?: Array<{ total_count: number; check_runs: Array<Record<string, unknown>> }>;
}

function shape(): Required<Fixture> {
  return JSON.parse(readFileSync(SHAPE_52136E8, "utf8")) as Required<Fixture>;
}

// The child's environment: GITHUB_TOKEN only when a test sets it, and no
// proxy for its requests to 127.0.0.1.
function childEnv(token?: string): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env["GITHUB_TOKEN"];
  delete env["NODE_USE_ENV_PROXY"];
  if (token !== undefined) env["GITHUB_TOKEN"] = token;
  return env;
}

function runGate(
  args: string[],
): { stdout: string; stderr: string; status: number | null; ms: number } {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [GATE, ...args], {
    encoding: "utf8",
    timeout: 25_000,
    env: childEnv(),
  });
  if (r.error !== undefined) throw r.error;
  return { stdout: r.stdout, stderr: r.stderr, status: r.status, ms: Date.now() - t0 };
}

// Asynchronous, so that a server in this process can answer the gate. With
// probeDir, the gate runs under test/fixtures/exit-probe.mjs, which writes
// what it saw as the process exited into that directory.
function runGateAsync(
  args: string[],
  token?: string,
  probeDir?: string,
): Promise<{ stdout: string; stderr: string; status: number | null; ms: number }> {
  return new Promise((done, fail) => {
    const t0 = Date.now();
    const env = childEnv(token);
    const pre: string[] = [];
    if (probeDir !== undefined) {
      env["EXIT_PROBE_DIR"] = probeDir;
      pre.push("--import", pathToFileURL(EXIT_PROBE).href);
    }
    const child = spawn(process.execPath, [...pre, GATE, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    const timer = setTimeout(() => child.kill(), 25_000);
    child.on("error", fail);
    child.on("close", (status) => {
      clearTimeout(timer);
      done({ stdout, stderr, status, ms: Date.now() - t0 });
    });
  });
}

// The last line the gate printed (GATE PASS or GATE FAIL (...) in text mode).
const lastLine = (stdout: string): string => stdout.trimEnd().split("\n").pop() ?? "";

// What test/fixtures/exit-probe.mjs recorded for each process it ran in.
interface Probe {
  main: string | null;
  fetches: number;
  exitAfterFetch: number;
  code: number;
  active: string[];
}
function readProbes(dir: string): Probe[] {
  return readdirSync(dir)
    .filter((f) => f.startsWith("exit-probe-"))
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Probe);
}

interface Answer {
  status: number;
  headers?: Record<string, string>;
  body: unknown;
}

// Serves answers[n] to the n-th request (the last one repeating) and records
// each request's path and headers.
async function checkRunsServer(
  answers: Answer[],
): Promise<{ base: string; seen: Array<{ url: string; headers: IncomingHttpHeaders }>; close: () => Promise<void> }> {
  const seen: Array<{ url: string; headers: IncomingHttpHeaders }> = [];
  const server: Server = createServer((req, res) => {
    seen.push({ url: req.url ?? "", headers: req.headers });
    const a = answers[Math.min(seen.length, answers.length) - 1]!;
    res.writeHead(a.status, { "content-type": "application/json", ...(a.headers ?? {}) });
    res.end(JSON.stringify(a.body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    seen,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const polls = (stdout: string): number => stdout.split("\n").filter((l) => /^poll \d+ at /.test(l)).length;

describe("release-gate --require-ci", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-ci-gate-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  function fixtureFile(fixture: Fixture): string {
    const file = join(tmp, "fixture.json");
    writeFileSync(file, JSON.stringify(fixture), "utf8");
    return file;
  }

  function gateOn(fixture: Fixture, ...extra: string[]) {
    return runGate([
      "--require-ci", SHA,
      "--expect-version", "0.5.2",
      "--from-file", fixtureFile(fixture),
      "--deadline-seconds", "1",
      "--poll-seconds", "0.25",
      ...extra,
    ]);
  }

  it("the 52136e8 shape (two successful runs of each job) passes on the first poll", () => {
    const r = gateOn(shape());
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("PASS  TAG  origin refs/tags/v0.5.2^{} = " + SHA);
    expect(r.stdout).toContain(
      "PASS  CI  6 run(s), every one completed with success: build-test-conformance x2, audit x2, scan x2",
    );
    expect(r.stdout).toContain("GATE PASS");
    expect(polls(r.stdout)).toBe(1);
  }, 20_000);

  it("by default it polls every 30 s with a 1200 s deadline: at most 40 requests", () => {
    const r = runGate(["--require-ci", SHA, "--expect-version", "0.5.2", "--from-file", SHAPE_52136E8]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("poll every 30 s, at most 40 poll(s) (deadline 1200 s)");
  }, 20_000);

  it("zero check runs fails at the deadline after ceil(deadline / poll) polls, never more", () => {
    const f = shape();
    f.responses = [{ total_count: 0, check_runs: [] }];
    const r = gateOn(f);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("at most 4 poll(s) (deadline 1 s)");
    expect(r.stdout).toMatch(/FAIL {2}CI {2}not complete at the deadline \(1 s, 4 poll\(s\)\): no check runs/);
    expect(r.stdout).toContain("GATE FAIL (CI)");
    expect(polls(r.stdout)).toBe(4);
    expect(r.ms).toBeGreaterThanOrEqual(750);
    const third = gateOn(f, "--deadline-seconds", "0.9", "--poll-seconds", "0.3");
    expect(polls(third.stdout)).toBe(3);
  }, 20_000);

  it("one run still in_progress fails at a short deadline", () => {
    const f = shape();
    const run = f.responses[0]!.check_runs[2]!;
    run.status = "in_progress";
    run.conclusion = null;
    run.completed_at = null;
    const r = gateOn(f);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/FAIL {2}CI {2}not complete at the deadline \(1 s, 4 poll\(s\)\): build-test-conformance in_progress/);
    expect(polls(r.stdout)).toBe(4);
  }, 20_000);

  it("one run that completed with failure fails at once, on the first poll", () => {
    const f = shape();
    f.responses[0]!.check_runs[1]!.conclusion = "failure";
    const r = gateOn(f, "--deadline-seconds", "60");
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("FAIL  CI  scan completed with failure");
    expect(polls(r.stdout)).toBe(1);
    expect(r.ms).toBeLessThan(10_000);
  }, 20_000);

  it("keeps polling while a run is in progress and passes once every run is done", () => {
    const done = shape();
    const pending = shape();
    const run = pending.responses[0]!.check_runs[0]!;
    run.status = "queued";
    run.conclusion = null;
    const f: Fixture = { tag_ref: SHA, responses: [pending.responses[0]!, done.responses[0]!] };
    const r = gateOn(f, "--deadline-seconds", "10");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("waiting: audit queued");
    expect(polls(r.stdout)).toBe(2);
  }, 20_000);

  it("a missing job fails at the deadline even when every listed run succeeded", () => {
    const f = shape();
    const runs = f.responses[0]!.check_runs.filter((c) => c["name"] !== "build-test-conformance");
    f.responses = [{ total_count: runs.length, check_runs: runs }];
    const r = gateOn(f);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/not complete at the deadline .*: missing build-test-conformance/);
  }, 20_000);

  it("a tag that is absent on origin, or points elsewhere, fails before any poll", () => {
    const f = shape();
    f.tag_ref = null;
    const absent = gateOn(f);
    expect(absent.status).toBe(1);
    expect(absent.stdout).toContain("FAIL  TAG  origin refs/tags/v0.5.2^{} = (absent");
    expect(polls(absent.stdout)).toBe(0);
    f.tag_ref = "f4086fbf0f6dca0855facbc2e1187db35f8e5c18";
    const elsewhere = gateOn(f);
    expect(elsewhere.status).toBe(1);
    expect(elsewhere.stdout).toContain("FAIL  TAG");
    expect(polls(elsewhere.stdout)).toBe(0);
  }, 20_000);

  it("--no-tag-check reads the check runs but never passes, even when every run succeeded", () => {
    const green = gateOn(shape(), "--no-tag-check");
    expect(green.status).toBe(1);
    expect(green.stdout).toContain("FAIL  TAG  not checked (--no-tag-check)");
    expect(green.stdout).toContain("PASS  CI  6 run(s)");
    expect(green.stdout).toContain("GATE FAIL (TAG)");
    const f = shape();
    f.responses = [{ total_count: 0, check_runs: [] }];
    const none = gateOn(f, "--no-tag-check");
    expect(none.status).toBe(1);
    expect(none.stdout).toContain("GATE FAIL (TAG, CI)");
    expect(polls(none.stdout)).toBe(4);
  }, 20_000);

  it("bad input is a harness error (exit 2)", () => {
    const short = runGate(["--require-ci", "52136e8"]);
    expect(short.status).toBe(2);
    expect(short.stderr).toContain("--require-ci needs the full 40-character lowercase commit sha");
    const alone = runGate(["--from-file", SHAPE_52136E8]);
    expect(alone.status).toBe(2);
    expect(alone.stderr).toContain("--from-file works only with --require-ci");
    const bad = join(tmp, "bad.json");
    writeFileSync(bad, JSON.stringify({ tag_ref: SHA, responses: [] }), "utf8");
    const malformed = runGate(["--require-ci", SHA, "--from-file", bad]);
    expect(malformed.status).toBe(2);
    expect(malformed.stderr).toContain('need {"tag_ref"');
    const noTag = runGate(["--no-tag-check"]);
    expect(noTag.status).toBe(2);
    expect(noTag.stderr).toContain("--no-tag-check works only with --require-ci");
    const remote = runGate(["--require-ci", SHA, "--from-file", bad, "--github-api", "https://api.github.com"]);
    expect(remote.status).toBe(2);
    expect(remote.stderr).toContain("--github-api takes only http://127.0.0.1:<port>");
    const noFile = runGate(["--require-ci", SHA, "--github-api", "http://127.0.0.1:9"]);
    expect(noFile.status).toBe(2);
    expect(noFile.stderr).toContain("--github-api is for tests");
  }, 20_000);

  describe("over HTTP, from a server on 127.0.0.1", () => {
    function httpArgs(base: string, ...extra: string[]): string[] {
      return [
        "--require-ci", SHA,
        "--expect-version", "0.5.2",
        "--from-file", fixtureFile({ tag_ref: SHA }),
        "--github-api", base,
        "--deadline-seconds", "2",
        "--poll-seconds", "0.25",
        ...extra,
      ];
    }
    function viaHttp(base: string, token?: string, ...extra: string[]) {
      return runGateAsync(httpArgs(base, ...extra), token);
    }
    function viaHttpProbed(base: string, probeDir: string) {
      return runGateAsync(httpArgs(base), undefined, probeDir);
    }

    it("a 200 with the 52136e8 shape passes after one request, which carries no authorization without GITHUB_TOKEN", async () => {
      const server = await checkRunsServer([{ status: 200, body: shape().responses[0] }]);
      try {
        const r = await viaHttp(server.base);
        expect(r.status).toBe(0);
        expect(r.stdout).toContain("auth: none");
        expect(r.stdout).toContain("PASS  CI  6 run(s)");
        expect(server.seen).toHaveLength(1);
        expect(server.seen[0]!.url).toBe(`/repos/LembaGang/chirindo/commits/${SHA}/check-runs?per_page=100&filter=latest`);
        expect(server.seen[0]!.headers["accept"]).toBe("application/vnd.github+json");
        expect(server.seen[0]!.headers["user-agent"]).toBe("chirindo-release-gate");
        expect(server.seen[0]!.headers["authorization"]).toBeUndefined();
      } finally {
        await server.close();
      }
    }, 20_000);

    it("with GITHUB_TOKEN set, each request carries it as a bearer token, and the token is printed nowhere", async () => {
      const server = await checkRunsServer([
        { status: 200, body: { total_count: 0, check_runs: [] } },
        { status: 200, body: shape().responses[0] },
      ]);
      try {
        const r = await viaHttp(server.base, FAKE_TOKEN);
        expect(r.status).toBe(0);
        expect(server.seen).toHaveLength(2);
        for (const s of server.seen) expect(s.headers["authorization"]).toBe(`Bearer ${FAKE_TOKEN}`);
        expect(r.stdout).toContain("auth: GITHUB_TOKEN, sent as a bearer token (not printed)");
        expect(r.stdout + r.stderr).not.toContain(FAKE_TOKEN);
        expect(r.stdout + r.stderr).not.toContain("gate-test-value");
      } finally {
        await server.close();
      }
    }, 20_000);

    it("a 403 from GitHub (rate limit) fails at once: one request, and the output says to run it later or set GITHUB_TOKEN", async () => {
      const server = await checkRunsServer([
        {
          status: 403,
          headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1792166400" },
          body: { message: "API rate limit exceeded for 203.0.113.7." },
        },
      ]);
      try {
        const r = await viaHttp(server.base, undefined, "--deadline-seconds", "60");
        expect(r.status).toBe(1);
        expect(server.seen).toHaveLength(1);
        expect(r.stdout).toContain(
          "FAIL  CI  GitHub answered HTTP 403 on poll 1 (rate limit remaining 0): run the gate again after 2026-10-16T16:00:00.000Z, or set GITHUB_TOKEN",
        );
        expect(r.stdout).not.toContain("203.0.113.7");
        expect(r.stdout).toContain("GATE FAIL (CI)");
      } finally {
        await server.close();
      }
    }, 20_000);

    it("a 429 fails at once, and a 401 with GITHUB_TOKEN set says the token was refused", async () => {
      const busy = await checkRunsServer([{ status: 429, headers: { "retry-after": "60" }, body: { message: "slow down" } }]);
      try {
        const r = await viaHttp(busy.base, undefined, "--deadline-seconds", "60");
        expect(r.status).toBe(1);
        expect(busy.seen).toHaveLength(1);
        expect(r.stdout).toContain("FAIL  CI  GitHub answered HTTP 429 on poll 1: run the gate again after 60 s, or set GITHUB_TOKEN");
      } finally {
        await busy.close();
      }
      const refused = await checkRunsServer([{ status: 401, body: { message: "Bad credentials" } }]);
      try {
        const r = await viaHttp(refused.base, FAKE_TOKEN, "--deadline-seconds", "60");
        expect(r.status).toBe(1);
        expect(refused.seen).toHaveLength(1);
        expect(r.stdout).toContain("GitHub answered HTTP 401 on poll 1: the request with GITHUB_TOKEN was refused");
        expect(r.stdout + r.stderr).not.toContain(FAKE_TOKEN);
      } finally {
        await refused.close();
      }
    }, 20_000);

    it("any other answer (a 502) is not yet a verdict: it polls again, and passes when the runs are green", async () => {
      const server = await checkRunsServer([
        { status: 502, body: { message: "Server Error" } },
        { status: 200, body: shape().responses[0] },
      ]);
      try {
        const r = await viaHttp(server.base);
        expect(r.status).toBe(0);
        expect(server.seen).toHaveLength(2);
        expect(r.stdout).toContain("poll 1 at ");
        expect(r.stdout).toContain("HTTP 502");
      } finally {
        await server.close();
      }
    }, 20_000);

    it("two polls, then PASS: the last line printed is GATE PASS, and the exit code is 0", async () => {
      const server = await checkRunsServer([
        { status: 200, body: { total_count: 0, check_runs: [] } },
        { status: 200, body: shape().responses[0] },
      ]);
      try {
        const r = await viaHttp(server.base);
        expect(server.seen).toHaveLength(2);
        expect(lastLine(r.stdout)).toBe("GATE PASS");
        expect(r.status).toBe(0);
        expect(r.stderr).toBe("");
      } finally {
        await server.close();
      }
    }, 20_000);

    it("two polls, then FAIL: the last line printed is GATE FAIL (CI), and the exit code is 1", async () => {
      const failing = shape().responses[0]!;
      failing.check_runs[1]!["conclusion"] = "failure";
      const server = await checkRunsServer([
        { status: 200, body: { total_count: 0, check_runs: [] } },
        { status: 200, body: failing },
      ]);
      try {
        const r = await viaHttp(server.base);
        expect(server.seen).toHaveLength(2);
        expect(r.stdout).toContain("FAIL  CI  scan completed with failure");
        expect(lastLine(r.stdout)).toBe("GATE FAIL (CI)");
        expect(r.status).toBe(1);
        expect(r.stderr).toBe("");
      } finally {
        await server.close();
      }
    }, 20_000);

    it("the exit code is always the one the last GATE line names: 0 after GATE PASS, 1 after GATE FAIL, over one poll or several", async () => {
      const green = shape().responses[0]!;
      const red = shape().responses[0]!;
      red.check_runs[0]!["conclusion"] = "cancelled";
      const none = { total_count: 0, check_runs: [] };
      const cases: Array<{ name: string; answers: Answer[]; requests: number }> = [
        { name: "one poll, pass", answers: [{ status: 200, body: green }], requests: 1 },
        { name: "two polls, pass", answers: [{ status: 502, body: { message: "Server Error" } }, { status: 200, body: green }], requests: 2 },
        { name: "three polls, pass", answers: [{ status: 200, body: none }, { status: 200, body: none }, { status: 200, body: green }], requests: 3 },
        { name: "one poll, fail", answers: [{ status: 200, body: red }], requests: 1 },
        { name: "two polls, fail", answers: [{ status: 200, body: none }, { status: 200, body: red }], requests: 2 },
        { name: "refused at once", answers: [{ status: 429, headers: { "retry-after": "60" }, body: { message: "slow down" } }], requests: 1 },
        { name: "deadline", answers: [{ status: 200, body: none }], requests: 8 },
      ];
      for (const c of cases) {
        const server = await checkRunsServer(c.answers);
        try {
          const r = await viaHttp(server.base);
          expect(server.seen, c.name).toHaveLength(c.requests);
          const gate = lastLine(r.stdout);
          expect(gate, c.name).toMatch(/^GATE (PASS|FAIL \(.+\))$/);
          expect(r.status, `${c.name}: ${gate}`).toBe(gate === "GATE PASS" ? 0 : 1);
        } finally {
          await server.close();
        }
      }
    }, 60_000);

    it("the gate ends on its own after its requests: no process.exit() after a fetch, every request asks for connection: close, and nothing is left open", async () => {
      const server = await checkRunsServer([
        { status: 502, body: { message: "Server Error" } },
        { status: 200, body: shape().responses[0] },
      ]);
      const probeDir = mkdtempSync(join(tmp, "probe-"));
      try {
        const r = await viaHttpProbed(server.base, probeDir);
        const probes = readProbes(probeDir);
        expect(probes).toHaveLength(1);
        expect(probes[0]).toMatchObject({ fetches: 2, exitAfterFetch: 0, code: 0 });
        // The stdio pipes may remain; no socket, timer or immediate may.
        expect(probes[0]!.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap")).toEqual([]);
        expect(server.seen.map((s) => s.headers["connection"])).toEqual(["close", "close"]);
        expect(r.status).toBe(0);
        expect(lastLine(r.stdout)).toBe("GATE PASS");
        // A request timer left pending (15 s) would hold the gate past this.
        expect(r.ms).toBeLessThan(10_000);
      } finally {
        await server.close();
      }
    }, 20_000);
  });
});
