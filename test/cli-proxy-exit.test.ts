// How `chirindo proxy` ends (B-329). The shutdown used to call process.exit(0)
// once the final checkpoint's witness POST was done; on Windows, Node 24 can
// trip a libuv assertion inside process.exit() after fetch requests (it did
// for scripts/release-gate.mjs, exit 0xC0000409). The proxy now sets
// process.exitCode and ends on its own, so nothing may keep it running: the
// client's stdin is closed, the downstream is let go, and every witness
// request asks for connection: close and clears its timer.
//
// The CLI runs as node on tsx's CLI file (test/helpers.ts), under
// test/fixtures/exit-probe.mjs (NODE_OPTIONS), which records, for each process,
// its fetch() calls, any process.exit() after one, and what was still active
// as it exited. A witness request has a 10 s timeout (WITNESS_POST_TIMEOUT_MS)
// and the shutdown waits at most 5 s for the witness, so a proxy that exits
// within 8 s of the end of its stdin was held by neither a request timer nor
// a request left open.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readSidecar, sidecarPathFor } from "../src/witness.js";
import {
  CLI_E2E_TIMEOUT_MS,
  CLI_ENTRY,
  CLI_SPAWN_TIMEOUT_MS,
  TSX_CLI,
  cleanupTmpDir,
  initIdentity,
  makeTmpDir,
  writePolicy,
} from "./helpers.js";

const ROOT = resolve(import.meta.dirname, "..");
const FAKE_SERVER = join(ROOT, "scripts", "fake-mcp-server.ts");
const EXIT_PROBE = join(ROOT, "test", "fixtures", "exit-probe.mjs");
const STUBBORN = join(ROOT, "test", "fixtures", "stubborn-downstream.mjs");

interface Probe {
  main: string | null;
  fetches: number;
  exitAfterFetch: number;
  code: number;
  active: string[];
}

// The probe file of the process that ran src/cli.ts (tsx's own process and the
// fake server's write one too, with no fetch).
function cliProbe(dir: string): Probe {
  const probes = readdirSync(dir)
    .filter((f) => f.startsWith("exit-probe-"))
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Probe)
    .filter((p) => p.main !== null && /[\\/]src[\\/]cli\.ts$/.test(p.main));
  expect(probes).toHaveLength(1);
  return probes[0]!;
}

// A witness that answers every request with 503 witness_unavailable, which the
// proxy records in the sidecar and permits, after `delayMs`; it records each
// request.
async function unavailableWitness(delayMs = 0): Promise<{
  url: string;
  seen: Array<{ method: string; url: string; headers: IncomingHttpHeaders }>;
  close: () => Promise<void>;
}> {
  const seen: Array<{ method: string; url: string; headers: IncomingHttpHeaders }> = [];
  const server: Server = createServer((req, res) => {
    seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers });
    req.resume();
    req.on("end", () => {
      const t = setTimeout(() => {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "witness_unavailable" }));
      }, delayMs);
      res.on("close", () => clearTimeout(t));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

// Starts `chirindo proxy` under the probe, sends `lines`, ends its stdin once
// its stdout holds `end.stdout`, or once `end.after` resolves (never, when
// `end` is null), and resolves on its exit. A proxy still running after
// CLI_SPAWN_TIMEOUT_MS is killed and the test fails as a named spawn timeout.
function runProxyCli(
  proxyArgs: string[],
  probeDir: string,
  lines: string[],
  end: { stdout: string } | { after: Promise<void> } | null,
): Promise<{ status: number | null; stdout: string; stderr: string; msAfterEnd: number | null }> {
  return new Promise((done, fail) => {
    let endedAt: number | null = null;
    const endStdin = () => {
      if (endedAt !== null) return;
      endedAt = Date.now();
      child.stdin.end();
    };
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      EXIT_PROBE_DIR: probeDir,
      NODE_OPTIONS: `--import ${pathToFileURL(EXIT_PROBE).href}`,
    };
    const child = spawn(process.execPath, [TSX_CLI, CLI_ENTRY, "proxy", ...proxyArgs], {
      stdio: ["pipe", "pipe", "pipe"],
      env,
    });
    const timer = setTimeout(() => {
      child.kill();
      fail(new Error(`spawn timeout: chirindo proxy did not exit within ${CLI_SPAWN_TIMEOUT_MS} ms and was killed`));
    }, CLI_SPAWN_TIMEOUT_MS);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => {
      stdout += c.toString("utf8");
      if (end !== null && "stdout" in end && stdout.includes(end.stdout)) endStdin();
    });
    if (end !== null && "after" in end) end.after.then(endStdin, fail);
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    // A proxy that is already gone when its stdin is ended fails the test by
    // its output, not by an EPIPE here.
    child.stdin.on("error", () => {});
    child.on("error", fail);
    child.on("close", (status) => {
      clearTimeout(timer);
      done({ status, stdout, stderr, msAfterEnd: endedAt === null ? null : Date.now() - endedAt });
    });
    for (const l of lines) child.stdin.write(l + "\n");
  });
}

describe("chirindo proxy ends on its own (exit code 0)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-proxy-exit-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("after its witness requests: no process.exit() after a fetch, each request asks for connection: close, nothing is left open", async () => {
    await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [] });
    const chainPath = join(tmp, "proxy.jsonl");
    const witness = await unavailableWitness();
    const probeDir = mkdtempSync(join(tmp, "probe-"));
    try {
      const r = await runProxyCli(
        [
          "--dir", tmp, "--chain", chainPath, "--session-id", "sess-exit", "--policy", policyPath,
          "--server-label", "fake", "--witness", witness.url,
          "--", "node", TSX_CLI, FAKE_SERVER,
        ],
        probeDir,
        [JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } })],
        { stdout: '"id":1' },
      );
      const probe = cliProbe(probeDir);
      expect(probe).toMatchObject({ fetches: 1, exitAfterFetch: 0, code: 0 });
      // The stdio pipes may remain; no socket, timer, child or immediate may.
      expect(probe.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap")).toEqual([]);
      expect(r.status).toBe(0);
      // The witness answers at once: no request timer may hold the proxy.
      expect(r.msAfterEnd).not.toBeNull();
      expect(r.msAfterEnd!).toBeLessThan(8_000);
      expect(r.stdout).toContain("echo: x");
      expect(r.stderr).toContain("[chirindo] proxy exiting (1 receipts written)");
      // The shutdown checkpoint went to the witness, which refused it.
      expect(witness.seen.map((s) => `${s.method} ${s.url} ${s.headers["connection"]}`)).toEqual([
        "POST /v1/witness/checkpoints close",
      ]);
      const sidecar = readSidecar(sidecarPathFor(chainPath));
      expect(sidecar).toHaveLength(1);
      expect(sidecar[0]!.witness_error).toBe("witness_unavailable");
    } finally {
      await witness.close();
    }
  }, CLI_E2E_TIMEOUT_MS);

  it("when the downstream exits first, while the client keeps its stdin open", async () => {
    await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [] });
    const probeDir = mkdtempSync(join(tmp, "probe-"));
    const r = await runProxyCli(
      [
        "--dir", tmp, "--chain", join(tmp, "gone.jsonl"), "--session-id", "sess-gone", "--policy", policyPath,
        "--server-label", "fake", "--", "node", "-e", "0",
      ],
      probeDir,
      [],
      null,
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toContain("[chirindo] proxy exiting (0 receipts written)");
    const probe = cliProbe(probeDir);
    expect(probe).toMatchObject({ fetches: 0, exitAfterFetch: 0, code: 0 });
    expect(probe.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap")).toEqual([]);
  }, CLI_E2E_TIMEOUT_MS);

  it("with a witness slower than the 5 s shutdown wait: the request is ended at the wait, witness_timeout is recorded, and the proxy exits", async () => {
    await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [] });
    const chainPath = join(tmp, "slow.jsonl");
    const witness = await unavailableWitness(12_000);
    const probeDir = mkdtempSync(join(tmp, "probe-"));
    try {
      const r = await runProxyCli(
        [
          "--dir", tmp, "--chain", chainPath, "--session-id", "sess-slow", "--policy", policyPath,
          "--server-label", "fake", "--witness", witness.url,
          "--", "node", TSX_CLI, FAKE_SERVER,
        ],
        probeDir,
        [JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } })],
        { stdout: '"id":1' },
      );
      const probe = cliProbe(probeDir);
      expect(probe).toMatchObject({ fetches: 1, exitAfterFetch: 0, code: 0 });
      expect(probe.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap")).toEqual([]);
      expect(r.status).toBe(0);
      // The witness would answer at 12 s and the request times out at 10 s;
      // ended at the 5 s wait, the proxy is gone before either.
      expect(r.msAfterEnd).not.toBeNull();
      expect(r.msAfterEnd!).toBeLessThan(8_000);
      const sidecar = readSidecar(sidecarPathFor(chainPath));
      expect(sidecar).toHaveLength(1);
      expect(sidecar[0]!.witness_error).toBe("witness_timeout");
    } finally {
      await witness.close();
    }
  }, CLI_E2E_TIMEOUT_MS);

  it("with a downstream that outlives its kill: the proxy lets it go and exits", async () => {
    await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [] });
    const probeDir = mkdtempSync(join(tmp, "probe-"));
    const pidFile = join(tmp, "stubborn.pid");
    // The downstream is up, its SIGTERM handler in place, once its pid file exists.
    const up = new Promise<void>((resolveUp, failUp) => {
      const t0 = Date.now();
      const poll = setInterval(() => {
        if (existsSync(pidFile) && readFileSync(pidFile, "utf8") !== "") {
          clearInterval(poll);
          resolveUp();
        } else if (Date.now() - t0 > CLI_SPAWN_TIMEOUT_MS) {
          clearInterval(poll);
          failUp(new Error("spawn timeout: the stubborn downstream never wrote its pid"));
        }
      }, 50);
    });
    try {
      const r = await runProxyCli(
        [
          "--dir", tmp, "--chain", join(tmp, "stubborn.jsonl"), "--session-id", "sess-stubborn", "--policy", policyPath,
          "--server-label", "fake", "--", "node", STUBBORN, pidFile,
        ],
        probeDir,
        [],
        { after: up },
      );
      const probe = cliProbe(probeDir);
      expect(probe).toMatchObject({ fetches: 0, exitAfterFetch: 0, code: 0 });
      expect(probe.active.filter((a) => a !== "PipeWrap" && a !== "TTYWrap")).toEqual([]);
      expect(r.status).toBe(0);
      expect(r.stderr).toContain("[chirindo] proxy exiting (0 receipts written)");
      // The downstream stays up for 20 s; the proxy did not wait for it.
      expect(r.msAfterEnd).not.toBeNull();
      expect(r.msAfterEnd!).toBeLessThan(8_000);
    } finally {
      // End the downstream the proxy let go.
      try {
        process.kill(Number(readFileSync(pidFile, "utf8")), "SIGKILL");
      } catch {
        /* already gone */
      }
    }
  }, CLI_E2E_TIMEOUT_MS);
});
