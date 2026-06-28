import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough, type Readable, type Writable } from "node:stream";
import { runInit, loadFullIdentity } from "../src/vendor/recorder/index.js";
import type { DownstreamProcess } from "../src/proxy.js";
import type { Policy } from "../src/policy.js";

export function makeTmpDir(prefix = "mcp-gate-test-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function cleanupTmpDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

// Pair of in-memory streams the proxy can speak through; tests write to
// clientIn (sim'd "from client") and read from clientOut (sim'd "to client").
export function makeClientPipes(): {
  clientIn: PassThrough;
  clientOut: PassThrough;
} {
  return {
    clientIn: new PassThrough(),
    clientOut: new PassThrough(),
  };
}

// Build a downstream that uses two in-memory streams + an exit promise we
// can resolve manually. Tests that want to drive a fake downstream can use
// this; tests that need real spawn() can pass spawnRealDownstream.
export function makeFakeDownstream(): {
  downstream: DownstreamProcess;
  toClient: PassThrough; // what we (the "downstream") write back to proxy
  fromClient: PassThrough; // what proxy writes to us
  exit: (code: number | null) => void;
} {
  const toClient = new PassThrough();
  const fromClient = new PassThrough();
  let resolveExit: (code: number | null) => void;
  const exited = new Promise<number | null>((r) => {
    resolveExit = r;
  });
  return {
    downstream: {
      stdin: fromClient,
      stdout: toClient,
      stderr: null,
      kill: () => resolveExit(0),
      exited,
    },
    toClient,
    fromClient,
    exit: (code) => resolveExit(code),
  };
}

// Collect newline-delimited JSON from a Readable into an array, until
// `until` returns true on the most recently collected message. Resolves
// when that happens or after `timeoutMs` (rejects on timeout).
export function collectJsonLines(
  src: Readable,
  until: (latest: unknown, all: unknown[]) => boolean,
  timeoutMs = 2000,
): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const messages: unknown[] = [];
    let buf = "";
    const t = setTimeout(() => {
      cleanup();
      reject(
        new Error(
          `timeout waiting for matching JSON line (got ${messages.length} so far)`,
        ),
      );
    }, timeoutMs);
    const onData = (chunk: Buffer | string) => {
      buf += chunk.toString("utf8");
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        try {
          const parsed = JSON.parse(line);
          messages.push(parsed);
          if (until(parsed, messages)) {
            cleanup();
            resolve(messages);
            return;
          }
        } catch {
          /* ignore */
        }
      }
    };
    const cleanup = () => {
      clearTimeout(t);
      src.off("data", onData);
    };
    src.on("data", onData);
  });
}

export function writeLine(out: Writable, obj: unknown): void {
  out.write(JSON.stringify(obj) + "\n");
}

export function writePolicy(dir: string, policy: Policy): string {
  const p = join(dir, "policy.json");
  writeFileSync(p, JSON.stringify(policy, null, 2), "utf8");
  return p;
}

export async function initIdentity(dir: string) {
  const r = runInit({ dir });
  if (r.kind !== "created") throw new Error("init returned " + r.kind);
  return loadFullIdentity(r.identityPath, r.privateKeyPath);
}

// Absolute path to scripts/fake-mcp-server.ts (used by integration tests
// that spawn the real downstream).
export function fakeServerPath(): string {
  return resolve(dirname(new URL(import.meta.url).pathname), "..", "scripts", "fake-mcp-server.ts");
}
