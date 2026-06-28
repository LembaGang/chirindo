// Integration: spawn the fake MCP server as a real child process via the
// production `spawnRealDownstream` path. This proves the proxy works
// end-to-end with newline-framed stdio across a real OS pipe — not just
// in-memory PassThroughs.

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import { loadPolicy } from "../src/policy.js";
import { runProxy, spawnRealDownstream } from "../src/proxy.js";
import {
  cleanupTmpDir,
  collectJsonLines,
  initIdentity,
  makeClientPipes,
  makeTmpDir,
  writeLine,
  writePolicy,
} from "./helpers.js";

const FAKE_SERVER = resolve(
  new URL("../scripts/fake-mcp-server.ts", import.meta.url).pathname.replace(
    /^\/([A-Za-z]:)/,
    "$1",
  ),
);
const IS_WIN = process.platform === "win32";

describe("proxy <-> real spawned fake server", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("ALLOW path: echo round-trip through spawned tsx subprocess", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [{ tool: "delete" }] });
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();

    const handle = runProxy({
      clientIn,
      clientOut,
      spawnDownstream: () =>
        spawnRealDownstream(
          IS_WIN ? "npx.cmd" : "npx",
          ["tsx", FAKE_SERVER],
          { shell: IS_WIN },
        ),
      loadPolicy: () => {
        try {
          return loadPolicy(policyPath);
        } catch {
          return null;
        }
      },
      identity,
      sessionId: "sess-spawn-allow",
      serverLabel: "fake-spawn",
      chainPath,
      log: () => {
        /* quiet */
      },
    });

    const collector = collectJsonLines(
      clientOut,
      (latest) =>
        typeof latest === "object" &&
        latest !== null &&
        (latest as { id?: unknown }).id === 11,
      10_000,
    );

    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: { name: "echo", arguments: { text: "spawned" } },
    });

    const received = (await collector) as Array<{
      id: number;
      result?: { content: Array<{ text: string }>; isError: boolean };
    }>;
    const resp = received.find((r) => r.id === 11)!;
    expect(resp.result?.isError).toBe(false);
    expect(resp.result?.content[0]?.text).toBe("echo: spawned");

    expect(handle.receiptCount()).toBe(1);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    expect(file.records).toHaveLength(1);
    expect(
      runVerify({ chainPath, identityPath: join(tmp, "identity.json") }).kind,
    ).toBe("valid");

    clientIn.end();
    await handle.done;
  }, 30_000);

  it("DENY path: delete tool is blocked before the fake server runs it", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, {
      deny: [{ tool: "delete", reason: "destructive" }],
    });
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();

    // Capture stderr from the fake server to confirm its DESTRUCTIVE-branch
    // log message NEVER appears.
    let fakeStderr = "";
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      const s = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      fakeStderr += s;
      return true;
    }) as typeof process.stderr.write;

    try {
      const handle = runProxy({
        clientIn,
        clientOut,
        spawnDownstream: () =>
          spawnRealDownstream(
          IS_WIN ? "npx.cmd" : "npx",
          ["tsx", FAKE_SERVER],
          { shell: IS_WIN },
        ),
        loadPolicy: () => {
          try {
            return loadPolicy(policyPath);
          } catch {
            return null;
          }
        },
        identity,
        sessionId: "sess-spawn-deny",
        serverLabel: "fake-spawn",
        chainPath,
        log: () => {
          /* quiet */
        },
      });

      const collector = collectJsonLines(
        clientOut,
        (latest) =>
          typeof latest === "object" &&
          latest !== null &&
          (latest as { id?: unknown }).id === 22,
        10_000,
      );

      writeLine(clientIn, {
        jsonrpc: "2.0",
        id: 22,
        method: "tools/call",
        params: { name: "delete", arguments: { path: "/etc" } },
      });

      const received = (await collector) as Array<{
        id: number;
        result?: { content: Array<{ text: string }>; isError: boolean };
      }>;
      const resp = received.find((r) => r.id === 22)!;
      expect(resp.result?.isError).toBe(true);

      // The headline: the fake server's destructive-branch log line MUST
      // NOT appear in its stderr — proving the gate intercepted before the
      // downstream ran the action.
      expect(fakeStderr).not.toContain("DESTRUCTIVE delete tool ran");

      clientIn.end();
      await handle.done;
    } finally {
      process.stderr.write = origStderrWrite;
    }
  }, 30_000);
});
