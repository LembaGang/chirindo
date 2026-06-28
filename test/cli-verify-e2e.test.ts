// End-to-end smoke for `chirindo verify`: spawn the CLI as an external
// process, point it at a real chain produced by the proxy, confirm the
// VALID / TAMPERED / usage-error vocabulary lines up. The chain is built
// in-process via runProxy + a fake downstream — same fixture the ALLOW
// test uses. We do not exercise the live JWKS network path here; the
// engine is the recorder's, already covered by the recorder suite.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, serializeChainJsonl } from "../src/vendor/recorder/index.js";
import { loadPolicy } from "../src/policy.js";
import { runProxy } from "../src/proxy.js";
import {
  cleanupTmpDir,
  collectJsonLines,
  initIdentity,
  makeClientPipes,
  makeFakeDownstream,
  makeTmpDir,
  writeLine,
  writePolicy,
} from "./helpers.js";

const CLI_ENTRY = resolve(import.meta.dirname, "..", "src", "cli.ts");
const IS_WIN = process.platform === "win32";

function runCli(args: string[]): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  // tsx via npx — same pattern the recorder uses for its CLI e2e tests.
  // shell:true on Windows is required for the .cmd shim.
  const r = spawnSync(
    IS_WIN ? "npx.cmd" : "npx",
    ["tsx", CLI_ENTRY, ...args],
    { encoding: "utf8", shell: IS_WIN },
  );
  return {
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    status: r.status,
  };
}

// Drive one ALLOW round-trip through the proxy to produce a real signed
// chain on disk. Returns the chain path + the identity path the CLI needs
// for `--key`. Mirrors proxy-allow.test.ts's fixture setup; condensed.
async function buildAllowChain(tmp: string): Promise<{
  chainPath: string;
  identityPath: string;
}> {
  const identity = await initIdentity(tmp);
  const policyPath = writePolicy(tmp, { deny: [] });
  const chainPath = join(tmp, "chain.jsonl");

  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();

  const handle = runProxy({
    clientIn,
    clientOut,
    spawnDownstream: () => downstream.downstream,
    loadPolicy: () => {
      try {
        return loadPolicy(policyPath);
      } catch {
        return null;
      }
    },
    identity,
    sessionId: "sess-verify-e2e",
    serverLabel: "fake",
    chainPath,
    log: () => {},
  });

  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    const lines = chunk.toString("utf8").split("\n").filter((l) => l.trim());
    for (const line of lines) {
      const req = JSON.parse(line) as { id: number; method: string };
      if (req.method === "tools/call") {
        downstream.toClient.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: req.id,
            result: { content: [{ type: "text", text: "ok" }], isError: false },
          }) + "\n",
        );
      }
    }
  });

  const collector = collectJsonLines(
    clientOut,
    (latest) =>
      typeof latest === "object" &&
      latest !== null &&
      (latest as { id?: unknown }).id === 1,
  );
  writeLine(clientIn, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "echo", arguments: { text: "hi" } },
  });
  await collector;

  downstream.exit(0);
  await handle.done;

  return { chainPath, identityPath: join(tmp, "identity.json") };
}

describe("chirindo verify (CLI end-to-end)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("verifies a fresh proxy-produced chain as VALID via --key", async () => {
    const { chainPath, identityPath } = await buildAllowChain(tmp);
    const r = runCli(["verify", chainPath, "--key", identityPath]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^VALID — \d+ entries, chain intact/);
    expect(r.stdout).toContain("session sess-verify-e2e");
  });

  it("reports TAMPERED + exit 1 when the chain has been mutated", async () => {
    const { chainPath, identityPath } = await buildAllowChain(tmp);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    // Flip the args_hash on the recorded mcp_call event. The receipt's
    // signed bytes no longer cover this value -> signature fails first.
    const rec = file.records[0]!;
    if (rec.event.type !== "mcp_call") throw new Error("expected mcp_call");
    rec.event.args_hash =
      "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    writeFileSync(chainPath, serializeChainJsonl(file), "utf8");

    const r = runCli(["verify", chainPath, "--key", identityPath]);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/^TAMPERED — entry 0:/);
  });

  it("rejects --key and --jwks together as a usage error (exit 2)", () => {
    const r = runCli([
      "verify",
      "/dev/null",
      "--key",
      "/some/identity.json",
      "--jwks",
      "https://example.invalid/jwks.json",
    ]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("alternative key sources");
  });
});
