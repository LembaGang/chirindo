// Witness client (WITNESS_SPEC v0.5): checkpoint sidecar, witness receipt
// acceptance, proxy checkpointing, and the verify --witness layer. Every test
// talks to the in-process STUB witness (test/witness-stub.ts), which signs with
// a throwaway key and says "witness":"stub.invalid" — so every acceptance path
// passes the stub's name explicitly, exactly as the CLI needs --witness-name.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ed25519PrivateKeyFromSeed,
  parseChainJsonl,
  readChainFile,
  serializeChainJsonl,
  type LoadedFullIdentity,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { runProxy } from "../src/proxy.js";
import { loadPolicy } from "../src/policy.js";
import { appendSidecarLine, buildCheckpoint } from "../src/checkpoint.js";
import {
  readSidecar,
  sidecarPathFor,
  verifyAgainstWitness,
  verifyWitnessSignature,
  witnessCheckpoint,
  witnessPubFromRaw,
  type WitnessPub,
  type WitnessTarget,
} from "../src/witness.js";
import {
  STUB_PRICING_URL,
  STUB_WITNESS_NAME,
  STUB_WITNESS_SEED,
  signWitnessReceipt,
  startStubWitness,
  type StubWitness,
} from "./witness-stub.js";
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

const ROOT = resolve(import.meta.dirname, "..");
const CLI_ENTRY = join(ROOT, "src", "cli.ts");
const TSX_CLI = join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
const FAKE_SERVER = join(ROOT, "scripts", "fake-mcp-server.ts");

// Async on purpose: the stub witness lives in THIS process, so a spawnSync
// would block the event loop the stub needs to answer the child.
// The child never inherits CHIRINDO_WITNESS_ACCOUNT_KEY from the test runner;
// `env` sets it (or anything else) explicitly.
const ACCOUNT_KEY_ENV = "CHIRINDO_WITNESS_ACCOUNT_KEY";
function runCli(
  args: string[],
  stdinLines: string[] = [],
  env: Record<string, string> = {},
): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((done) => {
    const childEnv: NodeJS.ProcessEnv = { ...process.env };
    delete childEnv[ACCOUNT_KEY_ENV];
    const child = spawn(process.execPath, [TSX_CLI, CLI_ENTRY, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...childEnv, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    for (const l of stdinLines) child.stdin.write(l + "\n");
    if (stdinLines.length === 0) child.stdin.end();
    child.on("exit", (status) => done({ stdout, stderr, status }));
  });
}

function pinOf(stub: StubWitness, id = stub.keyId): WitnessPub {
  const raw = Buffer.from(stub.publicKeyHex, "hex");
  return { pubObj: witnessPubFromRaw(raw), hex: stub.publicKeyHex, id };
}

function targetOf(stub: StubWitness, name = STUB_WITNESS_NAME): WitnessTarget {
  return { baseUrl: stub.url, name, pinned: pinOf(stub) };
}

// n receipts written by the real receipt writer; `argsAt` overrides the
// arguments of one index (the key holder's rewrite).
function writeChain(
  chainPath: string,
  identity: LoadedFullIdentity,
  sessionId: string,
  n: number,
  argsAt?: { index: number; args: unknown },
): void {
  for (let i = 0; i < n; i++) {
    appendReceipt({
      chainPath,
      sessionId,
      identity,
      server: "fake",
      toolName: "echo",
      toolArgs: argsAt?.index === i ? argsAt.args : { text: `call-${i}` },
      toolResult: { content: [{ type: "text", text: `echo: call-${i}` }], isError: false },
      decision: { kind: "allow" },
      ts: `2026-10-03T00:00:0${i}.000Z`,
    });
  }
}

// Checkpoint the first `count` records of `chainPath` and witness it into the
// sidecar of `sidecarChainPath` (defaults to the same chain).
async function witnessHead(
  chainPath: string,
  identity: LoadedFullIdentity,
  stub: StubWitness,
  count: number,
): Promise<void> {
  const records = readChainFile(chainPath).records.slice(0, count);
  const cp = buildCheckpoint(records, identity);
  const out = await witnessCheckpoint(cp, identity.publicKey, targetOf(stub));
  expect(out.error).toBeNull();
  appendSidecarLine(sidecarPathFor(chainPath), {
    checkpoint: cp,
    witness_receipt: out.receipt,
    witness_error: out.error,
  });
}

const VALID_TEXT = "VALID — (test)";

function verifyInput(chainPath: string, stub: StubWitness, mode: "url" | "file") {
  return {
    chainPath,
    validText: VALID_TEXT,
    validExit: 0,
    witnessName: STUB_WITNESS_NAME,
    pinned: pinOf(stub),
    ...(mode === "url" ? { baseUrl: stub.url } : { sidecarPath: sidecarPathFor(chainPath) }),
  };
}

function proxyFixture(tmp: string, identity: LoadedFullIdentity, extra: Record<string, unknown>) {
  const policyPath = writePolicy(tmp, { deny: [{ tool: "delete" }] });
  const chainPath = join(tmp, "chain.jsonl");
  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();
  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    for (const line of chunk.toString("utf8").split("\n").filter((l) => l.trim())) {
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
  const handle = runProxy({
    clientIn,
    clientOut,
    spawnDownstream: () => downstream.downstream,
    loadPolicy: () => loadPolicy(policyPath),
    identity,
    sessionId: "sess-witness-proxy",
    serverLabel: "fake",
    chainPath,
    log: () => {},
    ...extra,
  });
  const call = async (id: number) => {
    const got = collectJsonLines(clientOut, (m) => (m as { id?: unknown }).id === id, 5000);
    writeLine(clientIn, {
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "echo", arguments: { text: `t${id}` } },
    });
    const msgs = await got;
    return msgs[msgs.length - 1] as { result?: { isError?: boolean; content?: { text: string }[] } };
  };
  return { handle, call, chainPath, downstream };
}

describe("witness client", () => {
  let tmp: string;
  let identity: LoadedFullIdentity;
  const stubs: StubWitness[] = [];
  const stubOf = async (o: Parameters<typeof startStubWitness>[0] = {}) => {
    const s = await startStubWitness(o);
    stubs.push(s);
    return s;
  };
  beforeEach(async () => {
    tmp = makeTmpDir();
    identity = await initIdentity(tmp);
  });
  afterEach(async () => {
    await Promise.all(stubs.splice(0).map((s) => s.close()));
    cleanupTmpDir(tmp);
  });

  // ---- chirindo checkpoint ------------------------------------------------

  it("checkpoint writes <chain>.witness.ndjson with a verified receipt, never touches the chain, and is idempotent", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-cp", 3);
    const chainBefore = readFileSync(chainPath, "utf8");
    const args = [
      "checkpoint", chainPath, "--dir", tmp,
      "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ];
    const r = await runCli(args);
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    const sidecar = join(tmp, "s.jsonl.witness.ndjson");
    expect(sidecarPathFor(chainPath)).toBe(sidecar);
    const lines = readSidecar(sidecar);
    expect(lines).toHaveLength(1);
    expect(lines[0]!.witness_error).toBeNull();
    expect(lines[0]!.witness_receipt!["count"]).toBe("3");
    expect(verifyWitnessSignature(lines[0]!.witness_receipt!, pinOf(stub).pubObj)).toBe(true);
    expect(readFileSync(chainPath, "utf8")).toBe(chainBefore);

    const again = await runCli(args);
    expect(again.status).toBe(0);
    expect(again.stdout).toContain("head already checkpointed at count 3");
    expect(readSidecar(sidecar)).toHaveLength(1);
    expect(stub.posts).toBe(1);
  }, 60_000);

  it("checkpoint: a bad witness signature is recorded as witness_error, never as a receipt (exit 1)", async () => {
    const stub = await stubOf({ corruptSignature: true });
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-badsig", 2);
    const r = await runCli([
      "checkpoint", chainPath, "--dir", tmp,
      "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    expect(r.status).toBe(1);
    const lines = readSidecar(sidecarPathFor(chainPath));
    expect(lines).toHaveLength(1);
    expect(lines[0]!.witness_receipt).toBeNull();
    expect(lines[0]!.witness_error).toBe("bad_witness_signature");
  }, 60_000);

  it("checkpoint refuses a chain that does not verify VALID and writes nothing", async () => {
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-refuse", 2);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    file.records[1]!.ts = "2027-01-01T00:00:00.000Z"; // breaks the signature
    writeFileSync(chainPath, serializeChainJsonl(file), "utf8");
    const r = await runCli(["checkpoint", chainPath, "--dir", tmp]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("refused, nothing written");
    expect(existsSync(sidecarPathFor(chainPath))).toBe(false);
  }, 60_000);

  it("accepts a 200 idempotent reply whose checkpoint_ts differs from the request", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-idem", 2);
    const records = readChainFile(chainPath).records;
    const first = buildCheckpoint(records, identity, "2026-10-03T01:00:00.000Z");
    const second = buildCheckpoint(records, identity, "2026-10-03T02:00:00.000Z");
    const a = await witnessCheckpoint(first, identity.publicKey, targetOf(stub));
    const b = await witnessCheckpoint(second, identity.publicKey, targetOf(stub));
    expect(a.error).toBeNull();
    expect(b.error).toBeNull();
    expect(b.receipt!["checkpoint_ts"]).toBe("2026-10-03T01:00:00.000Z");
    expect(b.receipt).toEqual(a.receipt);
    expect(stub.rows).toHaveLength(1);
  });

  it("rejects a receipt whose witness differs from the expected name", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-name", 1);
    const cp = buildCheckpoint(readChainFile(chainPath).records, identity);
    const out = await witnessCheckpoint(cp, identity.publicKey, targetOf(stub, "headlessoracle.com"));
    expect(out).toEqual({ receipt: null, error: "witness_receipt_mismatch" });
  });

  // ---- proxy ------------------------------------------------------------

  it("proxy never denies on witness failure (witness unreachable)", async () => {
    const dead = await startStubWitness();
    const deadUrl = dead.url;
    await dead.close();
    const p = proxyFixture(tmp, identity, {
      checkpointEvery: 1,
      witness: { baseUrl: deadUrl, name: STUB_WITNESS_NAME, pinned: pinOf(dead) },
    });
    for (const id of [1, 2, 3]) {
      const resp = await p.call(id);
      expect(resp.result?.isError).toBe(false);
      expect(resp.result?.content?.[0]?.text).toBe("ok");
    }
    p.downstream.exit(0);
    await p.handle.done;
    await p.handle.finalCheckpoint(5000);
    // Shutdown retries a head whose witness POST failed, so a 4th line for
    // count 3 may follow; every line is an error, never a receipt.
    const lines = readSidecar(sidecarPathFor(p.chainPath));
    expect(lines.slice(0, 3).map((l) => l.checkpoint.count)).toEqual([1, 2, 3]);
    expect(lines.every((l) => l.witness_error === "witness_unreachable" && l.witness_receipt === null)).toBe(true);
    expect(readChainFile(p.chainPath).records).toHaveLength(3);
  });

  it("a hanging witness does not delay a tool-call response", async () => {
    const stub = await stubOf({ hangPosts: true });
    const p = proxyFixture(tmp, identity, { checkpointEvery: 1, witness: targetOf(stub) });
    await p.call(1);
    // Let the first checkpoint's POST reach the stub, where it hangs.
    for (let i = 0; i < 100 && stub.posts === 0; i++) await new Promise((r) => setTimeout(r, 20));
    expect(stub.posts).toBe(1);
    const t0 = Date.now();
    const resp = await p.call(2); // the witness POST is still hanging (10 s timeout)
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(resp.result?.isError).toBe(false);
    p.downstream.exit(0);
    await p.handle.done;
    const s0 = Date.now();
    await p.handle.finalCheckpoint(300);
    expect(Date.now() - s0).toBeLessThan(2000);
    const lines = readSidecar(sidecarPathFor(p.chainPath));
    expect(lines.map((l) => l.witness_error)).toEqual(["witness_timeout", "witness_timeout"]);
  });

  it("writes no shutdown checkpoint when no receipt was written", async () => {
    const stub = await stubOf();
    const p = proxyFixture(tmp, identity, { checkpointEvery: 2, witness: targetOf(stub) });
    p.downstream.exit(0);
    await p.handle.done;
    await p.handle.finalCheckpoint(1000);
    expect(existsSync(sidecarPathFor(p.chainPath))).toBe(false);
    expect(stub.posts).toBe(0);
  });

  it("the CLI proxy awaits the shutdown checkpoint's witness POST before exiting", async () => {
    const stub = await stubOf({ delayMs: 1500 });
    const policyPath = writePolicy(tmp, { deny: [] });
    const chainPath = join(tmp, "proxy.jsonl");
    const r = await new Promise<{ status: number | null; lines: string[] }>((done) => {
      const child = spawn(
        process.execPath,
        [
          TSX_CLI, CLI_ENTRY, "proxy", "--dir", tmp, "--chain", chainPath,
          "--session-id", "sess-shutdown", "--policy", policyPath, "--server-label", "fake",
          "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
          "--", "node", TSX_CLI, FAKE_SERVER,
        ],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      const lines: string[] = [];
      let buf = "";
      child.stdout.on("data", (c: Buffer) => {
        buf += c.toString("utf8");
        const parts = buf.split("\n");
        buf = parts.pop() ?? "";
        for (const l of parts) {
          lines.push(l);
          if (l.includes('"id":7')) child.stdin.end(); // response arrived: shut down cleanly
        }
      });
      child.stderr.resume();
      child.on("exit", (status) => done({ status, lines }));
      child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } }) + "\n",
      );
    });
    expect(r.status).toBe(0);
    expect(r.lines.some((l) => l.includes("echo: x"))).toBe(true);
    const lines = readSidecar(sidecarPathFor(chainPath));
    expect(lines).toHaveLength(1);
    expect(lines[0]!.witness_error).toBeNull();
    expect(lines[0]!.witness_receipt!["count"]).toBe("1");
  }, 60_000);

  // ---- verify --witness / --witness-file --------------------------------

  it("passes when every witnessed checkpoint matches the chain", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-pass", 5);
    await witnessHead(chainPath, identity, stub, 2);
    await witnessHead(chainPath, identity, stub, 4);
    for (const mode of ["url", "file"] as const) {
      const r = await verifyAgainstWitness(verifyInput(chainPath, stub, mode));
      expect(r.code).toBe(0);
      const lines = r.text.split("\n");
      expect(lines[0]).toBe(VALID_TEXT);
      expect(lines[1]).toBe(
        `WITNESSED through count 4, received_at 2026-10-03T00:00:01.000Z, witness key ${stub.publicKeyHex}`,
      );
      expect(lines[2]).toBe(
        "1 records after the last witnessed checkpoint are not witness-protected" +
          (mode === "file" ? " (sidecar supplied by the operator)" : ""),
      );
    }
  });

  it("detects truncation: a witnessed count beyond the chain", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-trunc", 4);
    await witnessHead(chainPath, identity, stub, 2);
    await witnessHead(chainPath, identity, stub, 4);
    const file = readChainFile(chainPath);
    writeFileSync(chainPath, serializeChainJsonl({ records: file.records.slice(0, 3), checkpoint: null }), "utf8");
    const r = await verifyAgainstWitness(verifyInput(chainPath, stub, "url"));
    expect(r).toEqual({ text: "TAMPERED — witnessed count 4 is beyond the chain (3 records)", code: 1 });
  });

  it("detects divergence: the key holder rewrites and re-signs (resigned case)", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-resign", 4);
    await witnessHead(chainPath, identity, stub, 2);
    await witnessHead(chainPath, identity, stub, 4);
    const resigned = join(tmp, "resigned.jsonl");
    writeChain(resigned, identity, "sess-resign", 4, { index: 2, args: { text: "rewritten" } });
    const r = await verifyAgainstWitness({ ...verifyInput(chainPath, stub, "url"), chainPath: resigned });
    expect(r).toEqual({ text: "TAMPERED — witnessed count 4: last_entry_hash mismatch", code: 1 });
  });

  it("detects a fork: two chains under one key and session_id", async () => {
    const stub = await stubOf();
    const a = join(tmp, "a.jsonl");
    const b = join(tmp, "b.jsonl");
    writeChain(a, identity, "sess-fork", 2);
    writeChain(b, identity, "sess-fork", 2, { index: 1, args: { text: "other" } });
    await witnessHead(a, identity, stub, 2);
    await witnessHead(b, identity, stub, 2);
    expect(stub.rows.map((x) => x["fork"])).toEqual(["false", "true"]);
    const r = await verifyAgainstWitness(verifyInput(a, stub, "url"));
    expect(r).toEqual({ text: "TAMPERED — witnessed count 2: fork", code: 1 });
  });

  it("reports NO WITNESS (exit 1) for an empty sidecar and for a witness with no receipts", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-none", 2);
    writeFileSync(sidecarPathFor(chainPath), "", "utf8");
    const expected = `NO WITNESS: chain VALID, no witness receipts for kid ${identity.kid} session sess-none`;
    expect(await verifyAgainstWitness(verifyInput(chainPath, stub, "file"))).toEqual({ text: expected, code: 1 });
    expect(await verifyAgainstWitness(verifyInput(chainPath, stub, "url"))).toEqual({ text: expected, code: 1 });
  });

  it("follows next_after across GET pages", async () => {
    const stub = await stubOf({ pageSize: 2 });
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-pages", 3);
    for (const c of [1, 2, 3]) await witnessHead(chainPath, identity, stub, c);
    const r = await verifyAgainstWitness(verifyInput(chainPath, stub, "url"));
    expect(r.code).toBe(0);
    expect(r.text).toContain("WITNESSED through count 3,");
    expect(stub.gets).toBe(2);
  });

  it("an unpinned (fetched) witness key is named and exits 1 even when every check passes", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-unpinned", 2);
    await witnessHead(chainPath, identity, stub, 2);
    const { pinned: _p, ...input } = verifyInput(chainPath, stub, "url");
    const r = await verifyAgainstWitness(input);
    expect(r.code).toBe(1);
    expect(r.text).toContain("WITNESSED through count 2,");
    expect(r.text.split("\n").pop()).toBe(
      `witness key ${stub.publicKeyHex} fetched from ${stub.url}/v5/keys, NOT pinned`,
    );
  });

  it("a receipt under a different public_key_id is UNVERIFIABLE (exit 1)", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-keyid", 2);
    await witnessHead(chainPath, identity, stub, 2);
    const r = await verifyAgainstWitness({ ...verifyInput(chainPath, stub, "url"), pinned: pinOf(stub, "key_2027_v2") });
    expect(r).toEqual({ text: "UNVERIFIABLE — witness key mismatch at count 2", code: 1 });
  });

  it("a validly signed receipt with the wrong type, or from another witness name, is TAMPERED", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-type", 2);
    await witnessHead(chainPath, identity, stub, 2);
    const line = readSidecar(sidecarPathFor(chainPath))[0]!;
    const witnessSigner = ed25519PrivateKeyFromSeed(STUB_WITNESS_SEED);
    const wrongType = signWitnessReceipt({ ...line.witness_receipt!, type: "market.state/1" }, witnessSigner);
    expect(verifyWitnessSignature(wrongType, pinOf(stub).pubObj)).toBe(true);
    writeFileSync(sidecarPathFor(chainPath), JSON.stringify({ ...line, witness_receipt: wrongType }) + "\n", "utf8");
    expect(await verifyAgainstWitness(verifyInput(chainPath, stub, "file"))).toEqual({
      text: "TAMPERED — witness receipt at count 2 invalid",
      code: 1,
    });
    // Original receipt, but the verifier expects the real service's name.
    writeFileSync(sidecarPathFor(chainPath), JSON.stringify(line) + "\n", "utf8");
    expect(
      await verifyAgainstWitness({ ...verifyInput(chainPath, stub, "file"), witnessName: "headlessoracle.com" }),
    ).toEqual({ text: "TAMPERED — witness receipt at count 2 invalid", code: 1 });
  });

  // ---- CLI surface of verify --------------------------------------------

  it("CLI verify: usage errors exit 2; --witness-file pass exits 0; --witness without --witness-key exits 1", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-cli", 3);
    await witnessHead(chainPath, identity, stub, 2);
    const idPath = join(tmp, "identity.json");
    const sidecar = sidecarPathFor(chainPath);

    const both = await runCli(["verify", chainPath, "--key", idPath, "--witness", stub.url, "--witness-file", sidecar, "--witness-key", stub.publicKeyHex]);
    expect(both.status).toBe(2);
    const noPin = await runCli(["verify", chainPath, "--key", idPath, "--witness-file", sidecar]);
    expect(noPin.status).toBe(2);

    const pass = await runCli([
      "verify", chainPath, "--key", idPath, "--witness-file", sidecar,
      "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    expect(pass.status).toBe(0);
    const out = pass.stdout.trimEnd().split("\n");
    expect(out[0]).toMatch(/^VALID — 3 entries, chain intact/);
    expect(out[2]).toMatch(/^WITNESSED through count 2, received_at /);
    expect(out[3]).toBe(
      "1 records after the last witnessed checkpoint are not witness-protected (sidecar supplied by the operator)",
    );

    const unpinned = await runCli(["verify", chainPath, "--key", idPath, "--witness", stub.url, "--witness-name", STUB_WITNESS_NAME]);
    expect(unpinned.status).toBe(1);
    expect(unpinned.stdout).toContain("NOT pinned");

    writeFileSync(sidecar, "", "utf8");
    const none = await runCli([
      "verify", chainPath, "--key", idPath, "--witness-file", sidecar,
      "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    expect(none.status).toBe(1);
    expect(none.stdout).toMatch(/^NO WITNESS: chain VALID, no witness receipts for kid /);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// WITNESS_SPEC v0.5: the optional Evidence plan account key
// ---------------------------------------------------------------------------

function newAccountKey(): string {
  return "ho_live_" + randomBytes(32).toString("hex");
}

// The key, its 64-hex body, and a 16-char window of it must appear nowhere.
function expectNoKey(text: string, key: string): void {
  expect(text).not.toContain(key);
  expect(text).not.toContain(key.slice(8));
  expect(text).not.toContain(key.slice(30, 46));
}

const HINT_MARK = "Plans: ";

describe("witness accounts (v0.5)", () => {
  let tmp: string;
  let identity: LoadedFullIdentity;
  const stubs: StubWitness[] = [];
  const stubOf = async (o: Parameters<typeof startStubWitness>[0] = {}) => {
    const s = await startStubWitness(o);
    stubs.push(s);
    return s;
  };
  beforeEach(async () => {
    tmp = makeTmpDir();
    identity = await initIdentity(tmp);
  });
  afterEach(async () => {
    await Promise.all(stubs.splice(0).map((s) => s.close()));
    cleanupTmpDir(tmp);
  });

  const writeKeyFile = (name: string, content: string): string => {
    const p = join(tmp, name);
    writeFileSync(p, content, "utf8");
    return p;
  };
  const checkpointArgs = (chainPath: string, stub: StubWitness): string[] => [
    "checkpoint", chainPath, "--dir", tmp,
    "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
  ];

  it("sends Authorization: Bearer <key> on the checkpoint POST iff a key is configured, and never on a GET", async () => {
    const key = newAccountKey();
    const stub = await stubOf({ accounts: { [key]: { status: "active", plan: "evidence_starter" } } });
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-hdr", 2);
    const records = readChainFile(chainPath).records;

    const anon = await witnessCheckpoint(buildCheckpoint(records.slice(0, 1), identity), identity.publicKey, targetOf(stub));
    expect(anon.error).toBeNull();
    // Unpinned, so the client also fetches /v5/keys: that GET must not carry the key.
    const { pinned: _p, ...unpinned } = targetOf(stub);
    const acct = await witnessCheckpoint(buildCheckpoint(records, identity), identity.publicKey, {
      ...unpinned,
      accountKey: key,
    });
    expect(acct.error).toBeNull();
    expect(stub.postAuth).toEqual([null, `Bearer ${key}`]);
    expect(stub.rowPools[0]).toBe("anon");
    expect(stub.rowPools[1]).toMatch(/^acct:[0-9a-f]{32}$/);
    // Receipts are identical in shape for both pools; nothing names the pool.
    expect(Object.keys(acct.receipt!).sort()).toEqual(Object.keys(anon.receipt!).sort());

    appendSidecarLine(sidecarPathFor(chainPath), { checkpoint: buildCheckpoint(records, identity), witness_receipt: acct.receipt, witness_error: null });
    const v = await verifyAgainstWitness(verifyInput(chainPath, stub, "url"));
    expect(v.code).toBe(0);
    expect(stub.keysAuth.length).toBeGreaterThan(0);
    expect(stub.keysAuth.every((h) => h === null)).toBe(true);
    expect(stub.getAuth.length).toBeGreaterThan(0);
    expect(stub.getAuth.every((h) => h === null)).toBe(true);
  });

  it("CLI checkpoint --witness-account-key-file: witnessed in the account pool; the key is in no sidecar line, stdout or stderr", async () => {
    const key = newAccountKey();
    const stub = await stubOf({ accounts: { [key]: { status: "active", plan: "evidence" } } });
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-acct-cli", 3);
    const keyFile = writeKeyFile("acct.key", key + "\n");
    const r = await runCli([...checkpointArgs(chainPath, stub), "--witness-account-key-file", keyFile]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("checkpoint at count 3 witnessed");
    expect(stub.postAuth).toEqual([`Bearer ${key}`]);
    expect(stub.rowPools).toHaveLength(1);
    expect(stub.rowPools[0]).toMatch(/^acct:/);
    const sidecarText = readFileSync(sidecarPathFor(chainPath), "utf8");
    expect(readSidecar(sidecarPathFor(chainPath))[0]!.witness_receipt!["count"]).toBe("3");
    for (const t of [sidecarText, r.stdout, r.stderr]) expectNoKey(t, key);
  }, 60_000);

  it("CLI checkpoint: 401 invalid_key, 402 payment_required and 403 witness_plan_required are recorded as witness_error (exit 1), never a receipt, never the key", async () => {
    const unknown = newAccountKey();
    const inactive = newAccountKey();
    const pro = newAccountKey();
    const stub = await stubOf({
      accounts: {
        [inactive]: { status: "inactive", plan: "evidence_starter" },
        [pro]: { status: "active", plan: "pro" },
      },
    });
    const cases = [
      { key: unknown, status: 401, code: "invalid_key" },
      { key: inactive, status: 402, code: "payment_required" },
      { key: pro, status: 403, code: "witness_plan_required" },
    ];
    for (const [i, c] of cases.entries()) {
      const chainPath = join(tmp, `c${i}.jsonl`);
      writeChain(chainPath, identity, `sess-refused-${i}`, 2);
      // Alternate the two sources so both are covered.
      const r =
        i % 2 === 0
          ? await runCli([...checkpointArgs(chainPath, stub), "--witness-account-key-file", writeKeyFile(`k${i}`, c.key)])
          : await runCli(checkpointArgs(chainPath, stub), [], { [ACCOUNT_KEY_ENV]: c.key });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain(`witness failed for count 2: ${c.code}`);
      expect(r.stderr).not.toContain(HINT_MARK);
      const lines = readSidecar(sidecarPathFor(chainPath));
      expect(lines).toHaveLength(1);
      expect(lines[0]!.witness_receipt).toBeNull();
      expect(lines[0]!.witness_error).toBe(c.code);
      expect(stub.postReplies[i]!.status).toBe(c.status);
      expect((stub.postReplies[i]!.body as Record<string, unknown>)["docs"]).toBe(`${stub.url}/v1/witness/spec`);
      for (const t of [readFileSync(sidecarPathFor(chainPath), "utf8"), r.stdout, r.stderr]) expectNoKey(t, c.key);
    }
    expect(stub.rows).toHaveLength(0);
  }, 120_000);

  it("proxy: a refused account key (401/402/403) never denies, delays or alters a tool call; each failure is a witness_error line", async () => {
    const unknown = newAccountKey();
    const inactive = newAccountKey();
    const pro = newAccountKey();
    const stub = await stubOf({
      accounts: {
        [inactive]: { status: "inactive", plan: "evidence" },
        [pro]: { status: "active", plan: "builder" },
      },
    });
    for (const [key, code] of [
      [unknown, "invalid_key"],
      [inactive, "payment_required"],
      [pro, "witness_plan_required"],
    ] as const) {
      const dir = join(tmp, code);
      mkdirSync(dir);
      const logs: string[] = [];
      const p = proxyFixture(dir, identity, {
        checkpointEvery: 1,
        witness: { ...targetOf(stub), accountKey: key },
        log: (m: string) => logs.push(m),
      });
      for (const id of [1, 2]) {
        const resp = await p.call(id);
        expect(resp.result?.isError).toBe(false);
        expect(resp.result?.content?.[0]?.text).toBe("ok");
      }
      p.downstream.exit(0);
      await p.handle.done;
      await p.handle.finalCheckpoint(5000);
      const lines = readSidecar(sidecarPathFor(p.chainPath));
      expect(lines.slice(0, 2).map((l) => l.checkpoint.count)).toEqual([1, 2]);
      expect(lines.every((l) => l.witness_error === code && l.witness_receipt === null)).toBe(true);
      expect(readChainFile(p.chainPath).records).toHaveLength(2);
      expect(logs.some((l) => l.includes(`: ${code} (call permitted;`))).toBe(true);
      expect(logs.some((l) => l.includes(HINT_MARK))).toBe(false);
      expectNoKey(logs.join("\n"), key);
      expectNoKey(readFileSync(sidecarPathFor(p.chainPath), "utf8"), key);
    }
  });

  it("CLI proxy with $CHIRINDO_WITNESS_ACCOUNT_KEY: a 402 leaves the tool call untouched and the key unprinted", async () => {
    const key = newAccountKey();
    const stub = await stubOf({ accounts: { [key]: { status: "inactive", plan: "evidence" } } });
    const policyPath = writePolicy(tmp, { deny: [] });
    const chainPath = join(tmp, "proxy.jsonl");
    const r = await new Promise<{ status: number | null; lines: string[]; stderr: string }>((done) => {
      const env: NodeJS.ProcessEnv = { ...process.env, [ACCOUNT_KEY_ENV]: key };
      const child = spawn(
        process.execPath,
        [
          TSX_CLI, CLI_ENTRY, "proxy", "--dir", tmp, "--chain", chainPath,
          "--session-id", "sess-proxy-env", "--policy", policyPath, "--server-label", "fake",
          "--checkpoint-every", "1",
          "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
          "--", "node", TSX_CLI, FAKE_SERVER,
        ],
        { stdio: ["pipe", "pipe", "pipe"], env },
      );
      const lines: string[] = [];
      let buf = "";
      let stderr = "";
      child.stdout.on("data", (c: Buffer) => {
        buf += c.toString("utf8");
        const parts = buf.split("\n");
        buf = parts.pop() ?? "";
        for (const l of parts) {
          lines.push(l);
          if (l.includes('"id":9')) child.stdin.end();
        }
      });
      child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
      child.on("exit", (status) => done({ status, lines, stderr }));
      child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } }) + "\n",
      );
    });
    expect(r.status).toBe(0);
    const resp = JSON.parse(r.lines.find((l) => l.includes('"id":9'))!) as { result: { isError: boolean; content: { text: string }[] } };
    expect(resp.result.isError).toBe(false);
    expect(resp.result.content[0]!.text).toBe("echo: x");
    expect(r.stderr).toContain(`account key from $${ACCOUNT_KEY_ENV} (not shown)`);
    expect(r.stderr).toContain("payment_required (call permitted;");
    expect(stub.postAuth.every((h) => h === `Bearer ${key}`)).toBe(true);
    const lines = readSidecar(sidecarPathFor(chainPath));
    expect(lines.length).toBeGreaterThanOrEqual(1);
    expect(lines.every((l) => l.witness_error === "payment_required" && l.witness_receipt === null)).toBe(true);
    for (const t of [r.stderr, r.lines.join("\n"), readFileSync(sidecarPathFor(chainPath), "utf8")]) expectNoKey(t, key);
  }, 60_000);

  it("429 quota_exceeded is recorded as an error, never a receipt; the proxy prints exactly one upgrade hint, from the reply", async () => {
    const key = newAccountKey();
    const stub = await stubOf({ accounts: { [key]: { status: "active", plan: "evidence_starter", quota: 1 } } });
    const logs: string[] = [];
    const p = proxyFixture(tmp, identity, {
      checkpointEvery: 1,
      witness: { ...targetOf(stub), accountKey: key },
      log: (m: string) => logs.push(m),
    });
    for (const id of [1, 2, 3]) {
      const resp = await p.call(id);
      expect(resp.result?.isError).toBe(false);
      expect(resp.result?.content?.[0]?.text).toBe("ok");
    }
    p.downstream.exit(0);
    await p.handle.done;
    await p.handle.finalCheckpoint(5000);
    const lines = readSidecar(sidecarPathFor(p.chainPath));
    expect(lines[0]!.witness_error).toBeNull();
    expect(lines[0]!.witness_receipt!["count"]).toBe("1");
    expect(lines.length).toBeGreaterThanOrEqual(3);
    for (const l of lines.slice(1)) {
      expect(l.witness_receipt).toBeNull();
      expect(l.witness_error).toBe("quota_exceeded");
    }
    expect(stub.rows).toHaveLength(1);
    const refused = stub.postReplies[1]!;
    expect(refused.status).toBe(429);
    const retryAfter = Number(refused.headers["retry-after"]);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(86_400);
    expect((refused.body as Record<string, unknown>)["upgrade"]).toBeDefined();
    const hints = logs.filter((l) => l.includes(HINT_MARK));
    expect(hints).toHaveLength(1);
    expect(hints[0]).toContain("quota_exceeded");
    expect(hints[0]!.endsWith(`${HINT_MARK}${STUB_PRICING_URL}`)).toBe(true);
    expectNoKey(logs.join("\n"), key);
    expectNoKey(readFileSync(sidecarPathFor(p.chainPath), "utf8"), key);
  });

  it("anonymous cap 503 with upgrade: recorded as witness_unavailable, one hint from the reply; an account key is not blocked by that cap", async () => {
    const key = newAccountKey();
    const stub = await stubOf({ anonymousCap: 0, accounts: { [key]: { status: "active", plan: "evidence_starter" } } });
    const anonChain = join(tmp, "anon.jsonl");
    writeChain(anonChain, identity, "sess-cap-anon", 2);
    const r = await runCli(checkpointArgs(anonChain, stub));
    expect(r.status).toBe(1);
    const line = readSidecar(sidecarPathFor(anonChain))[0]!;
    expect(line.witness_receipt).toBeNull();
    expect(line.witness_error).toBe("witness_unavailable");
    expect(stub.postReplies[0]!.status).toBe(503);
    const hints = r.stderr.split("\n").filter((l) => l.includes(HINT_MARK));
    expect(hints).toHaveLength(1);
    expect(hints[0]).toContain("witness_unavailable");
    expect(hints[0]!.endsWith(`${HINT_MARK}${STUB_PRICING_URL}`)).toBe(true);

    const acctChain = join(tmp, "acct.jsonl");
    writeChain(acctChain, identity, "sess-cap-acct", 2);
    const a = await runCli(checkpointArgs(acctChain, stub), [], { [ACCOUNT_KEY_ENV]: key });
    expect(a.status).toBe(0);
    expect(readSidecar(sidecarPathFor(acctChain))[0]!.witness_error).toBeNull();
  }, 60_000);

  it("no hint without a usable upgrade URL in the reply (hostile URL, store-down 503, RATE_LIMITED)", async () => {
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-nohint", 1);
    const cp = buildCheckpoint(readChainFile(chainPath).records, identity);

    const hostile = await stubOf({
      anonymousCap: 0,
      upgrade: { pricing: "https://evil.invalid/x?\u001b[2J", checkout: { url: "http://plain.invalid/checkout" } },
    });
    expect(await witnessCheckpoint(cp, identity.publicKey, targetOf(hostile))).toEqual({
      receipt: null,
      error: "witness_unavailable",
    });

    const key = newAccountKey();
    const down = await stubOf({ keyStoreDown: true, accounts: { [key]: { status: "active", plan: "evidence" } } });
    expect(await witnessCheckpoint(cp, identity.publicKey, { ...targetOf(down), accountKey: key })).toEqual({
      receipt: null,
      error: "witness_unavailable",
    });

    const limited = await stubOf({ rateLimited: true });
    expect(await witnessCheckpoint(cp, identity.publicKey, targetOf(limited))).toEqual({
      receipt: null,
      error: "RATE_LIMITED",
    });
    expect(limited.postReplies[0]!.headers["retry-after"]).toBe("60");

    // The usable case, for contrast: the URL is taken from the reply.
    const capped = await stubOf({ anonymousCap: 0 });
    expect(await witnessCheckpoint(cp, identity.publicKey, targetOf(capped))).toEqual({
      receipt: null,
      error: "witness_unavailable",
      upgrade: STUB_PRICING_URL,
    });
  });

  it("a witness that echoes the account key in its error code or upgrade URL cannot get it into the sidecar or logs", async () => {
    const key = newAccountKey();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-echo", 1);
    const cp = buildCheckpoint(readChainFile(chainPath).records, identity);
    const replies = [
      { status: 401, body: { error: key.slice(8) } }, // 64 hex chars: a well-formed "code"
      { status: 429, body: { error: "quota_exceeded", upgrade: { pricing: `https://x.invalid/${key.slice(8)}` } } },
    ];
    let i = 0;
    const server = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        const r = replies[i++]!;
        res.writeHead(r.status, { "content-type": "application/json" });
        res.end(JSON.stringify(r.body));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const target: WitnessTarget = { baseUrl: url, name: STUB_WITNESS_NAME, accountKey: key };
      expect(await witnessCheckpoint(cp, identity.publicKey, target)).toEqual({ receipt: null, error: "http_401" });
      expect(await witnessCheckpoint(cp, identity.publicKey, target)).toEqual({ receipt: null, error: "quota_exceeded" });
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("a malformed or misplaced account key is a usage error (exit 2) before any request, and is never echoed", async () => {
    const stub = await stubOf();
    const chainPath = join(tmp, "s.jsonl");
    writeChain(chainPath, identity, "sess-badkey", 1);
    const good = newAccountKey();
    const upper = "ho_live_" + randomBytes(32).toString("hex").toUpperCase();
    const short = "ho_live_" + randomBytes(31).toString("hex");
    const policyPath = writePolicy(tmp, { deny: [] });
    const proxyArgs = [
      "proxy", "--dir", tmp, "--chain", join(tmp, "p.jsonl"), "--policy", policyPath, "--server-label", "fake",
      "--witness", stub.url,
    ];
    const cases: { args: string[]; env?: Record<string, string>; secret: string }[] = [
      { args: [...checkpointArgs(chainPath, stub), "--witness-account-key-file", writeKeyFile("upper", upper)], secret: upper },
      { args: [...checkpointArgs(chainPath, stub), "--witness-account-key-file", writeKeyFile("short", short + "\n")], secret: short },
      { args: checkpointArgs(chainPath, stub), env: { [ACCOUNT_KEY_ENV]: upper }, secret: upper },
      { args: [...checkpointArgs(chainPath, stub), "--witness-account-key", good], secret: good },
      { args: [...checkpointArgs(chainPath, stub), `--witness-account-key=${good}`], secret: good },
      { args: [...checkpointArgs(chainPath, stub), "--witness-account-key-file", good], secret: good },
      { args: [...checkpointArgs(chainPath, stub), "--witness-account-key-file", join(tmp, "missing.key")], secret: good },
      { args: ["checkpoint", chainPath, "--dir", tmp, "--witness-account-key-file", writeKeyFile("nowit", good)], secret: good },
      { args: [...proxyArgs, "--", "node", TSX_CLI, FAKE_SERVER], env: { [ACCOUNT_KEY_ENV]: short }, secret: short },
      { args: ["verify", chainPath, "--key", join(tmp, "identity.json"), "--witness", stub.url, "--witness-account-key-file", writeKeyFile("v", good)], secret: good },
    ];
    for (const c of cases) {
      const r = await runCli(c.args, [], c.env ?? {});
      expect({ args: c.args.slice(-2), status: r.status }).toEqual({ args: c.args.slice(-2), status: 2 });
      expectNoKey(r.stdout + r.stderr, c.secret);
    }
    expect(stub.posts).toBe(0);
    expect(stub.gets).toBe(0);
    expect(stub.keysAuth).toHaveLength(0);
    expect(existsSync(sidecarPathFor(chainPath))).toBe(false);
  }, 180_000);

  it("precedence: --witness-account-key-file wins over $CHIRINDO_WITNESS_ACCOUNT_KEY (even an invalid one); the env var is used when the flag is absent", async () => {
    const fileKey = newAccountKey();
    const envKey = newAccountKey();
    const stub = await stubOf({
      accounts: {
        [fileKey]: { status: "active", plan: "evidence" },
        [envKey]: { status: "active", plan: "evidence" },
      },
    });
    const keyFile = writeKeyFile("file.key", fileKey);
    const run = async (name: string, extra: string[], env: Record<string, string>) => {
      const chainPath = join(tmp, `${name}.jsonl`);
      writeChain(chainPath, identity, `sess-prec-${name}`, 1);
      return runCli([...checkpointArgs(chainPath, stub), ...extra], [], env);
    };
    expect((await run("both", ["--witness-account-key-file", keyFile], { [ACCOUNT_KEY_ENV]: envKey })).status).toBe(0);
    expect((await run("envonly", [], { [ACCOUNT_KEY_ENV]: envKey })).status).toBe(0);
    expect((await run("badenv", ["--witness-account-key-file", keyFile], { [ACCOUNT_KEY_ENV]: "not-a-key" })).status).toBe(0);
    expect((await run("none", [], {})).status).toBe(0);
    expect(stub.postAuth).toEqual([`Bearer ${fileKey}`, `Bearer ${envKey}`, `Bearer ${fileKey}`, null]);
  }, 120_000);
});
