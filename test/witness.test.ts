// Witness client (WITNESS_SPEC v0.3): checkpoint sidecar, witness receipt
// acceptance, proxy checkpointing, and the verify --witness layer. Every test
// talks to the in-process STUB witness (test/witness-stub.ts), which signs with
// a throwaway key and says "witness":"stub.invalid" — so every acceptance path
// passes the stub's name explicitly, exactly as the CLI needs --witness-name.

import { spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
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
function runCli(
  args: string[],
  stdinLines: string[] = [],
): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [TSX_CLI, CLI_ENTRY, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
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
