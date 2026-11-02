// B-464: checking a witness payment attestation against the chain.
//
// The chain answers are recorded, not live: test/fixtures/payment/ holds the
// eth_chainId, eth_getTransactionReceipt and eth_getBlockByNumber responses
// two public Base nodes (node1 https://mainnet.base.org, node2
// https://base.drpc.org) gave on 2026-11-02 for
// 0x46db8fc8cfd79017375d76c5ad80256950f8437ff009ecbe90b6cd5ce97e9263, a
// settlement in Headless Oracle's x402 ledger (block 50,998,385, 1000 units of
// USDC to 0x26D4Ffe98017D2f160E2dAaE9d119e3d8b860AD3). The attestations are in
// the shape witness-spec/0.6.1 publishes, signed here with a test key.

import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyPaymentAttestation, type PaymentVerifyOptions } from "../src/payment.js";
import { CLI_ENTRY, CLI_E2E_TIMEOUT_MS, TSX_CLI, cleanupTmpDir, makeTmpDir } from "./helpers.js";

const FIX = join(import.meta.dirname, "fixtures", "payment");
const fixture = (name: string) => JSON.parse(readFileSync(join(FIX, name), "utf8")) as Record<string, unknown>;
const TX = "0x46db8fc8cfd79017375d76c5ad80256950f8437ff009ecbe90b6cd5ce97e9263";
const PAY_TO = "0x26D4Ffe98017D2f160E2dAaE9d119e3d8b860AD3";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const NODE1 = "https://node1.test";
const NODE2 = "https://node2.test";

// The receipt the attestation is bound to: the T3 example receipt's shape.
const RECEIPT = {
  type: "witness.checkpoint/1", witness: "headlessoracle.com", received_at: "2026-09-07T13:01:50.000Z",
  kid: "3FbQNDHv3UkmxeN8gfp8ilIG5xFbOod8kuiIoKuGTQk", session_id: "b464", count: "1",
  last_entry_hash: "sha256:" + "f".repeat(64), checkpoint_ts: "2026-09-07T13:01:49.000Z",
  checkpoint_sha256: "sha256:" + "6".repeat(64), fork: "false", public_key_id: "key_test_b464",
  signature: "b1".repeat(64),
};

// Written out independently of src: sorted keys, no whitespace (flat strings).
const sorted = (o: Record<string, unknown>) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const PUB_HEX = (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(12).toString("hex");
const KEYS = [{ key_id: "key_test_b464", public_key: PUB_HEX }];

function attestation(over: Record<string, string> = {}): Record<string, string> {
  const a: Record<string, string> = {
    type: "witness-payment-attestation/0.1", witness: "headlessoracle.com",
    checkpoint_id: sha256(sorted({ count: RECEIPT.count, kid: RECEIPT.kid, last_entry_hash: RECEIPT.last_entry_hash, session_id: RECEIPT.session_id })),
    receipt_sha256: `sha256:${sha256(sorted(RECEIPT))}`,
    resource: "checkpoint", amount_units: "1000", asset: USDC, network: "base", transaction: TX,
    settlement: "settled", issued_at: "2026-09-07T13:01:58.000Z", public_key_id: "key_test_b464", ...over,
  };
  a.signature = sign(null, Buffer.from(sorted(a)), privateKey).toString("hex");
  return a;
}

type Responses = Record<"chainId" | "receipt" | "block", Record<string, unknown>>;
const recorded = (n: 1 | 2): Responses => ({
  chainId: fixture(`node${n}.chainId.json`), receipt: fixture(`node${n}.receipt.json`), block: fixture(`node${n}.block.json`),
});
// The recorded receipt, edited the way a different chain answer would differ.
function editReceipt(r: Responses, edit: (res: { status: string; logs: Array<{ address: string; topics: string[]; data: string }> }) => void): Responses {
  const copy = JSON.parse(JSON.stringify(r)) as Responses;
  edit((copy.receipt as { result: never }).result);
  return copy;
}
const usdcLog = (res: { logs: Array<{ address: string; topics: string[]; data: string }> }) =>
  res.logs.find((l) => l.address.toLowerCase() === USDC.toLowerCase() && l.topics[0] === "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")!;

// A fetch that answers JSON-RPC from recorded responses, per node, and counts calls.
function chainFetch(nodes: Record<string, Responses>): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const node = nodes[url];
    if (!node) throw new Error(`no fixture for ${url}`);
    const method = (JSON.parse(String(init?.body)) as { method: string }).method;
    calls.push(`${url} ${method}`);
    const body = method === "eth_chainId" ? node.chainId : method === "eth_getTransactionReceipt" ? node.receipt : node.block;
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
  return { fetch: f, calls };
}

async function check(att: unknown, nodes: Record<string, Responses>, extra: Partial<PaymentVerifyOptions> = {}) {
  const net = chainFetch(nodes);
  const v = await verifyPaymentAttestation(att, { keys: KEYS, rpcUrl: Object.keys(nodes), payTo: PAY_TO, fetch: net.fetch, ...extra });
  const failed = [...v.checks, ...v.nodes.flatMap((n) => n.checks)].filter((c) => c.result === "fail" || c.result === "unknown").map((c) => c.name);
  return { v, failed, calls: net.calls };
}

describe("B-464: a payment attestation against the chain", () => {
  it("a good attestation and the recorded transaction verify on two agreeing nodes, with the receipt bound", async () => {
    const { v, failed } = await check(attestation(), { [NODE1]: recorded(1), [NODE2]: recorded(2) }, { receipt: RECEIPT });
    expect(failed).toEqual([]);
    expect(v.verdict).toBe("VERIFIED");
    expect(v.exit_code).toBe(0);
    expect(v.nodes.map((n) => n.observed?.matching_units)).toEqual(["1000", "1000"]);
    expect(v.nodes[0]!.checks.find((c) => c.name === "block_time")!.detail).toContain("2026-09-07T13:01:57.000Z");
    expect(v.summary).toContain("2 nodes agree");
  });

  const contradictions: Array<[string, (r: Responses) => Responses, string]> = [
    ["a smaller amount", (r) => editReceipt(r, (res) => { usdcLog(res).data = "0x" + (999).toString(16).padStart(64, "0"); }), "amount"],
    ["another payee", (r) => editReceipt(r, (res) => { usdcLog(res).topics[2] = "0x" + "0".repeat(24) + "11".repeat(20); }), "payee"],
    ["another asset", (r) => editReceipt(r, (res) => { for (const l of res.logs) l.address = "0x" + "22".repeat(20); }), "asset"],
    ["a reverted transaction", (r) => editReceipt(r, (res) => { res.status = "0x0"; }), "transaction_status"],
  ];
  for (const [what, edit, name] of contradictions) {
    it(`the chain shows ${what}: CONTRADICTED, by the check named ${name}`, async () => {
      const { v, failed } = await check(attestation(), { [NODE1]: edit(recorded(1)), [NODE2]: edit(recorded(2)) });
      expect(failed).toEqual([name, name]);
      expect(v.verdict).toBe("CONTRADICTED");
      expect(v.exit_code).toBe(1);
    });
  }

  it('an attested "failed" settlement whose transfer succeeded on chain: CONTRADICTED by settlement', async () => {
    const { v, failed } = await check(attestation({ settlement: "failed" }), { [NODE1]: recorded(1) });
    expect(failed).toEqual(["settlement"]);
    expect(v.verdict).toBe("CONTRADICTED");
  });

  it('an attested "failed" settlement that reverted on chain is consistent, not a contradiction', async () => {
    const reverted = editReceipt(recorded(1), (res) => { res.status = "0x0"; });
    const { v, failed } = await check(attestation({ settlement: "failed" }), { [NODE1]: reverted });
    expect(failed).toEqual([]);
    expect(v.verdict).toBe("VERIFIED");
    expect(v.summary).toContain("settlement failed");
  });

  it("an attestation naming another network: UNESTABLISHED by network, no RPC call", async () => {
    const { v, failed, calls } = await check(attestation({ network: "eip155:1" }), { [NODE1]: recorded(1) });
    expect(failed).toEqual(["network"]);
    expect(v.exit_code).toBe(2);
    expect(calls).toEqual([]);
  });

  it("a node on another chain: UNESTABLISHED by chain_id", async () => {
    const other = { ...recorded(1), chainId: { jsonrpc: "2.0", id: 1, result: "0x1" } };
    const { v, failed } = await check(attestation(), { [NODE1]: other });
    expect(failed).toEqual(["chain_id"]);
    expect(v.exit_code).toBe(2);
  });

  it("a bad signature fails before any RPC call, and so does any changed signed field", async () => {
    const good = attestation();
    for (const [field, value] of [["amount_units", "1"], ["asset", "0x" + "22".repeat(20)], ["network", "eip155:8453"], ["settlement", "failed"], ["transaction", "0x" + "33".repeat(32)]] as const) {
      const { v, failed, calls } = await check({ ...good, [field]: value }, { [NODE1]: recorded(1) });
      expect({ field, failed, verdict: v.verdict, calls }).toEqual({ field, failed: ["signature"], verdict: "CONTRADICTED", calls: [] });
    }
    const { failed, calls } = await check({ ...good, signature: "00".repeat(64) }, { [NODE1]: recorded(1) });
    expect({ failed, calls }).toEqual({ failed: ["signature"], calls: [] });
  });

  it("a receipt that is not the bound one: CONTRADICTED by receipt_sha256, before any RPC call", async () => {
    const { v, failed, calls } = await check(attestation(), { [NODE1]: recorded(1) }, { receipt: { ...RECEIPT, count: "2" } });
    expect(failed).toEqual(["receipt_sha256"]);
    expect(v.verdict).toBe("CONTRADICTED");
    expect(calls).toEqual([]);
  });

  it("two nodes that disagree: UNESTABLISHED (exit 2)", async () => {
    const lying = editReceipt(recorded(2), (res) => { usdcLog(res).data = "0x" + (1).toString(16).padStart(64, "0"); });
    const { v } = await check(attestation(), { [NODE1]: recorded(1), [NODE2]: lying });
    expect(v.verdict).toBe("UNESTABLISHED");
    expect(v.exit_code).toBe(2);
    expect(v.summary).toContain("the RPC nodes disagree");
  });

  it("an unknown key id, or a node that cannot answer, is UNESTABLISHED, never VERIFIED", async () => {
    const noKey = await check(attestation({ public_key_id: "key_other" }), { [NODE1]: recorded(1) });
    expect(noKey.failed).toEqual(["key"]);
    expect(noKey.v.exit_code).toBe(2);
    const down = await verifyPaymentAttestation(attestation(), {
      keys: KEYS, rpcUrl: [NODE1], payTo: PAY_TO,
      fetch: (async () => { throw new Error("connect ECONNREFUSED"); }) as typeof fetch,
    });
    expect(down.verdict).toBe("UNESTABLISHED");
    expect(down.exit_code).toBe(2);
  });
});

// The CLI, against a loopback node replaying the recorded responses.
describe("B-464: chirindo payment verify", () => {
  let dir: string;
  let server: Server;
  let rpcUrl: string;
  let answers: Responses = recorded(1);
  beforeAll(async () => {
    dir = makeTmpDir("chirindo-payment-");
    writeFileSync(join(dir, "keys.json"), JSON.stringify({ keys: KEYS }));
    writeFileSync(join(dir, "receipt.json"), JSON.stringify(RECEIPT));
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        const method = (JSON.parse(body) as { method: string }).method;
        const out = method === "eth_chainId" ? answers.chainId : method === "eth_getTransactionReceipt" ? answers.receipt : answers.block;
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(out));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    rpcUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    cleanupTmpDir(dir);
  });
  function cli(args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [TSX_CLI, CLI_ENTRY, ...args], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (c) => { stdout += c; });
      child.stderr.on("data", (c) => { stderr += c; });
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
  }
  const run = (att: Record<string, string>, extra: string[] = []) => {
    writeFileSync(join(dir, "att.json"), JSON.stringify(att));
    return cli(["payment", "verify", join(dir, "att.json"), "--rpc", rpcUrl, "--pay-to", PAY_TO, "--keys", join(dir, "keys.json"), ...extra]);
  };

  it("exit 0 VERIFIED, exit 1 CONTRADICTED, exit 2 UNESTABLISHED or usage", async () => {
    answers = recorded(1);
    const ok = await run(attestation(), ["--receipt", join(dir, "receipt.json")]);
    console.log("B464_CLI_VERIFIED\n" + ok.stdout);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toMatch(/^VERIFIED — /m);

    answers = editReceipt(recorded(1), (res) => { usdcLog(res).data = "0x" + (999).toString(16).padStart(64, "0"); });
    const bad = await run(attestation());
    console.log("B464_CLI_CONTRADICTED\n" + bad.stdout);
    expect(bad.status).toBe(1);
    expect(bad.stdout).toMatch(/^CONTRADICTED — amount: /m);

    answers = { ...recorded(1), chainId: { jsonrpc: "2.0", id: 1, result: "0x1" } };
    const off = await run(attestation());
    expect(off.status).toBe(2);
    expect(off.stdout).toMatch(/^UNESTABLISHED — /m);

    const usage = await cli(["payment", "verify", join(dir, "att.json")]);
    expect(usage.status).toBe(2);
    expect(usage.stderr).toContain("--rpc <url> and --pay-to <0x-address> are required");
  }, CLI_E2E_TIMEOUT_MS * 2);
});
