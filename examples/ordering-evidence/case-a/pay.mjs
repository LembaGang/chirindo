#!/usr/bin/env node
// Case A payment: an EIP-3009 transferWithAuthorization on Base Sepolia USDC
// whose nonce is the entry hash of the ALLOW receipt, settled through the
// public x402 facilitator (https://x402.org/facilitator), which pays the gas.
// The x402 v2 payment payload is built here from the x402 specification
// (repository commit dd927a26: specs/x402-specification-v2.md 5.1-5.2 and 7.1-7.2,
// specs/schemes/exact/scheme_exact_evm.md 21-79); no x402 client library.
// Run from the repo root, after `npm install` in examples/ordering-evidence:
//
//   node examples/ordering-evidence/case-a/pay.mjs --dry-run   # build + sign + local checks, contact no facilitator
//   node examples/ordering-evidence/case-a/pay.mjs             # POST /verify; only if valid, POST /settle; save the evidence
//
// The payer's secret is read from the file named by CHIRINDO_Y2_PAYER_FILE
// (outside the repository) and is never printed or sent; only the signed
// authorization leaves the machine.
//
// Edited after the run: the wait for a sealed block before saving, and reading
// the payer file path from the environment. This version was not re-run.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, http, parseAbi, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";

const { env } = process;
const PAYER_SECRET_FILE = env.CHIRINDO_Y2_PAYER_FILE;
if (!PAYER_SECRET_FILE) {
  process.stderr.write("[pay] CHIRINDO_Y2_PAYER_FILE is not set: set it to the file (outside this repository) holding the payer's hex secret\n");
  process.exit(2);
}
const HERE = dirname(fileURLToPath(import.meta.url));
const PAY_TO = "0xd8e1d2Faf5e4509EE295C50E0f5E369e71861215"; // second throwaway address (address only)
const FACILITATOR = "https://x402.org/facilitator";
const RPC_URL = "https://sepolia.base.org";
const CHAIN_ID = 84532;
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const AMOUNT = "10000"; // 0.01 test USDC (6 decimals)
const MAX_TIMEOUT_SECONDS = 300;
const DRY_RUN = process.argv.includes("--dry-run");

const manifest = JSON.parse(readFileSync(join(HERE, "case.json"), "utf8"));

// Entry hash per the recorder: "sha256:" + hex(SHA-256(JCS(record without sig))).
// Same JCS subset as check.mjs (strings, booleans, null, safe integers).
function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`JCS: number ${v} not supported`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const members = Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + members.map(([k, x]) => JSON.stringify(k) + ":" + jcs(x)).join(",") + "}";
}
const lines = (p) => readFileSync(p, "utf8").split("\n").map((l) => l.replace(/\r$/, "")).filter(Boolean).map((l) => JSON.parse(l));
const records = lines(join(HERE, manifest.hash_chain));
const { sig: _sig, ...content } = records[manifest.cited_seq];
const entryHash = "sha256:" + createHash("sha256").update(jcs(content), "utf8").digest("hex");
const [witnessed] = lines(join(HERE, manifest.witness_sidecar)).filter((l) => l.witness_receipt);
if (witnessed.checkpoint.last_entry_hash !== entryHash || witnessed.checkpoint.count !== manifest.cited_seq + 1) {
  throw new Error("recomputed entry hash does not equal the witnessed checkpoint's last_entry_hash");
}
const nonce = "0x" + entryHash.slice("sha256:".length);

const publicClient = createPublicClient({ chain: baseSepolia, transport: http(RPC_URL) });
const chainId = await publicClient.getChainId();
if (chainId !== CHAIN_ID) throw new Error(`provider chainId ${chainId} is not ${CHAIN_ID}; aborting`);

const account = privateKeyToAccount(readFileSync(PAYER_SECRET_FILE, "utf8").trim());
const abi = parseAbi([
  "function name() view returns (string)",
  "function version() view returns (string)",
  "function balanceOf(address) view returns (uint256)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
]);
const read = (functionName, args = []) => publicClient.readContract({ address: USDC, abi, functionName, args });
const [name, version, usdcBalance, used] = await Promise.all([
  read("name"), read("version"), read("balanceOf", [account.address]), read("authorizationState", [account.address, nonce]),
]);
console.log(`payer ${account.address} | payTo ${PAY_TO} | chainId ${chainId} | USDC domain name=${JSON.stringify(name)} version=${JSON.stringify(version)}`);
console.log(`payer USDC ${usdcBalance} base units | authorizationState(payer, nonce) = ${used}`);
console.log(`nonce = entry hash of record ${manifest.cited_seq} = ${nonce}`);
if (used) throw new Error("this nonce is already used for this payer; aborting");
if (usdcBalance < BigInt(AMOUNT)) throw new Error("payer USDC balance is below the amount; aborting");

// PaymentRequirements (v2 spec 5.1.2). extra.name/version are the token's
// EIP-712 domain, read from the contract above.
const paymentRequirements = {
  scheme: "exact",
  network: NETWORK,
  amount: AMOUNT,
  asset: USDC,
  payTo: PAY_TO,
  maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
  extra: { assetTransferMethod: "eip3009", name, version },
};

// Validity window as the reference client sets it
// (typescript/packages/mechanisms/evm/src/exact/client/eip3009.ts 28-29).
const now = Math.floor(Date.now() / 1000);
const authorization = {
  from: account.address,
  to: PAY_TO,
  value: AMOUNT,
  validAfter: String(now - 600),
  validBefore: String(now + MAX_TIMEOUT_SECONDS),
  nonce,
};
const domain = { name, version, chainId: CHAIN_ID, verifyingContract: USDC };
const types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const message = { ...authorization, value: BigInt(authorization.value), validAfter: BigInt(authorization.validAfter), validBefore: BigInt(authorization.validBefore) };
const signature = await account.signTypedData({ domain, types, primaryType: "TransferWithAuthorization", message });
const recovered = await recoverTypedDataAddress({ domain, types, primaryType: "TransferWithAuthorization", message, signature });
if (recovered !== account.address) throw new Error("signature does not recover to the payer");
console.log(`authorization signed: from ${authorization.from} to ${authorization.to} value ${AMOUNT} validAfter ${authorization.validAfter} validBefore ${authorization.validBefore}; recovers to payer`);

// PaymentPayload (v2 spec 5.2) and the /verify and /settle request body (7.1, 7.2).
const body = {
  x402Version: 2,
  paymentPayload: { x402Version: 2, accepted: paymentRequirements, payload: { signature, authorization } },
  paymentRequirements,
};
if (DRY_RUN) {
  console.log("dry run: no facilitator contacted");
  process.exit(0);
}

const outDir = join(HERE, "facilitator");
mkdirSync(outDir, { recursive: true });
const save = (file, value) => writeFileSync(join(outDir, file), JSON.stringify(value, null, 2) + "\n");
save("request.json", body);

async function post(path) {
  const requestedAt = new Date().toISOString();
  const res = await fetch(`${FACILITATOR}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  const receivedAt = new Date().toISOString();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text, requestedAt, receivedAt };
}

const verify = await post("/verify");
save("verify.response.json", verify.json ?? { unparsed_body: verify.text });
console.log(`POST ${FACILITATOR}/verify -> HTTP ${verify.status} ${verify.text}`);
const fetchLog = { facilitator: FACILITATOR, verify: { http_status: verify.status, requested_at: verify.requestedAt, received_at: verify.receivedAt } };
if (verify.status !== 200 || verify.json?.isValid !== true) {
  save("fetched.json", fetchLog);
  console.log("verify did not return isValid: true; not settling");
  process.exit(1);
}

const settle = await post("/settle");
save("settle.response.json", settle.json ?? { unparsed_body: settle.text });
fetchLog.settle = { http_status: settle.status, requested_at: settle.requestedAt, received_at: settle.receivedAt };
save("fetched.json", fetchLog);
console.log(`POST ${FACILITATOR}/settle -> HTTP ${settle.status} ${settle.text}`);
if (settle.status !== 200 || settle.json?.success !== true || !/^0x[0-9a-fA-F]{64}$/.test(settle.json?.transaction ?? "")) {
  console.log("settle did not succeed; stopping");
  process.exit(1);
}
const txHash = settle.json.transaction;
await publicClient.waitForTransactionReceipt({ hash: txHash });

// Save what the RPC returns, as it returns it, with fetch times.
async function rpc(method, params) {
  const fetchedAt = new Date().toISOString();
  const res = await fetch(RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const out = await res.json();
  if (out.error || out.result == null) throw new Error(`${method}: ${JSON.stringify(out.error ?? "null result")}`);
  return { result: out.result, fetchedAt };
}
// Base Sepolia serves a just-included transaction and receipt before its block
// is sealed (blockHash null or zero); case-a-1's first snapshots were taken in
// that window. Save only once all three agree on a real block hash and the
// block is at least 5 deep.
const ZERO_HASH = "0x" + "0".repeat(64);
const MIN_DEPTH = 5;
let tx, rc, blk;
for (let attempt = 1; ; attempt++) {
  tx = await rpc("eth_getTransactionByHash", [txHash]);
  rc = await rpc("eth_getTransactionReceipt", [txHash]);
  blk = await rpc("eth_getBlockByNumber", [rc.result.blockNumber, false]);
  const head = await rpc("eth_blockNumber", []);
  const h = rc.result.blockHash;
  const sealed = h && h !== ZERO_HASH && tx.result.blockHash === h && blk.result.hash === h;
  const depth = parseInt(head.result, 16) - parseInt(rc.result.blockNumber, 16);
  if (sealed && depth >= MIN_DEPTH) break;
  if (attempt >= 60) throw new Error(`block not sealed and ${MIN_DEPTH} deep after ${attempt} attempts; nothing saved`);
  await new Promise((resolve) => setTimeout(resolve, 2000));
}
mkdirSync(join(HERE, "rpc"), { recursive: true });
writeFileSync(join(HERE, "rpc", "transaction.json"), JSON.stringify(tx.result, null, 2) + "\n");
writeFileSync(join(HERE, "rpc", "receipt.json"), JSON.stringify(rc.result, null, 2) + "\n");
writeFileSync(join(HERE, "rpc", "block.json"), JSON.stringify(blk.result, null, 2) + "\n");
writeFileSync(join(HERE, "rpc", "fetched.json"), JSON.stringify({
  rpc_url: RPC_URL,
  transaction: { method: "eth_getTransactionByHash", fetched_at: tx.fetchedAt },
  receipt: { method: "eth_getTransactionReceipt", fetched_at: rc.fetchedAt },
  block: { method: "eth_getBlockByNumber(<receipt blockNumber>, false)", fetched_at: blk.fetchedAt },
}, null, 2) + "\n");

const authUsed = rc.result.logs.find((l) => l.topics[0] === "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5");
const ok = rc.result.status === "0x1" && authUsed !== undefined && authUsed.topics[2].toLowerCase() === nonce;
console.log(`transaction sender ${tx.result.from} | receipt status ${rc.result.status}, block ${parseInt(rc.result.blockNumber, 16)}, block timestamp ${new Date(parseInt(blk.result.timestamp, 16) * 1000).toISOString()}`);
console.log(`AuthorizationUsed nonce ${authUsed?.topics[2]} ${ok ? "equals" : "DOES NOT equal"} the entry hash`);

manifest.transaction = {
  chain_id: CHAIN_ID,
  rpc_url: RPC_URL,
  usdc: USDC,
  payer: account.address,
  pay_to: PAY_TO,
  settled_by: FACILITATOR,
  tx_hash: txHash,
  explorer: `https://sepolia.basescan.org/tx/${txHash}`,
  tx_file: "rpc/transaction.json",
  receipt_file: "rpc/receipt.json",
  block_file: "rpc/block.json",
  fetch_log: "rpc/fetched.json",
  facilitator_files: ["facilitator/request.json", "facilitator/verify.response.json", "facilitator/settle.response.json", "facilitator/fetched.json"],
};
writeFileSync(join(HERE, "case.json"), JSON.stringify(manifest, null, 2) + "\n");
process.exitCode = ok ? 0 : 1;
