// Network reads for --online. Only reads: JSON-RPC methods that read chain
// data (eth_getTransactionByHash, eth_getTransactionReceipt,
// eth_getBlockByNumber, eth_call) sent to public Base endpoints this checker
// names itself, and HTTPS GETs to Headless Oracle's witness and to the key
// document an issuer profile names. Nothing is written anywhere.

import { parseStrictJson } from "./formats.mjs";

// Public JSON-RPC endpoints per chain id. The case never chooses them; a
// verifier may name others with --rpc. Two must answer and agree.
export const RPC_ENDPOINTS = {
  8453: ["https://mainnet.base.org", "https://base.drpc.org", "https://base-mainnet.public.blastapi.io", "https://base-rpc.publicnode.com"],
  84532: ["https://sepolia.base.org", "https://base-sepolia.drpc.org", "https://base-sepolia-rpc.publicnode.com"],
};

export const WITNESS_BASE = "https://api.headlessoracle.com";
// src/witness.ts in this repository follows up to 10,000 pages of the same
// list (MAX_GET_PAGES); so does this checker.
export const MAX_WITNESS_PAGES = 10000;

async function readBody(res) {
  return Buffer.from(await res.arrayBuffer());
}

export async function rpc(url, method, params, fetchImpl = fetch) {
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(20000),
  });
  const body = await readBody(res);
  if (res.status !== 200) throw new Error(`${url} ${method}: HTTP ${res.status}`);
  const msg = parseStrictJson(body);
  if (msg.error) throw new Error(`${url} ${method}: error ${JSON.stringify(msg.error).slice(0, 200)}`);
  if (!("result" in msg)) throw new Error(`${url} ${method}: no result`);
  return msg.result;
}

export async function getJson(url, fetchImpl = fetch, { allowNonInteger = false } = {}) {
  const res = await fetchImpl(url, { method: "GET", signal: AbortSignal.timeout(20000) });
  const body = await readBody(res);
  if (res.status !== 200) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return { body, json: parseStrictJson(body, { allowNonInteger }) };
}

// Every receipt the witness lists for (kid, session_id), following
// next_after to the end, as its spec requires.
export async function witnessReceipts(kid, sessionId, fetchImpl = fetch) {
  const all = [];
  let after = null;
  for (let page = 0; page < MAX_WITNESS_PAGES; page++) {
    const q = new URLSearchParams({ kid, session_id: sessionId });
    if (after) q.set("after", after);
    const { json } = await getJson(`${WITNESS_BASE}/v1/witness/checkpoints?${q}`, fetchImpl);
    if (!Array.isArray(json.receipts)) throw new Error("witness answer has no receipts array");
    all.push(...json.receipts);
    if (!json.next_after) return { receipts: all, pages: page + 1 };
    after = json.next_after;
  }
  throw new Error(`witness list longer than ${MAX_WITNESS_PAGES} pages`);
}
