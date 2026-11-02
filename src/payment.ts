// Checking a paid checkpoint against the chain (B-464).
//
// Headless Oracle's witness signs a payment attestation for each paid
// checkpoint (witness-payment-attestation/0.1, witness-spec/0.6.1 section
// submit.paid_lane.attestation). That attestation is the operator's own
// statement. This module checks it against the chain itself: it fetches the
// named transaction by plain JSON-RPC from nodes the caller chooses, and
// confirms the transfer it names happened, of that asset, to the payee, for at
// least that amount, and succeeded. Nothing here trusts Headless Oracle beyond
// the signature check, which only establishes that the statement is theirs.
//
// verifyPaymentAttestation never throws. Its verdict names every check:
//   VERIFIED       (exit 0) the signed statement holds and the chain agrees
//   CONTRADICTED   (exit 1) the signature, the receipt binding or the chain
//                           contradicts the statement
//   UNESTABLISHED  (exit 2) the check could not be made: bad input, no key,
//                           a node unreachable or on the wrong chain, or two
//                           nodes that disagree

import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { jcsBytes } from "./vendor/recorder/index.js";

export const PAYMENT_ATTESTATION_TYPE = "witness-payment-attestation/0.1";
// The signed members, in the order the witness spec lists them.
export const PAYMENT_ATTESTATION_FIELDS = [
  "type", "witness", "checkpoint_id", "receipt_sha256", "resource", "amount_units", "asset", "network",
  "transaction", "settlement", "issued_at", "public_key_id",
] as const;
// Where the witness publishes its key set (witness-spec receipt.public_key).
export const DEFAULT_PAYMENT_KEYS_URL = "https://api.headlessoracle.com/v5/keys";
// The network names x402 v1 and v2 give Base mainnet, and its chain id.
const BASE_NETWORKS = new Set(["base", "eip155:8453"]);
const BASE_CHAIN_ID = 8453;
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const RPC_TIMEOUT_MS = 10_000;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const PAYMENT_LIMITS = [
  "It proves that a transfer happened on chain and that Headless Oracle's signed statement names it. It does not prove who paid: the sender is whoever signed the transfer.",
  "It does not prove anything about the checkpoint's content, only that the statement is bound to that receipt (when you pass it).",
  "It trusts the RPC nodes you chose to report the chain truthfully. Check against two nodes run by different operators; if they disagree the verdict is UNESTABLISHED.",
  "The payee is the address you pass. The attestation does not carry it: take it from the 402 challenge you paid, or from https://headlessoracle.com/.well-known/x402.json.",
];

type Attestation = Record<(typeof PAYMENT_ATTESTATION_FIELDS)[number] | "signature", string>;

export type CheckResult = "pass" | "fail" | "skip" | "unknown";
export interface PaymentCheck { name: string; result: CheckResult; detail: string }
export interface NodeObservation {
  rpc: string;
  checks: PaymentCheck[];
  outcome: "pass" | "fail" | "unknown";
  // What the node reported, for comparing nodes. Absent when it could not answer.
  observed?: { status: string; block: string; block_time: string | null; matching_units: string; any_success_transfer: boolean };
}
export interface PaymentVerdict {
  verdict: "VERIFIED" | "CONTRADICTED" | "UNESTABLISHED";
  exit_code: 0 | 1 | 2;
  summary: string;
  checks: PaymentCheck[];
  nodes: NodeObservation[];
  limits: string[];
}

export interface PaymentKey { key_id: string; public_key: string }
export interface PaymentVerifyOptions {
  // The witness key set, as /v5/keys serves it (keys[] of { key_id, public_key
  // hex }). Without it, the set is fetched from keysUrl.
  keys?: PaymentKey[] | undefined;
  keysUrl?: string | undefined;
  // One or more Base mainnet JSON-RPC URLs (https, or http on loopback).
  rpcUrl: string | string[];
  // The payee address the payment had to reach.
  payTo: string;
  // The checkpoint receipt the attestation is for, as served (object or JSON).
  receipt?: unknown;
  fetch?: typeof fetch | undefined;
  timeoutMs?: number | undefined;
}

const sha256Hex = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

function verdictOf(checks: PaymentCheck[], nodes: NodeObservation[], verdict: PaymentVerdict["verdict"], summary: string): PaymentVerdict {
  const exit_code = verdict === "VERIFIED" ? 0 : verdict === "CONTRADICTED" ? 1 : 2;
  return { verdict, exit_code, summary, checks, nodes, limits: PAYMENT_LIMITS };
}

function checkUrl(raw: string, what: string): string | null {
  let u: URL;
  try { u = new URL(raw); } catch { return `${what} is not a valid URL: ${raw}`; }
  const loopback = u.hostname === "localhost" || u.hostname === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) return `${what} must be https:// (http only for loopback): ${raw}`;
  return null;
}

async function postJson(f: typeof fetch, url: string, body: unknown, timeoutMs: number): Promise<unknown> {
  const res = await f(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  return JSON.parse(await res.text());
}

async function rpc(f: typeof fetch, url: string, method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
  const out = await postJson(f, url, { jsonrpc: "2.0", id: 1, method, params }, timeoutMs) as { result?: unknown; error?: { message?: string } };
  if (out && typeof out === "object" && "error" in out && out.error) throw new Error(`${method}: ${out.error.message ?? "JSON-RPC error"}`);
  if (!out || typeof out !== "object" || !("result" in out)) throw new Error(`${method}: no result`);
  return out.result;
}

const isHexQuantity = (v: unknown): v is string => typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v);

// One node's view of the transaction, as named checks.
async function observeNode(f: typeof fetch, url: string, att: Attestation, payTo: string, timeoutMs: number): Promise<NodeObservation> {
  const checks: PaymentCheck[] = [];
  const unknown = (name: string, detail: string): NodeObservation => {
    checks.push({ name, result: "unknown", detail });
    return { rpc: url, checks, outcome: "unknown" };
  };
  const bad = checkUrl(url, "--rpc");
  if (bad) return unknown("rpc_url", bad);
  let chainId: unknown;
  try { chainId = await rpc(f, url, "eth_chainId", [], timeoutMs); } catch (e) { return unknown("chain_id", `the node did not answer eth_chainId: ${(e as Error).message}`); }
  if (!isHexQuantity(chainId) || parseInt(chainId, 16) !== BASE_CHAIN_ID) {
    return unknown("chain_id", `the node reports chain ${String(chainId)}, not Base mainnet (${BASE_CHAIN_ID})`);
  }
  checks.push({ name: "chain_id", result: "pass", detail: `the node is on Base mainnet (chain ${BASE_CHAIN_ID})` });

  let receipt: unknown;
  try { receipt = await rpc(f, url, "eth_getTransactionReceipt", [att.transaction], timeoutMs); } catch (e) { return unknown("transaction_found", `eth_getTransactionReceipt failed: ${(e as Error).message}`); }
  const failed = att.settlement === "failed";
  if (receipt === null) {
    checks.push({ name: "transaction_found", result: failed ? "pass" : "fail", detail: `the node has no transaction ${att.transaction}` });
    return { rpc: url, checks, outcome: failed ? "pass" : "fail", observed: { status: "absent", block: "", block_time: null, matching_units: "0", any_success_transfer: false } };
  }
  if (typeof receipt !== "object") return unknown("transaction_found", "eth_getTransactionReceipt returned a non-object");
  const r = receipt as { status?: unknown; blockNumber?: unknown; logs?: unknown };
  if (!isHexQuantity(r.blockNumber) || !Array.isArray(r.logs) || typeof r.status !== "string") return unknown("transaction_found", "the receipt lacks status, blockNumber or logs");
  checks.push({ name: "transaction_found", result: "pass", detail: `in block ${parseInt(r.blockNumber, 16)}` });

  let blockTime: string | null = null;
  try {
    const block = await rpc(f, url, "eth_getBlockByNumber", [r.blockNumber, false], timeoutMs) as { timestamp?: unknown } | null;
    if (block && isHexQuantity(block.timestamp)) blockTime = new Date(parseInt(block.timestamp, 16) * 1000).toISOString();
  } catch { /* the time is reported, not checked */ }
  checks.push({ name: "block_time", result: blockTime ? "pass" : "skip", detail: blockTime ? `mined at ${blockTime} (attestation issued_at ${att.issued_at})` : "the node did not give the block time" });

  const succeeded = r.status === "0x1";
  // Transfer(from, to, value) logs emitted by the attested asset's contract.
  const assetLogs = (r.logs as Array<Record<string, unknown>>).filter((l) =>
    typeof l.address === "string" && l.address.toLowerCase() === att.asset.toLowerCase() &&
    Array.isArray(l.topics) && typeof l.topics[0] === "string" && l.topics[0].toLowerCase() === ERC20_TRANSFER_TOPIC);
  const toPayee = assetLogs.filter((l) => {
    const to = (l.topics as unknown[])[2];
    return typeof to === "string" && /^0x[0-9a-fA-F]{64}$/.test(to) && ("0x" + to.slice(-40)).toLowerCase() === payTo.toLowerCase();
  });
  let best = 0n;
  for (const l of toPayee) {
    if (isHexQuantity(l.data)) { const v = BigInt(l.data); if (v > best) best = v; }
  }
  const required = BigInt(att.amount_units);
  const matches = succeeded && best >= required;
  const observed = { status: r.status, block: r.blockNumber.toLowerCase(), block_time: blockTime, matching_units: best.toString(), any_success_transfer: matches };

  if (failed) {
    // A failed settlement is contradicted only by a successful matching transfer.
    checks.push({
      name: "settlement",
      result: matches ? "fail" : "pass",
      detail: matches
        ? `attested "failed", but the chain shows the transfer succeeded: ${best} units of ${att.asset} to ${payTo}`
        : `attested "failed"; the chain shows ${succeeded ? `no transfer of at least ${required} units of ${att.asset} to ${payTo}` : `the transaction reverted (status ${r.status})`}`,
    });
    return { rpc: url, checks, outcome: matches ? "fail" : "pass", observed };
  }
  checks.push({ name: "transaction_status", result: succeeded ? "pass" : "fail", detail: succeeded ? "status 0x1 (success)" : `status ${r.status}: the transaction reverted` });
  // Each check names one contradiction: a check that depends on a failed one
  // is skipped, not failed again.
  checks.push({ name: "asset", result: assetLogs.length > 0 ? "pass" : "fail", detail: assetLogs.length > 0 ? `a Transfer from ${att.asset}` : `no Transfer event from the attested asset ${att.asset}` });
  if (assetLogs.length === 0) {
    checks.push({ name: "payee", result: "skip", detail: "no Transfer of the attested asset to look at" });
    checks.push({ name: "amount", result: "skip", detail: "no Transfer of the attested asset to look at" });
  } else {
    checks.push({ name: "payee", result: toPayee.length > 0 ? "pass" : "fail", detail: toPayee.length > 0 ? `to ${payTo}` : `no Transfer of ${att.asset} to ${payTo}` });
    checks.push(toPayee.length > 0
      ? { name: "amount", result: best >= required ? "pass" : "fail", detail: `${best} units to the payee, ${required} attested` }
      : { name: "amount", result: "skip", detail: "no Transfer to the payee to measure" });
  }
  const ok = checks.every((c) => c.result === "pass" || c.result === "skip");
  return { rpc: url, checks, outcome: ok ? "pass" : "fail", observed };
}

function keyFrom(keys: PaymentKey[], id: string): KeyObject | string {
  const m = keys.filter((k) => k && k.key_id === id);
  if (m.length !== 1) return `the key set has ${m.length} entries for key_id ${id}`;
  const hex = m[0]!.public_key;
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) return `key ${id} is not 32 bytes of hex`;
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

export async function verifyPaymentAttestation(attestationJson: unknown, opts: PaymentVerifyOptions): Promise<PaymentVerdict> {
  const checks: PaymentCheck[] = [];
  const f = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? RPC_TIMEOUT_MS;
  const stop = (name: string, result: "fail" | "unknown", detail: string) => {
    checks.push({ name, result, detail });
    return verdictOf(checks, [], result === "fail" ? "CONTRADICTED" : "UNESTABLISHED", `${name}: ${detail}`);
  };
  try {
    // Input: one object whose signed members are all strings.
    let att: unknown = attestationJson;
    if (typeof att === "string") {
      try { att = JSON.parse(att); } catch { return stop("input", "unknown", "the attestation is not JSON"); }
    }
    if (typeof att !== "object" || att === null || Array.isArray(att)) return stop("input", "unknown", "the attestation is not a JSON object");
    const a = att as Record<string, unknown>;
    for (const k of [...PAYMENT_ATTESTATION_FIELDS, "signature"]) {
      if (typeof a[k] !== "string") return stop("input", "unknown", `member ${k} is missing or not a string`);
    }
    const s = a as Attestation;
    if (!/^0x[0-9a-fA-F]{40}$/.test(opts.payTo ?? "")) return stop("input", "unknown", "the payee address (payTo) is not a 0x-prefixed 20-byte address");
    if (!/^(0|[1-9][0-9]*)$/.test(s.amount_units)) return stop("input", "unknown", "amount_units is not a non-negative integer");
    checks.push({ name: "input", result: "pass", detail: "an attestation object with every signed member" });

    // (b) The type, before the signature: an attestation is never a receipt.
    if (s.type !== PAYMENT_ATTESTATION_TYPE) return stop("type", "fail", `type is ${JSON.stringify(s.type)}, not ${PAYMENT_ATTESTATION_TYPE}`);
    checks.push({ name: "type", result: "pass", detail: PAYMENT_ATTESTATION_TYPE });

    // (a) The signature, against the published key set. Nothing below runs
    // unless the statement is Headless Oracle's.
    let keys = opts.keys;
    if (!keys) {
      const url = opts.keysUrl ?? DEFAULT_PAYMENT_KEYS_URL;
      const bad = checkUrl(url, "--keys");
      if (bad) return stop("key", "unknown", bad);
      try {
        const res = await f(url, { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
        if (res.status !== 200) return stop("key", "unknown", `GET ${url} returned ${res.status}`);
        const body = JSON.parse(await res.text()) as { keys?: unknown };
        if (!Array.isArray(body.keys)) return stop("key", "unknown", `${url} has no keys[] array`);
        keys = body.keys as PaymentKey[];
      } catch (e) {
        return stop("key", "unknown", `GET ${url} failed: ${(e as Error).message}`);
      }
    }
    const key = keyFrom(keys, s.public_key_id);
    if (typeof key === "string") return stop("key", "unknown", key);
    checks.push({ name: "key", result: "pass", detail: `key_id ${s.public_key_id}` });
    const { signature, ...unsigned } = s;
    let sigOk = false;
    if (/^[0-9a-f]{128}$/.test(signature)) {
      try { sigOk = cryptoVerify(null, jcsBytes(unsigned), key, Buffer.from(signature, "hex")); } catch { sigOk = false; }
    }
    if (!sigOk) return stop("signature", "fail", "the Ed25519 signature does not verify over the attestation's JCS bytes: this is not Headless Oracle's statement, or it was changed");
    checks.push({ name: "signature", result: "pass", detail: "Ed25519 over the JCS bytes of every member but signature" });

    // (c) The receipt binding, when the caller holds the receipt.
    if (opts.receipt !== undefined) {
      let rc: unknown = opts.receipt;
      if (typeof rc === "string") {
        try { rc = JSON.parse(rc); } catch { return stop("receipt", "unknown", "the receipt is not JSON"); }
      }
      if (typeof rc !== "object" || rc === null || Array.isArray(rc)) return stop("receipt", "unknown", "the receipt is not a JSON object");
      const r = rc as Record<string, unknown>;
      const hash = `sha256:${sha256Hex(jcsBytes(r))}`;
      if (hash !== s.receipt_sha256) return stop("receipt_sha256", "fail", `the receipt hashes to ${hash}; the attestation binds ${s.receipt_sha256}`);
      checks.push({ name: "receipt_sha256", result: "pass", detail: "the receipt's JCS bytes, signature included, hash to the bound value" });
      const id = sha256Hex(jcsBytes({ count: r.count, kid: r.kid, last_entry_hash: r.last_entry_hash, session_id: r.session_id }));
      if (id !== s.checkpoint_id) return stop("checkpoint_id", "fail", `the receipt's identity gives ${id}; the attestation binds ${s.checkpoint_id}`);
      checks.push({ name: "checkpoint_id", result: "pass", detail: "the receipt's kid, session_id, count and last_entry_hash give the bound id" });
    } else {
      checks.push({ name: "receipt_sha256", result: "skip", detail: "no receipt given" });
    }

    // (d), (e) The chain.
    if (!BASE_NETWORKS.has(s.network)) return stop("network", "unknown", `the attested network ${JSON.stringify(s.network)} is not Base mainnet; only Base is checked`);
    checks.push({ name: "network", result: "pass", detail: `${s.network} is Base mainnet (chain ${BASE_CHAIN_ID})` });
    if (s.settlement !== "settled" && s.settlement !== "failed") return stop("settlement", "unknown", `settlement is ${JSON.stringify(s.settlement)}`);
    if (s.settlement === "failed" && s.transaction === "") {
      checks.push({ name: "settlement", result: "pass", detail: 'attested "failed" and names no transaction: there is nothing on chain to check' });
      return verdictOf(checks, [], "VERIFIED", "The signed statement says the settlement failed and names no transaction; the checkpoint was not charged.");
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(s.transaction)) return stop("input", "unknown", "transaction is not a 32-byte 0x-prefixed hash");
    const urls = (Array.isArray(opts.rpcUrl) ? opts.rpcUrl : [opts.rpcUrl]).filter((u) => typeof u === "string" && u !== "");
    if (urls.length === 0) return stop("rpc_url", "unknown", "no RPC URL given");
    const nodes: NodeObservation[] = [];
    for (const url of urls) nodes.push(await observeNode(f, url, s, opts.payTo, timeoutMs));

    const unknownNode = nodes.find((n) => n.outcome === "unknown");
    if (unknownNode) {
      const c = unknownNode.checks[unknownNode.checks.length - 1]!;
      return verdictOf(checks, nodes, "UNESTABLISHED", `${unknownNode.rpc}: ${c.name}: ${c.detail}`);
    }
    const sig = (n: NodeObservation) => JSON.stringify([n.outcome, n.observed]);
    if (nodes.some((n) => sig(n) !== sig(nodes[0]!))) {
      return verdictOf(checks, nodes, "UNESTABLISHED", `the RPC nodes disagree: ${nodes.map((n) => `${n.rpc} ${n.outcome} ${JSON.stringify(n.observed)}`).join("; ")}`);
    }
    const first = nodes[0]!;
    const failedCheck = first.checks.find((c) => c.result === "fail");
    if (failedCheck) return verdictOf(checks, nodes, "CONTRADICTED", `${failedCheck.name}: ${failedCheck.detail}`);
    const agreed = nodes.length > 1 ? `${nodes.length} nodes agree` : "1 node (check a second one)";
    return verdictOf(checks, nodes, "VERIFIED", s.settlement === "failed"
      ? `The signed statement says the settlement failed, and the chain shows no successful transfer to the payee (${agreed}).`
      : `Transaction ${s.transaction} moved ${first.observed!.matching_units} units of ${s.asset} to ${opts.payTo} and succeeded, as Headless Oracle's signed statement says (${agreed}).`);
  } catch (e) {
    return stop("internal", "unknown", `unexpected error: ${(e as Error).message}`);
  }
}
