// TEST FIXTURES for the refusal tests (test/refusals.mjs): logs, checkpoints,
// payments, blocks, instructions and gate receipts made with throwaway test
// keys derived at run time from the public seed strings below. Nothing these
// keys sign is evidence of anything, and no transaction here was broadcast.

import { createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import {
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  parseAbi,
  parseTransaction,
  toHex,
  toRlp,
} from "viem";
import { privateKeyToAccount, sign as secpSign } from "viem/accounts";
import { jcs, jcsSha256, okpThumbprint, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { AUTHORIZATION_USED_TOPIC, EIP3009_ABI, headerHash, TRANSFER_TOPIC, USEROP_ABI } from "../../ordering-evidence-h4/lib/evm.mjs";
import { requestCommitment } from "../lib/records.mjs";

const SEED = "chirindo examples/evidence-bundle TEST KEY, public seed, never for real use: ";
export const testSecp = (label) => keccak256(toHex(SEED + label));
export const testAccount = (label) => privateKeyToAccount(testSecp(label));
export const testAddress = (label) => getAddress("0x" + keccak256(toHex("chirindo evidence-bundle TEST ADDRESS: " + label)).slice(-40));
export function testEd(label) {
  const seed = Buffer.from(keccak256(toHex(SEED + label)).slice(2), "hex");
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x;
  return { priv, x, kid: okpThumbprint(x) };
}
const testValue = (label) => keccak256(toHex("chirindo evidence-bundle TEST VALUE: " + label));

export const q = (v) => "0x" + BigInt(v).toString(16);
const pad32 = (addr) => "0x" + addr.toLowerCase().slice(2).padStart(64, "0");
const word = (v) => "0x" + BigInt(v).toString(16).padStart(64, "0");
export const json = (v) => Buffer.from(JSON.stringify(v), "utf8");
export const pretty = (v) => Buffer.from(JSON.stringify(v, null, 2), "utf8");

export const jwkOf = (k) => ({ kty: "OKP", crv: "Ed25519", x: k.x, kid: k.kid });
export const jwksOf = (...ks) => json({ keys: ks.map(jwkOf) });

// A chirindo-evidence.action/1 log signed by a test key. `edit(records)` may
// change the unsigned records before they are linked and signed; record i
// names receiptUids[i] when that is given.
export function chirindoLog({ k, sessionId, n = 1, argsHash, resultHash, jwksUri, receiptUid, receiptUids = [], edit, t0 = Date.parse("2026-10-20T10:00:00.000Z") }) {
  let recs = [];
  for (let i = 0; i < n; i++) {
    const event = { type: "mcp_call", outcome: "executed", server: "evidence-bundle-test", tool_name: "test_tool", args_hash: argsHash, decision: "allow", decision_source: "config" };
    if (resultHash) event.result_hash = resultHash;
    const rc = requestCommitment(event);
    const r = {
      v: "evidence.action/1",
      seq: i,
      session_id: sessionId,
      ts: new Date(t0 + 1000 * i).toISOString(),
      agent: { vendor: "chirindo", version: "0.5.3" },
      event,
      request_commitment: rc,
      ["gate"]: { request_commitment: rc, gate_receipt: jcsSha256({ test: "gate receipt", seq: i }), gate_family: "permit", result: "act" },
      key_thumbprint: k.kid,
      iss: jwksUri ? new URL(jwksUri).origin : `urn:chirindo:key:${k.kid}`,
      kid: k.kid,
    };
    if (jwksUri) r.jwks_uri = jwksUri;
    if (receiptUid && i === 0) r.receipt_uid = receiptUid;
    if (receiptUids[i]) r.receipt_uid = receiptUids[i];
    recs.push(r);
  }
  if (edit) recs = edit(recs);
  let prev = jcsSha256({ v: "evidence.action/1", session_id: sessionId, marker: "genesis" });
  const out = [];
  const hashes = [];
  for (const r of recs) {
    const e = { ...r, prev_hash: prev };
    e.sig = edSign(null, Buffer.from(jcs(e), "utf8"), k.priv).toString("base64url");
    prev = jcsSha256(withoutMember(e, "sig"));
    hashes.push(prev);
    out.push(e);
  }
  return { records: out, hashes, bytes: Buffer.from(out.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8") };
}

// A jcs-sha256-chain/0.1 log (spec Annex B) signed by a test key. Record i
// names receiptUids[i] when that is given; `edit(record, i)` may change a
// record before it is linked and signed.
export function annexBLog({ k, sessionId, n = 1, receiptUid, receiptUids = [], argsHash, edit }) {
  let prev = jcsSha256({ v: "test.annex-b/1", session_id: sessionId, marker: "genesis" });
  const out = [];
  const hashes = [];
  for (let i = 0; i < n; i++) {
    let e = { v: "test.annex-b/1", seq: i, session_id: sessionId, prev_hash: prev, kid: k.kid, note: "TEST FIXTURE record" };
    if (receiptUid && i === 0) e.receipt_uid = receiptUid;
    if (receiptUids[i]) e.receipt_uid = receiptUids[i];
    if (argsHash) e.args_hash = argsHash;
    if (edit) e = edit(e, i);
    e.sig = edSign(null, Buffer.from(jcs(e), "utf8"), k.priv).toString("base64url");
    prev = jcsSha256(withoutMember(e, "sig"));
    hashes.push(prev);
    out.push(e);
  }
  return { records: out, hashes, bytes: Buffer.from(out.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8") };
}

// A checkpoint signed by a test key (the served witness spec's shape).
export function checkpoint({ k, sessionId, count, lastEntryHash, ts = "2026-10-20T10:00:05.000Z" }) {
  const c = { v: "evidence.action/1", type: "checkpoint", session_id: sessionId, count, last_entry_hash: lastEntryHash, ts, kid: k.kid };
  c.sig = edSign(null, Buffer.from(jcs(c), "utf8"), k.priv).toString("base64url");
  return c;
}
export const sidecarLine = (cp, receipt = null, error = receipt ? null : "TEST FIXTURE: not submitted to a witness") => Buffer.from(JSON.stringify({ checkpoint: cp, witness_receipt: receipt, witness_error: error }) + "\n", "utf8");

// An Annex A instruction signed by a test principal key; `constraints`
// replaces or adds constraint members.
export function instruction({ principal, agentKid, payee, token, constraints = {} }) {
  const ins = {
    v: "signed-instruction-ed25519/0.2",
    principal: { kid: principal.kid, public_key_jwk: { kty: "OKP", crv: "Ed25519", x: principal.x } },
    agent_kid: [agentKid],
    text: "TEST FIXTURE instruction: pay up to 0.01 test USDC to one payee",
    constraints: { chain_id: "eip155:84532", asset: token, max_amount: "10000", payees: [payee], valid_from: "2026-10-01T00:00:00Z", valid_until: "2026-12-31T00:00:00Z", ...constraints },
    iat: "2026-10-01T00:00:00Z",
  };
  ins.sig = edSign(null, Buffer.from(jcs(ins), "utf8"), principal.priv).toString("base64url");
  return ins;
}

// A TEST issuer's profile and one EIP-712 gate receipt under it (spec Annex C,
// in the issuer profile format of examples/ordering-evidence-h4/README.md).
const CHECK_FIELDS = [
  ["decision", "string"],
  ["action", "string"],
  ["requestDigest", "bytes32"],
  ["evaluatedAt", "uint256"],
  ["expiresAt", "uint256"],
  ["formatVersion", "uint256"],
].map(([name, type]) => ({ name, type }));
const CHECK_LAYOUT = { domain: { name: "Example Test Issuer Checks (TEST FIXTURE)", version: "1", chainId: 84532 }, types: { TestCheck: CHECK_FIELDS }, primaryType: "TestCheck" };
export function issuerProfile(issuerAddress, label = "TEST FIXTURE issuer profile; its signer is a throwaway test key") {
  return {
    format: "chirindo-h4-issuer-profile/1",
    label,
    test: true,
    issuer: "Example Test Issuer (TEST FIXTURE, not a real issuer)",
    chain_id: 84532,
    // The Base Sepolia test token the verifier's pins name: read and reported.
    tokens: [{ address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e", name: "USDC", version: "2" }],
    receipt: { eip712: CHECK_LAYOUT, fields: { checked_at: "evaluatedAt", valid_until: "expiresAt", request_hash: "requestDigest", verdict: "decision", schema_version: "formatVersion" }, schema_version: 1 },
    envelope: { unwrap: [], required: ["id", "format_version", "signer", "sig", "payload"], optional: ["expires_at", "ttl_seconds", "layout"], uid: "id", signature: "sig", signer: "signer", message: "payload", schema_version: "format_version", valid_until: "expires_at", valid_for_seconds: "ttl_seconds", layout: "layout" },
    signers: [{ address: issuerAddress.toLowerCase(), key_id: "test-issuer-key-1", valid_from: "2026-01-01T00:00:00.000Z", valid_until: null }],
  };
}
// `o` may set the signed decision, action, evaluatedAt and expiresAt.
export async function gateReceipt(issuerPk, o = {}) {
  const data = { decision: "allow", action: "test", requestDigest: testValue("request"), evaluatedAt: 1792000000, expiresAt: 1792000600, formatVersion: 1, ...o };
  const msg = {};
  for (const f of CHECK_FIELDS) msg[f.name] = f.type === "uint256" ? BigInt(data[f.name]) : data[f.name];
  const uid = hashTypedData({ ...CHECK_LAYOUT, message: msg });
  const sig = await secpSign({ hash: uid, privateKey: issuerPk, to: "hex" });
  return { uid, sealed: { id: uid, format_version: 1, signer: privateKeyToAccount(issuerPk).address, sig, payload: data } };
}

const TWA = (n) => EIP3009_ABI.find((f) => f.name === "transferWithAuthorization" && f.inputs.length === n);
const RWA = (n) => EIP3009_ABI.find((f) => f.name === "receiveWithAuthorization" && f.inputs.length === n);
const AUTH_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const RECEIVE_TYPES = { ReceiveWithAuthorization: AUTH_TYPES.TransferWithAuthorization };

// An EIP-3009 authorization signed by `signerPk` (normally the payer's key).
export async function authorization({ token, chainId, from, to, value, validAfter, validBefore, nonce, signerPk, receive = false }) {
  const domain = { name: "USDC", version: "2", chainId, verifyingContract: token };
  const message = { from, to, value, validAfter, validBefore, nonce };
  const digest = receive ? hashTypedData({ domain, types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization", message }) : hashTypedData({ domain, types: AUTH_TYPES, primaryType: "TransferWithAuthorization", message });
  const s = await secpSign({ hash: digest, privateKey: signerPk });
  return { ...message, v: Number(s.v), r: s.r, s: s.s };
}

// Calldata for each call shape the refusal tests carry.
export function callData(kind, a, extra = {}) {
  if (kind === "handleOps") return encodeFunctionData({ abi: [USEROP_ABI[1]], functionName: "handleOps", args: [[], extra.beneficiary] });
  const args9 = [a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s];
  const sig65 = a.r + a.s.slice(2) + a.v.toString(16).padStart(2, "0");
  if (kind === "twa9") return encodeFunctionData({ abi: [TWA(9)], functionName: "transferWithAuthorization", args: args9 });
  if (kind === "receive9") return encodeFunctionData({ abi: [RWA(9)], functionName: "receiveWithAuthorization", args: args9 });
  if (kind === "twaBytes64") return encodeFunctionData({ abi: [TWA(7)], functionName: "transferWithAuthorization", args: [a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce, a.r + a.s.slice(2)] });
  if (kind === "twaBytes65") return encodeFunctionData({ abi: [TWA(7)], functionName: "transferWithAuthorization", args: [a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce, sig65] });
  throw new Error(`no call shape ${kind}`);
}

// A signed transaction of type 0x0 (EIP-155), 0x1, 0x2 or 0x4 in JSON-RPC
// form, with its hash, from and the fields of its block.
export async function signedTx({ type, chainId, senderPk, to, value = 0n, input, nonce = 7, authorizationList, accessList = [] }) {
  const account = privateKeyToAccount(senderPk);
  const base = { chainId, nonce, gas: 200000n, to, value, data: input };
  let unsigned;
  if (type === "0x0") unsigned = { ...base, type: "legacy", gasPrice: 6000000n };
  else if (type === "0x1") unsigned = { ...base, type: "eip2930", gasPrice: 6000000n, accessList: [] };
  else if (type === "0x2") unsigned = { ...base, type: "eip1559", maxFeePerGas: 7000000n, maxPriorityFeePerGas: 1000000n, accessList };
  else if (type === "0x4") unsigned = { ...base, type: "eip7702", maxFeePerGas: 7000000n, maxPriorityFeePerGas: 1000000n, accessList: [], authorizationList };
  const signedHex = await account.signTransaction(unsigned);
  const sig = parseTransaction(signedHex);
  const yParity = type === "0x0" ? Number((sig.v - 35n) % 2n) : Number(sig.yParity);
  const tx = { type, chainId: q(chainId), nonce: q(nonce), gas: q(base.gas) };
  if (type === "0x0" || type === "0x1") tx.gasPrice = q(unsigned.gasPrice);
  else Object.assign(tx, { maxFeePerGas: q(unsigned.maxFeePerGas), maxPriorityFeePerGas: q(unsigned.maxPriorityFeePerGas) });
  tx.to = to === null ? null : to.toLowerCase();
  tx.value = q(value);
  if (type !== "0x0") tx.accessList = type === "0x2" ? accessList.map((e) => ({ address: e.address.toLowerCase(), storageKeys: e.storageKeys })) : [];
  if (type === "0x4")
    tx.authorizationList = authorizationList.map((t) => ({ chainId: q(t.chainId), address: t.address.toLowerCase(), nonce: q(t.nonce), yParity: q(t.yParity), r: q(BigInt(t.r)), s: q(BigInt(t.s)) }));
  tx.input = input;
  tx.r = q(BigInt(sig.r));
  tx.s = q(BigInt(sig.s));
  if (type === "0x0") tx.v = q(sig.v);
  else Object.assign(tx, { yParity: q(yParity), v: q(yParity) });
  tx.hash = keccak256(signedHex);
  tx.from = account.address.toLowerCase();
  return tx;
}

// The block, receipt and transaction of one payment, consistent with each
// other: the block's header hash recomputes, it lists the transaction at
// `index`, and the receipt and its logs name both.
// With `rawTransactions` (each an EIP-2718 encoding, the payment's last), the
// block lists their hashes and its transactionsRoot is their trie root.
export function placeInBlock({ tx, logs, baseBlock, number = 50000000n, timestamp, parentHash, stateRoot, index = 1, rawTransactions }) {
  const block = { ...baseBlock };
  block.number = q(number);
  block.timestamp = q(timestamp);
  if (parentHash) block.parentHash = parentHash;
  if (stateRoot) block.stateRoot = stateRoot;
  block.transactions = Array.from({ length: index + 1 }, (_, i) => (i === index ? tx.hash : testValue(`tx ${i} of the test block`)));
  if (rawTransactions) {
    index = rawTransactions.length - 1;
    block.transactions = rawTransactions.map((r) => keccak256(r));
    block.transactionsRoot = transactionsRoot(rawTransactions);
  }
  delete block.hash;
  block.hash = headerHash(block).recomputed;
  const placed = { ...tx, blockHash: block.hash, blockNumber: block.number, transactionIndex: q(index), blockTimestamp: block.timestamp };
  const receipt = {
    type: tx.type,
    status: "0x1",
    cumulativeGasUsed: "0x30000",
    logs: logs.map((l, i) => ({ address: l.address, topics: l.topics, data: l.data, blockHash: block.hash, blockNumber: block.number, blockTimestamp: block.timestamp, transactionHash: tx.hash, transactionIndex: q(index), logIndex: q(i + 3), removed: false })),
    logsBloom: "0x" + "00".repeat(256),
    transactionHash: tx.hash,
    transactionIndex: q(index),
    blockHash: block.hash,
    blockNumber: block.number,
    gasUsed: "0x20000",
    effectiveGasPrice: "0x5b8d80",
    from: tx.from,
    to: tx.to,
    contractAddress: tx.to === null ? testAddress("created contract").toLowerCase() : null,
  };
  return { tx: placed, receipt, block };
}

export const eip3009Logs = (token, a) => [
  { address: token, topics: [AUTHORIZATION_USED_TOPIC, pad32(a.from), a.nonce], data: "0x" },
  { address: token, topics: [TRANSFER_TOPIC, pad32(a.from), pad32(a.to)], data: word(a.value) },
];

// A single-account state trie: its root, and the proof of that account
// (EIP-1186 accountProof) as one leaf node; `codeHash` the account's (no code
// when absent).
export function singleAccountTrie({ address, nonce = 0n, balance = 0n, codeHash = keccak256("0x") }) {
  const storageHash = keccak256(toRlp("0x"));
  const path = keccak256(address.toLowerCase());
  const rq = (v) => (v === 0n ? "0x" : q(v).length % 2 ? "0x0" + q(v).slice(2) : q(v));
  const value = toRlp([rq(nonce), rq(balance), storageHash, codeHash]);
  const leaf = toRlp(["0x20" + path.slice(2), value]);
  return { root: keccak256(leaf), proof: [leaf], result: { address: address.toLowerCase(), accountProof: [leaf], balance: q(balance), codeHash, nonce: q(nonce), storageHash, storageProof: [] } };
}

export const ROUTER_ABI = parseAbi(["function testPull(bytes32 ref) payable"]);

// The transactions root of a list of raw transactions (EIP-2718: the root of
// patriciaTrie(rlp(index) => transaction)), built here for the test blocks, apart
// from the verifier's own reading of it: each node an RLP list, inlined in its
// parent when its encoding is under 32 bytes, else referenced by its keccak-256.
export function transactionsRoot(raws) {
  const nib = (hex) => [...hex.slice(2)].map((c) => parseInt(c, 16));
  const hp = (path, leaf) => "0x" + [((leaf ? 2 : 0) + (path.length % 2)), ...(path.length % 2 ? [] : [0]), ...path].map((n) => n.toString(16)).join("");
  const ref = (node) => (toRlp(node).length - 2 < 64 ? node : keccak256(toRlp(node)));
  const node = (pairs, d) => {
    if (pairs.length === 1) return [hp(pairs[0].k.slice(d), true), pairs[0].v];
    let p = 0;
    while (pairs.every((x) => x.k[d + p] !== undefined && x.k[d + p] === pairs[0].k[d + p])) p++;
    if (p > 0) return [hp(pairs[0].k.slice(d, d + p), false), ref(node(pairs, d + p))];
    const branch = Array.from({ length: 16 }, (_, i) => {
      const sub = pairs.filter((x) => x.k[d] === i);
      return sub.length ? ref(node(sub, d + 1)) : "0x";
    });
    return [...branch, pairs.find((x) => x.k.length === d)?.v ?? "0x"];
  };
  const pairs = raws.map((v, i) => ({ k: nib(toRlp(i === 0 ? "0x" : q(i).length % 2 ? "0x0" + q(i).slice(2) : q(i))), v }));
  return keccak256(toRlp(node(pairs, 0)));
}
export { testValue, withoutMember };
