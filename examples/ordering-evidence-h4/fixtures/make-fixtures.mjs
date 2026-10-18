// Builds the TEST FIXTURES for check-h4.mjs from public seed strings, so
// anyone can rebuild them byte for byte (`node fixtures/write-fixtures.mjs`
// writes fixtures/test-pins, fixtures/calldata and fixtures/eip3009).
//
// Every key here is a throwaway test key derived from a seed string printed
// in this file. Nothing these keys sign is evidence of anything: the issuer
// is a made-up TEST issuer with a made-up receipt layout, the witness key is
// a STUB that Headless Oracle never uses, the chain id is 31337 (a local test
// chain id, which the test profile names), and no transaction here was ever
// broadcast. These fixtures only show the checks working.

import { createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { encodeFunctionData, getAddress, hashTypedData, keccak256, parseAbi, serializeTransaction, toHex, toRlp } from "viem";
import { privateKeyToAccount, sign as secpSign } from "viem/accounts";
import { jcs, jcsSha256, okpThumbprint, sha256Hex, withoutMember } from "../lib/formats.mjs";

const SEED = "chirindo examples/ordering-evidence-h4 TEST KEY, public seed, never for real use: ";
export const CHAIN_ID = 31337;

export const testSecp = (label) => keccak256(toHex(SEED + label));
export const testAddress = (label) => getAddress("0x" + keccak256(toHex("chirindo h4 TEST ADDRESS: " + label)).slice(-40));
export function testEd(label) {
  const seed = Buffer.from(keccak256(toHex(SEED + label)).slice(2), "hex");
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const x = createPublicKey(key).export({ format: "jwk" }).x;
  return { key, x, pub: Buffer.from(x, "base64url") };
}

export const KEYS = {
  issuer: testSecp("test issuer signing key"),
  sampleIssuer: testSecp("test issuer sample-role key"),
  otherIssuer: testSecp("a key the test issuer profile does not list"),
  trader: testSecp("trader wallet"),
  relayer: testSecp("relayer that moves no value"),
  payer: testSecp("EIP-3009 payer"),
  facilitator: testSecp("payment facilitator"),
};
export const LOG_KEY = testEd("log key");
export const STUB_WITNESS = testEd("STUB witness key");
export const OTHER_STUB_WITNESS = testEd("another STUB witness key");

// The made-up TEST issuer's receipt layout and request layout. They exist
// only here; no real issuer signs under these domains.
const CHECK_FIELDS = [
  ["decision", "string"], ["testChain", "uint256"], ["action", "string"], ["sourceAsset", "string"], ["destinationAsset", "string"],
  ["testNotional", "uint256"], ["riskScoreBps", "uint256"], ["requestDigest", "bytes32"], ["evaluatedAt", "uint256"], ["expiresAt", "uint256"],
  ["formatVersion", "uint256"],
].map(([name, type]) => ({ name, type }));
const REQUEST_FIELDS = [["testChain", "uint256"], ["sourceAsset", "string"], ["destinationAsset", "string"], ["action", "string"], ["testNotional", "uint256"]].map(([name, type]) => ({ name, type }));
export const CHECK_LAYOUT = { domain: { name: "Example Test Issuer Checks (TEST FIXTURE)", version: "1", chainId: CHAIN_ID }, types: { TestTradeCheck: CHECK_FIELDS }, primaryType: "TestTradeCheck" };
export const REQUEST_LAYOUT = { domain: { name: "Example Test Issuer Requests (TEST FIXTURE)", version: "1", chainId: CHAIN_ID }, types: { TestTradeRequest: REQUEST_FIELDS }, primaryType: "TestTradeRequest" };
export const TEST_KEYS_URL = "https://test-issuer.invalid/keys.json";
// The made-up EIP-3009 token of the eip3009 fixture, which the test profile names.
export const TEST_TOKEN = { address: testAddress("test USD token"), name: "Example Test Token (TEST FIXTURE)", version: "2" };

const addrOf = (pk) => privateKeyToAccount(pk).address;

// The TEST issuer's profile (README.md, "Issuer profiles"). A deep copy each
// time, so an edit in a test cannot reach the shared layouts.
export function testProfile() {
  return structuredClone({
    format: "chirindo-h4-issuer-profile/1",
    label: "TEST FIXTURE issuer profile: a made-up issuer whose keys are throwaway test keys from public seed strings in fixtures/make-fixtures.mjs; not a real issuer",
    test: true,
    issuer: "Example Test Issuer (TEST FIXTURE, not a real issuer)",
    chain_id: CHAIN_ID,
    tokens: [{ address: TEST_TOKEN.address.toLowerCase(), name: TEST_TOKEN.name, version: TEST_TOKEN.version }],
    receipt: {
      eip712: CHECK_LAYOUT,
      fields: { checked_at: "evaluatedAt", valid_until: "expiresAt", request_hash: "requestDigest", verdict: "decision", schema_version: "formatVersion" },
      schema_version: 1,
    },
    envelope: {
      unwrap: ["result.receipt"],
      required: ["id", "format_version", "signer", "sig", "payload"],
      optional: ["label", "issued_at", "ttl_seconds", "expires_at", "info_url", "layout"],
      uid: "id",
      signature: "sig",
      signer: "signer",
      message: "payload",
      schema_version: "format_version",
      valid_until: "expires_at",
      valid_for_seconds: "ttl_seconds",
      layout: "layout",
      request_layout: { domain: "request_domain", types: "request_types", primaryType: "request_primary_type" },
    },
    request: { eip712: REQUEST_LAYOUT },
    signers: [{ address: addrOf(KEYS.issuer).toLowerCase(), key_id: "test-issuer-key-1", valid_from: "2026-01-01T00:00:00.000Z", valid_until: null }],
    key_document: { url: TEST_KEYS_URL, keys: "keys", address: "address", key_id: "id", valid_from: "valid_from", valid_until: "valid_until", require: { revoked: false }, role: "role", accepted_roles: ["production"], layout: "formats.check" },
  });
}

// What the TEST issuer serves at TEST_KEYS_URL (read by the --online tests).
export function testKeyDocument() {
  return structuredClone({
    note: "TEST FIXTURE key document of a made-up issuer; its keys are throwaway test keys",
    keys: [
      { id: "test-issuer-key-1", address: addrOf(KEYS.issuer), valid_from: "2026-01-01T00:00:00.000Z", valid_until: null, revoked: false },
      { id: "test-issuer-sample", address: addrOf(KEYS.sampleIssuer), valid_from: "2026-01-01T00:00:00.000Z", valid_until: null, revoked: false, role: "sample" },
    ],
    formats: { check: CHECK_LAYOUT },
  });
}

export function witnessKeysResponse(stub = STUB_WITNESS, keyId = "stub_test_v1") {
  return {
    keys: [{ key_id: keyId, algorithm: "Ed25519", format: "hex", public_key: stub.pub.toString("hex"), valid_from: "2026-01-01T00:00:00Z", valid_until: null }],
    note: "STUB witness key for the test fixtures of examples/ordering-evidence-h4. It is not Headless Oracle's key, Headless Oracle never signs with it, and a receipt signed with it is not a witness record.",
  };
}

// Files are Buffers. Documents whose bytes are pinned by sha256 are written
// compact with no line feed, so a checkout that converts line endings cannot
// change them; the rest are 2-space JSON with a final newline.
export const compact = (v) => Buffer.from(JSON.stringify(v), "utf8");
const pretty = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8");

// profiles: the profile files (Buffers) the test pins accept, by sha256.
export function testPins({ stub = STUB_WITNESS, keyId = "stub_test_v1", label, profiles } = {}) {
  const keys = compact(witnessKeysResponse(stub, keyId));
  const files = new Map();
  files.set("v5-keys.response.json", keys);
  files.set(
    "pins.json",
    pretty({
      format: "chirindo-h4-pins/2",
      label: label ?? "TEST FIXTURE PINS: the TEST issuer profile and a STUB witness key, both from public seed strings in fixtures/make-fixtures.mjs; not a real issuer's and not Headless Oracle's keys",
      test: true,
      witness_keys: { file: "v5-keys.response.json", url: "https://test-fixture.invalid/v5/keys", fetched_at: "2026-10-16T00:00:00.000Z", bytes: keys.length, sha256: sha256Hex(keys), key_id: keyId, public_key_hex: stub.pub.toString("hex") },
      issuer_profiles: (profiles ?? [compact(testProfile())]).map((b) => ({ label: "the TEST FIXTURE issuer profile", sha256: sha256Hex(b) })),
    }),
  );
  return files;
}

const iso = (s) => new Date(s * 1000).toISOString();
const h = (label) => keccak256(toHex("chirindo h4 TEST VALUE: " + label));
const qty = (v) => "0x" + BigInt(v).toString(16);

function checkFor({ role, checkedAt, verdict, signKey = KEYS.issuer, claimedSigner, formatVersion = 1 }) {
  const src = role === "source";
  const req = {
    testChain: CHAIN_ID,
    sourceAsset: src ? `eip155:${CHAIN_ID}/slip44:60` : `eip155:${CHAIN_ID}/erc20:${testAddress("test token out").toLowerCase()}`,
    destinationAsset: src ? `eip155:${CHAIN_ID}/erc20:${testAddress("test token out").toLowerCase()}` : `eip155:${CHAIN_ID}/slip44:60`,
    action: "swap",
    testNotional: 2500000,
  };
  const reqMsg = { ...req, testChain: BigInt(req.testChain), testNotional: BigInt(req.testNotional) };
  const requestDigest = hashTypedData({ ...REQUEST_LAYOUT, message: reqMsg });
  const data = {
    decision: verdict,
    testChain: CHAIN_ID,
    action: "swap",
    sourceAsset: req.sourceAsset,
    destinationAsset: req.destinationAsset,
    testNotional: 2500000,
    riskScoreBps: src ? 120 : 340,
    requestDigest,
    evaluatedAt: checkedAt,
    expiresAt: checkedAt + 600,
    formatVersion,
  };
  const msg = {};
  for (const f of CHECK_FIELDS) msg[f.name] = f.type === "uint256" ? BigInt(data[f.name]) : data[f.name];
  const uid = hashTypedData({ ...CHECK_LAYOUT, message: msg });
  return { req, uid, data, signKey, claimedSigner, checkedAt };
}

async function sealCheck(e) {
  const sig = await secpSign({ hash: e.uid, privateKey: e.signKey, to: "hex" });
  return {
    id: e.uid,
    format_version: 1,
    signer: e.claimedSigner ?? addrOf(e.signKey),
    label: "TEST issuer (fixture), not a real issuer",
    issued_at: iso(e.checkedAt).replace(".000Z", ".417Z"),
    ttl_seconds: 600,
    expires_at: e.data.expiresAt,
    sig,
    info_url: "https://test-issuer.invalid/receipts",
    payload: e.data,
    layout: { ...CHECK_LAYOUT, request_domain: REQUEST_LAYOUT.domain, request_types: REQUEST_LAYOUT.types, request_primary_type: REQUEST_LAYOUT.primaryType },
  };
}

// editEntries (tests only) changes the entries before they are linked, so a
// broken rule can be built into a log that is otherwise well formed.
function logEntries({ sessionId, uids, t0, sign, extraEntry = false, editEntries }) {
  const v = "test.h4-log/1";
  let base = ["source", "destination"].map((role, k) => ({ v, seq: k, session_id: sessionId, receipt_uid: uids[k], role, ts: iso(t0 + 1 + 2 * k) }));
  if (extraEntry) base.push({ v, seq: 2, session_id: sessionId, role: "after the checkpoint", ts: iso(t0 + 8) });
  if (editEntries) base = editEntries(base);
  const entries = [];
  let prev = jcsSha256({ v: base[0].v, session_id: base[0].session_id, marker: "genesis" });
  for (const b of base) {
    const e = { v: b.v, seq: b.seq, session_id: b.session_id, prev_hash: prev, ...Object.fromEntries(Object.entries(b).filter(([k]) => !["v", "seq", "session_id"].includes(k))) };
    if (sign) e.sig = edSign(null, Buffer.from(jcs(e), "utf8"), LOG_KEY.key).toString("base64url");
    entries.push(e);
    prev = jcsSha256(withoutMember(e, "sig"));
  }
  return { entries, hashes: entries.map((e) => jcsSha256(withoutMember(e, "sig"))) };
}

function checkpointAndWitness({ sessionId, lastHash, count, t0, stub = STUB_WITNESS, keyId = "stub_test_v1", witnessHead, witnessOtherCheckpoint, kidOverride, fork = "false", type = "witness.checkpoint/1" }) {
  const kid = kidOverride ?? okpThumbprint(LOG_KEY.x);
  const cp = { v: "evidence.action/1", type: "checkpoint", session_id: sessionId, count, last_entry_hash: lastHash, ts: iso(t0 + 6).replace(".000Z", ".250Z"), kid };
  cp.sig = edSign(null, Buffer.from(jcs(cp), "utf8"), LOG_KEY.key).toString("base64url");
  const head = witnessHead ?? { count, lastHash };
  // witnessOtherCheckpoint: the witness stored an earlier checkpoint of the same
  // head (another ts, so another sig and checkpoint_sha256), as its spec allows.
  let stored = cp;
  if (witnessOtherCheckpoint) {
    stored = { ...withoutMember(cp, "sig"), ts: iso(t0 + 5).replace(".000Z", ".125Z") };
    stored.sig = edSign(null, Buffer.from(jcs(stored), "utf8"), LOG_KEY.key).toString("base64url");
  }
  const w = {
    type,
    witness: "headlessoracle.com",
    received_at: iso(t0 + 7).replace(".000Z", ".731Z"),
    kid,
    session_id: sessionId,
    count: String(head.count),
    last_entry_hash: head.lastHash,
    checkpoint_ts: stored.ts,
    checkpoint_sha256: jcsSha256(stored),
    fork,
    public_key_id: keyId,
  };
  const ordered = {};
  for (const k of Object.keys(w).sort()) ordered[k] = w[k];
  ordered.signature = edSign(null, Buffer.from(jcs(w), "utf8"), stub.key).toString("hex");
  return { cp, w: ordered };
}

// A signed type-2 transaction in the JSON-RPC shape a Base node returns,
// built and hashed with viem's own serializer.
async function signedTx({ key, to, value, input, nonce, blockHash, blockNumber, blockTimestamp, index, type = "eip1559", chainId = CHAIN_ID }) {
  const unsigned = { type, chainId, nonce, maxPriorityFeePerGas: 1000000n, maxFeePerGas: 6000000n, gas: 210000n, to, value, data: input, accessList: [] };
  const hash = keccak256(serializeTransaction(unsigned));
  const sig = await secpSign({ hash, privateKey: key });
  const yParity = sig.yParity;
  const txHash = keccak256(serializeTransaction(unsigned, { r: sig.r, s: sig.s, yParity }));
  return {
    accessList: [],
    blockHash,
    blockNumber: qty(blockNumber),
    blockTimestamp: qty(blockTimestamp),
    chainId: qty(chainId),
    from: addrOf(key).toLowerCase(),
    gas: qty(210000),
    gasPrice: qty(2000000),
    hash: txHash,
    input,
    maxFeePerGas: qty(6000000),
    maxPriorityFeePerGas: qty(1000000),
    nonce: qty(nonce),
    r: qty(BigInt(sig.r)),
    s: qty(BigInt(sig.s)),
    to: to.toLowerCase(),
    transactionIndex: qty(index),
    type: "0x2",
    v: qty(yParity),
    value: qty(value),
    yParity: qty(yParity),
  };
}

const ZERO_BLOOM = "0x" + "00".repeat(256);
function blockFor({ number, timestamp, txHashes }) {
  const b = {
    baseFeePerGas: "0x4c4b40",
    blobGasUsed: "0x3a980",
    difficulty: "0x0",
    excessBlobGas: "0x0",
    extraData: "0x01000000640000000500000000004c4b40",
    gasLimit: "0x17d78400",
    gasUsed: "0x5b8d80",
    hash: null,
    logsBloom: ZERO_BLOOM,
    miner: "0x4200000000000000000000000000000000000011",
    mixHash: h(`block ${number} mixHash`),
    nonce: "0x0000000000000000",
    number: qty(number),
    parentBeaconBlockRoot: h(`block ${number} parentBeaconBlockRoot`),
    parentHash: h(`block ${number - 1} hash`),
    receiptsRoot: h(`block ${number} receiptsRoot (placeholder)`),
    requestsHash: "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    size: "0x2b9c",
    stateRoot: h(`block ${number} stateRoot`),
    timestamp: qty(timestamp),
    transactions: txHashes,
    transactionsRoot: h(`block ${number} transactionsRoot (placeholder)`),
    uncles: [],
    withdrawals: [],
    withdrawalsRoot: h(`block ${number} withdrawalsRoot`),
  };
  const order = ["parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"];
  const quantities = new Set(["difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed", "excessBlobGas"]);
  b.hash = keccak256(toRlp(order.map((k) => (quantities.has(k) ? (b[k] === "0x0" ? "0x" : "0x" + b[k].slice(2).padStart(b[k].length - 2 + ((b[k].length - 2) % 2), "0")) : b[k]))));
  return b;
}

const topicAddr = (a) => "0x" + "0".repeat(24) + a.slice(2).toLowerCase();
const word = (v) => "0x" + BigInt(v).toString(16).padStart(64, "0");

function receiptFor({ tx, logs }) {
  return {
    blobGasUsed: "0x1f40",
    blockHash: tx.blockHash,
    blockNumber: tx.blockNumber,
    contractAddress: null,
    cumulativeGasUsed: "0x2dc6c0",
    daFootprintGasScalar: "0x190",
    effectiveGasPrice: "0x1e8480",
    from: tx.from,
    gasUsed: "0x1d4c0",
    l1BaseFeeScalar: "0x8dd",
    l1BlobBaseFee: "0x1",
    l1BlobBaseFeeScalar: "0x101c12",
    l1Fee: "0x5a3",
    l1GasPrice: "0x2a5d6f8",
    l1GasUsed: "0x6c4",
    logs: logs.map((l, k) => ({ address: l.address.toLowerCase(), topics: l.topics, data: l.data, blockHash: tx.blockHash, blockNumber: tx.blockNumber, blockTimestamp: tx.blockTimestamp, transactionHash: tx.hash, transactionIndex: tx.transactionIndex, logIndex: qty(k + 3), removed: false })),
    logsBloom: ZERO_BLOOM,
    status: "0x1",
    to: tx.to,
    transactionHash: tx.hash,
    transactionIndex: tx.transactionIndex,
    type: tx.type,
  };
}

const TRANSFER = keccak256(toHex("Transfer(address,address,uint256)"));
const AUTH_USED = keccak256(toHex("AuthorizationUsed(address,bytes32)"));
export const ROUTER_ABI = parseAbi(["function swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline) payable returns (uint256[] amounts)"]);
const TWA_ABI = parseAbi(["function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)"]);
const TWA_BYTES_ABI = parseAbi(["function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)"]);
const RWA_ABI = parseAbi(["function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)"]);
const HANDLE_OPS_ABI = parseAbi(["function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[] ops, address beneficiary)"]);
// ERC-8021 schema 2 suffix: CBOR {"w": "test_facil"}, 2-byte length, schema id 2, marker.
export const TEST_8021_SUFFIX = "0xa161776a746573745f666163696c000e0280218021802180218021802180218021";

// Options (all optional) let the tests build broken variants:
//   issuerKey / claimedSigner: who signs the receipts and who the envelope names
//   sender: "trader" (default) or "relayer" (calldata kind: another account sends the trade)
//   value: native value of the calldata kind's transaction (default: the trader sends some, a relayer none)
//   omitHash: the calldata kind's trade does not carry the destination entry hash
//   nonceIsEntryHash: false puts an unrelated nonce in the EIP-3009 authorization
//   trailerHash: put the destination entry hash in the facilitator's trailer (EIP-3009 kind)
//   binding: overrides case.json binding
//   chainId: the chain id the transaction (and an EIP-3009 authorization) is signed for, and case.json names
//   tokenDomainFile: also write chain/token-domain.json (read only in trailer-report mode)
//   authValue: the EIP-3009 authorization's value (default 20000)
//   blockTimestamp: the block's timestamp (default 20 s after the source check time)
//   useropTarget: call an ERC-4337 EntryPoint instead (calldata kind)
//   extraEntry: a third log entry after the checkpoint's count
//   editEntries: change the entries before they are linked (seq, session_id, v)
//   checkpointSessionId: sign the checkpoint (and its witness receipt) for another session_id
//   witnessHead: the witness receipt names the head at count 1, not the checkpoint's
//   witnessOtherCheckpoint: the witness receipt is for another checkpoint of the same head
//   bytesSignature: the transferWithAuthorization overload with a bytes signature
//   receive: receiveWithAuthorization instead (EIP-3009 kind)
//   hashAsValidBefore: the destination entry hash as the authorization's validBefore
//   truncateInput: keep only this many bytes of the EIP-3009 transaction's input (it then does not decode)
//   checkpointKid: the checkpoint (and its witness receipt) names this kid, though the log key signs it
//   checkpointLastHash: the checkpoint (and its witness receipt) names this last entry hash
//   witnessFork: the witness receipt's fork value
//   authSignKey: the key that signs the EIP-3009 authorization (default the payer's)
//   authHighS: the authorization signature in its high-s form
//   validBefore: the authorization's validBefore (seconds)
//   duplicateAuthUsed: the receipt holds the AuthorizationUsed log twice
//   editProfile: changes the case's issuer profile (pin the result with testPins({ profiles }))
//   formatVersion: the schema version inside the signed receipt data (default 1)
//   witnessType: the witness receipt's type
//   authDomainContract: the authorization is signed for this verifyingContract, not the token's
export async function buildCase(kind, o = {}) {
  const t0 = 1792130000;
  const sessionId = `h4-fixture-${kind}-1`;
  const files = new Map();
  const add = (rel, buf) => files.set(rel, buf);

  const env = [];
  for (const [k, role] of ["source", "destination"].entries()) {
    const e = checkFor({ role, checkedAt: t0 + 2 * k, verdict: role === "source" ? "PASS" : "CAUTION", signKey: o.issuerKey ?? KEYS.issuer, claimedSigner: o.claimedSigner, formatVersion: o.formatVersion });
    env.push(e);
    add(`receipts/${role}.json`, pretty(await sealCheck(e)));
    if (kind === "calldata") add(`requests/${role}.json`, pretty(e.req));
  }
  add("issuer/profile.json", compact(o.editProfile ? o.editProfile(testProfile()) : testProfile()));

  const { entries, hashes } = logEntries({ sessionId, uids: env.map((e) => e.uid), t0, sign: kind === "calldata", extraEntry: o.extraEntry, editEntries: o.editEntries });
  add("log/entries.jsonl", Buffer.from(entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8"));
  add("log/public-key-jwk.json", pretty({ kty: "OKP", crv: "Ed25519", x: LOG_KEY.x }));
  const { cp, w } = checkpointAndWitness({ sessionId: o.checkpointSessionId ?? sessionId, lastHash: o.checkpointLastHash ?? hashes[1], count: 2, t0, witnessHead: o.witnessHead && { count: 1, lastHash: hashes[0] }, witnessOtherCheckpoint: o.witnessOtherCheckpoint, kidOverride: o.checkpointKid, fork: o.witnessFork, type: o.witnessType });
  add("log/checkpoint.json", pretty(cp));
  add("witness/receipt.json", pretty(w));
  const dest = "0x" + hashes[1].slice(7);

  const blockNumber = 33000000;
  const blockTs = o.blockTimestamp ?? t0 + 20;
  const blockHash0 = "0x" + "00".repeat(32);
  const chainId = o.chainId ?? CHAIN_ID;
  let tx;
  let logs;
  if (kind === "calldata") {
    const senderKey = o.sender === "relayer" ? KEYS.relayer : KEYS.trader;
    const traderAddr = addrOf(KEYS.trader);
    const tokenOut = testAddress("test token out");
    let input;
    let to;
    if (o.useropTarget) {
      to = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
      input = encodeFunctionData({ abi: HANDLE_OPS_ABI, functionName: "handleOps", args: [[[traderAddr, 0n, "0x", dest, h("gas limits"), 21000n, h("gas fees"), "0x", "0x" + "11".repeat(65)]], addrOf(senderKey)] });
    } else {
      to = testAddress("test router");
      input = encodeFunctionData({ abi: ROUTER_ABI, functionName: "swapExactETHForTokens", args: [2490000n, [testAddress("test wrapped ether"), tokenOut], traderAddr, BigInt(t0 + 300)] }) + (o.omitHash ? "" : dest.slice(2));
    }
    const value = o.value ?? (o.sender === "relayer" ? 0n : 1000000000000000n);
    tx = await signedTx({ key: senderKey, to, value, input, nonce: 7, blockHash: blockHash0, blockNumber, blockTimestamp: blockTs, index: 1, chainId });
    logs = [{ address: tokenOut, topics: [TRANSFER, topicAddr(testAddress("test pool")), topicAddr(traderAddr)], data: word(2491234) }];
    add("chain/target-abi.json", pretty(o.useropTarget ? HANDLE_OPS_ABI : ROUTER_ABI));
  } else {
    const token = TEST_TOKEN.address;
    const payer = addrOf(KEYS.payer);
    const payTo = testAddress("test payee");
    const nonce = o.nonceIsEntryHash === false ? h("an unrelated authorization nonce") : dest;
    const auth = { from: payer, to: payTo, value: o.authValue ?? 20000n, validAfter: BigInt(blockTs - 600), validBefore: o.hashAsValidBefore ? BigInt(dest) : BigInt(o.validBefore ?? blockTs + 300), nonce: o.hashAsValidBefore ? h("an unrelated authorization nonce") : nonce };
    const domain = { name: TEST_TOKEN.name, version: TEST_TOKEN.version, chainId, verifyingContract: o.authDomainContract ?? token };
    const primaryType = o.receive ? "ReceiveWithAuthorization" : "TransferWithAuthorization";
    const digest = hashTypedData({ domain, types: { [primaryType]: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] }, primaryType, message: auth });
    const sig = await secpSign({ hash: digest, privateKey: o.authSignKey ?? KEYS.payer });
    if (o.authHighS) {
      // The same signature in its other, high-s form (s replaced by n - s, the parity flipped).
      sig.s = "0x" + (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n - BigInt(sig.s)).toString(16).padStart(64, "0");
      sig.yParity = 1 - sig.yParity;
      sig.v = BigInt(27 + sig.yParity);
    }
    const args = [auth.from, auth.to, auth.value, auth.validAfter, auth.validBefore, auth.nonce];
    const call = o.bytesSignature
      ? encodeFunctionData({ abi: TWA_BYTES_ABI, functionName: "transferWithAuthorization", args: [...args, sig.r + sig.s.slice(2) + (sig.yParity === 0 ? "1b" : "1c")] })
      : encodeFunctionData({ abi: o.receive ? RWA_ABI : TWA_ABI, functionName: o.receive ? "receiveWithAuthorization" : "transferWithAuthorization", args: [...args, Number(sig.v), sig.r, sig.s] });
    const full = call + (o.trailerHash ? dest.slice(2) : "") + TEST_8021_SUFFIX.slice(2);
    const input = o.truncateInput ? full.slice(0, 2 + 2 * o.truncateInput) : full;
    tx = await signedTx({ key: KEYS.facilitator, to: token, value: 0n, input, nonce: 41, blockHash: blockHash0, blockNumber, blockTimestamp: blockTs, index: 1, chainId });
    logs = [
      { address: token, topics: [AUTH_USED, topicAddr(payer), auth.nonce], data: "0x" },
      ...(o.duplicateAuthUsed ? [{ address: token, topics: [AUTH_USED, topicAddr(payer), auth.nonce], data: "0x" }] : []),
      { address: token, topics: [TRANSFER, topicAddr(payer), topicAddr(payTo)], data: word(auth.value) },
    ];
    if (o.tokenDomainFile) add("chain/token-domain.json", pretty({ name: domain.name, version: domain.version, chainId, verifyingContract: domain.verifyingContract, source: { note: "TEST FIXTURE: written by fixtures/make-fixtures.mjs; no contract exists at this address; the token name is made up" } }));
  }
  const depositHash = h(`block ${blockNumber} deposit transaction (placeholder)`);
  const block = blockFor({ number: blockNumber, timestamp: blockTs, txHashes: [depositHash, tx.hash] });
  tx.blockHash = block.hash;
  add("chain/transaction.json", pretty(tx));
  add("chain/receipt.json", pretty(receiptFor({ tx, logs })));
  add("chain/block.json", pretty(block));
  const binding = o.binding ?? (kind === "calldata" ? "calldata" : "eip3009-nonce");
  add("case.json", pretty({ format: "chirindo-h4-case/1", mode: "ordering", chain_id: chainId, tx_hash: tx.hash, binding }));
  return files;
}

export function writeFiles(dir, files) {
  for (const [rel, buf] of files) {
    const p = path.join(dir, rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, buf);
  }
}
