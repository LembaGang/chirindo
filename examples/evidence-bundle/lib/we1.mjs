// The worked example WE-1 of spec section 7: Case A of
// examples/ordering-evidence as a bundle, read from the repository's files,
// each checked against its committed sha256 before it is used.

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PINNED_RESPONSE_SHA256 = JSON.parse(readFileSync(path.join(REPO_ROOT, "examples/evidence-bundle/pins/pins.json"), "utf8")).witness_keys.response_sha256;
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");

// Every file a builder here reads, with the sha256 of its committed bytes. On
// a checkout that rewrote line ends the digests differ, and the builder
// refuses rather than repairs.
export const SOURCES = {
  "examples/ordering-evidence/case-a/ordering-evidence-case-a-1.jsonl": "f7ed6c4532f0a7f9e28c71cb74b6df409b33d914897b0cdbd760b679ecb6e998",
  "examples/ordering-evidence/case-a/ordering-evidence-case-a-1.jsonl.witness.ndjson": "bb65a5c18705e45da9697a5ec2cd2c4663b1815162c266124d9caa5a630f17a2",
  "examples/ordering-evidence/keys/operator-jwks.json": "02041d6eba914bc4f1fe4dda9ad0201cbe2810ab66acecbb671d9881359d7993",
  // The /v5/keys response: its digest is the one pins/pins.json records.
  "examples/ordering-evidence/keys/v5-keys.response.json": PINNED_RESPONSE_SHA256,
  "examples/ordering-evidence/case-a/rpc/transaction.sealed.json": "ecdde59189ba98f5886cd16abf827db724581fec6e6363e066629c7db5d88664",
  "examples/ordering-evidence/case-a/rpc/receipt.sealed.json": "0265be18fa45a34cf32c735546c73835d559deb54da31b5f65b4d3ef06618174",
  "examples/ordering-evidence/case-a/rpc/block.sealed.json": "58ae84275cd531f60f88aa252b80a5c4fd980debbc021586d1a2a780c0dad10e",
  "examples/ordering-evidence/case-b/ordering-evidence-case-b-1.jsonl": "f9553dbf67d9095eb40e4c156c4fe973c224f6be23194fafdfa537cedd68ebc9",
  "examples/ordering-evidence/case-b/ordering-evidence-case-b-1.jsonl.witness.ndjson": "936766321f8ba40d4ed049dc3efb8c38c9bb6e61ef3e80b8cef04a2df0b2feea",
  "test/fixtures/legacy-v0/chain.jsonl": "2f9fd835d1793efb0714d5dcc746593c9309a513fa79abed2acdbe6859431fab",
  "test/fixtures/legacy-v0/identity.json": "278d42c944dd505cb61bd1c5c5eec5e18f163ea1c4b9ceeec0e1e9fa68d49358",
};
export const ARGS_A_SHA256 = "7abf24ca72b407e2510f88c812b28f00845a4700f1263024cd0408a57732a659";

export class SourceError extends Error {}

export function readSource(rel) {
  const want = SOURCES[rel];
  if (!want) throw new SourceError(`${rel} is not a source this builder reads`);
  let bytes;
  try {
    bytes = readFileSync(path.join(REPO_ROOT, rel));
  } catch (e) {
    throw new SourceError(`${rel} cannot be read (${e.code ?? e.message})`);
  }
  if (sha256Hex(bytes) !== want) throw new SourceError(`${rel} does not have its committed sha256 ${want} (a checkout that rewrote line ends?)`);
  return bytes;
}

// The fetch records of the Case A folder (spec section 3: source, fetched_at
// and capture are reported, and read by no check). A file with no fetch
// record takes the commit time of ba15707, which added it.
const BA15707_TIME = "2026-10-09T14:50:23Z";
const RPC_URL = "https://sepolia.base.org";
const RPC_FETCHED = { transaction: "2026-10-09T14:45:09.847Z", receipt: "2026-10-09T14:45:10.269Z", block: "2026-10-09T14:45:10.614Z" };
const KEYS_URL = "https://api.headlessoracle.com/v5/keys";
const KEYS_FETCHED = "2026-10-09T13:03:22Z";
const RESERIALISED = "reserialised-by examples/ordering-evidence/case-a/fetch-sealed.mjs:14-16";

export function member({ id, role, profile, bytes, source, fetched_at, capture, media_type }) {
  return { id, role, profile, media_type, sha256: "sha256:" + sha256Hex(bytes), bytes_b64: Buffer.from(bytes).toString("base64"), source, fetched_at, capture };
}

// The arguments of Case A's gated call, rebuilt as their RFC 8785 bytes from
// the value examples/ordering-evidence/client.mjs:105 sends.
export function argsA() {
  const line = readFileSync(path.join(REPO_ROOT, "examples/ordering-evidence/client.mjs"), "utf8").split("\n")[104];
  const m = /^ {2}arguments: \{ pair: "([^"]+)", amount_in: ([0-9.]+), slippage_bps: ([0-9]+) \},\r?$/.exec(line);
  if (!m) throw new SourceError("examples/ordering-evidence/client.mjs:105 is not the line Case A's arguments come from");
  const bytes = Buffer.from(canonicalize({ pair: m[1], amount_in: Number(m[2]), slippage_bps: Number(m[3]) }), "utf8");
  if (sha256Hex(bytes) !== ARGS_A_SHA256) throw new SourceError("the arguments rebuilt from client.mjs:105 do not have Case A's args_hash");
  return bytes;
}

const CASE_A = "examples/ordering-evidence/case-a/";
const KEYS = "examples/ordering-evidence/keys/";
const JSONL = "application/x-ndjson";
const JSON_T = "application/json";

// The eight members of spec section 7 (lines of the WE-1 members table), in order.
export function we1Members() {
  return [
    member({ id: "log-a", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: readSource(CASE_A + "ordering-evidence-case-a-1.jsonl"), source: CASE_A + "ordering-evidence-case-a-1.jsonl", fetched_at: BA15707_TIME, capture: "raw-response", media_type: JSONL }),
    member({ id: "args-a", role: "action-arguments", profile: "jcs-json", bytes: argsA(), source: "examples/ordering-evidence/client.mjs", fetched_at: BA15707_TIME, capture: "reconstructed-from examples/ordering-evidence/client.mjs:105", media_type: JSON_T }),
    member({ id: "sidecar-a", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: readSource(CASE_A + "ordering-evidence-case-a-1.jsonl.witness.ndjson"), source: CASE_A + "ordering-evidence-case-a-1.jsonl.witness.ndjson", fetched_at: BA15707_TIME, capture: "raw-response", media_type: JSONL }),
    member({ id: "opkey-a", role: "operator-key", profile: "jwks", bytes: readSource(KEYS + "operator-jwks.json"), source: KEYS + "operator-jwks.json", fetched_at: BA15707_TIME, capture: "raw-response", media_type: JSON_T }),
    member({ id: "wkey", role: "witness-key", profile: "ho-v5-keys", bytes: readSource(KEYS + "v5-keys.response.json"), source: KEYS_URL, fetched_at: KEYS_FETCHED, capture: "raw-response", media_type: JSON_T }),
    member({ id: "tx-a", role: "payment-transaction", profile: "eth-rpc-json", bytes: readSource(CASE_A + "rpc/transaction.sealed.json"), source: RPC_URL, fetched_at: RPC_FETCHED.transaction, capture: RESERIALISED, media_type: JSON_T }),
    member({ id: "rc-a", role: "payment-receipt", profile: "eth-rpc-json", bytes: readSource(CASE_A + "rpc/receipt.sealed.json"), source: RPC_URL, fetched_at: RPC_FETCHED.receipt, capture: RESERIALISED, media_type: JSON_T }),
    member({ id: "blk-a", role: "payment-block", profile: "eth-rpc-json", bytes: readSource(CASE_A + "rpc/block.sealed.json"), source: RPC_URL, fetched_at: RPC_FETCHED.block, capture: RESERIALISED, media_type: JSON_T }),
  ];
}

export const WE1_SUBJECT = {
  kind: "evm-payment",
  chain_id: "eip155:84532",
  tx_hash: "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3",
  cites: { log: "log-a", seq: 0 },
  carried_as: "eip3009-nonce",
};

export function bundleDoc({ createdAt, assembledBy, subject, members }) {
  return { type: "evidence-bundle/0.9", created_at: createdAt, assembled_by: assembledBy, subject, members };
}

// The bundle document as bytes: two-space JSON and a final LF.
export const bundleBytes = (doc) => Buffer.from(JSON.stringify(doc, null, 2) + "\n", "utf8");

// WE-1's stated inputs (spec section 7): the test payer, in its EIP-55 form,
// and the payment.
export const WE1_AUTHORIZER = "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673";
export const WE1_TX = WE1_SUBJECT.tx_hash;
