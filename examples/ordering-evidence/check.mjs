#!/usr/bin/env node
// Offline checker for the ordering-evidence example. Node built-ins only.
//
//   node examples/ordering-evidence/check.mjs [--online] [--case a|b]... [--root <dir>]
//
// One line per check, "PASS <id>: ..." or "FAIL <id>: ...", plus "INFO" lines
// that are printed for a reader and checked by nothing. Exit 0 only if every
// check passes; any exception inside a check is a FAIL (fail closed).
//
// Offline it reads only the committed files under --root (default: this
// directory). --online also re-fetches the Base Sepolia transaction, receipt
// and block from the RPC and the witness record from Headless Oracle, and
// compares them with the committed copies.
//
// The entry hash of a record is "sha256:" + hex(SHA-256(JCS(record without
// "sig"))), the value the next record's prev_hash carries. It is computed here
// from the record, never read from the record's gate_receipt member, which is
// a different hash (taken while gate_receipt still held the placeholder
// "self").

import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values: opts } = parseArgs({
  options: {
    root: { type: "string" },
    online: { type: "boolean", default: false },
    case: { type: "string", multiple: true },
  },
});
const ROOT = opts.root ?? dirname(fileURLToPath(import.meta.url));
const CASES = opts.case ?? ["a", "b"];

// transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
// selector, and topic0 of AuthorizationUsed(address,bytes32). keccak-256 is not
// in node:crypto, so both are constants here; README.md records how they were
// computed and checked.
const SELECTOR = "0xe3ee160e";
const AUTHORIZATION_USED_TOPIC = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5";
const BASE_SEPOLIA_CHAIN_ID = "0x14a34"; // 84532
const WITNESS_NAME = "headlessoracle.com";
const WITNESS_BASE = "https://api.headlessoracle.com";

let failed = 0;
function result(id, ok, detail) {
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${id}: ${detail}`);
}
function info(id, detail) {
  console.log(`INFO ${id}: ${detail}`);
}
async function check(id, fn) {
  try {
    const r = await fn();
    result(id, r.ok, r.detail);
  } catch (e) {
    result(id, false, `error: ${e.message}`);
  }
}

// RFC 8785 JCS for the values these files carry: objects, arrays, strings,
// booleans, null and safe integers. Anything else (a non-integer or unsafe
// number) is refused rather than serialized approximately.
function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`JCS: number ${v} is outside what this checker serializes`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    const members = Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + members.map(([k, x]) => JSON.stringify(k) + ":" + jcs(x)).join(",") + "}";
  }
  throw new Error(`JCS: unsupported ${typeof v}`);
}
const sha256Hex = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const without = (o, k) => {
  const { [k]: _drop, ...rest } = o;
  return rest;
};
const entryHash = (record) => "sha256:" + sha256Hex(jcs(without(record, "sig")));
const genesisPrevHash = (v, sessionId) => "sha256:" + sha256Hex(jcs({ v, session_id: sessionId, marker: "genesis" }));

function ed25519Pub(raw) {
  if (raw.length !== 32) throw new Error("Ed25519 public key is not 32 bytes");
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
}
function verifyB64url(obj, sigMember, pub) {
  const sig = Buffer.from(obj[sigMember], "base64url");
  return sig.length === 64 && edVerify(null, Buffer.from(jcs(without(obj, sigMember)), "utf8"), pub, sig);
}
function verifyHex(obj, sigMember, pub) {
  if (!/^[0-9a-f]{128}$/.test(obj[sigMember])) return false;
  return edVerify(null, Buffer.from(jcs(without(obj, sigMember)), "utf8"), pub, Buffer.from(obj[sigMember], "hex"));
}

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const readLines = (p) =>
  readFileSync(p, "utf8")
    .split("\n")
    .map((l) => l.replace(/\r$/, ""))
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));

// ---- keys ----------------------------------------------------------------
let operator = null;
let witness = null;

await check("keys.operator", () => {
  const id = readJson(join(ROOT, "keys", "operator-identity.json"));
  const { keys: jwkList } = readJson(join(ROOT, "keys", "operator-jwks.json"));
  const jwk = jwkList.find((k) => k.kid === id.kid);
  const raw = Buffer.from(id.public_key_b64url, "base64url");
  // RFC 7638 thumbprint of the Ed25519 JWK: required members in lexicographic order.
  const tp = createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${id.public_key_b64url}"}`).digest("base64url");
  const ok = jwk !== undefined && jwk.x === id.public_key_b64url && tp === id.kid && raw.length === 32;
  if (ok) operator = { kid: id.kid, pub: ed25519Pub(raw) };
  return { ok, detail: `kid ${id.kid}; JWK x matches identity.json; RFC 7638 thumbprint ${ok ? "equals" : "does not equal"} kid` };
});

await check("keys.witness-pin", () => {
  const jwk = readJson(join(ROOT, "keys", "witness-key.jwk.json"));
  const prov = readJson(join(ROOT, "keys", "witness-key.pin.json"));
  const raw = Buffer.from(jwk.x, "base64url");
  const ok =
    jwk.kty === "OKP" && jwk.crv === "Ed25519" && raw.length === 32 &&
    raw.toString("hex") === prov.public_key_hex &&
    createHash("sha256").update(raw).digest("hex") === prov.sha256_of_raw_32_key_bytes &&
    jwk.kid === prov.key_id;
  if (ok) witness = { id: jwk.kid, pub: ed25519Pub(raw), hex: prov.public_key_hex };
  return { ok, detail: `${jwk.kid} ${prov.public_key_hex}, pinned from ${prov.source_url} at ${prov.fetched_at}` };
});

// ---- per case --------------------------------------------------------------
async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

for (const c of CASES) {
  const dir = join(ROOT, `case-${c}`);
  let m, records, hashes, cp, wr;

  await check(`${c}.files`, () => {
    m = readJson(join(dir, "case.json"));
    records = readLines(join(dir, m.hash_chain));
    const side = readLines(join(dir, m.witness_sidecar)).filter((l) => l.witness_receipt);
    if (side.length !== 1) throw new Error(`expected exactly one witnessed checkpoint in the sidecar, found ${side.length}`);
    cp = side[0].checkpoint;
    wr = side[0].witness_receipt;
    return { ok: records.length > 0, detail: `${m.hash_chain}: ${records.length} record(s); ${m.witness_sidecar}: 1 witnessed checkpoint` };
  });

  await check(`${c}.receipt-signature`, () => {
    const bad = records.filter((r) => r.kid !== operator.kid || r.key_thumbprint !== operator.kid || !verifyB64url(r, "sig", operator.pub));
    return { ok: bad.length === 0, detail: `${records.length - bad.length}/${records.length} record signature(s) verify under ${operator.kid}` };
  });

  await check(`${c}.hash-chain-links`, () => {
    hashes = records.map(entryHash);
    const problems = [];
    records.forEach((r, i) => {
      if (r.seq !== i) problems.push(`seq ${r.seq} at line ${i + 1}`);
      if (r.session_id !== m.session_id) problems.push(`session_id at line ${i + 1}`);
      const expected = i === 0 ? genesisPrevHash(r.v, m.session_id) : hashes[i - 1];
      if (r.prev_hash !== expected) problems.push(`prev_hash at line ${i + 1}`);
    });
    return { ok: problems.length === 0, detail: problems.length ? problems.join("; ") : `${records.length} link(s) recomputed from genesis; entry hashes computed per record` };
  });

  await check(`${c}.receipt-decision`, () => {
    const { event, gate } = records[records.length - 1];
    const expected = m.expect_decision === "allow" ? ["allow", "executed", "act"] : ["deny", "denied", "halt"];
    const got = [event.decision, event.outcome, gate.result];
    return { ok: got.join() === expected.join(), detail: `last record: decision=${got[0]} outcome=${got[1]} result=${got[2]}, tool ${event.tool_name}` };
  });

  await check(`${c}.checkpoint-signature`, () => {
    const ok = cp.v === "evidence.action/1" && cp.type === "checkpoint" && cp.kid === operator.kid &&
      cp.session_id === m.session_id && verifyB64url(cp, "sig", operator.pub);
    return { ok, detail: `checkpoint count ${cp.count} signed by ${cp.kid}` };
  });

  await check(`${c}.inclusion`, () => {
    const ok = Number.isSafeInteger(cp.count) && cp.count >= 1 && cp.count === hashes.length &&
      hashes[cp.count - 1] === cp.last_entry_hash;
    return { ok, detail: `entry hash of record ${cp.count} recomputed ${hashes[hashes.length - 1]} ${ok ? "equals" : "does not equal"} checkpoint last_entry_hash ${cp.last_entry_hash} (count ${cp.count}, hash chain length ${hashes.length})` };
  });

  await check(`${c}.witness-signature`, () => {
    const ok = wr.public_key_id === witness.id && wr.type === "witness.checkpoint/1" && wr.witness === WITNESS_NAME &&
      verifyHex(wr, "signature", witness.pub);
    return { ok, detail: `witness receipt signed by pinned ${witness.id} (${witness.hex})` };
  });

  await check(`${c}.witness-covers-checkpoint`, () => {
    const ok = wr.kid === cp.kid && wr.session_id === cp.session_id && wr.count === String(cp.count) &&
      wr.last_entry_hash === cp.last_entry_hash && wr.fork === "false" &&
      wr.checkpoint_sha256 === "sha256:" + sha256Hex(jcs(cp));
    return { ok, detail: `kid, session_id, count ${wr.count}, last_entry_hash, checkpoint_sha256 match the checkpoint; fork=${wr.fork}` };
  });
  if (wr) info(`${c}.received_at`, `${wr.received_at} (Headless Oracle's clock)`);

  if (c === "a") {
    const t = m?.transaction ?? {};
    // The transaction's sender is whoever broadcast it (here the x402
    // facilitator), so no check reads tx.from; the payer is the authorization's
    // `from`, which the token contract checked against the signature.
    let tx, rc, blk, nonceHex, payer;

    await check("a.tx-files", () => {
      tx = readJson(join(dir, t.tx_file));
      rc = readJson(join(dir, t.receipt_file));
      blk = readJson(join(dir, t.block_file));
      const ok = tx.hash === t.tx_hash && tx.chainId === BASE_SEPOLIA_CHAIN_ID && tx.to.toLowerCase() === t.usdc.toLowerCase();
      return { ok, detail: `tx ${tx.hash} on chainId ${tx.chainId} to ${tx.to}` };
    });

    await check("a.tx-nonce", () => {
      const input = tx.input.toLowerCase();
      if (!input.startsWith(SELECTOR) || input.length !== 10 + 9 * 64) throw new Error("input is not transferWithAuthorization(...)");
      const word = (i) => input.slice(10 + i * 64, 10 + (i + 1) * 64);
      const from = "0x" + word(0).slice(24);
      const to = "0x" + word(1).slice(24);
      const value = BigInt("0x" + word(2));
      nonceHex = "0x" + word(5);
      payer = from;
      const cited = "0x" + entryHash(records[m.cited_seq]).slice("sha256:".length);
      const ok = nonceHex === cited && from === t.payer.toLowerCase() && to === t.pay_to.toLowerCase();
      return { ok, detail: `transferWithAuthorization from ${from} to ${to} value ${value}; nonce ${nonceHex} ${ok ? "equals" : "does not equal"} recomputed entry hash of record ${m.cited_seq}` };
    });

    await check("a.tx-status", () => {
      const sealed = /^0x[0-9a-f]{64}$/.test(tx.blockHash ?? "") && !/^0x0{64}$/.test(tx.blockHash);
      const ok = sealed && rc.transactionHash === tx.hash && rc.status === "0x1" && rc.blockNumber === tx.blockNumber && rc.blockHash === tx.blockHash;
      return { ok, detail: `receipt status ${rc.status}, block ${parseInt(rc.blockNumber, 16)}, block hash ${tx.blockHash} ${sealed ? "(sealed)" : "(NOT sealed)"}` };
    });

    await check("a.log-nonce", () => {
      const logs = rc.logs.filter((l) => l.address.toLowerCase() === t.usdc.toLowerCase() && l.topics[0] === AUTHORIZATION_USED_TOPIC);
      if (logs.length !== 1) throw new Error(`expected one AuthorizationUsed log from USDC, found ${logs.length}`);
      const [, authorizer, nonce] = logs[0].topics;
      const ok = nonce.toLowerCase() === nonceHex && "0x" + authorizer.slice(26).toLowerCase() === payer;
      return { ok, detail: `AuthorizationUsed(authorizer ${"0x" + authorizer.slice(26)}, nonce ${nonce}) ${ok ? "carries" : "does not carry"} the transaction's nonce` };
    });

    await check("a.block", () => {
      const ok = blk.number === rc.blockNumber && blk.hash === rc.blockHash && blk.transactions.includes(tx.hash);
      return { ok, detail: `block ${parseInt(blk.number, 16)} ${blk.hash} contains the transaction` };
    });

    // The first snapshots were fetched before the block was sealed. They are
    // kept unedited; this confirms they describe the same transaction as the
    // sealed copies checked above.
    await check("a.preseal-agrees", () => {
      const p = t.preseal;
      const ptx = readJson(join(dir, p.tx_file));
      const prc = readJson(join(dir, p.receipt_file));
      const authLog = (r) => r.logs
        .filter((l) => l.topics[0] === AUTHORIZATION_USED_TOPIC)
        .map((l) => ({ address: l.address.toLowerCase(), topics: l.topics, data: l.data }));
      const ok = ptx.hash === tx.hash && ptx.input === tx.input && prc.transactionHash === rc.transactionHash &&
        prc.status === rc.status && authLog(prc).length === 1 && jcs(authLog(prc)) === jcs(authLog(rc));
      return { ok, detail: `pre-seal ${p.tx_file} and ${p.receipt_file} ${ok ? "agree" : "do not agree"} with the sealed copies on tx hash, input, status and the AuthorizationUsed log` };
    });

    if (blk && wr) {
      const blockMs = parseInt(blk.timestamp, 16) * 1000;
      const delta = (blockMs - Date.parse(wr.received_at)) / 1000;
      info("a.times", `witness received_at ${wr.received_at} (Headless Oracle's clock) | block ${parseInt(blk.number, 16)} timestamp ${new Date(blockMs).toISOString()} (set by the block producer) | block minus received_at ${delta} s. Two clocks; the ordering on Base Sepolia rests on the nonce, not on these times.`);
    }

    if (opts.online) {
      await check("a.online-transaction", async () => {
        const url = t.rpc_url;
        const chainId = await rpc(url, "eth_chainId", []);
        const ltx = await rpc(url, "eth_getTransactionByHash", [t.tx_hash]);
        const lrc = await rpc(url, "eth_getTransactionReceipt", [t.tx_hash]);
        const lblk = await rpc(url, "eth_getBlockByNumber", [rc.blockNumber, false]);
        const same = (a, b, ks) => ks.every((k) => jcs(a[k]) === jcs(b[k]));
        const logs = (r) => r.logs.map((l) => ({ address: l.address.toLowerCase(), topics: l.topics, data: l.data }));
        const ok = chainId === BASE_SEPOLIA_CHAIN_ID &&
          same(ltx, tx, ["hash", "input", "from", "to", "blockNumber", "blockHash"]) &&
          same(lrc, rc, ["status", "blockNumber", "blockHash"]) && jcs(logs(lrc)) === jcs(logs(rc)) &&
          same(lblk, blk, ["number", "hash", "timestamp"]);
        return { ok, detail: `re-fetched from ${url}: chainId ${chainId}; transaction, receipt, logs and block ${ok ? "match" : "differ from"} the committed copies` };
      });
    }
  }

  if (opts.online) {
    await check(`${c}.online-witness`, async () => {
      const q = `${WITNESS_BASE}/v1/witness/checkpoints?kid=${encodeURIComponent(cp.kid)}&session_id=${encodeURIComponent(cp.session_id)}`;
      const res = await fetch(q);
      if (res.status !== 200) throw new Error(`GET ${q}: HTTP ${res.status}`);
      const body = await res.json();
      const live = body.receipts.filter((r) => r.count === wr.count && r.last_entry_hash === wr.last_entry_hash);
      const ok = live.length === 1 && jcs(live[0]) === jcs(wr) && body.receipts.length === 1;
      return { ok, detail: `GET ${q}: ${body.receipts.length} receipt(s); ${ok ? "identical to" : "differs from"} the committed witness receipt` };
    });
  }
}

console.log(failed === 0 ? "ALL CHECKS PASS" : `${failed} CHECK(S) FAILED`);
// exitCode, not exit(): exiting while fetch's sockets are still closing trips a
// libuv assertion on Windows (seen as exit 127 with --online).
process.exitCode = failed === 0 ? 0 : 1;
