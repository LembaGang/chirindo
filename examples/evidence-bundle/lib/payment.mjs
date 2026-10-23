// The payment: spec M5 (steps 0 to 5), the search of B-PAY rule 3, and the
// B-PAY binding (rules 1 to 10), offline.

import { keccak256 } from "viem";
import { FormatError, hexBytes, isPlainObject, parseStrictJson, quantity } from "../../ordering-evidence-h4/lib/formats.mjs";
import { address, AUTHORIZATION_USED_TOPIC, headerHash, recoverAuthorization, recoverSigner, TRANSFER_TOPIC } from "../../ordering-evidence-h4/lib/evm.mjs";
import { built } from "./built.mjs";
import { SUPPORTED_CHAINS, SUPPORTED_TYPES } from "./table.mjs";
import { eip3009Readable, recogniseCall, searchHash, signedFields, txChainId, txHashOf, txSerialization } from "./tx.mjs";

// An eth-rpc-json member: the JSON-RPC result, or the whole response holding
// it (spec D.1).
export function readRpcJson(bytes) {
  const v = parseStrictJson(bytes);
  if (isPlainObject(v)) {
    const names = Object.keys(v).sort();
    if (names.length === 3 && names[0] === "id" && names[1] === "jsonrpc" && names[2] === "result" && v.jsonrpc === "2.0") return v.result;
  }
  return v;
}

const d32 = (v, what) => hexBytes(v, what, 32);
const addrOrNull = (v, what) => (v === null ? null : address(v, what));

function attempt(fn) {
  try {
    const r = fn();
    return r ?? null;
  } catch (e) {
    if (e instanceof FormatError || e instanceof TypeError || e instanceof RangeError || e instanceof SyntaxError || e instanceof Error) return e.message;
    throw e;
  }
}

// Runs M5 on the carried payment members. `p` holds the parsed members
// ({ tx, rc, blk, txId, rcId, blkId, parseErrors }) and returns the rows and
// what later steps read (the call, the authorization, the payer, the times).
built("M5.chain", "M5.receipt", "M5.block", "M5.support", "M5.transaction", "M5.sender", "M5.block-hash", "M5.call", "M5.token-domain", "M5.authorization", "M5.token-logs", "M5.validity-window");
export async function m5(p, subject, pins) {
  const rows = [];
  const add = (id, member, status, reason, detail) => rows.push({ id, member, status, reason, detail });
  const out = { rows, call: null, auth: null, signer: null, sender: null, supported: false, type: null, blockTs: null, tokenPinned: false, authStatus: null, tokenLogsOk: false };
  const subjectChain = BigInt(subject.chain_id.slice("eip155:".length));
  const { tx, rc, blk } = p;

  // Step 0 and step 1: M5.chain.
  if (!tx || !rc || !blk) {
    add("M5.chain", p.txId ?? null, "FAIL", null, "offline, the payment-transaction, payment-receipt and payment-block members must all be carried");
    return out;
  }
  const chainErr =
    p.parseErrors.tx ??
    attempt(() => {
      if (!isPlainObject(tx)) return "the transaction is not a JSON object";
      quantity(tx.type, "type");
      const c = txChainId(tx);
      if (c === null) return "the transaction names no chain id (no chainId member, and no EIP-155 chain id in v)";
      if (c !== subjectChain) return `the transaction's chain id ${c} is not the subject's ${subjectChain}`;
      if (d32(tx.hash, "hash") !== subject.tx_hash) return "the transaction's hash is not subject.tx_hash";
    });
  add("M5.chain", p.txId, chainErr ? "FAIL" : "PASS", null, chainErr ?? `chain id ${subjectChain} and hash equal the subject's`);

  // Step 1: M5.receipt and M5.block compare the receipt and the block with a
  // transaction that reads as an object, whatever M5.chain found.
  const txOk = !p.parseErrors.tx && isPlainObject(tx);
  const rcErr =
    p.parseErrors.rc ??
    (!txOk
      ? "the transaction could not be read"
      : attempt(() => {
          if (!isPlainObject(rc)) return "the receipt is not a JSON object";
          if (quantity(rc.status, "status") !== 1n) return "status is not 0x1";
          if (d32(rc.transactionHash, "transactionHash") !== tx.hash) return "transactionHash is not the transaction's hash";
          if (d32(rc.blockHash, "blockHash") !== d32(tx.blockHash, "transaction blockHash")) return "blockHash is not the transaction's";
          if (quantity(rc.blockNumber, "blockNumber") !== quantity(tx.blockNumber, "transaction blockNumber")) return "blockNumber is not the transaction's";
          if (quantity(rc.transactionIndex, "transactionIndex") !== quantity(tx.transactionIndex, "transaction transactionIndex")) return "transactionIndex is not the transaction's";
          if (address(rc.from, "receipt from") !== address(tx.from, "transaction from")) return "from is not the transaction's";
          if (rc.to === undefined || tx.to === undefined || addrOrNull(rc.to, "receipt to") !== addrOrNull(tx.to, "transaction to")) return "to is not the transaction's";
          if (quantity(rc.type, "receipt type") !== quantity(tx.type, "type")) return "type is not the transaction's";
          if (tx.to !== null && (!Object.keys(rc).includes("contractAddress") || rc.contractAddress !== null)) return "contractAddress is not null for a call";
          if (!Array.isArray(rc.logs)) return "logs is not a list";
          rc.logs.forEach((l, i) => {
            const w = `logs[${i}]`;
            if (!isPlainObject(l)) throw new FormatError(`${w} is not an object`);
            for (const m of ["blockHash", "blockNumber", "transactionHash", "transactionIndex", "logIndex", "removed", "address", "topics", "data"]) if (!Object.keys(l).includes(m)) throw new FormatError(`${w} lacks ${m}`);
            address(l.address, `${w}.address`);
            if (!Array.isArray(l.topics)) throw new FormatError(`${w}.topics is not a list`);
            l.topics.forEach((t, j) => d32(t, `${w}.topics[${j}]`));
            hexBytes(l.data, `${w}.data`);
            quantity(l.logIndex, `${w}.logIndex`);
            if (d32(l.blockHash, `${w}.blockHash`) !== rc.blockHash) throw new FormatError(`${w}.blockHash is not the receipt's`);
            if (quantity(l.blockNumber, `${w}.blockNumber`) !== quantity(rc.blockNumber, "blockNumber")) throw new FormatError(`${w}.blockNumber is not the receipt's`);
            if (d32(l.transactionHash, `${w}.transactionHash`) !== rc.transactionHash) throw new FormatError(`${w}.transactionHash is not the receipt's`);
            if (quantity(l.transactionIndex, `${w}.transactionIndex`) !== quantity(rc.transactionIndex, "transactionIndex")) throw new FormatError(`${w}.transactionIndex is not the receipt's`);
            if (l.removed !== false) throw new FormatError(`${w}.removed is not false`);
          });
        }));
  add("M5.receipt", p.rcId, rcErr ? "FAIL" : "PASS", null, rcErr ?? "status 0x1; the receipt and its logs name the transaction, its block and its index");

  // Step 1: M5.block.
  const blkErr =
    p.parseErrors.blk ??
    (!txOk
      ? "the transaction could not be read"
      : attempt(() => {
          if (!isPlainObject(blk)) return "the block is not a JSON object";
          if (quantity(blk.number, "number") !== quantity(tx.blockNumber, "transaction blockNumber")) return "number is not the transaction's blockNumber";
          if (d32(blk.hash, "hash") !== d32(tx.blockHash, "transaction blockHash")) return "hash is not the transaction's blockHash";
          if (!Array.isArray(blk.transactions)) return "transactions is not a list";
          const idx = Number(quantity(tx.transactionIndex, "transactionIndex"));
          const e = blk.transactions[idx];
          const listed = isPlainObject(e) ? e.hash : e;
          if (listed !== tx.hash) return `transactions[${idx}] is not the transaction's hash`;
          const ts = quantity(blk.timestamp, "timestamp");
          if (Object.keys(tx).includes("blockTimestamp") && quantity(tx.blockTimestamp, "transaction blockTimestamp") !== ts) return "the transaction's blockTimestamp is not the block's timestamp";
          if (isPlainObject(rc) && Array.isArray(rc.logs))
            rc.logs.forEach((l, i) => {
              if (isPlainObject(l) && Object.keys(l).includes("blockTimestamp") && quantity(l.blockTimestamp, `logs[${i}].blockTimestamp`) !== ts) throw new FormatError(`logs[${i}].blockTimestamp is not the block's timestamp`);
            });
          out.blockTs = ts;
        }));
  add("M5.block", p.blkId, blkErr ? "FAIL" : "PASS", null, blkErr ?? "number and hash equal the transaction's; the transaction is listed at its index; block timestamps agree");

  // Step 2: M5.support.
  if (chainErr) {
    add("M5.support", null, "NOT-EVALUATED", "prerequisite-failed:M5.chain", "the transaction's chain id and type could not be read");
    return out;
  }
  out.type = tx.type;
  const supportReason = !SUPPORTED_CHAINS.includes(subjectChain) ? "unsupported-chain" : !SUPPORTED_TYPES.includes(tx.type) ? "unsupported-type" : null;
  // The call is recognised by its selector and to whatever the support test
  // gives, so that the checks of step 5 that apply are listed.
  let call = null;
  if (typeof tx.input === "string" && /^0x([0-9a-f]{2})*$/.test(tx.input) && (tx.to === null || typeof tx.to === "string")) {
    try {
      call = recogniseCall({ ...tx, to: tx.to === null ? null : tx.to.toLowerCase() }, pins.erc4337);
    } catch {
      call = null;
    }
  }
  out.call = call;
  const step5 = call && eip3009Readable(call);
  if (supportReason) {
    add("M5.support", null, "NOT-EVALUATED", supportReason, supportReason === "unsupported-chain" ? `chain id ${subjectChain} is not 8453 or 84532` : `type ${tx.type} is not 0x0, 0x1, 0x2 or 0x4`);
    const ne = "prerequisite-failed:M5.support";
    add("M5.transaction", p.txId, "NOT-EVALUATED", ne, "");
    add("M5.sender", p.txId, "NOT-EVALUATED", ne, "");
    add("M5.block-hash", p.blkId, "NOT-EVALUATED", ne, "");
    add("M5.call", p.txId, "NOT-EVALUATED", ne, "");
    if (step5) for (const [id, m] of [["M5.token-domain", null], ["M5.authorization", p.txId], ["M5.token-logs", p.rcId], ["M5.validity-window", null]]) add(id, m, "NOT-EVALUATED", ne, "");
    return out;
  }
  out.supported = true;
  add("M5.support", null, "PASS", null, `chain id ${subjectChain}, type ${tx.type}`);

  // Step 3.
  let ser = null;
  const txErr = attempt(() => {
    ser = txSerialization(tx);
    if (txHashOf(ser) !== tx.hash) return "the hash does not recompute from the signed fields";
  });
  add("M5.transaction", p.txId, txErr ? "FAIL" : "PASS", null, txErr ?? "the hash recomputes from the signed fields; v and yParity agree; r and s in range, low s");
  if (txErr) add("M5.sender", p.txId, "NOT-EVALUATED", "prerequisite-failed:M5.transaction", "");
  else {
    const sender = await recoverSigner(keccak256(ser.payloadHex), ser.r, ser.s, ser.yParity);
    const senderErr = attempt(() => (sender !== address(tx.from, "from") ? "the recovered sender is not from" : null));
    add("M5.sender", p.txId, senderErr ? "FAIL" : "PASS", null, senderErr ?? "the recovered sender is from");
    if (!senderErr) out.sender = sender;
  }
  const bhErr = attempt(() => {
    const h = headerHash(blk);
    if (h.recomputed !== blk.hash) return `the block hash does not recompute from its ${h.fields} header fields${h.unknown.length ? `; members this version does not know: ${h.unknown.join(", ")}` : ""}`;
  });
  add("M5.block-hash", p.blkId, bhErr ? "FAIL" : "PASS", null, bhErr ?? "the block hash recomputes from the header fields");

  // Step 4.
  if (txErr) {
    add("M5.call", p.txId, "NOT-EVALUATED", "prerequisite-failed:M5.transaction", "");
    if (step5) for (const [id, m] of [["M5.token-domain", null], ["M5.authorization", p.txId], ["M5.token-logs", p.rcId], ["M5.validity-window", null]]) add(id, m, "NOT-EVALUATED", "prerequisite-failed:M5.transaction", "");
    return out;
  }
  const callErr = call === null ? "the call could not be read" : call.fail ?? null;
  add("M5.call", p.txId, callErr ? "FAIL" : "PASS", null, callErr ?? `the call is recognised as ${call.kind}`);
  if (callErr || !step5) return out;

  // Step 5: EIP-3009.
  const a = call.auth;
  const token = (pins.tokens[subjectChain.toString()] ?? []).find((t) => t.address === tx.to.toLowerCase());
  if (!token) {
    add("M5.token-domain", null, "NOT-EVALUATED", "token-not-pinned", `the pins name no token ${tx.to.toLowerCase()} on chain ${subjectChain}`);
    for (const [id, m] of [["M5.authorization", p.txId], ["M5.token-logs", p.rcId], ["M5.validity-window", null]]) add(id, m, "NOT-EVALUATED", "prerequisite-failed:M5.token-domain", "");
    out.auth = a;
    return out;
  }
  out.tokenPinned = true;
  add("M5.token-domain", null, "PASS", null, `the pinned domain: name ${JSON.stringify(token.name)}, version ${JSON.stringify(token.version)}, chain id ${subjectChain}, the token's address`);
  const domain = { name: token.name, version: token.version, chainId: Number(subjectChain), verifyingContract: tx.to.toLowerCase() };
  let rec = null;
  try {
    rec = await recoverAuthorization(a, domain);
  } catch (e) {
    rec = { error: e.message };
  }
  if (rec.signer && rec.signer === a.from) {
    add("M5.authorization", p.txId, "PASS", null, "the authorization signature recovers to its from under the pinned domain");
    out.authStatus = "PASS";
  } else {
    add("M5.authorization", p.txId, "NOT-EVALUATED", "contract-signer", rec.error ?? "ECDSA recovery under the pinned domain does not give the authorization's from; the token accepted it by a path this version does not see");
    out.authStatus = "contract-signer";
  }
  out.signer = rec.signer ?? null;
  out.auth = a;
  const logsErr = attempt(() => {
    const pad = (addr) => "0x" + addr.slice(2).padStart(64, "0");
    const fromToken = rc.logs.filter((l) => l.address === tx.to.toLowerCase());
    const used = fromToken.filter((l) => l.topics[0] === AUTHORIZATION_USED_TOPIC && l.topics.length === 3 && l.topics[1] === pad(a.from) && l.topics[2] === a.nonce);
    if (used.length !== 1) return `the receipt holds ${used.length} AuthorizationUsed logs from the token naming the authorization's from and nonce, not exactly one`;
    const valueWord = "0x" + a.value.toString(16).padStart(64, "0");
    const moved = fromToken.filter((l) => l.topics[0] === TRANSFER_TOPIC && l.topics.length === 3 && l.topics[1] === pad(a.from) && l.topics[2] === pad(a.to) && l.data === valueWord);
    if (moved.length !== 1) return `the receipt holds ${moved.length} Transfer logs from the token with the authorization's from, to and value, not exactly one`;
    out.transferLogIndex = Number(quantity(moved[0].logIndex, "logIndex"));
  });
  add("M5.token-logs", p.rcId, logsErr ? "FAIL" : "PASS", null, logsErr ?? "one AuthorizationUsed and one Transfer log from the token, as the authorization says");
  out.tokenLogsOk = !logsErr;
  const winErr =
    out.blockTs === null
      ? "the block timestamp could not be read"
      : !(a.validAfter < out.blockTs && out.blockTs < a.validBefore)
        ? "the block timestamp is not strictly between validAfter and validBefore"
        : null;
  add("M5.validity-window", null, winErr ? "FAIL" : "PASS", null, winErr ?? "the block timestamp lies strictly between validAfter and validBefore");
  return out;
}

// B-PAY rule 3: the search, with the carrier and the matches that do not bind.
// `h` is the cited entry hash (64 hex digits) or null.
export function analyseSearch(tx, type, call, h) {
  if (h === null) return null;
  const matches = searchHash(tx, type, h);
  const eip = call && eip3009Readable(call);
  let carrier = null;
  const binding = [];
  const nonBinding = [];
  for (const m of matches) {
    if (m.field === "input" && m.form === "raw-32-bytes") {
      if (eip && m.offset === 164) {
        carrier = "eip3009-nonce";
        binding.push(m);
      } else if (eip && m.offset < 164 && m.offset + 32 > 4) nonBinding.push(m);
      else {
        if (carrier === null) carrier = "calldata";
        binding.push(m);
      }
    } else nonBinding.push(m);
  }
  // The nonce word is the carrier when it holds H, whatever else does.
  if (binding.some((m) => m.offset === 164) && eip) carrier = "eip3009-nonce";
  return { fields: signedFields(type), forms: ["raw-32-bytes", "hex-text"], matches, carrier, binding, nonBinding };
}

// The account that signed the bytes holding H at a binding match (B-PAY rules
// 4 and 5): on the EIP-3009 path the payer P for the nonce word, or for other
// calldata when the sender is P; otherwise the sender.
export function signerOfMatch(m, call, payer, sender) {
  if (call && eip3009Readable(call)) {
    if (m.offset === 164) return payer;
    return sender === payer ? payer : sender;
  }
  return sender;
}
