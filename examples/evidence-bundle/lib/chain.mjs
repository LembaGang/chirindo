// The payment block's parent, the account proofs and the block's raw
// transactions (spec M5 step 3), and the reads of the code window of B-PAY
// rule 10e that an offline run makes (spec 4.3, rule 10e; D.1): the
// authorization tuples of the payment transaction, and those of the earlier
// transactions of a carried list whose transactions root matches.

import { concat, fromRlp, keccak256, toRlp } from "viem";
import { address, headerHash, recoverSigner } from "../../ordering-evidence-h4/lib/evm.mjs";
import { exactMembers, FormatError, hexBytes, isPlainObject, quantity } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";
import { trieRoot, walkProof } from "./mpt.mjs";

// The keccak-256 of empty bytes: the code hash of an account without code
// (EIP-1186; EIP-7702's empty code hash).
export const EMPTY_CODE_HASH = keccak256("0x");
const intOf = (hex) => (hex === "0x" ? 0n : BigInt(hex));

// M5.parent-block: the parent's header hash recomputes, it is the payment
// block's parentHash, and its number is one less. Returns the problem or null.
built("M5.parent-block");
export function parentBlockProblem(parent, blk) {
  try {
    if (!isPlainObject(parent)) throw new FormatError("the parent block is not a JSON object");
    const h = headerHash(parent);
    if (h.recomputed !== hexBytes(parent.hash, "parent hash", 32)) throw new FormatError(`its hash does not recompute from its ${h.fields} header fields`);
    if (parent.hash !== blk.parentHash) throw new FormatError("its hash is not the payment block's parentHash");
    if (quantity(parent.number, "parent number") + 1n !== quantity(blk.number, "number")) throw new FormatError("its number is not one less than the payment block's");
    return null;
  } catch (e) {
    if (e instanceof Error) return e.message;
    throw e;
  }
}

const rlpInt = (v) => {
  if (v === 0n) return "0x";
  const h = v.toString(16);
  return "0x" + (h.length % 2 ? "0" : "") + h;
};

// M5.account-proof for one eth-proof-json member (D.1), its value `v` read as
// strict JSON: `headers` maps each carried header the proof may name (the
// payment block's, and the parent's when it passed M5.parent-block) by hash.
// Returns { problem } or { address, blockHash, code } (code false for an
// account the proof shows not to exist).
built("M5.account-proof");
export function accountProof(v, headers) {
  try {
    exactMembers(v, ["block_hash", "result"], [], "the proof member");
    const blockHash = hexBytes(v.block_hash, "block_hash", 32);
    const header = headers.get(blockHash);
    if (!header) throw new FormatError("block_hash names neither the payment block nor a carried parent that passed M5.parent-block");
    const x = v.result;
    exactMembers(x, ["address", "accountProof", "balance", "codeHash", "nonce", "storageHash", "storageProof"], [], "result");
    const a = address(x.address, "result.address");
    if (!Array.isArray(x.storageProof) || x.storageProof.length !== 0) throw new FormatError("result.storageProof is not an empty list");
    if (!Array.isArray(x.accountProof)) throw new FormatError("result.accountProof is not a list");
    x.accountProof.forEach((n, i) => hexBytes(n, `result.accountProof[${i}]`));
    const nonce = quantity(x.nonce, "result.nonce");
    const balance = quantity(x.balance, "result.balance");
    const codeHash = hexBytes(x.codeHash, "result.codeHash", 32);
    const storageHash = hexBytes(x.storageHash, "result.storageHash", 32);
    const w = walkProof(hexBytes(header.stateRoot, "stateRoot", 32), keccak256(a), x.accountProof);
    if (w.value === null) return { address: a, blockHash, code: false };
    const leaf = fromRlp(w.value);
    if (!Array.isArray(leaf) || leaf.length !== 4 || leaf.some((f) => typeof f !== "string")) throw new FormatError("the account's leaf is not the RLP list of nonce, balance, storageHash and codeHash");
    if (intOf(leaf[0]) !== nonce || intOf(leaf[1]) !== balance || leaf[2] !== storageHash || leaf[3] !== codeHash) throw new FormatError("the account's leaf differs from result's nonce, balance, storageHash or codeHash");
    return { address: a, blockHash, code: codeHash !== EMPTY_CODE_HASH };
  } catch (e) {
    if (e instanceof Error) return { problem: e.message };
    throw e;
  }
}

// The key of entry i of a transactions trie: the RLP encoding of the integer i.
const indexKey = (i) => toRlp(rlpInt(BigInt(i)));

// M5.block-transactions for an eth-raw-transactions member (D.1), its value
// `v` read as strict JSON: its block_hash is the payment block's, the
// transactions root recomputed from its entries is the block's
// transactionsRoot, and the entry at the payment's index is the payment
// transaction's encoding. Returns { list } when it meets all three, or
// { mismatch } (the list is then not used, and never FAILs).
built("M5.block-transactions");
export function blockTransactions(v, blk, index, encoding) {
  try {
    exactMembers(v, ["block_hash", "transactions"], [], "the member");
    if (hexBytes(v.block_hash, "block_hash", 32) !== blk.hash) throw new FormatError("block_hash is not the payment block's hash");
    if (!Array.isArray(v.transactions)) throw new FormatError("transactions is not a list");
    v.transactions.forEach((t, i) => {
      if (hexBytes(t, `transactions[${i}]`) === "0x") throw new FormatError(`transactions[${i}] is empty`);
    });
    if (trieRoot(v.transactions.map((t, i) => [indexKey(i), t])) !== blk.transactionsRoot) throw new FormatError(`the transactions root recomputed from its ${v.transactions.length} entries is not the block's transactionsRoot`);
    if (v.transactions[index] !== encoding) throw new FormatError(`entry ${index} is not the payment transaction's encoding`);
    return { list: v.transactions };
  } catch (e) {
    if (e instanceof Error) return { mismatch: e.message };
    throw e;
  }
}

// An authorization tuple's authority (EIP-7702): ecrecover over
// keccak(0x05 || rlp([chain_id, address, nonce])) with its y_parity, r and s,
// whatever its chain id, nonce or s. Null when no address recovers.
built("B-PAY.10e-tuples");
export async function tupleAuthority({ chainId, address, nonce, yParity, r, s }) {
  try {
    const msg = keccak256(concat(["0x05", toRlp([rlpInt(chainId), address, rlpInt(nonce)])]));
    return await recoverSigner(msg, r, s, Number(yParity));
  } catch {
    return null;
  }
}

// The tuples of a payment-transaction member's authorizationList (already
// read by M5.transaction), as numbers.
export const jsonTuples = (list) =>
  (list ?? []).map((t) => ({ chainId: quantity(t.chainId, "chainId"), address: t.address.toLowerCase(), nonce: quantity(t.nonce, "nonce"), yParity: t.yParity !== undefined ? quantity(t.yParity, "yParity") : quantity(t.v, "v"), r: quantity(t.r, "r"), s: quantity(t.s, "s") }));

// Rule 10e's scan of the entries before the payment's index in a carried list
// that M5.block-transactions passed, each read by its first byte ([0, 0x7f] a
// typed transaction of that type, [0xc0, 0xfe] a legacy one): only a type 0x04
// entry is decoded, as EIP-7702's payload, far enough to read its
// authorization_list. Returns { tupleFor: the first entry with a tuple whose
// authority is `account`, or null; unread: the first entry that does not
// decode or is of a type this version does not know, or null }.
built("B-PAY.10e-scan");
export async function scanEarlier(list, index, account) {
  let unread = null;
  for (let i = 0; i < index; i++) {
    const b0 = parseInt(list[i].slice(2, 4), 16);
    if (b0 >= 0xc0 && b0 <= 0xfe) continue;
    if ([0x01, 0x02, 0x7e].includes(b0)) continue;
    if (b0 !== 0x04) {
      unread ??= `entry ${i} is of type 0x${b0.toString(16).padStart(2, "0")}, which this version does not read`;
      continue;
    }
    let tuples;
    try {
      const f = fromRlp("0x" + list[i].slice(4));
      if (!Array.isArray(f) || f.length !== 13 || !Array.isArray(f[9])) throw new Error("not an EIP-7702 payload");
      tuples = f[9].map((t) => {
        if (!Array.isArray(t) || t.length !== 6 || t.some((x) => typeof x !== "string") || t[1].length !== 42) throw new Error("a malformed authorization tuple");
        return { chainId: intOf(t[0]), address: t[1], nonce: intOf(t[2]), yParity: intOf(t[3]), r: intOf(t[4]), s: intOf(t[5]) };
      });
    } catch {
      unread ??= `entry ${i}, of type 0x04, does not decode as an EIP-7702 payload`;
      continue;
    }
    for (const t of tuples) if ((await tupleAuthority(t)) === account) return { tupleFor: i, unread };
  }
  return { tupleFor: null, unread };
}
