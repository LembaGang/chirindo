// Spec 4.8: the classes of the WE-1 sweep for a change after which the verdict
// is not FAILS. `same-values`: the member (or the bundle document) parses to
// the same values in canonical form, an address in its other valid spelling
// included. `listed`: every value the change touches is one table 4-8 lists as
// not covered, or a value under one of its conditions. Anything else is
// `UNEXPECTED`. The not-covered column of table 4-8 is written below as a
// predicate over member paths, one function per row.

import canonicalize from "canonicalize";
import { getAddress } from "viem";
import { isPlainObject, parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";
import { parseChirindoLog, parseSidecar } from "./records.mjs";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

// The values a member's profile reads, in a form whose canonical JSON can be
// compared: an address written lowercase or in its EIP-55 form is lowercased
// (its other valid spelling is the same value), and a jcs-json member is read with JSON.parse (spec 4.1).
export function valuesOf(profile, bytes) {
  const norm = (v) => {
    if (typeof v === "string") return ADDRESS.test(v) && (v === v.toLowerCase() || v === getAddress(v)) ? v.toLowerCase() : v;
    if (Array.isArray(v)) return v.map(norm);
    if (isPlainObject(v)) return Object.fromEntries(Object.keys(v).map((k) => [k, norm(v[k])]));
    if (typeof v === "bigint") return { bigint: v.toString() };
    return v;
  };
  if (profile === "chirindo-evidence.action/1") {
    const { records, checkpoint } = parseChirindoLog(bytes);
    return norm({ records, checkpoint });
  }
  if (profile === "chirindo-witness-sidecar/1") return norm(parseSidecar(bytes).map(({ checkpoint, receipt, error }) => ({ checkpoint, receipt, error })));
  if (profile === "jcs-json") {
    parseStrictJson(bytes, { allowNonInteger: true });
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  }
  return norm(parseStrictJson(bytes));
}

export const canonical = (v) => canonicalize(v);

// Every path at which a and b differ: { path: [...], kind: changed | added | removed }.
export function diffPaths(a, b, path = []) {
  if (isPlainObject(a) && isPlainObject(b)) {
    const out = [];
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!(k in a)) out.push({ path: [...path, k], kind: "added" });
      else if (!(k in b)) out.push({ path: [...path, k], kind: "removed" });
      else out.push(...diffPaths(a[k], b[k], [...path, k]));
    }
    return out;
  }
  if (Array.isArray(a) && Array.isArray(b) && a.length === b.length) return a.flatMap((x, i) => diffPaths(x, b[i], [...path, i]));
  return canonicalize(a) === canonicalize(b) ? [] : [{ path, kind: "changed" }];
}

const RC_NOT_COVERED = new Set(["blobGasUsed", "cumulativeGasUsed", "daFootprintGasScalar", "effectiveGasPrice", "gasUsed", "logsBloom"]);
const TX_COVERED = new Set(["type", "chainId", "nonce", "gas", "maxPriorityFeePerGas", "maxFeePerGas", "to", "value", "input", "accessList", "authorizationList", "r", "s", "yParity", "v", "hash", "from", "blockHash", "blockNumber", "transactionIndex", "blockTimestamp"]);
const HEADER = new Set(["parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash", "hash"]);

// Table 4-8, column "not covered", per member role and profile. `orig` and
// `next` are the member's values before and after the change; `ctx` gives
// what a row's condition reads (the transaction's type and index, the receipt
// logs the EIP-3009 path reads, the key ids the verifier resolves).
export const NOT_COVERED = {
  // Row "payment-transaction": gasPrice on types 0x2 and 0x4; the name of v or
  // of yParity while the other is present; blockTimestamp when absent; any
  // other member.
  "payment-transaction": (d, orig, next) => {
    const [top] = d.path;
    if (d.path.length === 0) return false;
    if (top === "gasPrice" && ["0x2", "0x4"].includes(orig.type)) return true;
    if (!TX_COVERED.has(top)) return true;
    if (d.kind === "removed" && top === "v" && "yParity" in next) return true;
    if (d.kind === "removed" && top === "yParity" && "v" in next) return true;
    if (d.kind === "removed" && top === "blockTimestamp") return true;
    return false;
  },
  // Row "payment-receipt": the listed members, every l1 member, logsBloom,
  // each log's logIndex, a log's blockTimestamp when absent, and the address,
  // topics and data of every log the EIP-3009 path does not read. A member
  // added by a one-byte rename counts only beside the removal of a member that
  // is itself not covered (spec 4.8.2, renaming an eth-rpc-json member).
  "payment-receipt": (d, orig, next, ctx, all) => {
    const [top, i, field] = d.path;
    const inLog = top === "logs" && typeof i === "number";
    if (d.kind === "added") return all.some((x) => x.kind === "removed" && x.path.length === d.path.length && x.path.slice(0, -1).join("/") === d.path.slice(0, -1).join("/") && NOT_COVERED["payment-receipt"](x, orig, next, ctx, all));
    if (RC_NOT_COVERED.has(top) || (typeof top === "string" && top.startsWith("l1"))) return d.path.length === 1 || d.kind === "changed";
    if (inLog) {
      if (field === "logIndex" && d.kind === "changed") return true;
      if (field === "blockTimestamp" && d.kind === "removed") return true;
      if (["address", "topics", "data"].includes(field) && !ctx.readLogs.includes(i)) return true;
    }
    return false;
  },
  // Row "payment-block": size; totalDifficulty; every other entry of
  // transactions; the contents of uncles and withdrawals; a member that is not
  // a header field (renames of the non-header members among them).
  "payment-block": (d, orig, next, ctx) => {
    const [top, j] = d.path;
    if (["size", "totalDifficulty", "uncles", "withdrawals"].includes(top)) return true;
    if (top === "transactions" && typeof j === "number" && j !== ctx.txIndex) return true;
    if (d.kind === "added" && !HEADER.has(top) && top !== "transactions") return true;
    return false;
  },
  // Row "operator-key": other members of the JWK, kid when absent; in a JWKS,
  // other keys and other members.
  jwks: (d, orig, next, ctx) => {
    const [top, i, field] = d.path;
    if (top !== "keys") return true;
    if (typeof i !== "number") return false;
    if (!ctx.usedKeyIndexes.includes(i)) return true;
    if (!["kty", "crv", "x", "kid"].includes(field)) return true;
    if (field === "kid" && d.kind === "removed") return true;
    return false;
  },
  // Row "witness-key": canonical_payload_spec; entries for other key ids; any
  // other member.
  "ho-v5-keys": (d, orig, next, ctx) => {
    const [top, i] = d.path;
    if (top !== "keys") return true;
    // An entry that, after the change, is for a key id no receipt uses.
    if (typeof i === "number" && !ctx.resolvedKeyIds.includes(next.keys?.[i]?.key_id)) return true;
    return false;
  },
  // Row "witness-sidecar": the witness_error text; the values of a receipt
  // whose key id the verifier cannot resolve (row "witness-receipt"); every
  // value of an unattached checkpoint, whose kid has no carried operator key
  // (row "checkpoint").
  "chirindo-witness-sidecar/1": (d, orig, next, ctx) => {
    const [line, field] = d.path;
    if (field === "error") return true;
    if (field === "checkpoint" && typeof line === "number" && !ctx.carriedKids.includes(next[line]?.checkpoint?.kid)) return true;
    if (field === "receipt" && typeof line === "number" && !ctx.resolvedKeyIds.includes(next[line]?.receipt?.public_key_id)) return true;
    return false;
  },
  // Row "bundle document": created_at; assembled_by; each member's source,
  // fetched_at, capture and media_type; the id of a member nothing references.
  bundle: (d, orig) => {
    const [top, i, field] = d.path;
    if (top === "created_at" || top === "assembled_by") return true;
    if (top === "members" && typeof i === "number") {
      if (["source", "fetched_at", "capture", "media_type"].includes(field) && d.kind === "changed") return true;
      if (field === "id" && d.kind === "changed") {
        const id = orig.members[i].id;
        const referenced = orig.subject.cites.log === id || orig.members.some((m) => m.issuer_profile === id);
        return !referenced;
      }
    }
    return false;
  },
};

// Classifies one change after which the verdict was not FAILS.
export function classify({ key, origBytes, nextBytes, ctx }) {
  let a;
  let b;
  try {
    a = valuesOf(key, origBytes);
    b = valuesOf(key, nextBytes);
  } catch {
    return "UNEXPECTED";
  }
  if (canonical(a) === canonical(b)) return "same-values";
  const rule = NOT_COVERED[key];
  if (!rule) return "UNEXPECTED";
  const diffs = diffPaths(a, b);
  return diffs.length > 0 && diffs.every((d) => rule(d, a, b, ctx, diffs)) ? "listed" : "UNEXPECTED";
}

export const ROLE_KEY = (m) =>
  m.role === "payment-transaction" || m.role === "payment-receipt" || m.role === "payment-block" ? m.role : m.profile;
