// The payment transaction as spec M5 steps 3 and 4 and B-PAY rule 3 read it:
// its signed serialization, the top-level call, and the search for an entry
// hash in its signed fields.
//
// keccak-256, RLP, ABI coding and recovery come from viem, through the reused
// helpers of examples/ordering-evidence-h4/lib/evm.mjs. txSerialization there
// requires both v and yParity on a typed transaction; spec D.1 accepts either
// or both, agreeing when both, so the serialization below is this folder's.

import { keccak256, toFunctionSelector, toRlp } from "viem";
import { FormatError, hexBytes, isPlainObject, quantity } from "../../ordering-evidence-h4/lib/formats.mjs";
import { address, decodeCall, EIP3009_ABI, sigScalars } from "../../ordering-evidence-h4/lib/evm.mjs";

const rlpQty = (v) => {
  if (v === 0n) return "0x";
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return "0x" + h;
};

function accessListRlp(al, what) {
  if (!Array.isArray(al)) throw new FormatError(`${what} is not an array`);
  return al.map((e, k) => {
    if (!isPlainObject(e)) throw new FormatError(`${what}[${k}] is not an object`);
    const keys = Object.keys(e);
    if (keys.length !== 2 || !keys.includes("address") || !keys.includes("storageKeys")) throw new FormatError(`${what}[${k}] must have exactly address and storageKeys`);
    if (!Array.isArray(e.storageKeys)) throw new FormatError(`${what}[${k}].storageKeys is not an array`);
    return [address(e.address, `${what}[${k}].address`), e.storageKeys.map((sk, j) => hexBytes(sk, `${what}[${k}].storageKeys[${j}]`, 32))];
  });
}

function authorizationListRlp(list, what) {
  if (!Array.isArray(list)) throw new FormatError(`${what} is not an array`);
  return list.map((a, k) => {
    if (!isPlainObject(a)) throw new FormatError(`${what}[${k}] is not an object`);
    for (const key of Object.keys(a)) if (!["chainId", "address", "nonce", "yParity", "r", "s", "v"].includes(key)) throw new FormatError(`${what}[${k}] has an unexpected member ${key}`);
    const yp = a.yParity !== undefined ? quantity(a.yParity, `${what}[${k}].yParity`) : quantity(a.v, `${what}[${k}].v`);
    if (a.yParity !== undefined && a.v !== undefined && quantity(a.v, `${what}[${k}].v`) !== yp) throw new FormatError(`${what}[${k}]: v and yParity differ`);
    return [
      rlpQty(quantity(a.chainId, `${what}[${k}].chainId`)),
      address(a.address, `${what}[${k}].address`),
      rlpQty(quantity(a.nonce, `${what}[${k}].nonce`)),
      rlpQty(yp),
      rlpQty(quantity(a.r, `${what}[${k}].r`)),
      rlpQty(quantity(a.s, `${what}[${k}].s`)),
    ];
  });
}

// The chain id a transaction names: its chainId member, or for a legacy
// transaction the EIP-155 chain id in v (spec M5 step 1). Null when it names none.
export function txChainId(tx) {
  const type = quantity(tx.type, "type");
  if (type === 0n) {
    const v = quantity(tx.v, "v");
    if (v >= 35n) return (v - 35n) / 2n;
    return null;
  }
  if (tx.chainId === undefined || tx.chainId === null) return null;
  return quantity(tx.chainId, "chainId");
}

// Spec M5 step 3 and D.1: the signed serialization (whose keccak-256 is the
// hash) and the signing payload, for the types 0x0, 0x1, 0x2 and 0x4.
export function txSerialization(tx) {
  const type = tx.type;
  const nonce = rlpQty(quantity(tx.nonce, "nonce"));
  const gas = rlpQty(quantity(tx.gas, "gas"));
  if (tx.to === undefined) throw new FormatError("the transaction has no to member");
  const to = tx.to === null ? "0x" : address(tx.to, "to");
  if (tx.to === null && type === "0x4") throw new FormatError("an EIP-7702 transaction must have a to address");
  const value = rlpQty(quantity(tx.value, "value"));
  const input = hexBytes(tx.input, "input");
  const r = quantity(tx.r, "r");
  const s = quantity(tx.s, "s");
  sigScalars(r, s, "transaction signature");
  if (type === "0x0") {
    const gasPrice = rlpQty(quantity(tx.gasPrice, "gasPrice"));
    const v = quantity(tx.v, "v");
    let chainId = null;
    let yParity;
    if (v === 27n || v === 28n) yParity = Number(v - 27n);
    else if (v >= 35n) {
      chainId = (v - 35n) / 2n;
      yParity = Number((v - 35n) % 2n);
    } else throw new FormatError(`legacy v ${v} is neither 27 or 28 nor EIP-155`);
    if (tx.chainId !== undefined && tx.chainId !== null) {
      const c = quantity(tx.chainId, "chainId");
      if (chainId === null || c !== chainId) throw new FormatError(`chainId ${c} does not match the chain id in v`);
    }
    const base = [nonce, gasPrice, gas, to, value, input];
    const payload = chainId === null ? toRlp(base) : toRlp([...base, rlpQty(chainId), "0x", "0x"]);
    const signed = toRlp([...base, rlpQty(v), rlpQty(r), rlpQty(s)]);
    return { type, chainId, signedHex: signed, payloadHex: payload, r, s, yParity };
  }
  const chainId = quantity(tx.chainId, "chainId");
  // Spec D.1: a typed transaction carries v or yParity or both, and when both
  // they agree (the reused checker requires both).
  if (tx.yParity === undefined && tx.v === undefined) throw new FormatError("a typed transaction carries neither v nor yParity");
  const yParity = tx.yParity !== undefined ? quantity(tx.yParity, "yParity") : quantity(tx.v, "v");
  if (tx.yParity !== undefined && tx.v !== undefined && quantity(tx.v, "v") !== yParity) throw new FormatError("v and yParity differ");
  if (yParity !== 0n && yParity !== 1n) throw new FormatError("yParity is not 0 or 1");
  const accessList = accessListRlp(tx.accessList, "accessList");
  let fields;
  if (type === "0x1") {
    fields = [rlpQty(chainId), nonce, rlpQty(quantity(tx.gasPrice, "gasPrice")), gas, to, value, input, accessList];
  } else {
    const prio = rlpQty(quantity(tx.maxPriorityFeePerGas, "maxPriorityFeePerGas"));
    const max = rlpQty(quantity(tx.maxFeePerGas, "maxFeePerGas"));
    fields = [rlpQty(chainId), nonce, prio, max, gas, to, value, input, accessList];
    if (type === "0x4") fields.push(authorizationListRlp(tx.authorizationList, "authorizationList"));
  }
  const prefix = "0x0" + type.slice(2);
  const payload = prefix + toRlp(fields).slice(2);
  const signed = prefix + toRlp([...fields, rlpQty(yParity), rlpQty(r), rlpQty(s)]).slice(2);
  return { type, chainId, signedHex: signed, payloadHex: payload, r, s, yParity: Number(yParity) };
}

export const txHashOf = (ser) => keccak256(ser.signedHex);

const SEL = Object.fromEntries(EIP3009_ABI.map((f) => [`${f.name}/${f.inputs.length}`, toFunctionSelector(f)]));
const FRAGMENT = Object.fromEntries(EIP3009_ABI.map((f) => [`${f.name}/${f.inputs.length}`, f]));

// Spec M5 step 4 and B-PAY rule 2: the top-level call, recognised by its
// selector and to. Returns { kind, ... } where kind is one of twa9, twaBytes,
// receive9, receiveBytes, userop, creation, other. A transferWithAuthorization
// must be the canonical ABI encoding of its arguments, followed by any trailer;
// `fail` is set when it is not.
export function recogniseCall(tx, erc4337) {
  if (tx.to === null) return { kind: "creation" };
  const input = tx.input;
  const sel = input.length >= 10 ? input.slice(0, 10) : null;
  const entry = [
    ["twa9", "transferWithAuthorization/9"],
    ["twaBytes", "transferWithAuthorization/7"],
    ["receive9", "receiveWithAuthorization/9"],
    ["receiveBytes", "receiveWithAuthorization/7"],
  ].find(([, k]) => SEL[k] === sel);
  if (entry) {
    const [kind, key] = entry;
    if (kind.startsWith("receive")) return { kind };
    let d;
    try {
      d = decodeCall(input, FRAGMENT[key]);
    } catch (e) {
      return { kind, fail: e.message };
    }
    if (!d.canonical) return { kind, fail: d.reason };
    const [from, to, value, validAfter, validBefore, nonce] = d.args;
    const auth = { from: from.toLowerCase(), to: to.toLowerCase(), value, validAfter, validBefore, nonce: nonce.toLowerCase() };
    if (kind === "twa9") Object.assign(auth, { v: d.args[6], r: d.args[7], s: d.args[8] });
    else auth.signature = d.args[6];
    return { kind, auth, argsEnd: d.argsEnd, trailerHex: d.trailerHex };
  }
  if ((sel && erc4337.selectors.includes(sel)) || erc4337.entrypoints.includes(tx.to)) return { kind: "userop" };
  return { kind: "other" };
}

// The authorization the EIP-3009 path reads (spec M5 step 5): the nine-argument
// form, or the bytes signature form with a 65-byte signature.
export const eip3009Readable = (call) => call.kind === "twa9" || (call.kind === "twaBytes" && call.auth && call.auth.signature.length === 2 + 130);

// The calls B-PAY rule 2 makes UNSUPPORTED-PATH (unsupported-call):
// receiveWithAuthorization in either form, the bytes signature form with a
// signature that is not 65 bytes, an ERC-4337 EntryPoint call, a contract creation.
export const unreadByRule2 = (call) => ["receive9", "receiveBytes", "userop", "creation"].includes(call.kind) || (call.kind === "twaBytes" && !eip3009Readable(call));

// Spec B-PAY rule 3 and D.1: the signed fields of a type, by member name, in
// the order rule 3 lists them.
export function signedFields(type) {
  if (type === "0x0") return ["chainId", "nonce", "gas", "gasPrice", "to", "value", "input"];
  if (type === "0x1") return ["chainId", "nonce", "gas", "gasPrice", "to", "value", "input", "accessList"];
  if (type === "0x2") return ["chainId", "nonce", "gas", "maxPriorityFeePerGas", "maxFeePerGas", "to", "value", "input", "accessList"];
  if (type === "0x4") return ["chainId", "nonce", "gas", "maxPriorityFeePerGas", "maxFeePerGas", "to", "value", "input", "accessList", "authorizationList"];
  return [];
}

const QTY_FIELDS = new Set(["chainId", "nonce", "gas", "gasPrice", "maxPriorityFeePerGas", "maxFeePerGas", "value"]);

// Every match of the 32-byte hash h (64 lowercase hex digits, no 0x) in the
// signed fields: as 32 raw bytes, and as its 64 hex digits in ASCII without
// regard to case. Returns [{ field, form, offset }].
export function searchHash(tx, type, h) {
  const out = [];
  const hBig = BigInt("0x" + h);
  const asQty = (field, v) => {
    if (v === hBig) out.push({ field, form: "raw-32-bytes", offset: null });
  };
  for (const field of signedFields(type)) {
    if (field === "chainId") {
      const c = txChainId(tx);
      if (c !== null) asQty("chainId", c);
    } else if (QTY_FIELDS.has(field)) {
      asQty(field, quantity(tx[field], field));
    } else if (field === "input") {
      const hex = tx.input.slice(2);
      for (let k = hex.indexOf(h); k !== -1; k = hex.indexOf(h, k + 1)) if (k % 2 === 0) out.push({ field: "input", form: "raw-32-bytes", offset: k / 2 });
      const ascii = Buffer.from(hex, "hex").toString("latin1").toLowerCase();
      for (let k = ascii.indexOf(h); k !== -1; k = ascii.indexOf(h, k + 1)) out.push({ field: "input", form: "hex-text", offset: k });
    } else if (field === "accessList") {
      (tx.accessList ?? []).forEach((e, i) =>
        e.storageKeys.forEach((sk, j) => {
          if (sk.slice(2) === h) out.push({ field: `accessList[${i}].storageKeys[${j}]`, form: "raw-32-bytes", offset: null });
        }),
      );
    } else if (field === "authorizationList") {
      (tx.authorizationList ?? []).forEach((a, i) => {
        for (const m of ["chainId", "nonce", "yParity", "r", "s"]) if (a[m] !== undefined) asQty(`authorizationList[${i}].${m}`, quantity(a[m], m));
      });
    }
  }
  return out;
}
