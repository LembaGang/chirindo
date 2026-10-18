// Ethereum and Base formats used by check-h4.mjs: transaction serialization
// and sender recovery for the types an externally owned account sends on
// Base, the block header hash, call recognition and the end of ABI-encoded
// arguments, EIP-3009 authorizations, and ERC-8021 data suffixes.
//
// keccak-256, RLP, secp256k1 recovery, EIP-712 hashing and ABI coding come
// from viem (version pinned in package.json); nothing here re-implements them.

import {
  decodeAbiParameters,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  parseAbi,
  recoverAddress,
  toFunctionSelector,
  toRlp,
} from "viem";
import { FormatError, hexBytes, isPlainObject, quantity } from "./formats.mjs";

export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = SECP256K1_N / 2n;

// A 20-byte address, all lowercase or a valid EIP-55 checksum; returned lowercase.
export function address(s, what) {
  if (typeof s !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(s)) throw new FormatError(`${what} is not a 20-byte hex address`);
  if (s !== s.toLowerCase() && s !== getAddress(s)) throw new FormatError(`${what} has mixed case that is not a valid EIP-55 checksum`);
  return s.toLowerCase();
}

const rlpQty = (v) => {
  if (v === 0n) return "0x";
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return "0x" + h;
};
export const pad32 = (v) => "0x" + v.toString(16).padStart(64, "0");

// r and s of a secp256k1 signature as Ethereum accepts them: 1 <= r < n and
// 1 <= s <= n/2 (EIP-2 low s, which Ethereum nodes require of a transaction's signature).
export function sigScalars(r, s, what) {
  if (r < 1n || r >= SECP256K1_N) throw new FormatError(`${what}: r is out of range`);
  if (s < 1n || s >= SECP256K1_N) throw new FormatError(`${what}: s is out of range`);
  if (s > HALF_N) throw new FormatError(`${what}: s is in the upper half of the curve order (high-s), which Ethereum refuses`);
}

export async function recoverSigner(digest, r, s, yParity) {
  const a = await recoverAddress({ hash: digest, signature: { r: pad32(r), s: pad32(s), yParity } });
  return a.toLowerCase();
}

export const TX_TYPES = { "0x0": "legacy", "0x1": "EIP-2930", "0x2": "EIP-1559", "0x4": "EIP-7702" };

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
    const allowed = ["chainId", "address", "nonce", "yParity", "r", "s", "v"];
    for (const key of Object.keys(a)) if (!allowed.includes(key)) throw new FormatError(`${what}[${k}] has an unexpected member ${key}`);
    const yp = quantity(a.yParity, `${what}[${k}].yParity`);
    if (a.v !== undefined && quantity(a.v, `${what}[${k}].v`) !== yp) throw new FormatError(`${what}[${k}]: v and yParity differ`);
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

// From a JSON-RPC transaction object: the signed serialization (whose
// keccak-256 is the transaction hash) and the signing payload (whose
// keccak-256 the sender signed). Types other than TX_TYPES throw
// "unsupported type".
export function txSerialization(tx) {
  if (!isPlainObject(tx)) throw new FormatError("transaction is not a JSON object");
  if (typeof tx.type !== "string") throw new FormatError("transaction has no type member");
  const type = tx.type;
  if (!(type in TX_TYPES)) throw new FormatError(`unsupported type ${type} (supported: ${Object.keys(TX_TYPES).join(", ")})`);
  const nonce = rlpQty(quantity(tx.nonce, "nonce"));
  const gas = rlpQty(quantity(tx.gas, "gas"));
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
    } else throw new FormatError(`legacy v ${v} is neither 27/28 nor EIP-155`);
    if (tx.chainId !== undefined && tx.chainId !== null) {
      const c = quantity(tx.chainId, "chainId");
      if (chainId === null || c !== chainId) throw new FormatError(`chainId ${c} does not match the chain id in v (${chainId})`);
    }
    const base = [nonce, gasPrice, gas, to, value, input];
    const payload = chainId === null ? toRlp(base) : toRlp([...base, rlpQty(chainId), "0x", "0x"]);
    const signed = toRlp([...base, rlpQty(v), rlpQty(r), rlpQty(s)]);
    return { type, typeName: TX_TYPES[type], chainId, signedHex: signed, payloadHex: payload, r, s, yParity };
  }
  const chainId = quantity(tx.chainId, "chainId");
  // Base's endpoints return both for a typed transaction; both are required
  // and must agree, so neither can be dropped or renamed unnoticed.
  if (tx.yParity === undefined || tx.v === undefined) throw new FormatError("a typed transaction must carry both v and yParity");
  const yParity = quantity(tx.yParity, "yParity");
  if (quantity(tx.v, "v") !== yParity) throw new FormatError("v and yParity differ");
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
  return { type, typeName: TX_TYPES[type], chainId, signedHex: signed, payloadHex: payload, r, s, yParity: Number(yParity) };
}

// Block header fields in the order of the header's RLP list. The six after
// nonce are optional and appear in this order as forks add them (London,
// Shanghai, Cancun, Cancun, Cancun, Prague); Base mainnet blocks carry all 21.
export const HEADER_FIELDS = [
  ["parentHash", "h32"],
  ["sha3Uncles", "h32"],
  ["miner", "addr"],
  ["stateRoot", "h32"],
  ["transactionsRoot", "h32"],
  ["receiptsRoot", "h32"],
  ["logsBloom", "bloom"],
  ["difficulty", "q"],
  ["number", "q"],
  ["gasLimit", "q"],
  ["gasUsed", "q"],
  ["timestamp", "q"],
  ["extraData", "data"],
  ["mixHash", "h32"],
  ["nonce", "nonce"],
  ["baseFeePerGas", "q"],
  ["withdrawalsRoot", "h32"],
  ["blobGasUsed", "q"],
  ["excessBlobGas", "q"],
  ["parentBeaconBlockRoot", "h32"],
  ["requestsHash", "h32"],
];
const REQUIRED_HEADER = 15;
export const NON_HEADER_BLOCK_MEMBERS = ["hash", "size", "totalDifficulty", "transactions", "uncles", "withdrawals"];

// Returns { recomputed, fields, unknown }: the keccak-256 of the RLP list of
// the header fields this checker knows, and the block's members it does not
// know. A member it does not know is not hashed, so if it is a header field of
// a format this checker was not built for, the recomputed hash will not match
// and the caller fails; it never skips the comparison.
export function headerHash(block) {
  if (!isPlainObject(block)) throw new FormatError("block is not a JSON object");
  const known = new Set([...HEADER_FIELDS.map((f) => f[0]), ...NON_HEADER_BLOCK_MEMBERS]);
  const unknown = Object.keys(block).filter((k) => !known.has(k));
  const list = [];
  let ended = false;
  for (let k = 0; k < HEADER_FIELDS.length; k++) {
    const [name, kind] = HEADER_FIELDS[k];
    const present = block[name] !== undefined && block[name] !== null;
    if (!present) {
      if (k < REQUIRED_HEADER) throw new FormatError(`block lacks header field ${name}`);
      ended = true;
      continue;
    }
    if (ended) throw new FormatError(`block has header field ${name} without the fields before it`);
    const v = block[name];
    if (kind === "q") list.push(rlpQty(quantity(v, name)));
    else if (kind === "h32") list.push(hexBytes(v, name, 32));
    else if (kind === "addr") list.push(address(v, name));
    else if (kind === "bloom") list.push(hexBytes(v, name, 256));
    else if (kind === "nonce") list.push(hexBytes(v, name, 8));
    else list.push(hexBytes(v, name));
  }
  return { recomputed: keccak256(toRlp(list)), fields: list.length, unknown };
}

// Calls this checker recognises without help, by selector.
export const EIP3009_ABI = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)",
  "function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)",
]);
// ERC-4337 EntryPoint batch calls (v0.6, and v0.7/v0.8 which share a layout).
export const USEROP_ABI = parseAbi([
  "function handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[] ops, address beneficiary)",
  "function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[] ops, address beneficiary)",
  "function handleAggregatedOps(((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address,bytes)[] opsPerAggregator, address beneficiary)",
  "function handleAggregatedOps(((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address,bytes)[] opsPerAggregator, address beneficiary)",
]);
export const ENTRYPOINTS = new Set([
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789", // v0.6
  "0x0000000071727de22e5e9d8baf0edac6f37da032", // v0.7
  "0x4337084d9e255ff0702461cf8895ce9e3b5ff108", // v0.8
]);

function signatureOf(item) {
  return `${item.name}(${item.inputs.map((p) => p.type).join(",")})`;
}

// The first line of an error's summary. viem's errors carry a shortMessage;
// their full message adds details such as the data being decoded.
export function shortError(e) {
  return String(e?.shortMessage ?? e?.message ?? e).split("\n")[0];
}

// Decode a call by one ABI fragment and find where its ABI-encoded arguments
// end: the arguments are decoded, encoded again, and the result must be a
// prefix of the calldata. Bytes after it are the trailer.
export function decodeCall(input, fragment) {
  let decoded;
  try {
    decoded = decodeFunctionData({ abi: [fragment], data: input });
  } catch (e) {
    // viem's full message repeats the calldata, which can hold a party's
    // address; only its one-line summary is kept.
    throw new FormatError(`the calldata does not decode as ${signatureOf(fragment)}: ${shortError(e)}`);
  }
  let canonical;
  try {
    canonical = encodeFunctionData({ abi: [fragment], functionName: fragment.name, args: decoded.args });
  } catch (e) {
    return { fragment, signature: signatureOf(fragment), args: decoded.args, canonical: false, reason: `the arguments do not encode again (${shortError(e)})` };
  }
  if (!input.startsWith(canonical)) {
    return { fragment, signature: signatureOf(fragment), args: decoded.args, canonical: false, reason: "the calldata is not the canonical ABI encoding of its arguments" };
  }
  const argsEnd = (canonical.length - 2) / 2;
  return { fragment, signature: signatureOf(fragment), args: decoded.args, canonical: true, argsEnd, trailerHex: "0x" + input.slice(canonical.length) };
}

export function selectorOf(input) {
  return input.length >= 10 ? input.slice(0, 10) : null;
}

export function findFragment(abi, selector) {
  return abi.filter((f) => f.type === "function" && toFunctionSelector(f) === selector);
}

// All byte offsets of needle (32 bytes, 0x-hex) in hay (0x-hex), byte aligned.
export function findBytes(hayHex, needleHex) {
  const hay = hayHex.slice(2);
  const needle = needleHex.slice(2);
  const out = [];
  for (let k = hay.indexOf(needle); k !== -1; k = hay.indexOf(needle, k + 1)) if (k % 2 === 0) out.push(k / 2);
  return out;
}

export const TRANSFER_TOPIC = keccak256(new TextEncoder().encode("Transfer(address,address,uint256)"));
export const AUTHORIZATION_USED_TOPIC = keccak256(new TextEncoder().encode("AuthorizationUsed(address,bytes32)"));

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

// The EIP-3009 authorization digest under a token's EIP-712 domain, and the
// address that signed it. v must be 27 or 28 and s low: this checker accepts
// only those forms.
export async function recoverAuthorization(auth, domain) {
  const digest = hashTypedData({
    domain,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: { from: auth.from, to: auth.to, value: auth.value, validAfter: auth.validAfter, validBefore: auth.validBefore, nonce: auth.nonce },
  });
  let r, s, v;
  if (auth.signature !== undefined) {
    const sig = auth.signature.toLowerCase();
    if (sig.length !== 2 + 130) throw new FormatError(`authorization signature is ${(sig.length - 2) / 2} bytes, not 65 (a contract-wallet signature is not supported)`);
    r = BigInt("0x" + sig.slice(2, 66));
    s = BigInt("0x" + sig.slice(66, 130));
    v = parseInt(sig.slice(130, 132), 16);
  } else {
    r = BigInt(auth.r);
    s = BigInt(auth.s);
    v = Number(auth.v);
  }
  if (v !== 27 && v !== 28) throw new FormatError(`authorization v is ${v}, not 27 or 28`);
  sigScalars(r, s, "authorization signature");
  return { digest, signer: await recoverSigner(digest, r, s, v - 27) };
}

export function decodeAbiString(hex) {
  return decodeAbiParameters([{ type: "string" }], hex)[0];
}

// ERC-8021 data suffix, read from the end of `hex`. Returns null when the
// last 16 bytes are not the ERC-8021 marker. Layouts follow the draft ERC
// (ethereum/ERCs pull 1209): schema 0 codes, schema 1 codes plus a registry,
// schema 2 a CBOR map; any other schema id is reported as unknown.
export const ERC8021_MARKER = "80218021802180218021802180218021";

export function parseErc8021(hex) {
  const b = Buffer.from(hex.slice(2), "hex");
  const n = b.length;
  if (n < 17 || b.subarray(n - 16).toString("hex") !== ERC8021_MARKER) return null;
  const schemaId = b[n - 17];
  const out = { schemaId };
  const need = (k, what) => {
    if (k > n) throw new FormatError(`ERC-8021 suffix is truncated (${what})`);
  };
  const ascii = (buf) => {
    for (const c of buf) if (c > 0x7f) throw new FormatError("ERC-8021 codes are not 7-bit ASCII");
    return buf.toString("latin1");
  };
  if (schemaId === 0 || schemaId === 1) {
    need(18, "codes length");
    const codesLength = b[n - 18];
    need(18 + codesLength, "codes");
    const codes = ascii(b.subarray(n - 18 - codesLength, n - 18));
    out.codes = codes.length ? codes.split(",") : [];
    out.length = 18 + codesLength;
    if (schemaId === 1) {
      need(out.length + 1, "registry chain id length");
      const chainIdLength = b[n - out.length - 1];
      if (chainIdLength === 0) throw new FormatError("ERC-8021 registry chain id length is 0");
      need(out.length + 1 + chainIdLength + 20, "registry");
      const chainIdBytes = b.subarray(n - out.length - 1 - chainIdLength, n - out.length - 1);
      out.codeRegistryChainId = BigInt("0x" + chainIdBytes.toString("hex")).toString();
      out.codeRegistryAddress = "0x" + b.subarray(n - out.length - 1 - chainIdLength - 20, n - out.length - 1 - chainIdLength).toString("hex");
      out.length += 1 + chainIdLength + 20;
    }
    return out;
  }
  if (schemaId !== 2) {
    // The draft's parsing algorithm stops at an unknown schema id.
    out.unknown = true;
    return out;
  }
  need(19, "length");
  const len = b.readUInt16BE(n - 19);
  need(19 + len, "data");
  out.length = 19 + len;
  const data = b.subarray(n - 19 - len, n - 19);
  const [map, used] = cborDecode(data, 0, 0);
  if (used !== data.length) throw new FormatError("ERC-8021 CBOR data has bytes after its map");
  if (!(map instanceof Map)) throw new FormatError("ERC-8021 CBOR data is not a map");
  out.cbor = map;
  return out;
}

// Minimal CBOR (RFC 8949) reader: definite lengths only; maps keep their order.
export function cborDecode(buf, pos, depth) {
  if (depth > 16) throw new FormatError("CBOR nesting too deep");
  if (pos >= buf.length) throw new FormatError("CBOR is truncated");
  const first = buf[pos];
  const major = first >> 5;
  const ai = first & 0x1f;
  let p = pos + 1;
  let arg;
  if (ai < 24) arg = BigInt(ai);
  else if (ai >= 24 && ai <= 27) {
    const size = 1 << (ai - 24);
    if (p + size > buf.length) throw new FormatError("CBOR is truncated");
    arg = BigInt("0x" + buf.subarray(p, p + size).toString("hex"));
    p += size;
  } else throw new FormatError("CBOR indefinite lengths and reserved values are not read here");
  if (major === 0) return [arg, p];
  if (major === 1) return [-1n - arg, p];
  if (major === 2 || major === 3) {
    const end = p + Number(arg);
    if (end > buf.length) throw new FormatError("CBOR is truncated");
    const bytes = buf.subarray(p, end);
    if (major === 2) return ["0x" + bytes.toString("hex"), end];
    try {
      return [new TextDecoder("utf-8", { fatal: true }).decode(bytes), end];
    } catch {
      throw new FormatError("CBOR text is not UTF-8");
    }
  }
  if (major === 4) {
    const arr = [];
    for (let k = 0n; k < arg; k++) {
      const [v, q] = cborDecode(buf, p, depth + 1);
      arr.push(v);
      p = q;
    }
    return [arr, p];
  }
  if (major === 5) {
    const m = new Map();
    for (let k = 0n; k < arg; k++) {
      const [key, q] = cborDecode(buf, p, depth + 1);
      const [v, q2] = cborDecode(buf, q, depth + 1);
      m.set(key, v);
      p = q2;
    }
    return [m, p];
  }
  if (major === 7) {
    if (ai === 20) return [false, p];
    if (ai === 21) return [true, p];
    if (ai === 22) return [null, p];
  }
  throw new FormatError(`CBOR major type ${major} (${ai}) is not read here`);
}

export function cborToText(v) {
  if (v instanceof Map) return "{" + [...v.entries()].map(([k, x]) => `${cborToText(k)}: ${cborToText(x)}`).join(", ") + "}";
  if (Array.isArray(v)) return "[" + v.map(cborToText).join(", ") + "]";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "bigint") return v.toString();
  return String(v);
}
