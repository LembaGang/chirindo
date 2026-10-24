// The Merkle Patricia trie of the trie page EIP-1186 links (spec M5 step 3,
// D.1): a node is an RLP list, a branch of 17 items or a leaf or extension of
// 2 (a path in the compact encoding, and a value or a reference); a node whose
// RLP encoding is shorter than 32 bytes is inlined in its parent, any other is
// referenced by the keccak-256 of its encoding.

import { fromRlp, keccak256, toRlp } from "viem";

const EMPTY = "0x";
const nibbles = (hex) => [...hex.slice(2)].map((c) => parseInt(c, 16));

// The compact (hex-prefix) encoding of a nibble path, flagged leaf or not.
function compact(path, leaf) {
  const odd = path.length % 2;
  return "0x" + [(leaf ? 2 : 0) + odd, ...(odd ? [] : [0]), ...path].map((n) => n.toString(16)).join("");
}

// A node as its parent holds it: inline when its encoding is under 32 bytes.
const ref = (node) => {
  const enc = toRlp(node);
  return (enc.length - 2) / 2 < 32 ? node : keccak256(enc);
};

// The node over `pairs` ({ k: nibbles, v }) below nibble `depth`.
function nodeOf(pairs, depth) {
  if (pairs.length === 1) return [compact(pairs[0].k.slice(depth), true), pairs[0].v];
  let p = 0;
  while (pairs.every((x) => x.k[depth + p] !== undefined && x.k[depth + p] === pairs[0].k[depth + p])) p++;
  if (p > 0) return [compact(pairs[0].k.slice(depth, depth + p), false), ref(nodeOf(pairs, depth + p))];
  const branch = Array.from({ length: 16 }, (_, i) => {
    const sub = pairs.filter((x) => x.k[depth] === i);
    return sub.length ? ref(nodeOf(sub, depth + 1)) : EMPTY;
  });
  return [...branch, pairs.find((x) => x.k.length === depth)?.v ?? EMPTY];
}

// The root of a trie of [keyHex, valueHex] entries (distinct keys): the
// keccak-256 of the root node's encoding (the empty trie's: of RLP's empty string).
export function trieRoot(entries) {
  if (entries.length === 0) return keccak256(toRlp(EMPTY));
  return keccak256(toRlp(nodeOf(entries.map(([k, v]) => ({ k: nibbles(k), v })), 0)));
}

// A compact (hex-prefix) path: its flag nibble says leaf or extension, and odd
// or even length (an even path carries one padding nibble 0).
function decodeCompact(hex) {
  if (typeof hex !== "string") throw new Error("a node's path is not a byte string");
  const ns = nibbles(hex);
  if (ns.length === 0) throw new Error("an empty compact path");
  const flag = ns[0];
  if (flag > 3) throw new Error(`a compact path whose flag nibble is ${flag}`);
  const odd = flag % 2 === 1;
  if (!odd && ns[1] !== 0) throw new Error("an even compact path whose padding nibble is not 0");
  return { leaf: flag >= 2, path: ns.slice(odd ? 1 : 2) };
}

// Walks a proof (EIP-1186: "starting with the stateRoot-Node, following the
// path of the SHA3 (address) as key") from `root` along `key`. Returns
// { value } for the leaf's value, or { value: null } when the proof shows the
// key absent; throws when a node is not the one its parent references, or
// does not decode as a node.
export function walkProof(root, key, proof) {
  const want = nibbles(key);
  const byHash = new Map(proof.map((n) => [keccak256(n), n]));
  const load = (r) => {
    if (Array.isArray(r)) return r;
    if (r === EMPTY) return null;
    if ((r.length - 2) / 2 !== 32) throw new Error("a reference that is neither 32 bytes nor an inline node");
    const enc = byHash.get(r);
    if (!enc) throw new Error(`no node of the proof has the hash ${r}`);
    return fromRlp(enc);
  };
  if (proof.length === 0 || keccak256(proof[0]) !== root) throw new Error("the first node's keccak-256 is not the stateRoot");
  let node = fromRlp(proof[0]);
  let depth = 0;
  for (let steps = 0; steps < 130; steps++) {
    if (node === null) return { value: null };
    if (!Array.isArray(node)) throw new Error("a node that is not a list");
    if (node.length === 17) {
      if (depth === want.length) return { value: node[16] === EMPTY ? null : node[16] };
      node = load(node[want[depth]]);
      depth += 1;
      continue;
    }
    if (node.length !== 2) throw new Error(`a node of ${node.length} items`);
    const { leaf, path } = decodeCompact(node[0]);
    const match = path.every((n, i) => want[depth + i] === n);
    if (leaf) return { value: match && depth + path.length === want.length ? node[1] : null };
    if (!match) return { value: null };
    depth += path.length;
    node = load(node[1]);
  }
  throw new Error("the proof is longer than any path");
}
