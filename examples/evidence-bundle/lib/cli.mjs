// The command line of check-bundle.mjs and the pins it reads (spec 4.2).
// Exit codes: 0 with one verdict object on stdout, whatever the verdict; 2 for
// a usage error or a bundle outside the shape this build judges, with one line
// on stderr and nothing on stdout; 1 for an internal error, likewise.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress } from "viem";
import { isPlainObject, parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";

export class UsageError extends Error {}

export const DEFAULT_PINS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "pins");

// Spec 4.1 and 4.2: an address all lowercase or exactly its EIP-55 checksum
// form. The reused checker also reads an address written all in upper case;
// this verifier refuses that spelling, so one rule holds for every address.
export function statedAddress(s) {
  if (typeof s !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(s)) throw new UsageError("--authorizer is not 0x and 40 hex digits");
  if (s !== s.toLowerCase() && s !== getAddress(s)) throw new UsageError("--authorizer is neither all lowercase nor its EIP-55 checksum form");
  return s.toLowerCase();
}

// Spec 4.2: 0x and 64 hex digits, read without regard to case.
export function statedTx(s) {
  if (typeof s !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(s)) throw new UsageError("--tx is not 0x and 64 hex digits");
  return s.toLowerCase();
}

export function parseArgs(argv) {
  const o = { bundlePath: null, authorizer: null, tx: null, pinsDir: null };
  const seen = new Set();
  const once = (name) => {
    if (seen.has(name)) throw new UsageError(`${name} is given twice`);
    seen.add(name);
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new UsageError(`${a} needs a value`);
      return argv[++i];
    };
    if (a === "--authorizer") {
      once(a);
      o.authorizer = statedAddress(value());
    } else if (a === "--tx") {
      once(a);
      o.tx = statedTx(value());
    } else if (a === "--pins") {
      once(a);
      o.pinsDir = value();
    } else if (a === "--online" || a === "--rpc") throw new UsageError(`${a}: this build is offline only`);
    else if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
    else {
      if (o.bundlePath !== null) throw new UsageError("more than one bundle path");
      o.bundlePath = a;
    }
  }
  if (o.bundlePath === null) throw new UsageError("no bundle path");
  return o;
}

const isStr = (v) => typeof v === "string";

// Reads and checks <dir>/pins.json (format evidence-bundle-pins/1). Pins that
// are not of this format, or an issuer profile whose permit and refuse lists
// share a value (spec 4.2), are a usage error: the verifier does not run.
export function loadPins(dir = DEFAULT_PINS_DIR) {
  let p;
  try {
    p = parseStrictJson(readFileSync(path.join(dir, "pins.json")));
  } catch (e) {
    throw new UsageError(`the pins in ${dir} do not read: ${e.message}`);
  }
  const bad = (why) => {
    throw new UsageError(`invalid pins: ${why}`);
  };
  if (!isPlainObject(p) || p.format !== "evidence-bundle-pins/1") bad("format is not evidence-bundle-pins/1");
  const wk = p.witness_keys;
  if (!isPlainObject(wk) || !Array.isArray(wk.keys)) bad("witness_keys.keys is not a list");
  for (const k of wk.keys) {
    if (!isPlainObject(k) || !isStr(k.key_id) || k.algorithm !== "Ed25519" || k.format !== "hex" || !/^[0-9a-f]{64}$/.test(k.public_key ?? "") || !isStr(k.valid_from) || !(k.valid_until === null || isStr(k.valid_until)))
      bad("a witness key entry is not an Ed25519 key with its window");
  }
  if (!Array.isArray(p.operator_key_ids) || !p.operator_key_ids.every(isStr)) bad("operator_key_ids is not a list of strings");
  if (!Array.isArray(p.issuer_profiles)) bad("issuer_profiles is not a list");
  for (const ip of p.issuer_profiles) {
    if (!isPlainObject(ip) || !isStr(ip.sha256)) bad("an issuer profile pin has no sha256");
    const permit = ip.permit ?? [];
    const refuse = ip.refuse ?? [];
    if (!Array.isArray(permit) || !Array.isArray(refuse)) bad("an issuer profile's permit and refuse are not lists");
    if (permit.some((x) => refuse.includes(x))) bad(`issuer profile ${ip.sha256}: a value is in both permit and refuse`);
  }
  if (!isPlainObject(p.tokens)) bad("tokens is not an object");
  for (const [chain, list] of Object.entries(p.tokens)) {
    if (!/^[1-9][0-9]*$/.test(chain) || !Array.isArray(list)) bad("tokens must map decimal chain ids to lists");
    for (const t of list) if (!isPlainObject(t) || !/^0x[0-9a-f]{40}$/.test(t.address ?? "") || !isStr(t.name) || !isStr(t.version)) bad("a token pin lacks a lowercase address, a name or a version");
  }
  const e = p.erc4337;
  if (!isPlainObject(e) || !Array.isArray(e.selectors) || !Array.isArray(e.entrypoints)) bad("erc4337 lacks its selectors or entrypoints");
  return p;
}
