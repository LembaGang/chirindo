// The command line of check-bundle.mjs and the pins it reads (spec 4.2).
// Exit codes: 0 with one verdict object on stdout, whatever the verdict; 2 for
// a usage error or a bundle outside the shape this build judges, with one line
// on stderr and nothing on stdout; 1 for an internal error, likewise.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress } from "viem";
import { isPlainObject, parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";
import { judged } from "./allowlist.mjs";
import { TIME_RE } from "./table.mjs";

export class UsageError extends Error {}
// An input this build does not judge yet: exit 2 with "not supported in this
// build: <property>", as for a bundle outside the shape (lib/allowlist.mjs).
export class NotJudged extends Error {}

// The options of each input property, refused by name until it is judged.
const INPUT_OPTIONS = {
  "card:charge-stated": ["--charge-id", "--charge-amount", "--charge-currency", "--charge-authorized-at", "--merchant-order-id", "--checkout-ref"],
  pointer: ["--evidence-uri", "--evidence-entry", "--evidence-sha256"],
};

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

// Spec 4.2, S3.charge, and D.1's card forms: each option's value.
const PRINTABLE = /^[ -~]{1,256}$/;
const CHARGE_FORMS = {
  "--charge-id": [PRINTABLE, "1 to 256 printable ASCII characters"],
  "--charge-amount": [/^(0|[1-9][0-9]*)$/, "a decimal string of minor units with no sign and no leading zero"],
  "--charge-currency": [/^[A-Z]{3}$/, "three upper-case letters (ISO 4217)"],
  "--charge-authorized-at": [TIME_RE, "a time YYYY-MM-DDTHH:MM:SS[.fraction]Z"],
  "--merchant-order-id": [PRINTABLE, "1 to 256 printable ASCII characters"],
  "--checkout-ref": [PRINTABLE, "1 to 256 printable ASCII characters"],
};
function chargeValue(name, s) {
  const [re, form] = CHARGE_FORMS[name];
  if (!re.test(s) || (name === "--charge-authorized-at" && !Number.isFinite(Date.parse(s)))) throw new UsageError(`${name} is not ${form} (the stated charge, spec 4.2)`);
  return s;
}
// The four required charge options are given together or not at all, and the
// two references only with them (spec 4.2).
const CHARGE_REQUIRED = ["--charge-id", "--charge-amount", "--charge-currency", "--charge-authorized-at"];
function statedCharge(c) {
  if (Object.keys(c).length === 0) return null;
  if (!CHARGE_REQUIRED.every((k) => k in c)) throw new UsageError("the stated charge needs --charge-id, --charge-amount, --charge-currency and --charge-authorized-at together (spec 4.2)");
  return { id: c["--charge-id"], amount_minor: c["--charge-amount"], currency: c["--charge-currency"], authorized_at: c["--charge-authorized-at"], merchant_order_id: c["--merchant-order-id"] ?? null, checkout_ref: c["--checkout-ref"] ?? null };
}

// The subject's kind as the bundle's bytes name it, for the charge rule of
// spec 4.2 (the charge options are for a card-payment subject only), or null
// when the bundle does not read; M0 then judges it.
export function subjectKind(bytes) {
  try {
    const d = parseStrictJson(bytes);
    return isPlainObject(d) && isPlainObject(d.subject) ? d.subject.kind : null;
  } catch {
    return null;
  }
}

// Spec 4.2 and D.1: the pointer's URI, an absolute https URL of at most 2,048
// characters with no user information; its entry and digest, sha256: and 64
// hex digits, read lowercase.
function pointerValue(name, s) {
  if (name === "--evidence-uri") {
    if (s.length > 2048) throw new UsageError("--evidence-uri is longer than 2,048 characters (spec 4.2)");
    let u;
    try {
      u = new URL(s);
    } catch {
      throw new UsageError("--evidence-uri is not an absolute URL (spec 4.2)");
    }
    if (u.protocol !== "https:") throw new UsageError("--evidence-uri is not an https URL (spec 4.2)");
    if (u.username !== "" || u.password !== "") throw new UsageError("--evidence-uri carries user information (spec 4.2)");
    return s;
  }
  if (!/^sha256:[0-9a-fA-F]{64}$/.test(s)) throw new UsageError(`${name} is not sha256: and 64 hex digits (spec 4.2)`);
  return s.toLowerCase();
}

export function parseArgs(argv) {
  const o = { bundlePath: null, authorizer: null, tx: null, pinsDir: null, charge: null, pointer: null, online: false };
  const chargeIn = {};
  const pointerIn = {};
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
    } else if (a === "--online" && judged("online:card-witness")) {
      // The witness read of a card subject; check-bundle.mjs refuses it for
      // any other subject once the bundle is read.
      once(a);
      o.online = true;
    } else if (a === "--online" || a === "--rpc") throw new UsageError(`${a}: this build is offline only`);
    else if (Object.values(INPUT_OPTIONS).flat().includes(a)) {
      const property = Object.keys(INPUT_OPTIONS).find((p) => INPUT_OPTIONS[p].includes(a));
      if (!judged(property)) throw new NotJudged(property);
      once(a);
      if (property === "card:charge-stated") chargeIn[a] = chargeValue(a, value());
      else pointerIn[a] = pointerValue(a, value());
    }
    else if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
    else {
      if (o.bundlePath !== null) throw new UsageError("more than one bundle path");
      o.bundlePath = a;
    }
  }
  // The pointer takes the place of a bundle path: the URI and the entry
  // together, the digest only with them (spec 4.2).
  if (Object.keys(pointerIn).length) {
    if (!("--evidence-uri" in pointerIn) || !("--evidence-entry" in pointerIn)) throw new UsageError("the pointer needs --evidence-uri and --evidence-entry together, and --evidence-sha256 only with them (spec 4.2)");
    if (o.bundlePath !== null) throw new UsageError("a bundle path is given with the pointer, which takes its place (spec 4.2)");
    o.pointer = { uri: pointerIn["--evidence-uri"], entry: pointerIn["--evidence-entry"], sha256: pointerIn["--evidence-sha256"] ?? null };
  } else if (o.bundlePath === null) throw new UsageError("no bundle path");
  o.charge = statedCharge(chargeIn);
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
    if (!isPlainObject(ip) || !isStr(ip.sha256) || !/^[0-9a-f]{64}$/.test(ip.sha256)) bad("an issuer profile pin has no sha256 of 64 lowercase hex digits");
    const permit = ip.permit ?? [];
    const refuse = ip.refuse ?? [];
    if (!Array.isArray(permit) || !Array.isArray(refuse) || !permit.every(isStr) || !refuse.every(isStr)) bad("an issuer profile's permit and refuse are not lists of strings");
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
