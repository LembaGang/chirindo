// Three-way check: OUR canonicalizer vs @truestamp/canonify vs Fable's claim.
//
// All three must agree on canonical bytes AND SHA-256 for PRODUCE vectors
// (V1..V7, V10). For REJECT vectors (V8 unsafe integer, V9 duplicate keys)
// the point is that no canonical form exists — verify our code either
// rejects OR (if it doesn't) report a FINDING because that's a real gap in
// the gate.
//
// Any MISMATCH prints a three-column diff (ours | reference | Fable) and
// exits non-zero. Under the discipline for this task we do NOT paper over
// disagreements — the human decides what to do about them.

import { canonify } from "@truestamp/canonify";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

// Load Chirindo's own JCS via the built dist to avoid a runtime TS loader.
const { jcs: ourJcs, jcsBytes: ourJcsBytes } = await import(
  "file:///" + resolve(REPO, "dist", "vendor", "recorder", "canonicalize.js").replace(/\\/g, "/")
);

// Chirindo's strict-ingest gate (F3/F4) — drives the strict_parse reject vectors.
const { strictJsonParse, StrictJsonParseError } = await import(
  "file:///" + resolve(REPO, "dist", "vendor", "recorder", "strict-json.js").replace(/\\/g, "/")
);

const fixture = JSON.parse(
  readFileSync(resolve(REPO, "conformance", "vectors-v1.json"), "utf8"),
);

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toBytes(str) {
  return Buffer.from(str, "utf8");
}

const rows = [];
let anyMismatch = false;

console.log("=".repeat(80));
console.log("PRODUCE vectors — three-way check");
console.log("=".repeat(80));

for (const v of fixture.jcs_canonicalization) {
  if (v.name.endsWith("_REJECT")) continue;

  // Our code
  let ourStr, ourHex, ourSha;
  try {
    ourStr = ourJcs(v.input);
    const ourBytes = toBytes(ourStr);
    ourHex = ourBytes.toString("hex");
    ourSha = sha256Hex(ourBytes);
  } catch (e) {
    ourStr = null;
    ourHex = `THREW: ${e.message}`;
    ourSha = null;
  }

  // Reference
  let refStr, refHex, refSha;
  try {
    refStr = canonify(v.input);
    if (refStr === undefined) {
      refStr = null;
      refHex = "REF_UNDEFINED";
      refSha = null;
    } else {
      const refBytes = toBytes(refStr);
      refHex = refBytes.toString("hex");
      refSha = sha256Hex(refBytes);
    }
  } catch (e) {
    refStr = null;
    refHex = `THREW: ${e.message}`;
    refSha = null;
  }

  const fableStr = v.canonical_utf8;
  const fableHex = v.canonical_hex;
  const fableSha = v.sha256;

  const hexAgree = ourHex === refHex && ourHex === fableHex;
  const shaAgree = ourSha === refSha && ourSha === fableSha;
  const strAgree = ourStr === refStr && ourStr === fableStr;
  const agree = hexAgree && shaAgree && strAgree;

  if (!agree) anyMismatch = true;

  rows.push({
    name: v.name,
    verdict: agree ? "AGREE" : "MISMATCH",
    ourSha,
    refSha,
    fableSha,
  });

  console.log();
  console.log(`--- ${v.name} — ${agree ? "AGREE" : "MISMATCH"} ---`);
  console.log(`  ours utf8   : ${JSON.stringify(ourStr)}`);
  console.log(`  ref  utf8   : ${JSON.stringify(refStr)}`);
  console.log(`  fable utf8  : ${JSON.stringify(fableStr)}`);
  console.log(`  ours hex    : ${ourHex}`);
  console.log(`  ref  hex    : ${refHex}`);
  console.log(`  fable hex   : ${fableHex}`);
  console.log(`  ours sha256 : ${ourSha}`);
  console.log(`  ref  sha256 : ${refSha}`);
  console.log(`  fable sha256: ${fableSha}`);
}

console.log();
console.log("=".repeat(80));
console.log("REJECT vectors — verifying REJECTION behavior (not hash match)");
console.log("=".repeat(80));

const rejectRows = [];

// V8: unsafe integer 2^53+1
// Our code takes a parsed JS value. JS Number cannot represent 2^53+1 exactly;
// literal 9007199254740993 evaluates to 9007199254740992. The vector's rule is
// that a compliant PRODUCER must REJECT any number outside [-(2^53-1), 2^53-1]
// before canonicalization. We test: (a) demonstrate the silent-truncation
// hazard by parsing "9007199254740993" and observing the value, (b) probe
// whether our JCS or any surrounding code REJECTS.
{
  const name = "V8_unsafe_integer_REJECT";
  console.log(`\n--- ${name} ---`);
  const parsed = JSON.parse("9007199254740993");
  console.log(`  JSON.parse("9007199254740993") -> ${parsed}  (IEEE-754 truncation demonstrated: ${parsed === 9007199254740992})`);

  // Our JCS on the JS value:
  let ourBehavior;
  try {
    const s = ourJcs(parsed);
    ourBehavior = `CANONICALIZED (no rejection): ${s}`;
  } catch (e) {
    ourBehavior = `REJECTED: ${e.message}`;
  }
  console.log(`  our JCS behavior: ${ourBehavior}`);

  // Reference on the same JS value:
  let refBehavior;
  try {
    const s = canonify(parsed);
    refBehavior = `CANONICALIZED (no rejection): ${s}`;
  } catch (e) {
    refBehavior = `REJECTED: ${e.message}`;
  }
  console.log(`  ref  JCS behavior: ${refBehavior}`);

  console.log(`  Fable claim: canonical_utf8=null (no canonical form); rule says gate MUST reject.`);
  rejectRows.push({ name, our: ourBehavior, ref: refBehavior });
}

// V9: duplicate keys
{
  const name = "V9_duplicate_keys_REJECT";
  console.log(`\n--- ${name} ---`);
  // Two ways to probe: (a) at the JCS layer with a raw JSON string (which
  // Chirindo's argsHashFromJsonString accepts) and (b) at the JS-value layer
  // where JSON.parse has already collapsed duplicates.
  const raw = '{"a":1,"a":2}';
  let parseBehavior;
  try {
    parseBehavior = `JSON.parse silently kept last: ${JSON.stringify(JSON.parse(raw))}`;
  } catch (e) {
    parseBehavior = `JSON.parse REJECTED: ${e.message}`;
  }
  console.log(`  parse behavior : ${parseBehavior}`);

  // Our JCS accepts the parsed value (dupes already gone). The gate-level
  // rejection would have to happen pre-parse. Report whether Chirindo has
  // any duplicate-key rejection path.
  const ourJsResult = ourJcs(JSON.parse(raw));
  console.log(`  our JCS on parsed value: ${ourJsResult}   (dupes already collapsed by JSON.parse — canonicalizer never sees the collision)`);
  console.log(`  Fable claim: no canonical form; gate MUST reject duplicate member names pre-canonicalization.`);
  rejectRows.push({
    name,
    our: "JCS layer is post-parse (never sees the collision); the strict-ingest gate ABOVE it rejects pre-parse — see strict_parse/SP2 below",
    ref: "reference lib is also post-parse",
  });
}

// --- STRICT-INGEST reject vectors (strict_parse, F3/F4) ---
// The declarative V8/V9 above only DESCRIBE the requirement, and demonstrate
// that the JCS layer alone is post-parse and cannot catch either class. These
// vectors actually EXERCISE the gate: each `input` is raw JSON text driven
// through Chirindo's strictJsonParse, which MUST fail closed with the declared
// `expected_reason` before any value is produced. A vector that is NOT rejected
// (or is rejected for the wrong reason / with the wrong error type) is a real
// gap in the gate and exits the harness non-zero.
console.log();
console.log("=".repeat(80));
console.log("STRICT-INGEST reject vectors (strict_parse) — gate MUST fail closed");
console.log("=".repeat(80));

let strictAnyFail = false;
for (const v of fixture.strict_parse ?? []) {
  let verdict, detail;
  try {
    strictJsonParse(v.input);
    verdict = "FAIL (accepted, no rejection)";
    detail = "strictJsonParse returned a value";
    strictAnyFail = true;
  } catch (e) {
    if (e instanceof StrictJsonParseError && e.reason === v.expected_reason) {
      verdict = "REJECT (as expected)";
      detail = `StrictJsonParseError reason=${e.reason}`;
    } else if (e instanceof StrictJsonParseError) {
      verdict = "FAIL (wrong reason)";
      detail = `expected ${v.expected_reason}, got ${e.reason}`;
      strictAnyFail = true;
    } else {
      verdict = "FAIL (wrong error type)";
      detail = `${e.constructor?.name ?? "Error"}: ${e.message}`;
      strictAnyFail = true;
    }
  }
  console.log(`\n--- ${v.name} — ${verdict} ---`);
  console.log(`  input          : ${v.input}`);
  console.log(`  expected reason: ${v.expected_reason}`);
  console.log(`  observed       : ${detail}`);
  rejectRows.push({
    name: v.name,
    our: `${verdict} — ${detail}`,
    ref: "n/a (Chirindo strict-ingest gate, pre-canonicalization)",
  });
}

// --- V2 UTF-16 sort assertion ---
console.log();
console.log("=".repeat(80));
console.log("V2 focused check: UTF-16 code-unit sort with astral 💩");
console.log("=".repeat(80));
{
  const input = fixture.jcs_canonicalization.find((v) => v.name === "V2_key_sort_utf16_astral").input;
  const keys = Object.keys(input);
  console.log(`  input keys (JS-visible)  : ${keys.map((k) => `U+${k.codePointAt(0).toString(16).padStart(4, "0").toUpperCase()}`).join(", ")}`);

  // Code-point-order would be: 0x20AC, 0xFB01, 0x1F4A9 (€, ﬁ, 💩)
  // UTF-16 code-unit order is:  0x20AC, 0xD83D..., 0xFB01 (€, 💩, ﬁ)
  const cpOrder = [...keys].sort((a, b) => a.codePointAt(0) - b.codePointAt(0));
  const utf16Order = [...keys].sort();
  console.log(`  code-point-sorted order  : ${cpOrder.map((k) => `U+${k.codePointAt(0).toString(16).padStart(4, "0").toUpperCase()}`).join(", ")}`);
  console.log(`  UTF-16-unit-sorted order : ${utf16Order.map((k) => `U+${k.codePointAt(0).toString(16).padStart(4, "0").toUpperCase()}`).join(", ")}`);
  console.log(`  ours output order (canonical bytes):`);
  const ours = ourJcs(input);
  // extract key order from canonical output by scanning for the two quotes preceding a colon
  const keyOrder = [...ours.matchAll(/"([^"]+)":/g)].map((m) => m[1]);
  console.log(`      ${keyOrder.map((k) => `U+${k.codePointAt(0).toString(16).padStart(4, "0").toUpperCase()}`).join(", ")}`);
  const sortedByUtf16 = keyOrder.join(",") === utf16Order.join(",");
  console.log(`  matches UTF-16 order? ${sortedByUtf16}`);
  console.log(`  matches code-point order? ${keyOrder.join(",") === cpOrder.join(",")}`);
}

// --- V3 focused: show each number's shortest-form output ---
console.log();
console.log("=".repeat(80));
console.log("V3 focused check: per-number ES6 shortest-form");
console.log("=".repeat(80));
{
  const inputs = [1.0, 4.5, 0.002, 1e-7, 1e-6, 1e21, 1e20, -0.0, 333333333.3333333, 9007199254740992];
  for (const n of inputs) {
    const ourN = ourJcs(n);
    const refN = canonify(n);
    const marker = ourN === refN ? "" : "  <-- DIFFERS";
    console.log(`  ${String(n).padEnd(28)} -> ours=${ourN.padEnd(24)} ref=${refN.padEnd(24)} ${marker}`);
  }
}

// --- V7a vs V7b: MUST differ in bytes and hash ---
console.log();
console.log("=".repeat(80));
console.log("V7a vs V7b focused: NFC/NFD produce different bytes (no Unicode normalization in JCS)");
console.log("=".repeat(80));
{
  const v7a = fixture.jcs_canonicalization.find((v) => v.name === "V7a_nfc");
  const v7b = fixture.jcs_canonicalization.find((v) => v.name === "V7b_nfd");
  const a = ourJcsBytes(v7a.input);
  const b = ourJcsBytes(v7b.input);
  const aRef = Buffer.from(canonify(v7a.input), "utf8");
  const bRef = Buffer.from(canonify(v7b.input), "utf8");
  console.log(`  V7a ours hex: ${a.toString("hex")}  sha256=${sha256Hex(a)}`);
  console.log(`  V7a ref  hex: ${aRef.toString("hex")}  sha256=${sha256Hex(aRef)}`);
  console.log(`  V7b ours hex: ${b.toString("hex")}  sha256=${sha256Hex(b)}`);
  console.log(`  V7b ref  hex: ${bRef.toString("hex")}  sha256=${sha256Hex(bRef)}`);
  console.log(`  V7a bytes == V7b bytes? ${a.equals(b)}   (must be false)`);
  console.log(`  V7a sha256 == V7b sha256? ${sha256Hex(a) === sha256Hex(b)}   (must be false)`);
}

// --- V5a vs V5b: absent != null ---
console.log();
console.log("=".repeat(80));
console.log("V5a (null present) vs V5b (absent)");
console.log("=".repeat(80));
{
  const v5a = fixture.jcs_canonicalization.find((v) => v.name === "V5a_null_present");
  const v5b = fixture.jcs_canonicalization.find((v) => v.name === "V5b_absent");
  console.log(`  V5a ours: ${ourJcs(v5a.input)}   sha256=${sha256Hex(ourJcsBytes(v5a.input))}`);
  console.log(`  V5b ours: ${ourJcs(v5b.input)}   sha256=${sha256Hex(ourJcsBytes(v5b.input))}`);
  console.log(`  distinct? ${ourJcs(v5a.input) !== ourJcs(v5b.input)}   (must be true)`);
}

// --- summary table ---
console.log();
console.log("=".repeat(80));
console.log("SUMMARY TABLE");
console.log("=".repeat(80));
console.log(
  "vector".padEnd(28) +
    " our-sha256".padEnd(66) +
    " ref-sha256".padEnd(66) +
    " fable-sha256".padEnd(66) +
    " AGREE?",
);
for (const r of rows) {
  console.log(
    r.name.padEnd(28) +
      " " + (r.ourSha ?? "-").padEnd(65) +
      " " + (r.refSha ?? "-").padEnd(65) +
      " " + (r.fableSha ?? "-").padEnd(65) +
      " " + r.verdict,
  );
}
console.log();
for (const r of rejectRows) {
  console.log(
    r.name.padEnd(28) + " ours=" + r.our + " | ref=" + r.ref,
  );
}

console.log();
if (anyMismatch) {
  console.error("!! MISMATCH DETECTED — STOP AND REPORT");
  process.exit(2);
}
if (strictAnyFail) {
  console.error("!! STRICT-INGEST GATE FAILED A strict_parse VECTOR — STOP AND REPORT");
  process.exit(2);
}
console.log("ALL PRODUCE VECTORS: three-way byte-and-hash agreement");
console.log("ALL STRICT-INGEST VECTORS: gate failed closed with the expected reason");
