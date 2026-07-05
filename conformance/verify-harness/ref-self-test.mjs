// Self-test the independent reference RFC 8785 implementation against the
// worked example in RFC 8785 Appendix B. If the reference lib does not
// reproduce the RFC's own bytes, it is unusable as an oracle and this task
// STOPS.
//
// Reference chosen: @truestamp/canonify@2.1.0 (MIT, by Truestamp Inc).
// Chosen because:
//   - It is a genuinely independent implementation from `canonicalize` (the
//     npm package that Chirindo's own src/vendor/recorder/canonicalize.ts
//     wraps). Different author, different code, different repo.
//   - Truestamp is a data-integrity / timestamping company: they have real
//     production motivation to get RFC 8785 right.
//   - The source is ~80 lines, auditable end-to-end.
//
// If truestamp/canonify itself is somehow using `canonicalize` under the
// hood we would have no independence at all — the top of ref-self-test
// prints its resolved package.json so a reader can confirm.

import { canonify } from "@truestamp/canonify";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const canonifyPkg = JSON.parse(
  readFileSync(
    resolve(HERE, "node_modules", "@truestamp", "canonify", "package.json"),
    "utf8",
  ),
);
console.log(
  `reference: @truestamp/canonify@${canonifyPkg.version} (${canonifyPkg.license})`,
);

// Confirm no `canonicalize` dependency leaks in — independence check.
const depsAll = {
  ...(canonifyPkg.dependencies ?? {}),
  ...(canonifyPkg.peerDependencies ?? {}),
};
if ("canonicalize" in depsAll) {
  throw new Error(
    "@truestamp/canonify depends on `canonicalize` — not independent",
  );
}
console.log(
  `  runtime deps: ${Object.keys(depsAll).length === 0 ? "(none)" : Object.keys(depsAll).join(", ")}`,
);

// --- RFC 8785 Appendix B input (verbatim), Section 3.2.2 ---
// Constructed via JSON.parse so JS-level escape ambiguity is eliminated:
// the input JSON is exactly the bytes the RFC shows.
const rfcInputJson = `{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
  "literals": [null, true, false]
}`;
const rfcInput = JSON.parse(rfcInputJson);

// --- RFC 8785 Appendix B expected canonical bytes (Section 3.2.4) ---
const rfcExpectedHex = (
  "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 " +
  "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a " +
  "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 " +
  "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37 " +
  "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 " +
  "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d"
).replace(/\s+/g, "");
const rfcExpectedBytes = Buffer.from(rfcExpectedHex, "hex");
const rfcExpectedUtf8 = rfcExpectedBytes.toString("utf8");

// --- run the reference ---
const refOut = canonify(rfcInput);
if (typeof refOut !== "string") {
  throw new Error(`reference returned non-string: ${typeof refOut}`);
}
const refBytes = Buffer.from(refOut, "utf8");
const refHex = refBytes.toString("hex");
const refSha = createHash("sha256").update(refBytes).digest("hex");
const expSha = createHash("sha256").update(rfcExpectedBytes).digest("hex");

console.log();
console.log("RFC 8785 Appendix B self-test:");
console.log("  expected UTF-8 :", JSON.stringify(rfcExpectedUtf8));
console.log("  reference UTF-8:", JSON.stringify(refOut));
console.log("  expected hex   :", rfcExpectedHex);
console.log("  reference hex  :", refHex);
console.log("  expected sha256:", expSha);
console.log("  reference sha256:", refSha);

const bytesMatch = refHex === rfcExpectedHex;
const shaMatch = refSha === expSha;

if (!bytesMatch || !shaMatch) {
  console.error();
  console.error("SELF-TEST FAILED — reference does not reproduce RFC 8785 Appendix B bytes.");
  console.error("Reference library is unusable as an oracle.");
  process.exit(1);
}

console.log();
console.log("SELF-TEST PASSED — @truestamp/canonify reproduces RFC 8785 Appendix B byte-for-byte.");
