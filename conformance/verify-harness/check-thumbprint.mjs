// RFC 7638 JWK thumbprint verification.
//
// Two independent computations of the thumbprint:
//   (a) via @truestamp/canonify (independent RFC 8785 reference)
//   (b) via Chirindo's own jcs()
// Both must equal Fable's claimed value AND match the jwks.keys[0].kid.
//
// FINDING F2, as originally raised 2026-07-05 (retained verbatim as the
// historical record): Chirindo's makeKid() in
// src/vendor/recorder/identity.ts produces "ed25519/<12-char-b64url>",
// which is NOT an RFC 7638 thumbprint. The vector's rule ("kid MUST equal
// the RFC 7638 thumbprint") is aspirational for our current impl.
//
// RESOLVED 2026-07-06. makeKid() now returns the bare RFC 7638 thumbprint;
// the legacy "ed25519/<fp>" scheme is accepted read-only via kidMatchesKey.
// Re-verified and red-proofed 2026-08-27 -- see
// conformance/VERIFICATION-REPORT.md, section "v0.4.x re-verification -
// 2026-08-27" (F2), and test/conformance-key-binding.test.ts.

import { canonify } from "@truestamp/canonify";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

const { jcs: ourJcs } = await import(
  "file:///" + resolve(REPO, "dist", "vendor", "recorder", "canonicalize.js").replace(/\\/g, "/")
);

const fixture = JSON.parse(
  readFileSync(resolve(REPO, "conformance", "vectors-v1.json"), "utf8"),
);
const kb = fixture.key_binding;
const jwk = kb.jwk;

// --- RFC 7638 defines the thumbprint input as the JCS canonicalization of a
// JSON object containing ONLY the required members, in lexicographic order.
// For an OKP key (RFC 8037 / RFC 8785 registry): kty, crv, x.
// Lex order of those keys: crv, kty, x. That is the input Fable claims.
const thumbInputSubset = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };

const ourInput = ourJcs(thumbInputSubset);
const refInput = canonify(thumbInputSubset);

function b64u(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function thumbprintFromInput(inputStr) {
  const digest = createHash("sha256").update(Buffer.from(inputStr, "utf8")).digest();
  return b64u(digest);
}

const ourTp = thumbprintFromInput(ourInput);
const refTp = thumbprintFromInput(refInput);
const fableInput = kb.rfc7638_thumbprint_input;
const fableTp = kb.rfc7638_thumbprint;
const jwksKid = kb.jwks_document.keys[0].kid;

console.log("--- RFC 7638 thumbprint verification ---");
console.log(`JWK subset for thumbprint : ${JSON.stringify(thumbInputSubset)}`);
console.log();
console.log(`ours JCS input string      : ${JSON.stringify(ourInput)}`);
console.log(`ref  JCS input string      : ${JSON.stringify(refInput)}`);
console.log(`fable claimed input string : ${JSON.stringify(fableInput)}`);
console.log(`input strings all equal?   : ${ourInput === refInput && ourInput === fableInput}`);
console.log();
console.log(`ours thumbprint           : ${ourTp}`);
console.log(`ref  thumbprint           : ${refTp}`);
console.log(`fable thumbprint          : ${fableTp}`);
console.log(`thumbprints all equal?    : ${ourTp === refTp && ourTp === fableTp}`);
console.log();
console.log(`jwks.keys[0].kid          : ${jwksKid}`);
console.log(`kid == thumbprint?        : ${jwksKid === ourTp}`);

// Sanity: confirm the canonicalization sorts crv,kty,x lex and emits no whitespace.
const lex = ["crv", "kty", "x"].sort();
console.log();
console.log("Structural checks on input string:");
console.log(`  keys in output order    : ${[...ourInput.matchAll(/"([^"]+)":/g)].map((m) => m[1]).join(",")}`);
console.log(`  expected lex order      : ${lex.join(",")}`);
console.log(`  contains whitespace?    : ${/\s/.test(ourInput)}`);
console.log(`  starts with '{' ends '}': ${ourInput.startsWith("{") && ourInput.endsWith("}")}`);

let anyFail = false;
if (ourInput !== fableInput) { console.error("!! ourInput != fableInput"); anyFail = true; }
if (refInput !== fableInput) { console.error("!! refInput != fableInput"); anyFail = true; }
if (ourTp !== fableTp) { console.error("!! ourTp != fableTp"); anyFail = true; }
if (refTp !== fableTp) { console.error("!! refTp != fableTp"); anyFail = true; }
if (jwksKid !== ourTp) { console.error("!! kid != thumbprint"); anyFail = true; }

console.log();
const REPORT_SECTION =
  'conformance/VERIFICATION-REPORT.md "v0.4.x re-verification — 2026-08-27"';

console.log("FINDING F2 (raised 2026-07-05) - RESOLVED 2026-07-06:");
console.log("  As raised: \"Chirindo's makeKid() (src/vendor/recorder/identity.ts) uses");
console.log("  a proprietary scheme 'ed25519/<12-char-b64url-of-sha256(raw-pubkey)>',");
console.log("  NOT RFC 7638. The vector's rule 'kid MUST equal the RFC 7638 thumbprint'");
console.log("  is aspirational for the current implementation.\"");
console.log();
console.log("  CURRENT STATUS: makeKid() returns the bare RFC 7638 thumbprint, so a");
console.log("  consumer cross-checks kid against the JWK by construction. The legacy");
console.log("  scheme is accepted read-only (kidMatchesKey), so chains spanning the");
console.log("  migration still verify. Re-verified and red-proofed 2026-08-27.");
console.log("  Record: " + REPORT_SECTION + " (F2).");
console.log("  Tests:  test/conformance-key-binding.test.ts (anchors the thumbprint to");
console.log("          this corpus's key_binding literals), test/kid-scheme.test.ts.");
console.log("  NOTE: this script does not itself exercise makeKid() - it checks the");
console.log("  corpus thumbprint two ways. The closure is proven by those tests.");

if (anyFail) process.exit(2);
console.log();
console.log("THUMBPRINT VERIFIED — two-way agreement on canonical input and thumbprint value; matches jwks kid.");
