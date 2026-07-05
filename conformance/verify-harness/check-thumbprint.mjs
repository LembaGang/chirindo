// RFC 7638 JWK thumbprint verification.
//
// Two independent computations of the thumbprint:
//   (a) via @truestamp/canonify (independent RFC 8785 reference)
//   (b) via Chirindo's own jcs()
// Both must equal Fable's claimed value AND match the jwks.keys[0].kid.
//
// FINDING (flagged, not fixed here): Chirindo's makeKid() in
// src/vendor/recorder/identity.ts produces "ed25519/<12-char-b64url>",
// which is NOT an RFC 7638 thumbprint. The vector's rule ("kid MUST equal
// the RFC 7638 thumbprint") is aspirational for our current impl.

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
console.log("FINDING (not verified here, flagged for backlog):");
console.log("  Chirindo's makeKid() (src/vendor/recorder/identity.ts) uses a proprietary");
console.log("  scheme 'ed25519/<12-char-b64url-of-sha256(raw-pubkey)>', NOT RFC 7638.");
console.log("  The vector's rule 'kid MUST equal the RFC 7638 thumbprint' is aspirational");
console.log("  for the current implementation.");

if (anyFail) process.exit(2);
console.log();
console.log("THUMBPRINT VERIFIED — two-way agreement on canonical input and thumbprint value; matches jwks kid.");
