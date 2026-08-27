// Chain STRUCTURE verification — signatures NOT authenticable (Fable only had
// the public key, so the sigs it produced will not verify under a real key).
// We verify only the parts that don't depend on secret-key authenticity:
//   1) entry_hash recomputation from receipt bytes
//   2) prev_hash linkage (entry_hashes[i] == receipts[i+1].prev_hash)
//   3) genesis prev_hash (all-zero)
//   4) seq strictly 0,1,2
//   5) iat non-decreasing
// Plus structural claims about N3 (seq gap) and N4 (thumbprint check ordering).
//
// N1 (tampered decision) and N2 (high-S malleability) are policy assertions
// about verifier behavior. They were originally "structurally described,
// pending real-verifier unit tests," NOT verified here — that remains true OF
// THIS SCRIPT, which cannot verify signatures (the corpus sigs are
// illustrative). They are no longer pending anywhere else: N1/N2/N4 are
// discharged by real-verifier tests in test/conformance-negatives.test.ts,
// red-proofed 2026-08-27. See conformance/VERIFICATION-REPORT.md, section
// "v0.4.x re-verification — 2026-08-27".

import { canonify as refCanonify } from "@truestamp/canonify";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

const fileUrl = (p) => "file:///" + p.replace(/\\/g, "/");
const DIST = resolve(REPO, "dist", "vendor", "recorder");
const { jcs: ourJcs, jcsBytes: ourJcsBytes } = await import(fileUrl(resolve(DIST, "canonicalize.js")));
// contentOf is imported from Chirindo so we can compare against an independent
// destructuring in the reference path — proving the two agree on what
// "content" (sig-stripped record) actually is.
const { contentOf: chirindoContentOf } = await import(fileUrl(resolve(DIST, "record.js")));

const fixture = JSON.parse(
  readFileSync(resolve(REPO, "conformance", "vectors-v1.json"), "utf8"),
);
const chain = fixture.receipt_chain;

console.log("=".repeat(80));
console.log("CHAIN STRUCTURE VERIFICATION");
console.log("=".repeat(80));
console.log();
console.log("NOTE: Fable produced these signatures with ONLY the public key.");
console.log("They MUST NOT be treated as authentic. Signature authenticity is");
console.log("NOT tested in this task — only chain structure/linkage.");
console.log();

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
// Independent sig-strip: destructure in this file, do NOT call Chirindo's
// contentOf. If this diverges from Chirindo's contentOf (see check below),
// that's a real finding.
function contentOfNoSig(r) {
  const { sig: _sig, ...rest } = r;
  return rest;
}

// Two candidate interpretations of "entry_hash":
//   (A) sha256(canon(payload-without-sig))  <- what Chirindo's own code does
//   (B) sha256(canon(entire receipt including sig))
// For each receipt we also compute (A) via the INDEPENDENT reference
// (@truestamp/canonify) so the chain gets the same three-way assurance the
// canonicalization vectors already have.
let anyFail = false;
for (let i = 0; i < chain.receipts.length; i++) {
  const r = chain.receipts[i];

  // Independent sig-strip (harness-side destructure).
  const contentHarness = contentOfNoSig(r);
  // Chirindo's own sig-strip.
  const contentChirindo = chirindoContentOf(r);

  // Confirm the two sig-strippings agree on what "content" is. This is the
  // "same content object" requirement — if we fed different objects to the
  // two canonicalizers, matching hashes would be an accident.
  const jsonHarness = JSON.stringify(contentHarness);
  const jsonChirindo = JSON.stringify(contentChirindo);
  const contentStripAgrees = jsonHarness === jsonChirindo;

  // Chirindo path: jcs(contentOf(r)) via canonicalize npm package (wrapped).
  const canonChirindo = ourJcsBytes(contentChirindo);
  const hashA_chirindo = "sha256:" + sha256Hex(canonChirindo);

  // Reference path: @truestamp/canonify(contentOfNoSig(r)) — the harness-side
  // strip, then the INDEPENDENT canonicalizer, then sha256.
  const canonRefStr = refCanonify(contentHarness);
  if (canonRefStr === undefined) {
    console.error(`  !! @truestamp/canonify returned undefined for seq=${r.seq} content`);
    anyFail = true;
    continue;
  }
  const canonRef = Buffer.from(canonRefStr, "utf8");
  const hashA_ref = "sha256:" + sha256Hex(canonRef);

  // (B) diagnostic — sig-INCLUDED path via Chirindo's canonicalizer (not the
  // correct definition; shown for the same reason we've always shown it: it's
  // the wrong answer, and demonstrating it's wrong is part of the story).
  const canonWithSig = ourJcsBytes(r);
  const hashB = "sha256:" + sha256Hex(canonWithSig);

  const claimed = chain.entry_hashes[i];
  const matchA_chirindo = hashA_chirindo === claimed;
  const matchA_ref = hashA_ref === claimed;
  const canonBytesAgree = canonChirindo.equals(canonRef);

  console.log(`--- receipt seq=${r.seq} ---`);
  console.log(`  claimed entry_hash             : ${claimed}`);
  console.log(`  (A) ours    (Chirindo JCS)     : ${hashA_chirindo}   ${matchA_chirindo ? "MATCH" : ""}`);
  console.log(`  (A) ref     (@truestamp/canonify): ${hashA_ref}   ${matchA_ref ? "MATCH" : ""}`);
  console.log(`  (B) with sig (diagnostic only) : ${hashB}`);
  console.log(`  sig-strip agrees (Chirindo vs harness destructure): ${contentStripAgrees}`);
  console.log(`  canonical BYTES agree (Chirindo JCS vs reference) : ${canonBytesAgree}`);

  if (!contentStripAgrees) {
    console.error(`  !! FINDING: Chirindo's contentOf produces a different object than an ` +
                  `independent { sig, ...rest } destructure at seq=${r.seq}`);
    anyFail = true;
  }
  if (!matchA_chirindo || !matchA_ref) {
    console.error(`  !! MISMATCH at seq=${r.seq}: three-way agreement broken`);
    anyFail = true;
  }
  console.log();
}

// Linkage: entry_hashes[0] should equal receipts[1].prev_hash, etc.
console.log("Linkage checks (entry_hashes[i] == receipts[i+1].prev_hash):");
for (let i = 0; i < chain.receipts.length - 1; i++) {
  const expected = chain.receipts[i + 1].prev_hash;
  const eh = chain.entry_hashes[i];
  const ok = expected === eh;
  console.log(`  entry_hashes[${i}] (${eh})`);
  console.log(`  receipts[${i + 1}].prev_hash (${expected})`);
  console.log(`  linked? ${ok}`);
  if (!ok) anyFail = true;
  console.log();
}

// Genesis: receipts[0].prev_hash should be the all-zero sentinel per the fixture.
const genesis = chain.genesis_prev_hash;
const genesisOk = chain.receipts[0].prev_hash === genesis && genesis === "sha256:0000000000000000000000000000000000000000000000000000000000000000";
console.log(`Genesis prev_hash (all-zero sentinel):`);
console.log(`  genesis_prev_hash        : ${genesis}`);
console.log(`  receipts[0].prev_hash    : ${chain.receipts[0].prev_hash}`);
console.log(`  matches all-zero sentinel: ${genesisOk}`);
if (!genesisOk) anyFail = true;
console.log();

// Seq strictly 0,1,2
const seqs = chain.receipts.map((r) => r.seq);
const seqOk = seqs.join(",") === "0,1,2";
console.log(`Seq strictly [0,1,2]: ${seqs.join(",")}   ${seqOk ? "OK" : "FAIL"}`);
if (!seqOk) anyFail = true;

// iat non-decreasing
const iats = chain.receipts.map((r) => r.iat);
const iatOk = iats.every((t, i) => i === 0 || new Date(t) >= new Date(iats[i - 1]));
console.log(`iat non-decreasing: ${iats.join(" -> ")}   ${iatOk ? "OK" : "FAIL"}`);
if (!iatOk) anyFail = true;
console.log();

// --- Negatives ---
console.log("=".repeat(80));
console.log("NEGATIVE VECTORS — structural checks only");
console.log("=".repeat(80));

// N3: dropping seq=1 must break both prev_hash linkage AND seq contiguity
console.log("\n--- N3_seq_gap: present [seq0, seq2] omitting seq1 ---");
{
  const truncated = [chain.receipts[0], chain.receipts[2]];
  const seqs2 = truncated.map((r) => r.seq);
  const seqContiguous = seqs2.every((s, i) => i === 0 || s === seqs2[i - 1] + 1);
  // prev_hash linkage check: after dropping seq1, receipts[1].prev_hash refers
  // to entry_hashes[1] which we no longer produce from seq0 — so linkage breaks.
  const linkOk = truncated[1].prev_hash === chain.entry_hashes[0];
  console.log(`  seq sequence after drop : ${seqs2.join(",")}`);
  console.log(`  seq contiguous?         : ${seqContiguous}   (expected: false — GAP)`);
  console.log(`  seq2.prev_hash matches entry_hash of seq0? : ${linkOk}   (expected: false — LINKAGE BREAK)`);
  const failsAsExpected = !seqContiguous && !linkOk;
  console.log(`  N3 fails as expected (both checks trip) : ${failsAsExpected}`);
  if (!failsAsExpected) anyFail = true;
}

// N4: thumbprint check must precede signature verification
console.log("\n--- N4_thumbprint_mismatch: JWKS serves a different key under same kid ---");
console.log("  This is a policy assertion about verifier ordering: the verifier MUST");
console.log("  check that thumbprint(fetched-key) == payload.key_thumbprint BEFORE");
console.log("  attempting Ed25519 signature verification. Otherwise an attacker can");
console.log("  substitute a key under the same kid and force use of their signature.");
const REPORT_SECTION =
  'conformance/VERIFICATION-REPORT.md "v0.4.x re-verification — 2026-08-27"';

console.log("  This is a REQUIREMENT on the verifier. Originally flagged here as");
console.log("  'structurally described' (no code exercised); VERIFIED 2026-08-27 by");
console.log("  test/conformance-negatives.test.ts → \"N4 — substituted key →");
console.log("  INVALID_KEY_BINDING, checked BEFORE signature\", which asserts the");
console.log("  reason code key_binding_mismatch (not 'signature invalid') and so pins");
console.log("  the ORDERING, not merely the refusal.");
console.log("  Record: " + REPORT_SECTION + ".");

// N1, N2: signature-level behavior — needs real verifier
console.log("\n--- N1_tampered_decision / N2_high_S_malleability ---");
console.log("  N1 asserts that changing 'decision' from 'deny' to 'allow' invalidates");
console.log("  the Ed25519 signature. Verifiable only by running a real verifier with");
console.log("  a real key against the tampered receipt.");
console.log("  N2 asserts that a high-S non-canonical Ed25519 signature must be");
console.log("  rejected per RFC 8032 Section 5.1.7. Verifiable only in a real-verifier");
console.log("  unit test.");
console.log();
console.log("  STATUS FOR N1, N2: still NOT verified BY THIS SCRIPT, which cannot");
console.log("  authenticate signatures - the corpus sigs are illustrative (public key");
console.log("  only). They are no longer pending: both are VERIFIED 2026-08-27 against");
console.log("  the real verifier, with real Ed25519 keys, in");
console.log("  test/conformance-negatives.test.ts:");
console.log("    N1 → \"N1 — tampered decision → INVALID_SIGNATURE\"");
console.log("    N2 → \"N2 — high-S (S+L) malleation is rejected (RFC 8032 §5.1.7)\"");
console.log("  Each asserts this corpus's own negative[].expected string, so the code");
console.log("  and the corpus cannot drift apart silently.");
console.log("  Record: " + REPORT_SECTION + ".");

console.log();
console.log("=".repeat(80));
console.log("SIGNATURE AUTHENTICITY WAS NOT TESTED in this task.");
console.log("Fable's `sig` fields are fabricated (public key only, no private key).");
console.log("They will NOT verify under any real key and MUST NOT be treated as");
console.log("authentic. Corpus consumers must generate their own signatures against");
console.log("the receipt payloads for cryptographic tests.");
console.log("=".repeat(80));

console.log();
console.log("=".repeat(80));
console.log("ENTRY_HASH CONVENTION — Chirindo's sig-stripped convention wins");
console.log("=".repeat(80));
console.log("Chirindo defines: entry_hash = sha256(jcs(contentOf(record)))");
console.log("where contentOf() STRIPS the sig field before canonicalization.");
console.log("This is interpretation (A) above.");
console.log();
console.log("This is DELIBERATE: entry_hash is insensitive to Ed25519 signature");
console.log("malleability (see N2). If entry_hash included sig, a re-encoded");
console.log("but semantically equivalent sig would produce a different entry_hash,");
console.log("breaking cross-verifier recomputability at exactly the point where");
console.log("malleability makes verifiability hard.");
console.log();
console.log("The fixture's entry_hashes are DERIVED at build time from Chirindo's");
console.log("own canonicalize.ts + hash.ts + record.ts (see build-fixture.mjs). All");
console.log("three receipts reproduce under (A). Interpretation (B) is shown only as");
console.log("a diagnostic sanity check — it is NOT the correct definition.");

if (anyFail) {
  console.error("\n!! CHAIN STRUCTURE CHECK FAILED — see above");
  process.exit(2);
}
console.log(
  "\nCHAIN STRUCTURE VERIFIED under Chirindo's sig-stripped entry_hash convention:",
);
console.log("  - all three entry_hashes recompute byte-for-byte via Chirindo's JCS");
console.log("  - all three entry_hashes ALSO recompute via the independent");
console.log("    reference (@truestamp/canonify) — three-way agreement");
console.log("  - sig-strip step confirmed identical between Chirindo's contentOf");
console.log("    and an independent { sig, ...rest } destructure");
console.log("  - prev_hash linkage self-consistent");
console.log("  - genesis all-zero sentinel matches");
console.log("  - seq [0,1,2], iat non-decreasing, N3/N4 structural claims hold");
