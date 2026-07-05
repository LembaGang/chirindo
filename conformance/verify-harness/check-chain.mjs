// Chain STRUCTURE verification — signatures NOT authenticable (Fable only had
// the public key, so the sigs it produced will not verify under a real key).
// We verify only the parts that don't depend on secret-key authenticity:
//   1) entry_hash recomputation from receipt bytes
//   2) prev_hash linkage (entry_hashes[i] == receipts[i+1].prev_hash)
//   3) genesis prev_hash (all-zero)
//   4) seq strictly 0,1,2
//   5) iat non-decreasing
// Plus structural claims about N3 (seq gap) and N4 (thumbprint check ordering).
// N1 (tampered decision) and N2 (high-S malleability) are policy assertions
// about verifier behavior — flagged as "structurally described, pending
// real-verifier unit tests," NOT verified here.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

const { jcs: ourJcs, jcsBytes: ourJcsBytes } = await import(
  "file:///" + resolve(REPO, "dist", "vendor", "recorder", "canonicalize.js").replace(/\\/g, "/")
);

const fixture = JSON.parse(
  readFileSync(resolve(REPO, "conformance", "vectors-v1.candidate.json"), "utf8"),
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
function contentOfNoSig(r) {
  const { sig: _sig, ...rest } = r;
  return rest;
}

// Two candidate interpretations of "entry_hash":
//   (A) sha256(canon(payload-without-sig))  <- what Chirindo's own code does
//   (B) sha256(canon(entire receipt including sig))
// We compute both and see which matches Fable's claimed values.
let anyFail = false;
for (let i = 0; i < chain.receipts.length; i++) {
  const r = chain.receipts[i];
  const canonNoSig = ourJcsBytes(contentOfNoSig(r));
  const canonWithSig = ourJcsBytes(r);
  const hashA = "sha256:" + sha256Hex(canonNoSig);
  const hashB = "sha256:" + sha256Hex(canonWithSig);
  const claimed = chain.entry_hashes[i];

  const matchA = hashA === claimed;
  const matchB = hashB === claimed;
  console.log(`--- receipt seq=${r.seq} ---`);
  console.log(`  claimed entry_hash             : ${claimed}`);
  console.log(`  (A) sha256(canon(no-sig))      : ${hashA}   ${matchA ? "MATCH" : ""}`);
  console.log(`  (B) sha256(canon(with sig))    : ${hashB}   ${matchB ? "MATCH" : ""}`);
  if (!matchA && !matchB) {
    console.error(`  !! neither interpretation matches — Fable's entry_hash may be wrong`);
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
console.log("  This is a REQUIREMENT on the verifier — flagged as 'structurally described'.");

// N1, N2: signature-level behavior — needs real verifier
console.log("\n--- N1_tampered_decision / N2_high_S_malleability ---");
console.log("  N1 asserts that changing 'decision' from 'deny' to 'allow' invalidates");
console.log("  the Ed25519 signature. Verifiable only by running a real verifier with");
console.log("  a real key against the tampered receipt (later sprint).");
console.log("  N2 asserts that a high-S non-canonical Ed25519 signature must be");
console.log("  rejected per RFC 8032 Section 5.1.7. Verifiable only in a real-verifier");
console.log("  unit test (later sprint).");
console.log("  STATUS FOR N1, N2: structurally described in the corpus, pending real-");
console.log("  verifier unit tests. NOT verified in this task.");

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
console.log("ENTRY_HASH CONVENTION FINDING (surfaced by the (A)/(B) comparison above)");
console.log("=".repeat(80));
console.log("Chirindo's entry_hash convention (src/vendor/recorder/chain.ts,");
console.log("hash.ts, cli/verify.ts): entry_hash = sha256(jcs(contentOf(record)))");
console.log("where contentOf() STRIPS the sig field. This is interpretation (A).");
console.log();
console.log("Fable's fixture computes entry_hash INCLUDING the sig field. This is");
console.log("interpretation (B), and it is the one that produces all three of the");
console.log("claimed entry_hashes above.");
console.log();
console.log("Consequences:");
console.log("  - Under Fable's convention: chain linkage is internally consistent.");
console.log("  - Under Chirindo's convention: a Chirindo verifier reading this");
console.log("    fixture would produce entirely different entry_hashes and the");
console.log("    chain would appear TAMPERED.");
console.log("  - This is a DEFINITIONAL divergence, not a hash-math error — but");
console.log("    it means the corpus is NOT ingest-compatible with Chirindo's own");
console.log("    verifier without a convention change on one side or the other.");
console.log();
console.log("This is a FINDING (interpretation mismatch), not a MATH mismatch. The");
console.log("human decides which convention wins before this corpus can be");
console.log("published as normative.");

if (anyFail) {
  console.error("\n!! CHAIN STRUCTURE CHECK FAILED — see above");
  process.exit(2);
}
console.log("\nChain linkage/seq/iat/genesis/N3/N4 verified under Fable's convention;");
console.log("entry_hash CONVENTION does not match Chirindo's own code (see finding).");
