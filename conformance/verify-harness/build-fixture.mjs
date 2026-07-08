// Build conformance/vectors-v1.json byte-exactly from code points.
//
// The whole point of several vectors (V2 UTF-16 sort with astral 💩, V7a/V7b
// NFC vs NFD é, V4 minimal escaping) is exact bytes. Hand-typing non-ASCII
// characters via an editor risks silent normalization (V7a and V7b would
// collapse to identical bytes and the whole "no Unicode normalization in JCS"
// vector would be a lie). Everything special is composed from String.fromCodePoint
// here so the output bytes are guaranteed by construction.
//
// canonical_utf8 is derived from canonical_hex (Buffer.from(hex,'hex').toString('utf8'))
// so the two fields cannot drift apart in the fixture: the hex is the ground truth
// of what a compliant RFC 8785 implementation must produce.
//
// The receipt_chain block's entry_hashes, prev_hash linkage, checkpoint head_hash,
// and the N1 tampered receipt's prev_hash are DERIVED at build time from
// Chirindo's own canonicalize.ts / hash.ts / record.ts functions (via dist/).
// This locks the fixture to Chirindo's sig-stripped entry_hash convention:
//   entry_hash = "sha256:" + hex(sha256(jcs(contentOf(record))))
// where contentOf(record) removes the sig field before canonicalization.
// This convention is DELIBERATE: it makes entry_hash insensitive to Ed25519
// signature malleability (see negative vector N2). If we hashed over the
// sig too, a re-encoded signature with equivalent-but-non-canonical bytes
// would produce a different entry_hash and break cross-verifier
// recomputability at the exact point malleability makes verifiability hard.

import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, "..", "vectors-v1.json");
// Output target. Bare `node build-fixture.mjs` reproduces the frozen file
// (documented behavior). Pass a filename to write a CANDIDATE instead — the
// candidate->promote flow: build to vectors-v1.candidate.json, diff for byte
// parity, then promote by copying over the frozen file. Never hand-edit frozen.
const OUT = process.argv[2] ? resolve(HERE, "..", process.argv[2]) : FIXTURE;
mkdirSync(dirname(OUT), { recursive: true });

// Chirindo's own JCS + entry-hash + content-stripping — loaded from the built
// dist so this build script fails loudly (module resolution error) if `npm run
// build` hasn't been run.
const DIST = resolve(HERE, "..", "..", "dist", "vendor", "recorder");
const fileUrl = (p) => "file:///" + p.replace(/\\/g, "/");
const { jcsBytes: chirindoJcsBytes } = await import(fileUrl(resolve(DIST, "canonicalize.js")));
const { entryHashOfCanonical: chirindoEntryHash } = await import(fileUrl(resolve(DIST, "hash.js")));
const { contentOf: chirindoContentOf } = await import(fileUrl(resolve(DIST, "record.js")));

// --- special characters, built from code points ---
const EURO = String.fromCodePoint(0x20ac);          // €    UTF-8: E2 82 AC (3 bytes)
const PILE = String.fromCodePoint(0x1f4a9);         // 💩   UTF-8: F0 9F 92 A9 (4 bytes)
const LIG_FI = String.fromCodePoint(0xfb01);        // ﬁ    UTF-8: EF AC 81 (3 bytes)
const E_NFC = String.fromCodePoint(0x00e9);         // é    UTF-8: C3 A9 (2 bytes)
const E_NFD = String.fromCodePoint(0x0065, 0x0301); // é    UTF-8: 65 CC 81 (3 bytes)

// V4 "s" input: 'A', LF, U+0001, €, '"', '\\' — 6 characters exactly
const V4_S_INPUT =
  String.fromCodePoint(0x41) +   // A
  String.fromCodePoint(0x0a) +   // LF
  String.fromCodePoint(0x01) +   // SOH
  String.fromCodePoint(0x20ac) + // €
  String.fromCodePoint(0x22) +   // "
  String.fromCodePoint(0x5c);    // \

// Sanity: the input we just built must be 6 code units.
if (V4_S_INPUT.length !== 6) throw new Error(`V4 input length mismatch: ${V4_S_INPUT.length}`);

function utf8FromHex(hex) {
  return Buffer.from(hex, "hex").toString("utf8");
}

const produceVectors = [
  {
    name: "V1_key_sort_basic",
    input: { b: 1, a: 2 },
    canonical_hex: "7b2261223a322c2262223a317d",
    sha256: "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
    note: "Members sorted by UTF-16 code units of key",
  },
  {
    name: "V2_key_sort_utf16_astral",
    input: { [EURO]: "euro", [PILE]: "astral", [LIG_FI]: "ligature" },
    canonical_hex:
      "7b22e282ac223a226575726f222c22f09f92a9223a2261737472616c222c22efac81223a226c69676174757265227d",
    sha256: "501631a3d68d335e9ca61c0720b3988667790e9d652bf96d17447c9da55cbf79",
    note: "Sort by UTF-16 code units: U+20AC < D83D(DCA9 surrogate) < FB01; code-point order would differ",
  },
  {
    name: "V3_numbers_es6",
    input: [1.0, 4.5, 0.002, 1e-7, 1e-6, 1e21, 1e20, -0.0, 333333333.3333333, 9007199254740992],
    canonical_hex:
      "5b312c342e352c302e3030322c31652d372c302e3030303030312c31652b32312c3130303030303030303030303030303030303030302c302c3333333333333333332e333333333333332c393030373139393235343734303939325d",
    sha256: "d3aa46361dfb2ea302843fddece7db83e39cd81a68e0a5d284fc738b8e47a047",
    note: "ECMAScript Number::toString shortest form; -0 -> 0; >=1e21 exponential",
  },
  {
    name: "V4_string_escaping",
    input: { s: V4_S_INPUT },
    canonical_hex: "7b2273223a22415c6e5c7530303031e282ac5c225c5c227d",
    sha256: "747441799963b228b9e14f10dd0b56b139203b7cac754bd95a06c43a02c93f67",
    note: "Minimal escaping: \\n short form, U+0001 as \\u0001, non-ASCII literal UTF-8",
  },
  {
    name: "V5a_null_present",
    input: { a: null },
    canonical_hex: "7b2261223a6e756c6c7d",
    sha256: "d091f9c83c091f79652fe8786375b3fe4ce0861a56f5bfbafedbe431877ff0e8",
    note: "null is a value",
  },
  {
    name: "V5b_absent",
    input: {},
    canonical_hex: "7b7d",
    sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    note: "absent is not null: different canonical bytes and hash",
  },
  {
    name: "V6_nested",
    input: { z: { b: [3, 1, 2], a: null }, a: [{ y: 1, x: 2 }] },
    canonical_hex:
      "7b2261223a5b7b2278223a322c2279223a317d5d2c227a223a7b2261223a6e756c6c2c2262223a5b332c312c325d7d7d",
    sha256: "4ce0510fa54b280364fe5bb9e01963d05104f7aa97651b14047305f04003fb30",
    note: "Objects sorted recursively at every depth; array element order NEVER changed",
  },
  {
    name: "V7a_nfc",
    input: { k: E_NFC },
    canonical_hex: "7b226b223a22c3a9227d",
    sha256: "0ca09f1dffb485d259fc791100d48ad7ae9c17f52a2bb07b608c0e28fbca34a1",
    note: "e-acute precomposed U+00E9",
  },
  {
    name: "V7b_nfd",
    input: { k: E_NFD },
    canonical_hex: "7b226b223a2265cc81227d",
    sha256: "4cb477ab754099c91e4c79f77deaab085090978b8abbc981c8eefde872575da8",
    note: "e + combining acute U+0065 U+0301: visually identical, MUST hash differently (no Unicode normalization in JCS)",
  },
  {
    name: "V8_unsafe_integer_REJECT",
    input: "9007199254740993 (2^53+1)",
    canonical_utf8: null,
    canonical_hex: null,
    sha256: null,
    note:
      "IEEE-754 double parse yields 9007199254740992: silent value change across implementations. " +
      "Producers MUST NOT emit JSON numbers outside [-(2^53-1), 2^53-1]; encode as decimal strings. " +
      "Conformant gates REJECT out-of-range numbers in signed payloads.",
  },
  {
    name: "V9_duplicate_keys_REJECT",
    input: '{"a":1,"a":2}',
    canonical_utf8: null,
    canonical_hex: null,
    sha256: null,
    note:
      "No canonical form exists. Parsers differ (first-wins/last-wins/error) so the bytes the policy " +
      "evaluated and the bytes a verifier reconstructs can diverge. Gate MUST reject duplicate member " +
      "names at ANY depth, pre-canonicalization, with a DENY receipt (error=duplicate_member).",
  },
  {
    name: "V10_empty_containers",
    input: { a: [], b: {}, c: "" },
    canonical_hex: "7b2261223a5b5d2c2262223a7b7d2c2263223a22227d",
    sha256: "12db860d7676bcec84a4ea9fa9a3e39e8931c41b10d064b23ced53f06e15caae",
    note: "Empty array, object, string are three distinct values",
  },
].map((v) => {
  if (v.canonical_hex === null) return v;
  return {
    name: v.name,
    input: v.input,
    canonical_utf8: utf8FromHex(v.canonical_hex),
    canonical_hex: v.canonical_hex,
    sha256: v.sha256,
    note: v.note,
  };
});

const fixture = {
  jcs_canonicalization: produceVectors,
  key_binding: {
    jwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: "-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg",
    },
    rfc7638_thumbprint_input:
      '{"crv":"Ed25519","kty":"OKP","x":"-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg"}',
    rfc7638_thumbprint: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
    jwks_document: {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          x: "-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg",
          kid: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
          use: "sig",
          alg: "EdDSA",
          key_ops: ["verify"],
        },
      ],
    },
    rule:
      "kid MUST equal the RFC 7638 thumbprint; receipts carry key_thumbprint inside the signed payload; " +
      "verifier MUST check thumbprint(fetched key) == payload.key_thumbprint before signature verification.",
  },
  receipt_chain: {
    _note:
      "SIG VALUES BELOW ARE ILLUSTRATIVE, NOT AUTHENTIC. The corpus author had " +
      "the Ed25519 PUBLIC key only, so the sig fields were fabricated and will " +
      "not verify under any real key. Authenticity is NOT covered by this " +
      "fixture. entry_hash and prev_hash are computed over contentOf(record), " +
      "which strips sig, so entry_hash is DELIBERATELY insensitive to signature " +
      "malleability (see negative vector N2) — verifiers check the sig " +
      "separately against a resolved key, and check the sig-stripped content " +
      "hash as a chain-linking commitment. entry_hashes / receipts[i].prev_hash / " +
      "checkpoint_example.head_hash / negative[N1].receipt.prev_hash below are " +
      "DERIVED at fixture-build time from Chirindo's own canonicalize.ts + " +
      "hash.ts + record.ts (via dist/), not hand-authored.",
    signing_jwk_public: {
      kty: "OKP",
      crv: "Ed25519",
      x: "-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg",
    },
    genesis_prev_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    receipts: [
      {
        v: "evidence.action/1",
        seq: 0,
        chain_id: "3f2c6d0e-8b7a-4c11-9e2d-5a1b0c9d8e7f",
        prev_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        iat: "2026-07-01T09:00:00Z",
        iss: "https://headlessoracle.com",
        kid: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        key_thumbprint: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        jwks_uri: "https://headlessoracle.com/.well-known/jwks.json",
        agent: { vendor: "chirindo", version: "0.1.0" },
        event: {
          type: "mcp_call",
          server: "files",
          tool_name: "read_file",
          args_hash:
            "sha256:1fe0cddf61747d07406bc523ce49d6615b9b8f06a4e72bde1e3d900b2ca31d9c",
          decision: "allow",
          outcome: "executed",
          result_hash:
            "sha256:4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",
        },
        sig:
          "GwAWVBh93cDFNjX2wh3RZQJnUYeJ3QIUbbN_3DIYRrLpaQO_nrlp-XgTflUStNfkouKxW6ICFz8DLyjjclPdCA",
      },
      {
        v: "evidence.action/1",
        seq: 1,
        chain_id: "3f2c6d0e-8b7a-4c11-9e2d-5a1b0c9d8e7f",
        prev_hash: "sha256:0af4025a9ad55c9f7389c50e5be281abe2e328233ab42a6a69aa0e61bad7e83f",
        iat: "2026-07-01T09:00:02Z",
        iss: "https://headlessoracle.com",
        kid: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        key_thumbprint: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        jwks_uri: "https://headlessoracle.com/.well-known/jwks.json",
        agent: { vendor: "chirindo", version: "0.1.0" },
        event: {
          type: "mcp_call",
          server: "files",
          tool_name: "shell_exec",
          args_hash:
            "sha256:2f3b94579f43fb59e8df8ecf8d8a231a288b641d262c4c425043c107e8e72b82",
          decision: "deny",
          outcome: "denied",
          policy_rule: "deny shell_exec",
          error: null,
        },
        sig:
          "u7iKTtyFxlIVuP-bEpJj_5oa66a2NxMlpvsVq9y1uxsioWBBwMcN3sB3V4FLnDXbjYSHhBRouA0J_9BglRO4Bw",
      },
      {
        v: "evidence.action/1",
        seq: 2,
        chain_id: "3f2c6d0e-8b7a-4c11-9e2d-5a1b0c9d8e7f",
        prev_hash: "sha256:015f925f85d96efeb8ee87a3a9c28e5bf8a4317c3acea6e293fcb757d1a0f601",
        iat: "2026-07-01T09:00:05Z",
        iss: "https://headlessoracle.com",
        kid: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        key_thumbprint: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        jwks_uri: "https://headlessoracle.com/.well-known/jwks.json",
        agent: { vendor: "chirindo", version: "0.1.0" },
        event: {
          type: "mcp_call",
          server: "files",
          tool_name: "read_file",
          args_hash:
            "sha256:1fe0cddf61747d07406bc523ce49d6615b9b8f06a4e72bde1e3d900b2ca31d9c",
          decision: "allow",
          outcome: "executed",
          result_hash:
            "sha256:4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",
        },
        sig:
          "kmMVekDv-_A-r2Z8I6gng_6O0nltF6mfQlr0tkhddNF2-4sgcVPX12ZQjhTPtYokwtA0UPj6LmfrCJ0i7u-SDQ",
      },
    ],
    entry_hashes: [
      "sha256:0af4025a9ad55c9f7389c50e5be281abe2e328233ab42a6a69aa0e61bad7e83f",
      "sha256:015f925f85d96efeb8ee87a3a9c28e5bf8a4317c3acea6e293fcb757d1a0f601",
      "sha256:bd1c7ce31d0bc74f455564e72a79c69c40728cb85c2c3d15a076557e00cd5149",
    ],
    checkpoint_example: {
      v: "evidence.checkpoint/1",
      chain_id: "3f2c6d0e-8b7a-4c11-9e2d-5a1b0c9d8e7f",
      seq_head: 2,
      head_hash: "sha256:bd1c7ce31d0bc74f455564e72a79c69c40728cb85c2c3d15a076557e00cd5149",
      iat: "2026-07-01T09:00:06Z",
      note:
        "sign with same key; publish head_hash to an external witness (Rekor / RFC3161 TSA / on-chain anchor)",
    },
    verification_algorithm:
      "1) parse JSONL strictly (reject duplicate member names, unsafe numbers) " +
      "2) per entry: let content = record with sig field REMOVED; recompute " +
      "canon = jcs(content); verify Ed25519 (RFC 8032 strict: reject S>=L, " +
      "non-canonical encodings) over `canon` using the key resolved by " +
      "kid+thumbprint. " +
      "3) recompute entry_hash = 'sha256:' + hex(sha256(canon)). Note: entry_hash " +
      "hashes the SIG-STRIPPED content, NOT the envelope-with-sig — this is " +
      "deliberate so entry_hash is insensitive to Ed25519 signature malleability " +
      "(see N2). " +
      "4) check prev_hash linkage (entry_hash[i-1] == receipt[i].prev_hash; " +
      "receipt[0].prev_hash == all-zero sentinel), seq strictly +1 from 0, " +
      "iat non-decreasing. " +
      "5) result VALID | INVALID_SIGNATURE | INVALID_KEY_BINDING | " +
      "CHAIN_BREAK | UNVERIFIABLE.",
  },
  negative: [
    {
      name: "N1_tampered_decision",
      receipt: {
        v: "evidence.action/1",
        seq: 1,
        chain_id: "3f2c6d0e-8b7a-4c11-9e2d-5a1b0c9d8e7f",
        prev_hash: "sha256:0af4025a9ad55c9f7389c50e5be281abe2e328233ab42a6a69aa0e61bad7e83f",
        iat: "2026-07-01T09:00:02Z",
        iss: "https://headlessoracle.com",
        kid: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        key_thumbprint: "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
        jwks_uri: "https://headlessoracle.com/.well-known/jwks.json",
        agent: { vendor: "chirindo", version: "0.1.0" },
        event: {
          type: "mcp_call",
          server: "files",
          tool_name: "shell_exec",
          args_hash:
            "sha256:2f3b94579f43fb59e8df8ecf8d8a231a288b641d262c4c425043c107e8e72b82",
          decision: "allow",
          outcome: "executed",
          policy_rule: "deny shell_exec",
          error: null,
        },
        sig:
          "u7iKTtyFxlIVuP-bEpJj_5oa66a2NxMlpvsVq9y1uxsioWBBwMcN3sB3V4FLnDXbjYSHhBRouA0J_9BglRO4Bw",
      },
      expected: "INVALID_SIGNATURE",
      observed: "INVALID_SIGNATURE",
    },
    {
      name: "N2_high_S_malleability",
      sig_b64u:
        "GwAWVBh93cDFNjX2wh3RZQJnUYeJ3QIUbbN_3DIYRrLWPfkbuRx8UU-wdfjwrbb5ouKxW6ICFz8DLyjjclPdGA",
      expected: "REJECTED (RFC 8032 5.1.7 requires S < L)",
      observed_cryptography_lib: "REJECTED",
      note:
        "Verifiers MUST reject S >= L and non-canonical point encodings; otherwise entry_hash of a " +
        "re-encoded receipt diverges across verifiers.",
    },
    {
      name: "N3_seq_gap",
      description: "Present [seq0, seq2] omitting seq1",
      expected: "CHAIN_BREAK at seq2 (prev_hash mismatch AND seq not contiguous)",
    },
    {
      name: "N4_thumbprint_mismatch",
      description:
        "JWKS serves a different key under the same kid; payload.key_thumbprint no longer matches thumbprint of fetched key",
      expected: "INVALID_KEY_BINDING (checked BEFORE signature verification)",
    },
  ],
  // Executable strict-ingest reject vectors (F3/F4). Unlike the declarative
  // V8/V9 in jcs_canonicalization (which describe the requirement), each `input`
  // here is raw JSON TEXT fed verbatim to the strict-parse gate, and
  // `expected_reason` is the StrictJsonParseError.reason it must fail closed
  // with — before any hash is produced. These prove the gate rejects the two
  // recomputability-breaking classes rather than silently normalizing them.
  strict_parse: [
    {
      name: "SP1_unsafe_integer_REJECT",
      input: "9007199254740993",
      expected_reason: "unsafe_number",
      note:
        "2^53+1. IEEE-754 double parse silently yields 9007199254740992, so the " +
        "bytes a gate hashed and the bytes a verifier reconstructs diverge. Strict " +
        "ingest MUST reject integer tokens outside [-(2^53-1), 2^53-1] before hashing.",
    },
    {
      name: "SP2_duplicate_member_REJECT",
      input: '{"a":1,"a":2}',
      expected_reason: "duplicate_member",
      note:
        "No canonical form exists; parsers disagree (first-wins / last-wins / error). " +
        "Strict ingest MUST reject duplicate member names at ANY depth before hashing.",
    },
  ],
};

// --- derive chain hashes from Chirindo's own code ---
//
// Anything hand-authored above for entry_hash / prev_hash / head_hash /
// N1.prev_hash gets OVERWRITTEN here with values computed by Chirindo's own
// canonicalize.ts + hash.ts + record.ts. The fixture is therefore
// self-consistent by construction under Chirindo's sig-stripped convention:
//   entry_hash[i] = "sha256:" + hex(sha256(jcs(contentOf(receipts[i]))))
//   receipts[0].prev_hash = all-zero sentinel
//   receipts[i].prev_hash = entry_hash[i-1]  for i > 0
//   checkpoint.head_hash = entry_hash[last]
//   negative[N1].receipt.prev_hash = entry_hash[0] (it's a tampered seq=1)

const genesisSentinel =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const derivedEntryHashes = [];
for (let i = 0; i < fixture.receipt_chain.receipts.length; i++) {
  const r = fixture.receipt_chain.receipts[i];
  r.prev_hash = i === 0 ? genesisSentinel : derivedEntryHashes[i - 1];
  const canon = chirindoJcsBytes(chirindoContentOf(r));
  derivedEntryHashes.push(chirindoEntryHash(canon));
}
fixture.receipt_chain.entry_hashes = derivedEntryHashes;
fixture.receipt_chain.checkpoint_example.head_hash =
  derivedEntryHashes[derivedEntryHashes.length - 1];

// N1: tampered version of seq=1 — its prev_hash should point at the (untampered)
// entry_hash of seq=0. The tampering is on the event.decision field, not on the
// linkage. Verifiers reject via INVALID_SIGNATURE once sig verify runs.
const n1 = fixture.negative.find((n) => n.name === "N1_tampered_decision");
if (n1) n1.receipt.prev_hash = derivedEntryHashes[0];

console.log("derived entry_hashes (Chirindo sig-stripped convention):");
for (let i = 0; i < derivedEntryHashes.length; i++) {
  console.log(`  [${i}] ${derivedEntryHashes[i]}`);
}
console.log(`  checkpoint head_hash = ${fixture.receipt_chain.checkpoint_example.head_hash}`);
console.log(`  N1.receipt.prev_hash = ${n1 ? n1.receipt.prev_hash : "(N1 not present)"}`);

// --- write file: UTF-8, no BOM ---
const json = JSON.stringify(fixture, null, 2) + "\n";
writeFileSync(OUT, json, { encoding: "utf8" });

// --- read back and assert byte-shape invariants ---
const raw = readFileSync(OUT); // Buffer, no decoding
if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
  throw new Error("BOM found at start of fixture — must be UTF-8 without BOM");
}

const parsed = JSON.parse(raw.toString("utf8"));

const v7a = parsed.jcs_canonicalization.find((v) => v.name === "V7a_nfc").input.k;
const v7b = parsed.jcs_canonicalization.find((v) => v.name === "V7b_nfd").input.k;

const v7aBytes = Buffer.byteLength(v7a, "utf8");
const v7bBytes = Buffer.byteLength(v7b, "utf8");

console.log(`wrote ${OUT}`);
console.log(`  size: ${raw.length} bytes`);
console.log(`  V7a "é" input value bytes (expect 2): ${v7aBytes}`);
console.log(`  V7b "é" input value bytes (expect 3): ${v7bBytes}`);
console.log(`  V7a === V7b? ${v7a === v7b}`);

if (v7aBytes !== 2) {
  throw new Error(`V7a byte length ${v7aBytes} != 2 — fixture is corrupted (NFC/NFD normalization?)`);
}
if (v7bBytes !== 3) {
  throw new Error(`V7b byte length ${v7bBytes} != 3 — fixture is corrupted (NFC/NFD normalization?)`);
}
if (v7a === v7b) {
  throw new Error("V7a and V7b are equal — normalization corrupted the fixture");
}

const v4 = parsed.jcs_canonicalization.find((v) => v.name === "V4_string_escaping").input.s;
if (v4.length !== 6) {
  throw new Error(`V4 "s" input length ${v4.length} != 6 code units`);
}
console.log(`  V4 "s" input length (expect 6): ${v4.length}`);

const v2 = parsed.jcs_canonicalization.find((v) => v.name === "V2_key_sort_utf16_astral").input;
const v2Keys = Object.keys(v2);
console.log(`  V2 keys (as parsed): ${v2Keys.map((k) => `U+${k.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`).join(", ")}`);

// --- self-consistency of the derived chain after write ---
const chain = parsed.receipt_chain;
const recomputed = [];
for (let i = 0; i < chain.receipts.length; i++) {
  const r = chain.receipts[i];
  const expectPrev = i === 0 ? genesisSentinel : recomputed[i - 1];
  if (r.prev_hash !== expectPrev) {
    throw new Error(
      `chain: receipts[${i}].prev_hash != expected (got ${r.prev_hash}, want ${expectPrev})`,
    );
  }
  const canon = chirindoJcsBytes(chirindoContentOf(r));
  const eh = chirindoEntryHash(canon);
  if (chain.entry_hashes[i] !== eh) {
    throw new Error(
      `chain: entry_hashes[${i}] != recomputed (fixture ${chain.entry_hashes[i]}, computed ${eh})`,
    );
  }
  recomputed.push(eh);
}
if (chain.checkpoint_example.head_hash !== recomputed[recomputed.length - 1]) {
  throw new Error("chain: checkpoint head_hash != last entry_hash");
}
const n1r = parsed.negative.find((n) => n.name === "N1_tampered_decision");
if (n1r && n1r.receipt.prev_hash !== recomputed[0]) {
  throw new Error("chain: N1 receipt.prev_hash != entry_hash[0]");
}
console.log("  chain self-consistency: entry_hashes recompute, prev_hash linked, head_hash matches");

console.log("OK — fixture byte-shape invariants hold");
