# Conformance Vector Verification — Chirindo v0.2.0

**Fixture under review:** `conformance/vectors-v1.candidate.json`
**Fixture author:** Fable (external model), by reasoning about RFC 8785, RFC 8032, RFC 7638 — **not** by executing Chirindo code.
**Verification harness:** `conformance/verify-harness/` (dev-only, `private: true`, not in the parent package's `files` list).

---

## Top-line verdict

**MISMATCHES FOUND — corpus NOT publishable as-is until resolved.**

- **Publishable segment:** all ten JCS PRODUCE vectors (V1–V7b, V10). Three-way byte-and-hash agreement between Chirindo, the independent RFC 8785 reference, and Fable's claims.
- **Blocking mismatch:** `entry_hash` in the receipt chain uses a *different definition* from Chirindo's implementation. Under Fable's convention the chain is self-consistent; under Chirindo's convention none of the three `entry_hash` values recompute. The corpus cannot be consumed by Chirindo's own verifier without a convention change on one side.
- **Related findings** (do not block corpus publication but are real gaps in Chirindo): unsafe-integer and duplicate-key rejection are absent at the input-parse boundary; `makeKid` does not implement RFC 7638.

The specific mismatches are listed in section 4.

---

## 1. Reference library and self-test

**Chosen reference:** [`@truestamp/canonify`](https://www.npmjs.com/package/@truestamp/canonify) v2.1.0 (MIT, Truestamp Inc.).

**Why this one, and not `canonicalize`:** Chirindo's own `src/vendor/recorder/canonicalize.ts` is a thin wrapper around the `canonicalize` npm package. Using `canonicalize` as the "independent" reference would be circular — it is our own code by another name. `@truestamp/canonify` is:
- a genuinely independent implementation (different author, ~80 lines of code, auditable end-to-end),
- has zero runtime dependencies (the harness verifies at load time that `@truestamp/canonify` does not itself pull in `canonicalize`),
- authored by a data-integrity/timestamping company with real production motivation to get RFC 8785 right.

**RFC 8785 self-test result:** PASS.

The self-test (`conformance/verify-harness/ref-self-test.mjs`) uses the input, expected canonical string, and expected UTF-8 byte sequence from **RFC 8785 Appendix B (Section 3.2.2 and 3.2.4)** — copied verbatim from the RFC. The reference reproduces the RFC's own bytes:

```
sha256 of RFC 8785 Appendix B canonical output:
  2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb
```

Both the reference library's output and the RFC's expected bytes hash to this value.

---

## 2. JCS PRODUCE vectors V1–V7b, V10 — three-way check

Command: `node conformance/verify-harness/check-vectors.mjs`

| Vector | ours vs reference vs Fable — sha256 | Result |
|---|---|---|
| V1_key_sort_basic | `d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772` | **AGREE** |
| V2_key_sort_utf16_astral | `501631a3d68d335e9ca61c0720b3988667790e9d652bf96d17447c9da55cbf79` | **AGREE** |
| V3_numbers_es6 | `d3aa46361dfb2ea302843fddece7db83e39cd81a68e0a5d284fc738b8e47a047` | **AGREE** |
| V4_string_escaping | `747441799963b228b9e14f10dd0b56b139203b7cac754bd95a06c43a02c93f67` | **AGREE** |
| V5a_null_present | `d091f9c83c091f79652fe8786375b3fe4ce0861a56f5bfbafedbe431877ff0e8` | **AGREE** |
| V5b_absent | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` | **AGREE** |
| V6_nested | `4ce0510fa54b280364fe5bb9e01963d05104f7aa97651b14047305f04003fb30` | **AGREE** |
| V7a_nfc | `0ca09f1dffb485d259fc791100d48ad7ae9c17f52a2bb07b608c0e28fbca34a1` | **AGREE** |
| V7b_nfd | `4cb477ab754099c91e4c79f77deaab085090978b8abbc981c8eefde872575da8` | **AGREE** |
| V10_empty_containers | `12db860d7676bcec84a4ea9fa9a3e39e8931c41b10d064b23ced53f06e15caae` | **AGREE** |

Every column (Chirindo, `@truestamp/canonify`, Fable's claim) produced the same UTF-8 canonical bytes AND the same SHA-256 for every PRODUCE vector.

Focused sub-checks (see `check-vectors.mjs` output):

- **V2 UTF-16 sort with astral 💩.** Input keys `U+20AC €`, `U+1F4A9 💩`, `U+FB01 ﬁ`. Chirindo emits them in the order `U+20AC, U+1F4A9, U+FB01`. That matches UTF-16 code-unit order (the astral pair leads with the low surrogate `D83D`, which sorts between `U+20AC` and `U+FB01`). It does **not** match code-point order, which would put `ﬁ U+FB01` before `💩 U+1F4A9`. RFC 8785 mandates UTF-16 code-unit sort — confirmed.
- **V3 numbers.** Every one of the ten values renders per ECMAScript `Number::toString` shortest form: `-0` → `0`, `1e-7` → `1e-7` (exponential), `1e+21` → `1e+21` (exponential), `1e20` → `100000000000000000000` (integer, 21 digits), `9007199254740992` (=2^53) → integer. Chirindo and reference agree per-value.
- **V7a vs V7b.** NFC `é` (`C3 A9`, 2 bytes) and NFD `é` (`65 CC 81`, 3 bytes) produce different UTF-8 bytes AND different SHA-256 under both Chirindo and reference. JCS applies **no** Unicode normalization — confirmed. This is the single most important vector: it prevents a class of substitution attacks where visually identical strings would otherwise collide.
- **V5a vs V5b.** `{"a":null}` and `{}` produce distinct canonical forms and distinct SHA-256. Absent is not null — confirmed.

### 2a. REJECT vectors — findings

| Vector | Fable's claim | Chirindo's behavior | Status |
|---|---|---|---|
| V8_unsafe_integer_REJECT | Gate MUST reject numbers outside `[-(2^53-1), 2^53-1]` | JCS canonicalizes silently (JS Number has already truncated `9007199254740993` to `9007199254740992` before JCS runs). Same for the reference lib. | **FINDING** — Chirindo does not enforce this at any input-parse boundary. Mitigation belongs upstream of JCS (strict JSON parser that rejects unsafe numbers). |
| V9_duplicate_keys_REJECT | Gate MUST reject duplicate member names pre-canonicalization | `JSON.parse` silently keeps the last occurrence — JCS never sees the collision. | **FINDING** — Chirindo has no duplicate-key detection at parse time. Mitigation belongs at the parse boundary. |

Neither is a hash-math error and neither invalidates the vector as a **normative requirement**. They are pre-existing gaps in Chirindo's `argsHash` / payload ingest pipeline.

---

## 3. RFC 7638 thumbprint

Command: `node conformance/verify-harness/check-thumbprint.mjs`

- **JCS-canonical thumbprint input string** (from `{"crv":"Ed25519","kty":"OKP","x":"..."}`):

  ```
  {"crv":"Ed25519","kty":"OKP","x":"-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg"}
  ```

  Confirmed byte-identical when computed with Chirindo's JCS AND with `@truestamp/canonify`. Members in lexicographic order (`crv, kty, x`), no whitespace, no non-required members — a valid RFC 7638 preimage.

- **Thumbprint** (`base64url-nopad(sha256(input))`):

  ```
  NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0
  ```

  Computed independently two ways (Chirindo JCS + `@truestamp/canonify` JCS, both feeding a SHA-256 → b64url). Both agree with Fable's claim AND with `jwks.keys[0].kid` in the fixture.

- **FINDING — `makeKid` does not produce RFC 7638 thumbprint.** Chirindo's `makeKid()` in `src/vendor/recorder/identity.ts` produces `ed25519/<12-char-b64url-of-sha256(raw-pubkey)>`, a proprietary scheme. The vector's rule "`kid` MUST equal the RFC 7638 thumbprint" is currently aspirational for Chirindo. This is a real gap: consumers of a Chirindo receipt cannot compute the JWK thumbprint from the receipt's `kid` and cross-check against the JWKS entry.

---

## 4. Receipt chain — STRUCTURE only (signatures NOT authenticable)

Command: `node conformance/verify-harness/check-chain.mjs`

Important limitation acknowledged upfront: Fable produced the `sig` fields with the **public key only**. They will not verify under any real Ed25519 key and MUST NOT be treated as authentic. Signature authenticity is not tested in this task.

### 4a. **BLOCKING mismatch — `entry_hash` definition**

Fable's fixture computes `entry_hash` **including** the `sig` field in the JCS preimage. Chirindo's implementation (`src/vendor/recorder/chain.ts`, `src/vendor/recorder/hash.ts`, `src/vendor/recorder/cli/verify.ts`) uses `contentOf(record)`, which **strips** the `sig` field before hashing.

Three-column diff, per receipt:

| seq | Fable's `entry_hash` | Chirindo (sig-STRIPPED) | with-sig recompute |
|---|---|---|---|
| 0 | `sha256:0af4025a9ad55c9f7389c50e5be281abe2e328233ab42a6a69aa0e61bad7e83f` | `sha256:6b8f2464ff5a5200b77bf1ffc9e80aa0dedad74a71005922cd00976436d0d2f4` | `sha256:0af4025a9ad55c9f7389c50e5be281abe2e328233ab42a6a69aa0e61bad7e83f` |
| 1 | `sha256:015f925f85d96efeb8ee87a3a9c28e5bf8a4317c3acea6e293fcb757d1a0f601` | `sha256:9aad48172bae241813ca1f9b3d04a7157d51f65ab044eb352545824d13c407ac` | `sha256:015f925f85d96efeb8ee87a3a9c28e5bf8a4317c3acea6e293fcb757d1a0f601` |
| 2 | `sha256:bd1c7ce31d0bc74f455564e72a79c69c40728cb85c2c3d15a076557e00cd5149` | `sha256:f378f4491e71f0044e71aa5f5fac6d7267796fa53ef9a2643d01e08436172754` | `sha256:bd1c7ce31d0bc74f455564e72a79c69c40728cb85c2c3d15a076557e00cd5149` |

**Interpretation:** this is a definitional divergence, not a hash-math error. Both conventions are internally consistent and defensible:

- *Sig-excluded (Chirindo)*: entry_hash is stable across resignings; a chain can be re-signed by a new key without invalidating the linkage. Trust boundary lives entirely in the thumbprint-before-verify check.
- *Sig-included (Fable)*: entry_hash uniquely identifies the (content, signature) pair; any resigning creates a new entry_hash and thus a new chain-position identity.

**Consequence for corpus publication:** as-is, a Chirindo verifier reading this fixture would compute entirely different `entry_hash` values and would report the chain as TAMPERED. The corpus is not ingest-compatible with the current implementation. The human decides which convention wins before this becomes a normative artifact.

### 4b. Other chain structure checks (evaluated under Fable's convention)

| Check | Result |
|---|---|
| genesis `prev_hash` = all-zero sentinel and equals `receipts[0].prev_hash` | **OK** |
| `entry_hashes[0]` == `receipts[1].prev_hash` | **OK** |
| `entry_hashes[1]` == `receipts[2].prev_hash` | **OK** |
| `seq` strictly `[0, 1, 2]` | **OK** |
| `iat` non-decreasing (`09:00:00Z` → `09:00:02Z` → `09:00:05Z`) | **OK** |
| N3 (drop seq=1): breaks both linkage AND seq contiguity, as designed | **OK** |
| N4 (thumbprint check ordering before signature verify) | **structurally described** — verifier ordering requirement, no code exercised here |

### 4c. NOT verified in this task

- **Signature authenticity for any of the three receipts.** Fable had the public key only; the sigs were fabricated. Cryptographic verification requires re-signing the payloads against a real private key in a later sprint.
- **N1 (tampered decision → INVALID_SIGNATURE).** Assertion about verifier behavior. Verifiable only by running a real verifier with a real key against the tampered receipt.
- **N2 (high-S malleability → REJECTED per RFC 8032 §5.1.7).** Assertion about verifier behavior. Verifiable only in a real-verifier unit test.
- **N4 (thumbprint precedes signature verify).** Assertion about verifier ordering. Verifiable only by testing the real verifier's failure path when JWKS serves a different key under the same `kid`.

Status for N1, N2, N4: **structurally described in the corpus, pending real-verifier unit tests.**

---

## 5. Findings summary (open items, not blocking the JCS PRODUCE segment)

Each of these is a real gap in Chirindo v0.2.0 surfaced by the vector corpus. None is a bug in the fixture; each is a design decision the fixture makes explicit.

| # | Finding | Where |
|---|---|---|
| F1 | `entry_hash` convention: Fable includes `sig`, Chirindo excludes `sig`. Corpus not ingest-compatible with Chirindo verifier as-is. | `src/vendor/recorder/chain.ts` (line 48, 89), `src/vendor/recorder/hash.ts` (line 72), `src/vendor/recorder/cli/verify.ts` (line 191) |
| F2 | `makeKid` produces proprietary `ed25519/<12-char>`, not RFC 7638 thumbprint. Consumers cannot cross-check `kid` against JWK thumbprint. | `src/vendor/recorder/identity.ts` (`makeKid`, line 55) |
| F3 | No unsafe-integer rejection at the input-parse boundary. JCS canonicalizes silently-truncated `2^53+1` as if it were `2^53`. | `argsHashFromJsonString`, `resultHashFromJsonString`, any caller feeding raw JSON strings |
| F4 | No duplicate-key detection at parse time. `JSON.parse` silently drops earlier duplicates before JCS sees them. | Same call sites as F3 |

---

## 6. Verification commands

```
# From the repo root:
npm run build

# From conformance/verify-harness/:
npm install
node ref-self-test.mjs      # RFC 8785 Appendix B self-test
node check-vectors.mjs      # V1–V10 three-way check
node check-thumbprint.mjs   # RFC 7638 two-way check
node check-chain.mjs        # chain structure check (surfaces F1)
```

---

## 7. Decision requested

Do not promote `conformance/vectors-v1.candidate.json` to `conformance/vectors-v1.json` yet.

The human must decide:

1. **`entry_hash` convention (F1).** Adopt Fable's sig-inclusive definition (change Chirindo), or keep Chirindo's sig-exclusive definition (regenerate the fixture's `entry_hashes` and `prev_hash` links)? Both are defensible; the choice affects re-signing semantics.
2. **`makeKid` → RFC 7638 (F2).** Change Chirindo's `kid` scheme to RFC 7638 thumbprint? This is a cross-cutting change (JWKS `kid`, identity file, existing receipts).
3. **Unsafe-integer / duplicate-key rejection (F3, F4).** Add a strict JSON parse layer above `argsHashFromJsonString` / `resultHashFromJsonString` that rejects with `unsafe_number` / `duplicate_member` errors? These are gate-policy requirements the fixture makes explicit.

Once (1) is decided, either update the fixture or the code so the entry_hash column reconciles. Then the corpus is publishable.
