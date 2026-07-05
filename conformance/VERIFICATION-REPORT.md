# Conformance Vector Verification — Chirindo v0.2.0

**Fixture (frozen v1):** `conformance/vectors-v1.json` — promoted 2026-07-05 from `vectors-v1.candidate.json` after three-way verification below.
**Fixture author:** Fable (external model), by reasoning about RFC 8785, RFC 8032, RFC 7638 — **not** by executing Chirindo code. The receipt-chain `entry_hash` fields were subsequently rederived at fixture-build time from Chirindo's own code path; see §4a.
**Verification harness:** `conformance/verify-harness/` (dev-only, `private: true`, not in the parent package's `files` list).

---

## Top-line verdict

**PROMOTED (2026-07-05).** All canonicalization vectors + RFC 7638 thumbprint three-way confirmed. Chain is self-consistent under Chirindo's (correct) sig-stripped `entry_hash` convention, with all three `entry_hash` values reproducing three-way (Chirindo JCS + `@truestamp/canonify` + fixture-claimed). F1 resolved in favor of the implementation. F2/F3/F4 remain open as hardening items for the next sprint. The fixture is frozen at `conformance/vectors-v1.json`.

- **JCS PRODUCE (V1–V7b, V10):** three-way byte-and-hash agreement between Chirindo (via `canonicalize`), `@truestamp/canonify` (independent RFC 8785 reference), and the fixture. ✔
- **RFC 7638 thumbprint:** two independent JCS paths produce the same canonical input string AND the same b64url thumbprint; matches `jwks.keys[0].kid`. ✔
- **Receipt chain:** `entry_hashes`, `receipts[i].prev_hash`, `checkpoint_example.head_hash`, and `negative[N1].receipt.prev_hash` are DERIVED at fixture-build time from Chirindo's own `canonicalize.ts` + `hash.ts` + `record.ts` (via `dist/`). All three `entry_hash` values also recompute byte-for-byte through the independent RFC 8785 reference (`@truestamp/canonify`) applied to a harness-side sig-strip — three-way agreement matches the assurance already held by the canonicalization vectors. ✔
- **`entry_hash` convention (F1) — resolved in code's favor.** Chirindo defines `entry_hash = sha256(jcs(contentOf(record)))` (sig field REMOVED). This is deliberate: it makes `entry_hash` insensitive to Ed25519 signature malleability (the exact issue N2 describes). Hashing over the sig would break cross-verifier recomputability at the moment malleability makes verifiability hard. The candidate fixture now matches this convention. See §4.
- **Non-blocking findings still open** (do not affect corpus math; belong in the hardening sprint under proper test coverage): F2 `makeKid` is proprietary, not RFC 7638; F3 no unsafe-integer rejection at input-parse boundary; F4 no duplicate-key detection at input-parse boundary. See §5.
- **Explicitly NOT verified in this task:** signature authenticity for any of the three receipts (Fable had public key only; sigs are illustrative). N1, N2, N4 remain "structurally described, pending real-verifier unit tests in a later sprint." Unchanged.

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

Important limitation acknowledged upfront: the `sig` fields were fabricated with the **public key only**. They will not verify under any real Ed25519 key and MUST NOT be treated as authentic. Signature authenticity is not tested in this task. The fixture carries a top-level `_note` on `receipt_chain` documenting this.

### 4a. **F1 resolved — Chirindo's sig-stripped `entry_hash` convention retained; fixture regenerated**

Chirindo's implementation is intentional:

```
entry_hash = "sha256:" + hex(sha256(jcs(contentOf(record))))
                                        ^^^^^^^^^^^^^^^^^^^
                                        sig field REMOVED before canonicalization
```

References: `src/vendor/recorder/chain.ts` (lines 48, 89), `src/vendor/recorder/hash.ts` (line 72), `src/vendor/recorder/cli/verify.ts` (line 191), `src/vendor/recorder/record.ts` (line 181, `contentOf`).

**Why this convention is load-bearing:** it makes `entry_hash` insensitive to Ed25519 signature malleability. Vector N2 describes exactly this risk — a high-S or non-canonical Ed25519 encoding produces a different byte sequence for the same underlying signature. If `entry_hash` folded the sig into its preimage, a re-encoded receipt (same content, malleated sig) would produce a different `entry_hash` and break cross-verifier recomputability at the exact point where malleability makes verifiability hard. Chirindo's convention keeps `entry_hash` a stable commitment to the CONTENT, with sig verification a separate, independent check against a resolved key.

**Fixture change (this pass):** the receipt-chain block was regenerated. `entry_hashes`, `receipts[i].prev_hash`, `checkpoint_example.head_hash`, and `negative[N1].receipt.prev_hash` are now DERIVED at fixture-build time by importing Chirindo's own `jcsBytes`, `contentOf`, and `entryHashOfCanonical` from the built `dist/`. The candidate fixture is therefore self-consistent by construction under the sig-stripped convention. See `conformance/verify-harness/build-fixture.mjs`.

Recomputed `entry_hash` values under the sig-stripped convention:

| seq | `entry_hash` — Chirindo JCS | `entry_hash` — reference (`@truestamp/canonify`) | three-way |
|---|---|---|---|
| 0 | `sha256:6b8f2464ff5a5200b77bf1ffc9e80aa0dedad74a71005922cd00976436d0d2f4` | `sha256:6b8f2464ff5a5200b77bf1ffc9e80aa0dedad74a71005922cd00976436d0d2f4` | **AGREE** |
| 1 | `sha256:82f8c644d1d347f75a5961de93331e6400fd8c3ba5e8459b0289efff6d3852d3` | `sha256:82f8c644d1d347f75a5961de93331e6400fd8c3ba5e8459b0289efff6d3852d3` | **AGREE** |
| 2 | `sha256:37cf65da9b5230ba5b664a4e73c5fa6a2710da4cd7e83e6ee917ed90258a6080` | `sha256:37cf65da9b5230ba5b664a4e73c5fa6a2710da4cd7e83e6ee917ed90258a6080` | **AGREE** |

**Chain entry_hashes independently confirmed via `@truestamp/canonify` (sig-stripped content), three-way agreement.** The check-chain harness also verifies that Chirindo's `contentOf(record)` produces a byte-identical content object to an independent `{sig, ...rest}` destructure — so the sig-strip step itself agrees between the two independent paths, and the matching hashes are not an artifact of feeding the same object to both canonicalizers.

`checkpoint_example.head_hash = entry_hashes[2]`. `N1.receipt.prev_hash = entry_hashes[0]` (the tampered receipt is a mutation of seq=1, so it links to entry_hash of seq=0). Verifiers reject N1 via `INVALID_SIGNATURE` after sig verification, not via linkage break.

The fixture also carries `receipt_chain.verification_algorithm` (rewritten this pass) documenting the sig-stripped rule explicitly, and a top-level `receipt_chain._note` documenting the illustrative-sig limitation.

### 4b. Structural checks under Chirindo's (correct) convention

| Check | Result |
|---|---|
| genesis `prev_hash` = all-zero sentinel and equals `receipts[0].prev_hash` | **OK** |
| `entry_hashes[0]` == `receipts[1].prev_hash` | **OK** |
| `entry_hashes[1]` == `receipts[2].prev_hash` | **OK** |
| `entry_hashes[2]` == `checkpoint_example.head_hash` | **OK** |
| `N1.receipt.prev_hash` == `entry_hashes[0]` | **OK** |
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

## 5. Findings summary

| # | Finding | Where | Status |
|---|---|---|---|
| F1 | `entry_hash` convention divergence between authored fixture and code. | `src/vendor/recorder/chain.ts:48,89`, `src/vendor/recorder/hash.ts:72`, `src/vendor/recorder/cli/verify.ts:191` | **RESOLVED** — code's sig-stripped convention retained (deliberately protects against N2 malleability); fixture regenerated to match. See §4a. |
| F2 | `makeKid` produces proprietary `ed25519/<12-char>`, not RFC 7638 thumbprint. Consumers cannot cross-check `kid` against JWK thumbprint by construction. | `src/vendor/recorder/identity.ts:55` (`makeKid`) | **Open — hardening sprint.** Touches `src/`; needs test coverage before change. |
| F3 | No unsafe-integer rejection at the input-parse boundary. JS `Number` silently truncates `2^53+1` to `2^53`; JCS canonicalizes the truncated value with no protest. Reference lib has the same limitation. | `argsHashFromJsonString`, `resultHashFromJsonString`, any caller feeding raw JSON strings | **Open — hardening sprint.** Mitigation is a strict JSON parse layer above hashing that rejects with `unsafe_number`. |
| F4 | No duplicate-key detection at parse time. `JSON.parse` silently keeps last occurrence before JCS sees the collision. | Same call sites as F3 | **Open — hardening sprint.** Mitigation is a strict JSON parse layer that rejects with `duplicate_member` at any depth. |

F2/F3/F4 are pre-existing implementation gaps in Chirindo v0.2.0 surfaced by the fixture. They do NOT block corpus math (all three-way checks pass) but should be closed in the next hardening sprint under proper test coverage. They are not fixed in this task because they touch `src/` behavior.

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

## 7. Promotion + open items for the hardening sprint

`conformance/vectors-v1.candidate.json` → `conformance/vectors-v1.json`. Frozen. The fixture generator (`conformance/verify-harness/build-fixture.mjs`) is deterministic — anyone can rebuild from source and confirm byte-equality against the frozen file.

The following remain open, deferred to the hardening sprint (none affect the frozen corpus math; each touches `src/` and belongs under proper test coverage):

1. **F2 — `makeKid` → RFC 7638.** Change Chirindo's `kid` scheme so consumers can cross-check `kid` against the JWK thumbprint by construction. Cross-cutting: JWKS `kid`, identity file, existing receipts. Needs a migration plan for any receipts already emitted under the old scheme.
2. **F3 / F4 — strict JSON parse layer.** Add pre-canonicalization rejection with structured errors (`unsafe_number`, `duplicate_member`) at `argsHashFromJsonString`, `resultHashFromJsonString`, and any receipt-parsing verifier path. These are gate-policy requirements the fixture makes explicit.
3. **N1 / N2 / N4 — real-verifier unit tests.** Author a verifier test suite that:
   - Signs each of the three receipt payloads with a real Ed25519 key, then confirms N1's tampered version returns `INVALID_SIGNATURE`.
   - Feeds a hand-crafted high-S signature at N2 and confirms the verifier rejects per RFC 8032 §5.1.7.
   - Runs the N4 flow (JWKS serves a different key under the same `kid`) and confirms `INVALID_KEY_BINDING` fires BEFORE any Ed25519 verify attempt.

Future changes to the corpus itself go through a new `.candidate` → promotion cycle — do not edit `vectors-v1.json` in place.
