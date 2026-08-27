// F2 closure, anchored to an EXTERNAL known answer (spec G / corpus key_binding).
//
// `test/kid-scheme.test.ts` proves kid == rfc7638Thumbprint(key). That is a
// self-consistency check: makeKid CALLS rfc7638Thumbprint, so it stays green
// even if our thumbprint routine drifts from RFC 7638 entirely. This file
// closes that hole by pinning both against the frozen corpus's independently
// authored values (conformance/vectors-v1.json key_binding — three-way
// confirmed in VERIFICATION-REPORT §3, not produced by running Chirindo).
//
// Red case: change the member set / ordering / hash in rfc7638Thumbprint, or
// point makeKid back at legacyKid, and the assertions below fail.

import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  jcsBytes,
  kidMatchesKey,
  legacyKid,
  makeKid,
  publicKeyBase64Url,
  rfc7638Thumbprint,
} from "../src/vendor/recorder/index.js";

interface KeyBinding {
  jwk: { kty: string; crv: string; x: string };
  rfc7638_thumbprint_input: string;
  rfc7638_thumbprint: string;
  jwks_document: { keys: Array<{ kid: string; x: string }> };
  rule: string;
}

const CORPUS = JSON.parse(
  readFileSync(
    join(import.meta.dirname, "..", "conformance", "vectors-v1.json"),
    "utf8",
  ),
) as { key_binding: KeyBinding };

const KB = CORPUS.key_binding;

// The corpus JWK, imported as a real KeyObject so the production routines run
// against genuine key material rather than a hand-fed string.
const corpusKey = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: KB.jwk.x } as never,
  format: "jwk",
});

describe("F2 — kid is the RFC 7638 thumbprint (external known answer)", () => {
  it("the imported corpus key really carries the corpus x coordinate", () => {
    // Guards the anchor itself: if the JWK import silently produced a
    // different key, every assertion below would be meaningless.
    expect(publicKeyBase64Url(corpusKey)).toBe(KB.jwk.x);
  });

  it("our JCS reproduces the corpus's declared RFC 7638 preimage byte-for-byte", () => {
    const preimage = jcsBytes({ crv: "Ed25519", kty: "OKP", x: KB.jwk.x });
    expect(preimage.toString("utf8")).toBe(KB.rfc7638_thumbprint_input);
  });

  it("rfc7638Thumbprint matches the corpus thumbprint (not just itself)", () => {
    expect(rfc7638Thumbprint(corpusKey)).toBe(KB.rfc7638_thumbprint);
  });

  it("makeKid emits that same thumbprint — this is what closes F2", () => {
    expect(makeKid(corpusKey)).toBe(KB.rfc7638_thumbprint);
    // And it is NOT the legacy proprietary scheme the finding named.
    expect(makeKid(corpusKey)).not.toBe(legacyKid(corpusKey));
    expect(makeKid(corpusKey).startsWith("ed25519/")).toBe(false);
  });

  it("kid in the corpus JWKS document cross-checks against the key by construction", () => {
    const kid = KB.jwks_document.keys[0]!.kid;
    expect(kid).toBe(KB.rfc7638_thumbprint);
    expect(kidMatchesKey(corpusKey, kid)).toBe(true);
  });

  it("the corpus rule this test discharges is the one still on file", () => {
    // If the corpus rule is ever reworded away from the kid==thumbprint
    // requirement, this test is discharging a claim nobody made any more.
    expect(KB.rule).toContain("kid MUST equal the RFC 7638 thumbprint");
  });
});
