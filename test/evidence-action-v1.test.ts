// evidence.action/1 — key binding (spec A + B).
//
// A v1 receipt carries, inside its signed bytes, the RFC 7638 thumbprint of
// the signing key (`key_thumbprint`) plus an issuer string (`iss`). The
// verifier recomputes the thumbprint of whatever key it resolves and compares
// it to the committed value BEFORE checking the signature — so a substituted
// key cannot "pass" by verifying under itself. This suite pins:
//
//   1. rfc7638Thumbprint matches the frozen conformance corpus value.
//   2. A fresh v1 receipt round-trips VALID and carries key_thumbprint + iss.
//   3. A genuine legacy /0 chain STILL verifies VALID (mandatory backward
//      compat — a /0 regression is a hard stop).
//   4. Key-binding mismatch (the N4 shape: JWKS serves a different key under
//      the same kid) → INVALID(key_binding_mismatch), and it fires before the
//      signature check.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  _setJwksCacheEntry,
  buildJwk,
  buildJwks,
  ed25519PublicKeyFromJwk,
  parseChainJsonl,
  publicKeyBase64Url,
  rfc7638Thumbprint,
  runVerify,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "legacy-v0");

describe("evidence.action/1 — key binding", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
    _clearJwksCache();
  });
  afterEach(() => {
    cleanupTmpDir(tmp);
    _clearJwksCache();
  });

  it("rfc7638Thumbprint reproduces the frozen conformance corpus value", () => {
    // conformance/vectors-v1.json key_binding.jwk / .rfc7638_thumbprint.
    const publicKey = ed25519PublicKeyFromJwk({
      kty: "OKP",
      crv: "Ed25519",
      x: "-_bzJTHbOeC2OM10w11xq81-MHi_XuREpEqtKDxkvMg",
    });
    expect(rfc7638Thumbprint(publicKey)).toBe(
      "NvrZE4rGdm3rW7l4aFU_Y4r_KGtb8s-b6BAxEdC-vT0",
    );
  });

  it("a fresh v1 receipt carries key_thumbprint + iss and verifies VALID", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const jwksUri = "https://adopter.example/.well-known/jwks.json";

    appendReceipt({
      chainPath,
      sessionId: "sess-v1",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri,
      decision: { kind: "allow" },
    });

    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const rec = file.records[0]!;
    expect(rec.v).toBe("evidence.action/1");
    // The committed thumbprint is the RFC 7638 thumbprint of the signing key.
    const expectedTp = rfc7638Thumbprint(identity.publicKey);
    expect(rec.key_thumbprint).toBe(expectedTp);
    // iss defaults to the jwks_uri origin — the operator's domain, not HO.
    expect(rec.iss).toBe("https://adopter.example");

    // Verify against the same key (local identity). Binding passes → VALID.
    const result = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(result.kind).toBe("valid");
  });

  it("iss falls back to a key-scoped URN when no jwks_uri is set", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");

    appendReceipt({
      chainPath,
      sessionId: "sess-v1-nourn",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      // no jwksUri
      decision: { kind: "allow" },
    });

    const rec = parseChainJsonl(readFileSync(chainPath, "utf8")).records[0]!;
    const tp = rfc7638Thumbprint(identity.publicKey);
    expect(rec.iss).toBe(`urn:chirindo:key:${tp}`);
    expect(rec.key_thumbprint).toBe(tp);
  });

  it("a genuine legacy /0 chain STILL verifies VALID (backward compat, mandatory)", () => {
    const chainPath = join(FIXTURE_DIR, "chain.jsonl");
    const identityPath = join(FIXTURE_DIR, "identity.json");

    // Sanity: the fixture really is v0 and carries none of the v1 fields.
    const rec = parseChainJsonl(readFileSync(chainPath, "utf8")).records[0]!;
    expect(rec.v).toBe("evidence.action/0");
    expect("key_thumbprint" in rec).toBe(false);
    expect("iss" in rec).toBe(false);

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid");
    if (result.kind === "valid") {
      expect(result.count).toBe(2);
    }
  });

  it("key-binding mismatch → INVALID(key_binding_mismatch), before signature check", async () => {
    // idA signs the receipt; the JWKS serves idB's key material under idA's
    // kid (the N4 substitution shape). The receipt committed to thumbprint(A);
    // the verifier resolves B → thumbprint(B) ≠ thumbprint(A) → INVALID, and
    // it must surface as key_binding_mismatch (NOT "signature invalid"), which
    // proves the binding check ran BEFORE the signature check.
    const idA = await initIdentity(tmp);
    const tmpB = makeTmpDir();
    try {
      const idB = await initIdentity(tmpB);
      const chainPath = join(tmp, "chain.jsonl");
      const jwksUri = "https://adopter.example/.well-known/jwks.json";

      // JWKS serves B's public key BUT under A's kid.
      _setJwksCacheEntry(
        jwksUri,
        buildJwks([
          buildJwk({
            kid: idA.kid,
            publicKeyBase64Url: publicKeyBase64Url(idB.publicKey),
          }),
        ]),
      );

      appendReceipt({
        chainPath,
        sessionId: "sess-binding-mismatch",
        identity: idA,
        server: "files",
        toolName: "echo",
        toolArgs: { text: "hi" },
        toolResult: {
          content: [{ type: "text", text: "hi" }],
          isError: false,
        },
        jwksUri,
        decision: { kind: "allow" },
      });

      const result = await runVerify({ chainPath, jwksUrl: jwksUri });
      expect(result.kind).toBe("invalid");
      if (result.kind === "invalid") {
        expect(result.reason).toBe("key_binding_mismatch");
        expect(result.entry).toBe(0);
      }
    } finally {
      cleanupTmpDir(tmpB);
    }
  });
});
