// JWKS key selection guards (specs H, I, J).
//
//   H — a JWKS serving two keys under one kid is ambiguous → reject
//       (never pick-first): duplicate_kid.
//   I — the selected key must be kty:OKP / crv:Ed25519 / use:sig (when
//       present); a mismatch is refused, even if the raw bytes are Ed25519.
//   J — publish-then-sign: if the signing key is absent from the JWKS the
//       verdict is UNVERIFIABLE with reason issuer_key_unresolvable.

import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  _setJwksCacheEntry,
  buildJwk,
  buildJwks,
  ed25519PublicKeyFromJwk,
  publicKeyBase64Url,
  runVerify,
  type Jwk,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

describe("JWKS key selection (specs H / I / J)", () => {
  let tmp: string;
  const jwksUri = "https://adopter.example/.well-known/jwks.json";

  beforeEach(() => {
    tmp = makeTmpDir();
    _clearJwksCache();
  });
  afterEach(() => {
    cleanupTmpDir(tmp);
    _clearJwksCache();
  });

  async function makeChain() {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-keysel",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri,
      decision: { kind: "allow" },
    });
    return { identity, chainPath };
  }

  it("H — duplicate kid in the JWKS → UNVERIFIABLE(duplicate_kid), never pick-first", async () => {
    const { identity, chainPath } = await makeChain();
    const good = buildJwk({
      kid: identity.kid,
      publicKeyBase64Url: publicKeyBase64Url(identity.publicKey),
    });
    // A rogue second key published under the SAME kid.
    const rogue: Jwk = { ...good, x: publicKeyBase64Url((await initIdentity(makeTmpDirDecoy())).publicKey) };
    _setJwksCacheEntry(jwksUri, buildJwks([good, rogue]));

    const result = await runVerify({ chainPath, jwksUrl: jwksUri });
    expect(result.kind).toBe("unverifiable");
    if (result.kind === "unverifiable") {
      expect(result.reason).toContain("duplicate_kid");
    }
  });

  it("I — a key marked use:enc is refused even with Ed25519 bytes", async () => {
    const { identity, chainPath } = await makeChain();
    const encKey: Jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: publicKeyBase64Url(identity.publicKey),
      kid: identity.kid,
      use: "enc", // wrong: an encryption key must not verify a signature
    };
    _setJwksCacheEntry(jwksUri, buildJwks([encKey]));

    const result = await runVerify({ chainPath, jwksUrl: jwksUri });
    expect(result.kind).toBe("unverifiable");
  });

  it("I — ed25519PublicKeyFromJwk rejects kty/crv/use mismatches (unit)", () => {
    const goodX = "Adg8vN0iVIAsej_gYCf8mS4nBErIz9XW4tX8HkYd0oM"; // any 32-byte b64url
    expect(() =>
      ed25519PublicKeyFromJwk({ kty: "EC", crv: "Ed25519", x: goodX }),
    ).toThrow(/kty/);
    expect(() =>
      ed25519PublicKeyFromJwk({ kty: "OKP", crv: "X25519", x: goodX }),
    ).toThrow(/crv/);
    expect(() =>
      ed25519PublicKeyFromJwk({ kty: "OKP", crv: "Ed25519", x: goodX, use: "enc" }),
    ).toThrow(/use/);
  });

  it("J — signing key absent from the JWKS → UNVERIFIABLE(issuer_key_unresolvable)", async () => {
    const { chainPath } = await makeChain();
    // A JWKS that has SOME key, but not the one the receipt was signed with.
    const strangerId = await initIdentity(makeTmpDirDecoy());
    _setJwksCacheEntry(
      jwksUri,
      buildJwks([
        buildJwk({
          kid: strangerId.kid,
          publicKeyBase64Url: publicKeyBase64Url(strangerId.publicKey),
        }),
      ]),
    );

    const result = await runVerify({ chainPath, jwksUrl: jwksUri });
    expect(result.kind).toBe("unverifiable");
    if (result.kind === "unverifiable") {
      expect(result.reason).toContain("issuer_key_unresolvable");
    }
  });

  // Decoy identities live in their own tmp dirs; collect them for cleanup via
  // the outer afterEach by tracking a shared list.
  const decoyDirs: string[] = [];
  function makeTmpDirDecoy(): string {
    const d = makeTmpDir("mcp-gate-decoy-");
    decoyDirs.push(d);
    return d;
  }
  afterEach(() => {
    while (decoyDirs.length) cleanupTmpDir(decoyDirs.pop()!);
  });
});
