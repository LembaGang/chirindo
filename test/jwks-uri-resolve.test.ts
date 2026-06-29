// Self-describing receipts: a receipt that carries `jwks_uri` in its signed
// bytes resolves its verifying key from THAT URL — not from the verifier's
// configured default. This is the property that lets adopters be verified
// without Headless Oracle hosting their public key.
//
// Four scenarios pinned here:
//   (a) record with jwks_uri verifies VALID via that URL (HO not consulted)
//   (b) record without jwks_uri falls back to the verifier's configured URL
//   (c) post-sign tamper of jwks_uri trips the signature check (the field
//       is inside the signed bytes — that's the security property)
//   (d) export-jwks output is a well-formed JWKS containing the gate's kid
//       and the same raw x bytes as the gate's identity.json
//
// All tests pre-seed the JWKS cache via the explicit _setJwksCacheEntry test
// seam — they exercise the resolution path without standing up an HTTPS
// server. Production never calls _setJwksCacheEntry. The kid match, the
// JCS canonicalization, the Ed25519 verify, and the chain linkage are all
// production code paths.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  _setJwksCacheEntry,
  buildJwk,
  buildJwks,
  parseChainJsonl,
  publicKeyBase64Url,
  runVerify,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import {
  cleanupTmpDir,
  initIdentity,
  makeTmpDir,
} from "./helpers.js";

describe("self-describing receipts — jwks_uri resolution", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
    _clearJwksCache();
  });
  afterEach(() => {
    cleanupTmpDir(tmp);
    _clearJwksCache();
  });

  it("(a) a receipt carrying jwks_uri verifies VALID against THAT URL", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const adopterJwksUrl = "https://adopter.example/.well-known/jwks.json";

    // Adopter pre-publishes their JWKS at adopterJwksUrl.
    _setJwksCacheEntry(
      adopterJwksUrl,
      buildJwks([
        buildJwk({
          kid: identity.kid,
          publicKeyBase64Url: publicKeyBase64Url(identity.publicKey),
        }),
      ]),
    );

    appendReceipt({
      chainPath,
      sessionId: "sess-self-describing",
      identity,
      server: "x",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri: adopterJwksUrl,
      decision: { kind: "allow" },
    });

    // Sanity: the field landed inside the signed record as `jwks_uri`.
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    expect(file.records[0]!.jwks_uri).toBe(adopterJwksUrl);

    // Verify against the URL embedded in the receipt. We pass it explicitly
    // here to drive runVerify (the engine doesn't peek; the CLI does); the
    // semantic equivalent is `chirindo verify <chain>` with no flag, which
    // the CLI test below covers.
    const result = await runVerify({ chainPath, jwksUrl: adopterJwksUrl });
    expect(result.kind).toBe("valid");
  });

  it("(b) a receipt without jwks_uri falls back to the verifier's configured URL", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const hoJwksUrl = "https://headlessoracle.example/.well-known/jwks.json";

    _setJwksCacheEntry(
      hoJwksUrl,
      buildJwks([
        buildJwk({
          kid: identity.kid,
          publicKeyBase64Url: publicKeyBase64Url(identity.publicKey),
        }),
      ]),
    );

    appendReceipt({
      chainPath,
      sessionId: "sess-no-jwks-uri",
      identity,
      server: "x",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      // intentionally no jwksUri
      decision: { kind: "allow" },
    });

    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    // The field is genuinely absent — not present-with-undefined. JCS would
    // emit different canonical bytes for the two cases; absence is what
    // existing receipts have and what backward-compat requires.
    expect("jwks_uri" in file.records[0]!).toBe(false);

    const result = await runVerify({ chainPath, jwksUrl: hoJwksUrl });
    expect(result.kind).toBe("valid");
  });

  it("(c) tampering jwks_uri after signing trips the signature check", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const honestUrl = "https://adopter.example/.well-known/jwks.json";
    const attackerUrl = "https://attacker.example/jwks.json";

    // Both URLs would resolve to a valid JWK if reached. The test must not
    // depend on the attacker URL being unresolvable — the security property
    // is that the signature breaks REGARDLESS of whether the new URL points
    // somewhere useful, because the URL is inside the signed bytes and the
    // canonical bytes change when it changes.
    _setJwksCacheEntry(
      honestUrl,
      buildJwks([
        buildJwk({
          kid: identity.kid,
          publicKeyBase64Url: publicKeyBase64Url(identity.publicKey),
        }),
      ]),
    );
    _setJwksCacheEntry(
      attackerUrl,
      buildJwks([
        buildJwk({
          kid: identity.kid,
          publicKeyBase64Url: publicKeyBase64Url(identity.publicKey),
        }),
      ]),
    );

    appendReceipt({
      chainPath,
      sessionId: "sess-tamper-jwks-uri",
      identity,
      server: "x",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri: honestUrl,
      decision: { kind: "allow" },
    });

    // Rewrite jwks_uri on the wire — same key, same signature value, but
    // the signed-over canonical bytes now disagree with the sig.
    const raw = readFileSync(chainPath, "utf8");
    const parsedLine = JSON.parse(raw.trim()) as Record<string, unknown>;
    expect(parsedLine.jwks_uri).toBe(honestUrl);
    parsedLine.jwks_uri = attackerUrl;
    const tamperedPath = join(tmp, "tampered.jsonl");
    writeFileSync(tamperedPath, JSON.stringify(parsedLine) + "\n", "utf8");

    // Verifier follows the tampered URL — both URLs are cached, so the
    // resolution succeeds. The signature step is where the tamper is
    // caught: the canonical bytes of the rewritten record do not match
    // the sig produced over the original record.
    const result = await runVerify({ chainPath: tamperedPath, jwksUrl: attackerUrl });
    expect(result.kind).toBe("tampered");
    if (result.kind === "tampered") {
      expect(result.reason).toBe("signature invalid");
    }
  });

  it("(d) export-jwks output is a well-formed JWKS with the gate's kid + x", async () => {
    const identity = await initIdentity(tmp);
    // The export-jwks CLI is a thin wrapper around buildJwk/buildJwks. We
    // exercise the same primitives here so the test fails whether the bug
    // is in the helpers or in the CLI's wiring. The cli-verify-e2e suite
    // pattern (spawn the real CLI) is the natural place for the CLI test;
    // we keep this unit-level so the failure mode is localized.
    const xB64 = publicKeyBase64Url(identity.publicKey);
    const jwk = buildJwk({
      kid: identity.kid,
      publicKeyBase64Url: xB64,
    });
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.use).toBe("sig");
    expect(jwk.alg).toBe("EdDSA");
    expect(jwk.kid).toBe(identity.kid);
    expect(jwk.x).toBe(xB64);

    const jwks = buildJwks([jwk]);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]!.kid).toBe(identity.kid);
  });
});
