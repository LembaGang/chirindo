// Conformance negatives wired into the unit suite (specs K + L), anchored to
// the frozen corpus at conformance/vectors-v1.json.
//
// The corpus receipts carry illustrative (public-key-only) signatures that
// cannot verify under a real key — so, per VERIFICATION-REPORT §4c, each
// negative is RECONSTRUCTED here with a real Ed25519 key while asserting the
// corpus's own declared expectation, so the two cannot silently drift.
//
//   N1 — a tampered decision breaks the signature → INVALID_SIGNATURE.
//   N4 — a substituted key (same kid, different material) fails the thumbprint
//        binding, and that check fires BEFORE the signature.
//   N2 — a high-S (S+L) malleated signature is rejected; RFC 8032 §5.1.7
//        strictness is pinned at the crypto layer so a lib swap can't lose it.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  _setJwksCacheEntry,
  base64UrlDecode,
  base64UrlNoPad,
  buildJwk,
  buildJwks,
  contentOf,
  jcsBytes,
  parseChainJsonl,
  publicKeyBase64Url,
  runVerify,
  serializeChainJsonl,
  verifyEd25519,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

// The Ed25519 group order L. RFC 8032 §5.1.7 requires the signature scalar
// S < L; a strict verifier rejects S >= L. (S, S+L) are both mathematically
// valid but S+L is the non-canonical malleated form.
const ED25519_L =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n;

const CORPUS = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "conformance", "vectors-v1.json"), "utf8"),
) as { negative: Array<{ name: string; expected: string }> };

function corpusNegative(name: string): { name: string; expected: string } {
  const n = CORPUS.negative.find((x) => x.name === name);
  if (!n) throw new Error(`corpus negative ${name} not found`);
  return n;
}

// Add L to the S scalar (little-endian, low 32 bytes) of a 64-byte Ed25519
// signature, producing the non-canonical high-S malleation.
function malleateHighS(sigB64u: string): string {
  const raw = base64UrlDecode(sigB64u);
  if (raw.length !== 64) throw new Error(`expected 64-byte sig, got ${raw.length}`);
  const R = raw.subarray(0, 32);
  const S = raw.subarray(32, 64);
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(S[i]!);
  let sPrime = s + ED25519_L;
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(sPrime & 0xffn);
    sPrime >>= 8n;
  }
  return base64UrlNoPad(Buffer.concat([R, out]));
}

describe("conformance negatives (specs K + L)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
    _clearJwksCache();
  });
  afterEach(() => {
    cleanupTmpDir(tmp);
    _clearJwksCache();
  });

  it("N1 — tampered decision → INVALID_SIGNATURE", async () => {
    expect(corpusNegative("N1_tampered_decision").expected).toBe("INVALID_SIGNATURE");

    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-n1",
      identity,
      server: "files",
      toolName: "shell_exec",
      toolArgs: { cmd: "rm -rf /" },
      decision: { kind: "deny", reason: "deny shell_exec" },
    });

    // Flip the recorded decision allow<->deny on the wire. decision is NOT part
    // of the request_descriptor, so request_commitment still matches — the
    // tamper surfaces purely as a broken signature (the corpus INVALID_SIGNATURE
    // case), not as a request_commitment mismatch.
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const rec = file.records[0]!;
    if (rec.event.type !== "mcp_call") throw new Error("expected mcp_call");
    rec.event.decision = "allow";
    const tamperedPath = join(tmp, "tampered.jsonl");
    writeChain(tamperedPath, file);

    const result = runVerify({
      chainPath: tamperedPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(result.kind).toBe("tampered");
    if (result.kind === "tampered") expect(result.reason).toBe("signature invalid");
  });

  it("N4 — substituted key → INVALID_KEY_BINDING, checked BEFORE signature", async () => {
    const expected = corpusNegative("N4_thumbprint_mismatch").expected;
    expect(expected).toContain("INVALID_KEY_BINDING");
    expect(expected).toContain("BEFORE");

    const idA = await initIdentity(tmp);
    const tmpB = makeTmpDir("mcp-gate-n4-");
    try {
      const idB = await initIdentity(tmpB);
      const chainPath = join(tmp, "chain.jsonl");
      const jwksUri = "https://issuer.example/.well-known/jwks.json";
      // JWKS serves idB's key material under idA's kid.
      _setJwksCacheEntry(
        jwksUri,
        buildJwks([
          buildJwk({ kid: idA.kid, publicKeyBase64Url: publicKeyBase64Url(idB.publicKey) }),
        ]),
      );
      appendReceipt({
        chainPath,
        sessionId: "sess-n4",
        identity: idA,
        server: "files",
        toolName: "echo",
        toolArgs: { text: "hi" },
        toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
        jwksUri,
        decision: { kind: "allow" },
      });

      const result = await runVerify({ chainPath, jwksUrl: jwksUri });
      expect(result.kind).toBe("invalid");
      if (result.kind === "invalid") {
        // key_binding_mismatch (NOT "signature invalid") proves the binding
        // check ran before any Ed25519 verification.
        expect(result.reason).toBe("key_binding_mismatch");
      }
    } finally {
      cleanupTmpDir(tmpB);
    }
  });

  it("N2 — high-S (S+L) malleation is rejected (RFC 8032 §5.1.7)", async () => {
    expect(corpusNegative("N2_high_S_malleability").expected).toContain("S < L");

    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-n2",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      decision: { kind: "allow" },
    });

    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const rec = file.records[0]!;
    const canon = jcsBytes(contentOf(rec));
    const malleated = malleateHighS(rec.sig);

    // Crypto layer: the original verifies, the malleated form does NOT. This is
    // the load-bearing assertion — if a future crypto backend accepted high-S,
    // THIS line flips to true and the test fails loudly.
    expect(verifyEd25519(identity.publicKey, canon, rec.sig)).toBe(true);
    expect(verifyEd25519(identity.publicKey, canon, malleated)).toBe(false);

    // Chain layer: a receipt carrying the malleated signature fails to verify.
    rec.sig = malleated;
    const tamperedPath = join(tmp, "malleated.jsonl");
    writeChain(tamperedPath, file);
    const result = runVerify({
      chainPath: tamperedPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(result.kind).toBe("tampered");
    if (result.kind === "tampered") expect(result.reason).toBe("signature invalid");
  });
});

function writeChain(path: string, file: ReturnType<typeof parseChainJsonl>): void {
  // serializeChainJsonl round-trips the (mutated) records to disk.
  writeFileSync(path, serializeChainJsonl(file), "utf8");
}
