// Hardened JWKS fetch profile (spec D) + present-but-down = UNVERIFIABLE
// (spec E). A verifier that follows a URL out of an untrusted receipt is an
// SSRF primitive unless every guard holds. These tests pin:
//
//   - isPrivateAddress classifies loopback/link-local/private/ULA/mapped as
//     unsafe and real public addresses as safe (the core of the DNS guard).
//   - Static target rejections (non-https, non-443 port, IP-literal host) fail
//     WITHOUT a network round-trip.
//   - A hostname that resolves inward (localhost → 127.0.0.1/::1) is refused
//     at connect time with a private_address error — the DNS-rebind-safe path.
//   - A receipt whose jwks_uri is present but unfetchable → UNVERIFIABLE, and
//     the engine never falls back to another key (spec E).
//   - A receipt that names an http:// jwks_uri is malformed → INVALID (spec D),
//     surfaced even on an offline --key verify.
//   - The legacy /0 chain still verifies VALID.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  isPrivateAddress,
  parseChainJsonl,
  resolveKeyFromJwks,
  runVerify,
  serializeChainJsonl,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "legacy-v0");

describe("SSRF guard — isPrivateAddress", () => {
  it("classifies non-public addresses as unsafe", () => {
    for (const ip of [
      "127.0.0.1", // loopback
      "0.0.0.0", // this-network
      "10.1.2.3", // private
      "172.16.0.1", // private
      "172.31.255.255", // private (upper bound of /12)
      "192.168.1.1", // private
      "169.254.169.254", // link-local (cloud metadata)
      "100.64.0.1", // CGNAT
      "224.0.0.1", // multicast
      "::1", // loopback v6
      "fe80::1", // link-local v6
      "fc00::1", // ULA
      "fd12:3456::1", // ULA
      "::ffff:127.0.0.1", // IPv4-mapped loopback
      "::ffff:10.0.0.1", // IPv4-mapped private
      "not-an-ip", // unparseable → fail-closed unsafe
    ]) {
      expect(isPrivateAddress(ip), `${ip} should be unsafe`).toBe(true);
    }
  });

  it("classifies real public addresses as safe", () => {
    for (const ip of [
      "8.8.8.8",
      "1.1.1.1",
      "172.15.0.1", // just below the private /12
      "172.32.0.1", // just above the private /12
      "93.184.216.34", // example.com
      "2606:4700:4700::1111", // public v6 (Cloudflare)
    ]) {
      expect(isPrivateAddress(ip), `${ip} should be safe`).toBe(false);
    }
  });
});

describe("hardened JWKS fetch", () => {
  beforeEach(() => _clearJwksCache());
  afterEach(() => _clearJwksCache());

  it("rejects non-https targets without a network call", async () => {
    const r = await resolveKeyFromJwks({
      url: "http://example.com/.well-known/jwks.json",
      kid: "anything",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("non_https");
  });

  it("rejects a non-443 port", async () => {
    const r = await resolveKeyFromJwks({
      url: "https://example.com:8443/jwks.json",
      kid: "anything",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("forbidden_port");
  });

  it("rejects an IP-literal host (even a public one) before DNS", async () => {
    for (const url of [
      "https://8.8.8.8/jwks.json",
      "https://127.0.0.1/jwks.json",
      "https://[::1]/jwks.json",
    ]) {
      const r = await resolveKeyFromJwks({ url, kid: "anything" });
      expect(r.ok, url).toBe(false);
      if (!r.ok) expect(r.error.kind, url).toBe("ip_literal_host");
    }
  });

  it("refuses a hostname that resolves to a private address (DNS guard)", async () => {
    // localhost resolves to 127.0.0.1 / ::1 — the guard must fire at connect
    // time, so the socket never actually reaches a local service.
    const r = await resolveKeyFromJwks({
      url: "https://localhost/.well-known/jwks.json",
      kid: "anything",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("private_address");
  }, 10_000);
});

describe("verify — present-but-down and malformed jwks_uri", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
    _clearJwksCache();
  });
  afterEach(() => {
    cleanupTmpDir(tmp);
    _clearJwksCache();
  });

  it("present-but-down jwks_uri → UNVERIFIABLE (no silent fallback)", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    // https, well-formed, but resolves inward → the fetch is refused.
    const downUri = "https://localhost/.well-known/jwks.json";
    appendReceipt({
      chainPath,
      sessionId: "sess-down",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri: downUri,
      decision: { kind: "allow" },
    });

    const result = await runVerify({ chainPath, jwksUrl: downUri });
    expect(result.kind).toBe("unverifiable");
    if (result.kind === "unverifiable") {
      expect(result.reason).toContain("non-public address");
    }
  }, 10_000);

  it("a receipt naming an http:// jwks_uri is INVALID(insecure_jwks_uri) offline", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    // appendReceipt is the low-level primitive and does not itself police the
    // scheme (the proxy does). That lets us mint a validly-SIGNED receipt whose
    // committed jwks_uri is insecure — exactly the malformed shape the verifier
    // must reject on its own, before it would ever fetch.
    appendReceipt({
      chainPath,
      sessionId: "sess-insecure",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      jwksUri: "http://evil.example/jwks.json",
      decision: { kind: "allow" },
    });

    // Sanity: the http jwks_uri really is in the signed record.
    const rec = parseChainJsonl(readFileSync(chainPath, "utf8")).records[0]!;
    expect(rec.jwks_uri).toBe("http://evil.example/jwks.json");

    // Offline --key verify: no fetch happens, yet the malformed jwks_uri is
    // still caught → INVALID(insecure_jwks_uri).
    const result = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(result.kind).toBe("invalid");
    if (result.kind === "invalid") {
      expect(result.reason).toBe("insecure_jwks_uri");
    }
  });

  it("the legacy /0 chain still verifies VALID", () => {
    const result = runVerify({
      chainPath: join(FIXTURE_DIR, "chain.jsonl"),
      identityPath: join(FIXTURE_DIR, "identity.json"),
    });
    expect(result.kind).toBe("valid");
  });

  it("a tampered-in-flight http jwks_uri also fails closed", () => {
    // Defense in depth: even if the scheme check were bypassed, rewriting
    // jwks_uri breaks the signature. Here the scheme check fires first, but the
    // point is the chain never verifies VALID with an http URL in it.
    const doTamper = async () => {
      const identity = await initIdentity(tmp);
      const chainPath = join(tmp, "chain.jsonl");
      appendReceipt({
        chainPath,
        sessionId: "sess-tamper-http",
        identity,
        server: "files",
        toolName: "echo",
        toolArgs: { text: "hi" },
        jwksUri: "https://ok.example/jwks.json",
        decision: { kind: "allow" },
      });
      const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
      (file.records[0] as { jwks_uri?: string }).jwks_uri =
        "http://evil.example/jwks.json";
      writeFileSync(chainPath, serializeChainJsonl(file), "utf8");
      return runVerify({ chainPath, identityPath: join(tmp, "identity.json") });
    };
    return doTamper().then((result) => {
      expect(result.kind).not.toBe("valid");
    });
  });
});
