// SSRF follow-up (post-review hardening).
//
// The Task 3 suite proved the DNS guard via `localhost` (a real name that
// resolves inward). This adds the harder proofs the review flagged:
//   - a STUBBED resolver so an arbitrary public-looking hostname can be made to
//     resolve to 169.254.169.254 (cloud metadata) — the resolved-address guard
//     must refuse it, and it must refuse if ANY resolved address is private
//     (the DNS-rebind / mixed-A-record shape);
//   - the two IPv6 embedded-v4 edge gaps: hex-form IPv4-mapped (::ffff:7f00:1)
//     and NAT64 (64:ff9b::/96), in both dotted and hex tail encodings.

import { afterEach, describe, expect, it } from "vitest";
import {
  _clearJwksCache,
  _setLookupForTests,
  isPrivateAddress,
  resolveKeyFromJwks,
} from "../src/vendor/recorder/index.js";

describe("SSRF follow-up", () => {
  afterEach(() => {
    _setLookupForTests(null); // ALWAYS restore the real resolver
    _clearJwksCache();
  });

  describe("isPrivateAddress — IPv6 embedded-v4 (edge gaps)", () => {
    it("hex-form IPv4-mapped (::ffff:HHHH:HHHH) classifies by embedded v4", () => {
      expect(isPrivateAddress("::ffff:7f00:1")).toBe(true); // 127.0.0.1
      expect(isPrivateAddress("::ffff:a9fe:a9fe")).toBe(true); // 169.254.169.254
      expect(isPrivateAddress("::ffff:127.0.0.1")).toBe(true); // dotted still ok
      expect(isPrivateAddress("::ffff:808:808")).toBe(false); // 8.8.8.8 public
    });

    it("NAT64 (64:ff9b::/96) classifies by embedded v4", () => {
      expect(isPrivateAddress("64:ff9b::a9fe:a9fe")).toBe(true); // 169.254.169.254
      expect(isPrivateAddress("64:ff9b::a00:1")).toBe(true); // 10.0.0.1
      expect(isPrivateAddress("64:ff9b::10.0.0.1")).toBe(true); // dotted
      expect(isPrivateAddress("64:ff9b::808:808")).toBe(false); // 8.8.8.8 via NAT64
    });
  });

  describe("resolved-address guard via a stubbed resolver", () => {
    it("a public-looking hostname resolving to 169.254.169.254 → private_address", async () => {
      _setLookupForTests((_hostname, _options, cb) => {
        // The attacker controls DNS: a perfectly innocent name points at the
        // cloud metadata endpoint. The guard checks the RESOLVED address.
        cb(null, [{ address: "169.254.169.254", family: 4 }]);
      });

      const r = await resolveKeyFromJwks({
        url: "https://metadata.attacker.example/.well-known/jwks.json",
        kid: "anything",
      });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.kind).toBe("private_address");
        if (r.error.kind === "private_address") {
          expect(r.error.address).toBe("169.254.169.254");
          expect(r.error.host).toBe("metadata.attacker.example");
        }
      }
    });

    it("refuses if ANY resolved address is private (mixed A records)", async () => {
      _setLookupForTests((_hostname, _options, cb) => {
        // A public address first, a loopback second — a rebind/split-horizon
        // shape. The public entry must NOT make the private one reachable.
        cb(null, [
          { address: "93.184.216.34", family: 4 },
          { address: "127.0.0.1", family: 4 },
        ]);
      });

      const r = await resolveKeyFromJwks({
        url: "https://mixed.attacker.example/jwks.json",
        kid: "anything",
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.kind).toBe("private_address");
    });

    it("refuses a metadata IP reached via NAT64 resolution", async () => {
      _setLookupForTests((_hostname, _options, cb) => {
        cb(null, [{ address: "64:ff9b::a9fe:a9fe", family: 6 }]);
      });

      const r = await resolveKeyFromJwks({
        url: "https://nat64.attacker.example/jwks.json",
        kid: "anything",
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.kind).toBe("private_address");
    });
  });
});
