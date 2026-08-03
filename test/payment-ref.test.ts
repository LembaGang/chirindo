// x402 delivery-proof payment reference — subset extraction, the registry
// gate, and strict-ingest behavior. Spec: docs/spec/delivery-proof.md §2/§3.
//
// Artifact fixtures below use the SHAPES AND FIELD NAMES observed in the
// 2026-08-02 live base-sepolia / Coinbase CDP capture
// (x402-capture-rig/capture/, outside this repo). Wallet-identifying values
// and the settlement id are synthetic placeholders per that capture's
// redaction rules — only the KEY NAMES and value TYPES are load-bearing here.
// The asset address is the public base-sepolia USDC test contract already
// carried in the spec's §3.3 example.

import { describe, expect, it } from "vitest";
import {
  PaymentRefError,
  StrictJsonParseError,
  buildPaymentRefSubset,
  findRegistryRow,
  isPaymentRefFormat,
  jcsBytes,
  paymentRef,
  paymentRefFromArtifacts,
  paymentRefFromJsonStrings,
  sha256Hex,
  X402_REGISTRY_VERSION,
  type PaymentRefSelector,
  type X402Artifacts,
} from "../src/vendor/recorder/index.js";

const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const RESOURCE_URL = "http://localhost:4021/paid";
const SETTLEMENT_TX = "0x" + "ab".repeat(32); // synthetic; 0x + 64 hex, the observed shape

// Artifact A — PaymentRequirements. OBSERVED to arrive in the PAYMENT-REQUIRED
// *response header* (base64 JSON); the 402 body was literally `{}`.
function requirements(overrides: Record<string, unknown> = {}): unknown {
  return {
    x402Version: 2,
    error: "Payment required",
    // `resource` is a TOP-LEVEL object beside accepts[], not a member of the
    // accepts entry — the subset takes its `url`.
    resource: {
      url: RESOURCE_URL,
      description: "delivery-proof capture: one paid call",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        // Observed key is `amount` (NOT the hypothesized maxAmountRequired),
        // and its value is a base-unit decimal STRING.
        amount: "1000",
        asset: USDC_BASE_SEPOLIA,
        payTo: "<PAYTO_REDACTED>",
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2" },
      },
    ],
    ...overrides,
  };
}

// Artifact C — SettleResponse, from the PAYMENT-RESPONSE header.
function settle(overrides: Record<string, unknown> = {}): unknown {
  return {
    success: true,
    payer: "<PAYER_REDACTED>",
    transaction: SETTLEMENT_TX,
    network: "eip155:84532",
    ...overrides,
  };
}

const VERIFIED_SELECTOR: PaymentRefSelector = {
  scheme: "exact",
  network: "eip155:84532",
  facilitator: "coinbase-cdp",
  acceptsIndex: 0,
};

const FULL_ARTIFACTS: X402Artifacts = {
  requirements: requirements(),
  settle: settle(),
};

describe("payment_ref_subset extraction (spec §3.2/§3.4)", () => {
  it("selects EXACTLY the six subset keys from the observed artifacts", () => {
    const subset = buildPaymentRefSubset(FULL_ARTIFACTS, VERIFIED_SELECTOR);
    expect(subset).toEqual({
      scheme: "exact",
      network: "eip155:84532",
      asset: USDC_BASE_SEPOLIA,
      amount: "1000",
      resource: RESOURCE_URL,
      settlement: SETTLEMENT_TX,
    });
    // No key outside the list — this is what keeps wallet internals and PII
    // out of the signed bytes.
    expect(Object.keys(subset).sort()).toEqual([
      "amount",
      "asset",
      "network",
      "resource",
      "scheme",
      "settlement",
    ]);
  });

  it("carries amount as a decimal string, never coerced to a number", () => {
    const subset = buildPaymentRefSubset(FULL_ARTIFACTS, VERIFIED_SELECTOR);
    expect(typeof subset.amount).toBe("string");
    expect(subset.amount).toBe("1000");
  });

  it("OMITS settlement (never null) when the settle response carries none", () => {
    const subset = buildPaymentRefSubset(
      { requirements: requirements(), settle: settle({ transaction: undefined }) },
      VERIFIED_SELECTOR,
    );
    expect("settlement" in subset).toBe(false);
    // A null placeholder would change the JCS bytes; absence does not.
    expect(jcsBytes(subset).toString("utf8")).not.toContain("settlement");
    expect(paymentRef(subset)).not.toBe(
      paymentRef({ ...subset, settlement: null } as never),
    );
  });

  it("omits settlement when the settle artifact does not exist at all (pre-confirmation)", () => {
    const subset = buildPaymentRefSubset(
      { requirements: requirements() },
      VERIFIED_SELECTOR,
    );
    expect("settlement" in subset).toBe(false);
    expect(subset.scheme).toBe("exact");
  });

  it("selects the accepts[] offer the payer actually paid, by index", () => {
    const twoOffers = requirements({
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: "500",
          asset: USDC_BASE_SEPOLIA,
        },
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: "1000",
          asset: USDC_BASE_SEPOLIA,
        },
      ],
    });
    const paidSecond = buildPaymentRefSubset(
      { requirements: twoOffers, settle: settle() },
      { ...VERIFIED_SELECTOR, acceptsIndex: 1 },
    );
    expect(paidSecond.amount).toBe("1000");
  });
});

describe("x402_payment_ref hashing (spec §2)", () => {
  it("is sha256 over the JCS canonical bytes of the subset", () => {
    const subset = buildPaymentRefSubset(FULL_ARTIFACTS, VERIFIED_SELECTOR);
    const expected = "sha256:" + sha256Hex(jcsBytes(subset));
    expect(paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR)).toBe(expected);
    expect(isPaymentRefFormat(expected)).toBe(true);
  });

  it("is independent of authoring key order (JCS re-sorts)", () => {
    const ordered = {
      amount: "1000",
      asset: USDC_BASE_SEPOLIA,
      network: "eip155:84532",
      resource: RESOURCE_URL,
      scheme: "exact",
      settlement: SETTLEMENT_TX,
    };
    const shuffled = {
      settlement: SETTLEMENT_TX,
      scheme: "exact",
      resource: RESOURCE_URL,
      network: "eip155:84532",
      asset: USDC_BASE_SEPOLIA,
      amount: "1000",
    };
    expect(paymentRef(shuffled)).toBe(paymentRef(ordered));
    expect(paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR)).toBe(
      paymentRef(ordered),
    );
  });

  it("changes when any subset value changes", () => {
    const base = paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR);
    const other = paymentRefFromArtifacts(
      {
        requirements: requirements({
          accepts: [
            {
              scheme: "exact",
              network: "eip155:84532",
              amount: "1001",
              asset: USDC_BASE_SEPOLIA,
            },
          ],
        }),
        settle: settle(),
      },
      VERIFIED_SELECTOR,
    );
    expect(other).not.toBe(base);
  });
});

describe("registry gate — fail closed without a VERIFIED row (spec §3.4.1)", () => {
  it("registry is at v3 with the promoted row VERIFIED", () => {
    expect(X402_REGISTRY_VERSION).toBe(3);
    const row = findRegistryRow({
      scheme: "exact",
      network: "eip155:84532",
      facilitator: "coinbase-cdp",
    });
    expect(row?.status).toBe("VERIFIED");
    // Every mapped field must be `observed` for a VERIFIED row (rule 4).
    for (const mapping of Object.values(row!.map)) {
      expect(mapping?.provenance).toBe("observed");
    }
  });

  it("refuses an unregistered (scheme, network, facilitator) tuple", () => {
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        scheme: "upto",
      }),
    ).toThrowError(
      expect.objectContaining({ reason: "unregistered_mapping" }),
    );
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        facilitator: "some-other-facilitator",
      }),
    ).toThrowError(
      expect.objectContaining({ reason: "unregistered_mapping" }),
    );
  });

  it("refuses a PROVISIONAL row — registered for review is NOT registered for emission", () => {
    const row = findRegistryRow({
      scheme: "exact",
      network: "base-sepolia",
      facilitator: "coinbase-cdp",
    });
    expect(row?.status).toBe("PROVISIONAL");
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        network: "base-sepolia",
      }),
    ).toThrowError(expect.objectContaining({ reason: "unverified_row" }));
  });

  it("refuses when the artifacts describe a different scheme/network than the selected row", () => {
    const mismatched = requirements({
      accepts: [
        {
          scheme: "exact",
          network: "eip155:8453", // mainnet id under a base-sepolia row
          amount: "1000",
          asset: USDC_BASE_SEPOLIA,
        },
      ],
    });
    expect(() =>
      paymentRefFromArtifacts(
        { requirements: mismatched, settle: settle() },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "row_mismatch" }));
  });

  it("refuses rather than fabricating a subset when a required key is absent", () => {
    const noAmount = requirements({
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          asset: USDC_BASE_SEPOLIA,
        },
      ],
    });
    expect(() =>
      paymentRefFromArtifacts(
        { requirements: noAmount, settle: settle() },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(
      expect.objectContaining({ reason: "missing_required_field" }),
    );
  });

  it("refuses a required key of the wrong type instead of coercing it", () => {
    const numericAmount = requirements({
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: 1000, // a JSON number, not the observed decimal string
          asset: USDC_BASE_SEPOLIA,
        },
      ],
    });
    expect(() =>
      paymentRefFromArtifacts(
        { requirements: numericAmount, settle: settle() },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "invalid_field_type" }));
  });

  it("refuses an accepts index the 402 never offered", () => {
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        acceptsIndex: 3,
      }),
    ).toThrowError(
      expect.objectContaining({ reason: "accepts_index_out_of_range" }),
    );
  });

  it("refuses when a required artifact was not supplied", () => {
    expect(() =>
      paymentRefFromArtifacts({ settle: settle() }, VERIFIED_SELECTOR),
    ).toThrowError(expect.objectContaining({ reason: "missing_artifact" }));
  });

  it("every registry failure is a typed PaymentRefError with a machine-readable reason", () => {
    try {
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        scheme: "unknown-scheme",
      });
      throw new Error("expected a throw");
    } catch (e) {
      expect(e).toBeInstanceOf(PaymentRefError);
      expect((e as PaymentRefError).reason).toBe("unregistered_mapping");
    }
  });
});

// The registry v3 tuple: the SAME scheme and network settled through the
// x402.org facilitator instead of Coinbase CDP. `x402org` is the registry key
// the demo's FACILITATOR=x402org resolves to.
const X402ORG_SELECTOR: PaymentRefSelector = {
  ...VERIFIED_SELECTOR,
  facilitator: "x402org",
};

describe("registry v3 — second VERIFIED row (exact / eip155:84532 / x402org)", () => {
  it("registers the x402org tuple as VERIFIED at registry v3", () => {
    const row = findRegistryRow({
      scheme: "exact",
      network: "eip155:84532",
      facilitator: "x402org",
    });
    expect(row?.status).toBe("VERIFIED");
    expect(row?.since).toBe(3);
    expect(row?.since).toBeLessThanOrEqual(X402_REGISTRY_VERSION);
    // Rule 4 — a VERIFIED row may not carry a documentation-derived field.
    for (const mapping of Object.values(row!.map)) {
      expect(mapping?.provenance).toBe("observed");
    }
    expect(row!.provenance).toMatch(/x402\.org/);
  });

  it("PERMITS emission under the new tuple", () => {
    const ref = paymentRefFromArtifacts(FULL_ARTIFACTS, X402ORG_SELECTOR);
    expect(isPaymentRefFormat(ref)).toBe(true);
    expect(ref).toBe(
      "sha256:" +
        sha256Hex(jcsBytes(buildPaymentRefSubset(FULL_ARTIFACTS, X402ORG_SELECTOR))),
    );
  });

  it("commits to the same bytes as the CDP row for the same exchange", () => {
    // Not a coincidence to paper over: the facilitator is NOT one of the six
    // §3.2 subset keys, and both rows map the six keys to the same source
    // paths, so identical artifacts MUST produce an identical commitment. The
    // registry row is what makes the commitment *comparable*; it is not itself
    // committed to.
    expect(paymentRefFromArtifacts(FULL_ARTIFACTS, X402ORG_SELECTOR)).toBe(
      paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR),
    );
  });

  it("still REFUSES any facilitator that is not registered", () => {
    for (const facilitator of ["x402-org", "x402.org", "X402ORG", "stripe", ""]) {
      expect(() =>
        paymentRefFromArtifacts(FULL_ARTIFACTS, { ...VERIFIED_SELECTOR, facilitator }),
      ).toThrowError(expect.objectContaining({ reason: "unregistered_mapping" }));
    }
  });

  it("does not register the new facilitator on any OTHER scheme or network", () => {
    // The row is one tuple, not a facilitator-wide grant.
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, { ...X402ORG_SELECTOR, scheme: "upto" }),
    ).toThrowError(expect.objectContaining({ reason: "unregistered_mapping" }));
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...X402ORG_SELECTOR,
        network: "eip155:8453",
      }),
    ).toThrowError(expect.objectContaining({ reason: "unregistered_mapping" }));
    // Including the superseded v0 network id — adding a row never revives one.
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...X402ORG_SELECTOR,
        network: "base-sepolia",
      }),
    ).toThrowError(expect.objectContaining({ reason: "unregistered_mapping" }));
  });

  it("carries the v2 amount cross-check — refuses when A and B disagree", () => {
    expect(() =>
      paymentRefFromArtifacts(
        { ...FULL_ARTIFACTS, payload: payload("9999") },
        X402ORG_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "amount_disagreement" }));
    expect(
      paymentRefFromArtifacts(
        { ...FULL_ARTIFACTS, payload: payload("1000") },
        X402ORG_SELECTOR,
      ),
    ).toBe(paymentRefFromArtifacts(FULL_ARTIFACTS, X402ORG_SELECTOR));
  });

  it("keeps settlement OPTIONAL — two observations are not 'always'", () => {
    // Presence is now observed twice, across two facilitators. That is still
    // an observation, not a rule: an absent `transaction` omits the member, it
    // does not fail the emission.
    const subset = buildPaymentRefSubset(
      { requirements: requirements(), settle: settle({ transaction: undefined }) },
      X402ORG_SELECTOR,
    );
    expect("settlement" in subset).toBe(false);
    expect(subset.amount).toBe("1000");
  });

  it("leaves the pre-existing rows behaving exactly as before", () => {
    // Rule 2 in test form: an additive row changes nothing about the rows
    // already shipped.
    expect(
      findRegistryRow({
        scheme: "exact",
        network: "eip155:84532",
        facilitator: "coinbase-cdp",
      })?.status,
    ).toBe("VERIFIED");
    const v0 = findRegistryRow({
      scheme: "exact",
      network: "base-sepolia",
      facilitator: "coinbase-cdp",
    });
    expect(v0?.status).toBe("PROVISIONAL");
    expect(v0?.supersededBy).toEqual({ network: "eip155:84532", since: 1 });
    expect(() =>
      paymentRefFromArtifacts(FULL_ARTIFACTS, {
        ...VERIFIED_SELECTOR,
        network: "base-sepolia",
      }),
    ).toThrowError(expect.objectContaining({ reason: "unverified_row" }));
  });
});

// Artifact B — PaymentPayload, from the PAYMENT-SIGNATURE request header. Only
// the cross-checked path matters here; wallet-identifying members are
// placeholders.
function payload(authorizationValue: unknown): unknown {
  return {
    x402Version: 2,
    payload: {
      authorization: {
        from: "<PAYER_REDACTED>",
        to: "<PAYTO_REDACTED>",
        value: authorizationValue,
        validAfter: "0",
        validBefore: "1785696192",
        nonce: "<NONCE_REDACTED>",
      },
      signature: "<SIG_REDACTED>",
    },
    accepted: { scheme: "exact", network: "eip155:84532", amount: "1000" },
  };
}

describe("amount cross-check — A vs the signed authorization (spec §8.1.1a)", () => {
  it("emits when A and B agree", () => {
    const ref = paymentRefFromArtifacts(
      { ...FULL_ARTIFACTS, payload: payload("1000") },
      VERIFIED_SELECTOR,
    );
    // The cross-check never supplies a value, so the commitment is identical to
    // the one built without B present.
    expect(ref).toBe(paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR));
  });

  it("emits from A when B is absent (only one source available)", () => {
    const subset = buildPaymentRefSubset(FULL_ARTIFACTS, VERIFIED_SELECTOR);
    expect(subset.amount).toBe("1000");
  });

  it("emits from A when B is present but carries no authorization value", () => {
    const subset = buildPaymentRefSubset(
      { ...FULL_ARTIFACTS, payload: payload(undefined) },
      VERIFIED_SELECTOR,
    );
    expect(subset.amount).toBe("1000");
  });

  it("REFUSES when A and B disagree — ambiguous payment evidence", () => {
    expect(() =>
      paymentRefFromArtifacts(
        { ...FULL_ARTIFACTS, payload: payload("9999") },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "amount_disagreement" }));
  });

  it("treats a type mismatch between the two sources as a disagreement", () => {
    // A JSON number 1000 is not the observed decimal string "1000"; the sources
    // are not saying the same thing, and normalizing would hide that.
    expect(() =>
      paymentRefFromArtifacts(
        { ...FULL_ARTIFACTS, payload: payload(1000) },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "amount_disagreement" }));
  });

  it("refuses on disagreement through the JSON-string ingest path too", () => {
    expect(() =>
      paymentRefFromJsonStrings(
        {
          requirements: JSON.stringify(requirements()),
          payload: JSON.stringify(payload("9999")),
          settle: JSON.stringify(settle()),
        },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "amount_disagreement" }));
  });
});

describe("strict JSON ingest on payment-ref artifacts (D7 / spec §2.1)", () => {
  const requirementsJson = JSON.stringify(requirements());
  const settleJson = JSON.stringify(settle());

  it("hashes identically whether ingested as values or as JSON text", () => {
    expect(
      paymentRefFromJsonStrings(
        { requirements: requirementsJson, settle: settleJson },
        VERIFIED_SELECTOR,
      ),
    ).toBe(paymentRefFromArtifacts(FULL_ARTIFACTS, VERIFIED_SELECTOR));
  });

  it("rejects a duplicate member at any depth — never hashes it", () => {
    const dup = requirementsJson.replace(
      '"amount":"1000"',
      '"amount":"1000","amount":"9999"',
    );
    expect(() =>
      paymentRefFromJsonStrings(
        { requirements: dup, settle: settleJson },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(
      expect.objectContaining({ reason: "duplicate_member" }),
    );
  });

  it("rejects an unsafe integer — never hashes it", () => {
    const unsafe = requirementsJson.replace(
      '"maxTimeoutSeconds":300',
      '"maxTimeoutSeconds":9007199254740993',
    );
    try {
      paymentRefFromJsonStrings(
        { requirements: unsafe, settle: settleJson },
        VERIFIED_SELECTOR,
      );
      throw new Error("expected a throw");
    } catch (e) {
      expect(e).toBeInstanceOf(StrictJsonParseError);
      expect((e as StrictJsonParseError).reason).toBe("unsafe_number");
    }
  });

  it("rejects a strict violation in the settle artifact too", () => {
    const dupSettle = settleJson.replace(
      '"success":true',
      '"success":true,"success":false',
    );
    expect(() =>
      paymentRefFromJsonStrings(
        { requirements: requirementsJson, settle: dupSettle },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(expect.objectContaining({ reason: "duplicate_member" }));
  });

  it("has NO raw-UTF-8 fallback: unparseable text throws instead of hashing bytes", () => {
    expect(() =>
      paymentRefFromJsonStrings(
        { requirements: "not json at all", settle: settleJson },
        VERIFIED_SELECTOR,
      ),
    ).toThrowError(SyntaxError);
  });
});

describe("payment-ref format guard", () => {
  it("accepts only sha256: + 64 lowercase hex", () => {
    expect(isPaymentRefFormat("sha256:" + "a".repeat(64))).toBe(true);
    expect(isPaymentRefFormat("sha256:" + "A".repeat(64))).toBe(false);
    expect(isPaymentRefFormat("sha256:" + "a".repeat(63))).toBe(false);
    expect(isPaymentRefFormat("a".repeat(64))).toBe(false);
    expect(isPaymentRefFormat("")).toBe(false);
  });
});
