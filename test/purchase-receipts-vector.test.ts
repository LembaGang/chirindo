// B-432 test 3, the byte vector: a receipt written without `check` equals,
// byte for byte, two receipts written by appendReceipt at commit 84b52d7
// (test/fixtures/purchase-check-84b52d7.ts).
//
// That vector was written at package version 0.5.3, and agent.version sits
// inside the signed bytes. So that the vector keeps pinning exactly the bytes
// it pinned through any version bump, this file, and only this file, mocks
// src/version.ts to the version the vector was written with (B-428 ruling).
// No production surface can set the version. The test asserts the mock took
// effect, so it cannot silently pass against the real version.

import { createHash, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { PURCHASE_CHECK_VERSION, type PurchaseCheckMember } from "../src/purchase/member.js";
import { jcsSha256 } from "../src/purchase/m6.js";
import { GATE_AGENT, appendReceipt } from "../src/receipt.js";
import { IDENTITY_FILENAME, PRIVATE_KEY_FILENAME, loadFullIdentity, runVerify, writeIdentity } from "../src/vendor/recorder/index.js";
import { CHAIN_84B52D7, CHAIN_SHA256_84B52D7, KID_84B52D7, VERSION_84B52D7 } from "./fixtures/purchase-check-84b52d7.js";
import { cleanupTmpDir } from "./helpers.js";
import { GATE } from "./purchase-helpers.js";

vi.mock("../src/version.js", async () => ({ GATE_VERSION: (await import("./fixtures/purchase-check-84b52d7.js")).VERSION_84B52D7 }));

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));
const sha256 = (b: Buffer | string) => "sha256:" + createHash("sha256").update(b).digest("hex");

describe("test 3: the 84b52d7 byte vector", () => {
  it("a receipt written without check equals the 84b52d7 vector byte for byte", () => {
    // The mock is in effect: receipts here carry the vector's version.
    expect(GATE_AGENT.version).toBe(VERSION_84B52D7);
    const dir = mkdtempSync(join(tmpdir(), "purchase-vec-"));
    dirs.push(dir);
    writeIdentity(dir, GATE.priv, createPublicKey(GATE.priv));
    const identity = loadFullIdentity(join(dir, IDENTITY_FILENAME), join(dir, PRIVATE_KEY_FILENAME));
    expect(identity.kid).toBe(KID_84B52D7);
    const ord = { merchant_id: "hotel.example", merchant_order_id: "H-1", currency: "EUR", total_minor: "28000", items: [{ sku: "ROOM", quantity: 2, unit_price_minor: "14000" }] };
    const write = (chainPath: string, withCheck: boolean) => {
      const base = { chainPath, sessionId: "b432-byte-vector", identity, server: "purchase-check", toolName: "check", jwksUri: "https://gate.example/.well-known/jwks.json" };
      const member = (reasons: string[]): PurchaseCheckMember => ({ v: PURCHASE_CHECK_VERSION, instruction_sha256: "sha256:" + "a".repeat(64), order_sha256: jcsSha256(ord), merchant_id: "hotel.example", merchant_order_id: "H-1", checkout_ref: null, at: "2026-11-05T12:00:00.000Z", reasons, exceeded: [] });
      appendReceipt({ ...base, toolArgs: { order: ord, instruction_sha256: "sha256:" + "a".repeat(64) }, decision: { kind: "allow" }, ts: "2026-11-05T12:00:00.000Z", ...(withCheck ? { check: member([]) } : {}) });
      appendReceipt({ ...base, toolArgs: { order: ord, denied_instruction_sha256: "sha256:" + "b".repeat(64) }, decision: { kind: "deny", reason: "x" }, ts: "2026-11-05T12:00:01.000Z", ...(withCheck ? { check: { ...member(["expired"]), at: "2026-11-05T12:00:01.000Z" } } : {}) });
      return readFileSync(chainPath, "utf8");
    };
    const plain = write(join(dir, "plain.jsonl"), false);
    expect(sha256(CHAIN_84B52D7)).toBe("sha256:" + CHAIN_SHA256_84B52D7);
    expect(plain).toBe(CHAIN_84B52D7);
    // The control: the same receipts with check differ, and still verify.
    const withCheck = write(join(dir, "with-check.jsonl"), true);
    expect(withCheck).not.toBe(CHAIN_84B52D7);
    expect(runVerify({ chainPath: join(dir, "with-check.jsonl"), identityPath: join(dir, IDENTITY_FILENAME) })).toMatchObject({ kind: "valid", count: 2 });
  });
});
