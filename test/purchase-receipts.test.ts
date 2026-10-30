// B-432 test 3, receipts (design §5 and §8.3): a deny receipt verifies and
// holds `check`; a step 1 refusal writes nothing. (The 84b52d7 byte vector is
// in purchase-receipts-vector.test.ts.) Also the retained arguments
// (T0 ruling 6): one file per receipt, the arguments value itself as JCS
// bytes, whose SHA-256 is the receipt's args_hash.

import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { PURCHASE_CHECK_VERSION, type PurchaseCheckMember } from "../src/purchase/member.js";
import { jcsSha256 } from "../src/purchase/m6.js";
import { IDENTITY_FILENAME, runVerify } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { argsFiles, chainPathOf, checkDir, checkOf, checked, clockAt, itemOf, openCheck, order, recordsOf, signedText } from "./purchase-helpers.js";

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));
const fresh = () => {
  const d = checkDir();
  dirs.push(d);
  return d;
};
const sha256 = (b: Buffer | string) => "sha256:" + createHash("sha256").update(b).digest("hex");

describe("test 3: receipts", () => {
  it("a deny receipt verifies and holds check; an allow receipt too", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt());
    const over = order((o) => (o["total_minor"] = "30001"));
    const d = checked(pc, signedText(), over);
    expect(d).toMatchObject({ decision: "deny", reasons: ["limit-exceeded:max_total_minor"], exceeded: ["max_total_minor"], repeat: false });
    expect(d.receipt).toMatchObject({ seq: 0 });
    const a = checked(pc, signedText(), order((o) => (o["merchant_order_id"] = "H-2")));
    expect(a).toMatchObject({ decision: "allow", reasons: [], receipt: { seq: 1 } });
    await pc.close();

    const chain = chainPathOf(dir, pc.session_id);
    expect(runVerify({ chainPath: chain, identityPath: join(dir, IDENTITY_FILENAME) })).toMatchObject({ kind: "valid", count: 2 });
    const [r0, r1] = recordsOf(dir, pc.session_id);
    const want: PurchaseCheckMember = {
      v: PURCHASE_CHECK_VERSION,
      instruction_sha256: d.instruction_sha256!,
      order_sha256: jcsSha256(over),
      merchant_id: "hotel.example",
      merchant_order_id: "H-1",
      checkout_ref: null,
      at: "2026-11-05T12:00:00.000Z",
      reasons: ["limit-exceeded:max_total_minor"],
      exceeded: ["max_total_minor"],
    };
    expect(checkOf(r0!)).toEqual(want);
    expect(r0!.ts).toBe(want.at);
    expect(r0!.event).toMatchObject({ server: "purchase-check", tool_name: "check", decision: "deny", outcome: "denied" });
    expect(r1!.event).toMatchObject({ decision: "allow", outcome: "executed" });
    expect(checkOf(r1!)).toMatchObject({ reasons: [], merchant_order_id: "H-2" });
    // On an allow and on a step-3 deny, the digest is the instruction's M6 digest.
    expect(checkOf(r1!)["instruction_sha256"]).toBe(d.instruction_sha256);
    expect(d.receipt!.entry_hash).toMatch(/^sha256:[0-9a-f]{64}$/);

    // The retained arguments: one file per receipt, named <session>/<seq>-<32 hex>.json.
    const files = argsFiles(dir);
    expect([...files.keys()].sort()).toEqual([
      `${pc.session_id}/0-${(r0!.event as { args_hash: string }).args_hash.slice(7, 39)}.json`,
      `${pc.session_id}/1-${(r1!.event as { args_hash: string }).args_hash.slice(7, 39)}.json`,
    ].sort());
    for (const [name, bytes] of files) {
      const r = name.includes("/0-") ? r0! : r1!;
      expect(sha256(bytes)).toBe((r.event as { args_hash: string }).args_hash);
      const v = JSON.parse(bytes.toString("utf8"));
      expect(Object.keys(v).sort()).toEqual(r === r0 ? ["denied_instruction_sha256", "order"] : ["instruction_sha256", "order"]);
    }
    // Nothing of the trial recorder's.
    expect(existsSync(join(dir, "chains"))).toBe(false);
    expect(existsSync(join(dir, "args"))).toBe(false);
  });

  it("a step 2 deny holds the JCS digest of the parsed instruction and denied_instruction_sha256", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt());
    const t = JSON.parse(signedText());
    t.text = "tampered";
    const text = JSON.stringify(t);
    const r = checked(pc, text, order());
    expect(r).toMatchObject({ decision: "deny", reasons: ["instruction-invalid:bad-signature"], receipt: { seq: 0 } });
    expect(r.instruction_sha256).toBe(jcsSha256(JSON.parse(text)));
    await pc.close();
    const [rec] = recordsOf(dir, pc.session_id);
    expect(checkOf(rec!)["instruction_sha256"]).toBe(r.instruction_sha256);
    const [bytes] = [...argsFiles(dir).values()];
    expect(JSON.parse(bytes!.toString("utf8")).denied_instruction_sha256).toBe(r.instruction_sha256);
  });

  // The 84b52d7 byte vector is in test/purchase-receipts-vector.test.ts, which
  // pins src/version.ts to the version that vector was written at (B-428).

  it("a step 1 refusal writes nothing", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt());
    for (const [ins, ord] of [
      ["{", order()],
      [signedText(), order((o) => (itemOf(o)["quantity"] = 0))],
      [signedText(), order((o) => (itemOf(o)["name"] = "card 4111 1111 1111 1111"))],
      [{ parsed: true }, order()],
    ] as [unknown, unknown][]) {
      const r = checked(pc, ins, ord);
      expect(r.decision).toBe("deny");
      expect(r.receipt).toBeNull();
      expect(r.instruction_sha256).toBeNull();
      expect(r.at).toBe("2026-11-05T12:00:00.000Z");
    }
    await pc.close();
    expect(readdirSync(join(dir, "purchase-chains"))).toEqual([]);
    expect(argsFiles(dir).size).toBe(0);
  });
});
