// B-432 test 9, end to end (design rev 3 §8.9): a Crossmint-shaped order
// intent, USD 150.00 with max_uses 2, mapped, signed by the provider as
// principal, and checked over POST /v1/check.
//   - An order of 120.00 at the named merchant is allowed.
//   - One of 180.00 is denied limit-exceeded:max_total_minor.
//   - bIns (the HOLD-4 call, with orderProblem asserted) gives BOUND for the
//     120.00 order.
//   - The 180.00 receipt's check.reasons holds the reason, read from the chain.
// evm.mjs needs viem (not installed in CI); a lowercase-only `address` stands in.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  createPurchaseServer,
  mapCrossmintOrderIntent,
  merchantIdOf,
  signInstruction,
  type PurchaseServer,
} from "../src/purchase/index.js";
import { argsHash } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { GATE, PRINCIPAL, argsFiles, chainPathOf, checkDir, checkOf, expectVocabulary, openCheck, recordsOf, type Obj } from "./purchase-helpers.js";
import { httpCall } from "./trial-helpers.js";
// @ts-expect-error -- plain .mjs without declarations; the reference verifier
import { ANNEX_A3, bIns, m6Instruction } from "../examples/evidence-bundle/lib/instructions.mjs";
// @ts-expect-error -- as above
import { orderProblem } from "../examples/evidence-bundle/lib/card.mjs";
// @ts-expect-error -- as above
import { parseChirindoLog } from "../examples/evidence-bundle/lib/records.mjs";

vi.mock("../examples/ordering-evidence-h4/lib/evm.mjs", () => ({
  address: (s: unknown, what: string) => {
    if (typeof s !== "string" || !/^0x[0-9a-f]{40}$/.test(s)) throw new Error(`${what} is not a lowercase 20-byte hex address`);
    return s;
  },
}));

const TOKEN = "e2e-token-" + "x".repeat(22);
const dirs: string[] = [];
let server: PurchaseServer | null = null;
let close: (() => Promise<void>) | null = null;
afterAll(async () => {
  await server?.close();
  await close?.();
  dirs.forEach(cleanupTmpDir);
});

describe("test 9: end to end", () => {
  it("a Crossmint-shaped intent, USD 150.00, max_uses 2: 120.00 allowed, 180.00 denied, bIns BOUND, the reason on the chain", async () => {
    // The provider's side: map its order intent and sign the instruction.
    const intent = {
      amount: { value: "150.00", currency: "USD" },
      merchant: { name: "Acme Store", url: "https://acme.example.com/store", countryCode: "US" },
      description: "Groceries this week, up to USD 150.00",
      expiresAt: "2026-11-30T00:00:00Z",
    };
    const body = mapCrossmintOrderIntent(intent, { principalKey: PRINCIPAL.priv, agentKids: [GATE.kid], maxUses: 2, approvedAt: "2026-11-01T00:00:00Z" });
    const instruction = JSON.stringify(signInstruction(body, PRINCIPAL.priv));

    // The gate, over HTTP.
    const dir = checkDir();
    dirs.push(dir);
    const pc = openCheck(dir, { now: () => "2026-11-05T12:00:00.000Z" });
    close = () => pc.close();
    server = createPurchaseServer({ check: pc, host: "127.0.0.1", port: 0, token: TOKEN });
    const { url } = await server.listen();
    const headers = { "content-type": "application/json", host: new URL(url).host, authorization: `Bearer ${TOKEN}` };
    const merchant = merchantIdOf("https://acme.example.com/checkout");
    const orderOf = (id: string, total: string) => ({
      merchant_id: merchant,
      merchant_order_id: id,
      currency: "USD",
      total_minor: total,
      items: [{ sku: "GROC", quantity: 1, unit_price_minor: total, name: "Groceries" }],
    });
    const post = async (order: Obj) => {
      const r = await httpCall(url, { path: "/v1/check", headers, body: JSON.stringify({ instruction, order }) });
      const b = JSON.parse(r.body) as { decision: string; reasons: string[]; receipt: { seq: number; entry_hash: string } | null };
      expectVocabulary(b.reasons);
      return { status: r.status, ...b };
    };

    const ok = await post(orderOf("A-120", "12000"));
    expect(ok).toMatchObject({ status: 200, decision: "allow", reasons: [], receipt: { seq: 0 } });
    const over = await post(orderOf("A-180", "18000"));
    expect(over).toMatchObject({ status: 200, decision: "deny", reasons: ["limit-exceeded:max_total_minor"], receipt: { seq: 1 } });
    await pc.close();

    // The 180.00 receipt's reason, read from the chain.
    const records = recordsOf(dir, pc.session_id);
    expect(records).toHaveLength(2);
    expect(checkOf(records[1]!)).toMatchObject({ reasons: ["limit-exceeded:max_total_minor"], exceeded: ["max_total_minor"], merchant_order_id: "A-180" });
    expect(records[1]!.event).toMatchObject({ decision: "deny" });

    // bIns, with the HOLD-4 inputs, for the 120.00 order.
    const m6 = m6Instruction(Buffer.from(instruction, "utf8"), ANNEX_A3);
    expect(m6.problem).toBeUndefined();
    const ins = [{ member: "instruction", profile: ANNEX_A3, digest: m6.digest, value: m6.value, m6: "PASS" }];
    const log = parseChirindoLog(readFileSync(chainPathOf(dir, pc.session_id)));
    const logs = [{ member: "gate-log", profile: "chirindo-evidence.action/1", records: log.records }];
    const argMembers = [...argsFiles(dir).entries()].map(([name, bytes]) => {
      const value = JSON.parse(bytes.toString("utf8"));
      expect("sha256:" + createHash("sha256").update(bytes).digest("hex")).toBe(argsHash(value));
      return { member: name, digest: argsHash(value), value };
    });
    const rec = log.records[0];
    const A = argMembers.find((a) => a.digest === rec.event.args_hash);
    expect(A).toBeDefined();
    expect(orderProblem(A!.value.order)).toBeNull();
    const r = bIns({ ins, A, pv: null, bpayState: "NOT-EVALUATED", logs, argMembers, card: { order: A!.value.order, orderOk: true, kid: rec.kid, authorizedAt: rec.check.at } });
    expect(r.agg.state).toBe("BOUND");
    expect(r.rows[0]).toMatchObject({ cited: true, state: "BOUND", exceeded: [], uses: 1 });
  });
});
