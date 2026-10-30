// B-432 T4: the purchase check's loopback HTTP endpoint (src/purchase/http.ts)
// and `chirindo purchase-check`. Each status code of T0 ruling 7, the
// required token, the Host header, the 256 KB cap and the fatal UTF-8 decode.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createPurchaseServer, MAX_BODY_BYTES, type PurchaseServer } from "../src/purchase/http.js";
import { cleanupTmpDir } from "./helpers.js";
import { AT, checkDir, clockAt, expectVocabulary, itemOf, openCheck, order, signedText } from "./purchase-helpers.js";
import { httpCall, listeningUrl, startCli, type HttpReply } from "./trial-helpers.js";

const TOKEN = "t".repeat(32);
const dirs: string[] = [];
const servers: PurchaseServer[] = [];
const closers: (() => Promise<void>)[] = [];
afterAll(async () => {
  for (const s of servers) await s.close();
  for (const c of closers) await c();
  dirs.forEach(cleanupTmpDir);
});

async function serve(now: () => string = () => AT) {
  const dir = checkDir();
  dirs.push(dir);
  const pc = openCheck(dir, { now });
  closers.push(() => pc.close());
  const server = createPurchaseServer({ check: pc, host: "127.0.0.1", port: 0, token: TOKEN });
  servers.push(server);
  const { url } = await server.listen();
  const host = new URL(url).host;
  const headers = { "content-type": "application/json", host, authorization: `Bearer ${TOKEN}` };
  const post = (body: string | Buffer, over: Record<string, string> = {}, path = "/v1/check", method = "POST") =>
    httpCall(url, { method, path, headers: { ...headers, ...over }, body });
  return { url, host, post, pc };
}
const bodyOf = (r: HttpReply) => JSON.parse(r.body) as Record<string, unknown>;
const json = (instruction: unknown, ord: unknown) => JSON.stringify({ instruction, order: ord });

describe("POST /v1/check: decided answers are 200", () => {
  it("allow, a deny with a receipt, and a repeat", async () => {
    const { post } = await serve();
    const ins = signedText();
    const allow = await post(json(ins, order()));
    expect(allow.status).toBe(200);
    expect(bodyOf(allow)).toMatchObject({ decision: "allow", reasons: [], repeat: false, receipt: { seq: 0 } });
    const deny = await post(json(ins, order((o) => ((o["merchant_order_id"] = "H-2"), (o["total_minor"] = "30001")))));
    expect(deny.status).toBe(200);
    // max_uses 1 is spent by the allow, so uses-exhausted comes first (design §4.2 order).
    expect(bodyOf(deny)).toMatchObject({ decision: "deny", reasons: ["uses-exhausted", "limit-exceeded:max_total_minor"], receipt: { seq: 1 } });
    const repeat = await post(json(ins, order()));
    expect(repeat.status).toBe(200);
    expect(bodyOf(repeat)).toMatchObject({ decision: "allow", repeat: true, receipt: { seq: 0 } });
    expect(allow.headers["access-control-allow-origin"]).toBeUndefined();
    expect(allow.headers["cache-control"]).toBe("no-store");
  });
});

describe("POST /v1/check: refusals", () => {
  it("422 for a step-1 refusal, with the result and no receipt", async () => {
    const { post } = await serve();
    for (const body of [json("{", order()), json(signedText(), order((o) => (itemOf(o)["quantity"] = 0))), "[]", '"x"', "{}"]) {
      const r = await post(body);
      expect([body.slice(0, 20), r.status]).toEqual([body.slice(0, 20), 422]);
      const b = bodyOf(r);
      expect(b).toMatchObject({ decision: "deny", receipt: null });
      expectVocabulary(b["reasons"] as string[]);
    }
  });

  it("503 for record-failed (a gate clock that fails)", async () => {
    const { post } = await serve(() => "not a time");
    const r = await post(json(signedText(), order()));
    expect(r.status).toBe(503);
    expect(bodyOf(r)).toMatchObject({ decision: "deny", reasons: ["record-failed"], receipt: null });
  });

  it("400 for invalid UTF-8 and for a body that is not strict JSON; no decision is made", async () => {
    const { post } = await serve();
    const bad = Buffer.concat([Buffer.from('{"instruction":"'), Buffer.from([0xff]), Buffer.from('","order":{}}')]);
    const r1 = await post(bad);
    expect([r1.status, bodyOf(r1)]).toEqual([400, { error: "invalid-utf8" }]);
    for (const body of ["{", '{"instruction":"a","instruction":"b"}', '{"order":{"q":1.5}}', '{"a":"\\ud800"}', "﻿{}"]) {
      const r = await post(body);
      expect([body, r.status, bodyOf(r)]).toEqual([body, 400, { error: "invalid-json" }]);
    }
  });

  it("401 without the token, with a wrong one, or with another scheme; the scheme's case does not matter", async () => {
    const { post } = await serve();
    const ok = json(signedText(), order());
    for (const auth of [undefined, `Bearer ${"u".repeat(32)}`, `Basic ${TOKEN}`, `Bearer ${TOKEN.toUpperCase()}`, TOKEN]) {
      const r = await post(ok, auth === undefined ? { authorization: "" } : { authorization: auth });
      expect([auth, r.status, bodyOf(r)]).toEqual([auth, 401, { error: "unauthorized" }]);
      expect(r.headers["www-authenticate"]).toBe("Bearer");
    }
    expect((await post(ok, { authorization: `bearer ${TOKEN}` })).status).toBe(200);
  });

  it("403 when the Host header does not name the bound address and port", async () => {
    const { post, host } = await serve();
    const port = host.split(":")[1]!;
    for (const h of [`localhost:${port}`, "127.0.0.1", `127.0.0.1:${Number(port) + 1}`, "evil.example"]) {
      const r = await post(json(signedText(), order()), { host: h });
      expect([h, r.status, bodyOf(r)]).toEqual([h, 403, { error: "host-not-allowed" }]);
    }
  });

  it("413 over 256 KB, at the cap not", async () => {
    const { post } = await serve();
    const at = Buffer.alloc(MAX_BODY_BYTES, 0x20);
    Buffer.from("{}").copy(at, 0);
    expect((await post(at)).status).toBe(422);
    const over = Buffer.alloc(MAX_BODY_BYTES + 1, 0x20);
    Buffer.from("{}").copy(over, 0);
    const r = await post(over);
    expect([r.status, bodyOf(r)]).toEqual([413, { error: "body-too-large" }]);
  });

  it("415 without Content-Type: application/json; 404 elsewhere; 405 for another method", async () => {
    const { post } = await serve();
    const ok = json(signedText(), order());
    expect((await post(ok, { "content-type": "text/plain" })).status).toBe(415);
    expect((await post(ok, { "content-type": "application/json; charset=utf-8" })).status).toBe(200);
    expect((await post(ok, {}, "/v1/other")).status).toBe(404);
    const r = await post("", {}, "/v1/check", "GET");
    expect([r.status, r.headers["allow"]]).toEqual([405, "POST"]);
  });

  it("the server refuses to start without a token", () => {
    const dir = checkDir();
    dirs.push(dir);
    const pc = openCheck(dir, clockAt());
    closers.push(() => pc.close());
    expect(() => createPurchaseServer({ check: pc, host: "127.0.0.1", port: 0, token: "" })).toThrow(/token is required/);
  });
});

describe("chirindo purchase-check", () => {
  it("refuses to start without --token-file (exit 2), or with an empty one", async () => {
    const dir = checkDir();
    dirs.push(dir);
    const c = startCli(["purchase-check", "--dir", dir, "--port", "0"]);
    expect(await c.exited).toBe(2);
    expect(c.stderr()).toMatch(/--token-file <file> is required/);
    const empty = join(dir, "empty-token");
    writeFileSync(empty, "\n");
    const d = startCli(["purchase-check", "--dir", dir, "--port", "0", "--token-file", empty]);
    expect(await d.exited).toBe(2);
    expect(d.stderr()).toMatch(/is empty/);
  }, 60_000);

  it("serves POST /v1/check on 127.0.0.1 with the token, and exits 0 on SIGTERM", async () => {
    const dir = checkDir();
    dirs.push(dir);
    const tokenFile = join(dir, "token");
    writeFileSync(tokenFile, TOKEN + "\n");
    const c = startCli(["purchase-check", "--dir", dir, "--port", "0", "--token-file", tokenFile]);
    const url = await listeningUrl(c);
    expect(url, c.stderr()).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const headers = { "content-type": "application/json", host: new URL(url!).host, authorization: `Bearer ${TOKEN}` };
    // The real clock is 2026-10-30, before the base instruction's window: a decided deny.
    const r = await httpCall(url!, { path: "/v1/check", headers, body: json(signedText(), order()) });
    expect(r.status).toBe(200);
    expect(bodyOf(r)).toMatchObject({ decision: "deny", receipt: { seq: 0 } });
    expect(c.stderr()).toMatch(/token=required/);
    c.child.kill("SIGTERM");
    const code = await c.exited;
    // Windows has no SIGTERM handler delivery for a child: it is killed outright.
    if (process.platform !== "win32") expect(code).toBe(0);
  }, 60_000);
});
