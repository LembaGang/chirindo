// The purchase check's loopback HTTP endpoint (`chirindo purchase-check`):
// POST /v1/check. The trial recorder's patterns (src/trial/http.ts), copied
// rather than shared, so that file is unchanged:
//
//   - bound to 127.0.0.1 or ::1 only, and the Host header must name that
//     address and port, so a web page cannot reach it through DNS rebinding;
//   - a Bearer token, REQUIRED here, compared in constant time;
//   - Content-Type: application/json, the body capped at 256 KB while it
//     streams, read with a fatal UTF-8 decode and parsed strictly (a
//     duplicate member, a fraction, an exponent or a lone surrogate is refused);
//   - no CORS header is ever sent, and no error body echoes the request.
//
// Status codes (T0 ruling 7): 200 for a decided answer (allow, a deny with
// a receipt, or a repeat); 422 for a step-1 refusal (receipt null); 503 for
// record-failed; each with the CheckResult. Request errors carry
// { "error": <code> }: 400 invalid-utf8 or invalid-json, 401 unauthorized,
// 403 host-not-allowed, 404 not-found, 405 method-not-allowed, 413
// body-too-large, 415 content-type-not-json.

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { CheckResult, PurchaseCheck } from "./check.js";
import { parseStrictJsonBytes } from "./m6.js";

export const MAX_BODY_BYTES = 262_144;

export interface PurchaseServerOptions {
  check: PurchaseCheck;
  host: "127.0.0.1" | "::1";
  port: number;
  // Required: every POST must carry Authorization: Bearer <token>.
  token: string;
}

export interface PurchaseServer {
  listen(): Promise<{ port: number; url: string }>;
  close(): Promise<void>;
}

// The status of a check's answer.
export function statusOf(r: CheckResult): 200 | 422 | 503 {
  if (r.reasons.includes("record-failed")) return 503;
  if (r.receipt === null) return 422;
  return 200;
}

const digest = (s: string) => createHash("sha256").update(s, "utf8").digest();

export function createPurchaseServer(o: PurchaseServerOptions): PurchaseServer {
  if (typeof o.token !== "string" || o.token === "") throw new Error("createPurchaseServer: token is required");
  if (o.host !== "127.0.0.1" && o.host !== "::1") throw new Error("createPurchaseServer: host must be 127.0.0.1 or ::1");
  let port = o.port;
  const expectedHost = () => (o.host === "::1" ? `[::1]:${port}` : `127.0.0.1:${port}`);
  const tokenDigest = digest(o.token);

  const send = (res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    const text = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(text)),
      "cache-control": "no-store",
      ...extra,
    });
    res.end(text);
  };
  // An early refusal: the rest of the body is not read, so the connection closes.
  const refuse = (res: ServerResponse, status: number, code: string, extra: Record<string, string> = {}) =>
    send(res, status, { error: code }, { connection: "close", ...extra });

  const authorized = (req: IncomingMessage): boolean => {
    const h = req.headers["authorization"];
    // The scheme is case-insensitive (RFC 9110 section 11.1); the token is not.
    if (typeof h !== "string" || !/^bearer /i.test(h)) return false;
    return timingSafeEqual(digest(h.slice("Bearer ".length)), tokenDigest);
  };

  const readBody = (req: IncomingMessage): Promise<Buffer | null> =>
    new Promise((done) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let over = false;
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) over = true;
        // Past the cap the rest is read and dropped, so the 413 reaches the caller.
        if (!over) chunks.push(c);
      });
      req.on("end", () => done(over ? null : Buffer.concat(chunks)));
      req.on("error", () => done(null));
    });

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    if (req.headers.host !== expectedHost()) return refuse(res, 403, "host-not-allowed");
    const path = (req.url ?? "/").split("?")[0];
    if (path !== "/v1/check") return refuse(res, 404, "not-found");
    if (req.method !== "POST") return refuse(res, 405, "method-not-allowed", { allow: "POST" });
    if (!authorized(req)) return refuse(res, 401, "unauthorized", { "www-authenticate": "Bearer" });
    const type = String(req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") return refuse(res, 415, "content-type-not-json");
    const raw = await readBody(req);
    if (raw === null) {
      res.on("finish", () => req.destroy());
      return send(res, 413, { error: "body-too-large" }, { connection: "close" });
    }
    const parsed = parseStrictJsonBytes(raw);
    if (!parsed.ok) return send(res, 400, { error: parsed.problem === "not-utf8" ? "invalid-utf8" : "invalid-json" });
    // Any body that parses goes to check(), which refuses a wrong shape at step 1.
    const r = o.check.check(parsed.value as never);
    return send(res, statusOf(r), r);
  };

  const server: Server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal" });
      else res.destroy();
    });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.timeout = 5_000;
  server.maxConnections = 32;

  return {
    listen: () =>
      new Promise((done, failListen) => {
        server.once("error", failListen);
        server.listen(o.port, o.host, () => {
          server.off("error", failListen);
          port = (server.address() as AddressInfo).port;
          done({ port, url: o.host === "::1" ? `http://[::1]:${port}` : `http://127.0.0.1:${port}` });
        });
      }),
    close: () =>
      new Promise((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}
