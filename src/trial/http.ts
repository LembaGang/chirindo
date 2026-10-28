// The trial recorder's loopback HTTP endpoint (`chirindo trial-recorder`):
// POST /record, POST /await, POST /gap, GET /health.
//
// Bound to 127.0.0.1 or ::1 only, and the Host header must name that address
// and port, so a web page cannot reach it through DNS rebinding. Each POST
// needs Content-Type: application/json and, with a token, a matching Bearer
// token (compared in constant time). Bodies are capped at 256 KB while they
// stream and parsed strictly (a duplicate member or an unsafe integer is
// refused). No CORS header is ever sent, and no error body echoes the request.
//
// Status codes: 200 only when the result's `ok` is true. A refusal of the
// caller's input is 422, an awaitWitness timeout 504, and a failure on the
// recorder's side (write-failed, internal, no-witness, stopped, closed) 503;
// each carries the result object. Request errors carry { "error": <code> }.

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { strictJsonParse } from "../vendor/recorder/index.js";
import { MAX_INPUT_BYTES } from "./rules.js";
import type { AwaitResult, GapResult, RecordResult, TrialRecorder } from "./types.js";

export interface TrialServerOptions {
  recorder: TrialRecorder;
  host: "127.0.0.1" | "::1";
  port: number;
  token?: string;
}

export interface TrialServer {
  listen(): Promise<{ port: number; url: string }>;
  close(): Promise<void>;
}

const CALLER_REASONS = new Set(["invalid-input", "refused-field", "refused-value", "invalid-order", "unknown-entry"]);

function statusOf(r: RecordResult | GapResult | AwaitResult): number {
  if (r.ok) return 200;
  if (CALLER_REASONS.has(r.reason)) return 422;
  if (r.reason === "timeout") return 504;
  return 503;
}

const digest = (s: string) => createHash("sha256").update(s, "utf8").digest();

export function createTrialServer(o: TrialServerOptions): TrialServer {
  let port = o.port;
  const expectedHost = () => (o.host === "::1" ? `[::1]:${port}` : `127.0.0.1:${port}`);
  const tokenDigest = o.token !== undefined ? digest(o.token) : undefined;

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
    if (tokenDigest === undefined) return true;
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
        if (size > MAX_INPUT_BYTES) over = true;
        // Past the cap the rest is read and dropped, so the 413 reaches the caller.
        if (!over) chunks.push(c);
      });
      req.on("end", () => done(over ? null : Buffer.concat(chunks)));
      req.on("error", () => done(null));
    });

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    if (req.headers.host !== expectedHost()) return refuse(res, 403, "host-not-allowed");
    const path = (req.url ?? "/").split("?")[0];
    if (path === "/health") {
      if (req.method !== "GET") return refuse(res, 405, "method-not-allowed", { allow: "GET" });
      return send(res, 200, { ok: true, session_id: o.recorder.session_id });
    }
    if (path !== "/record" && path !== "/await" && path !== "/gap") return refuse(res, 404, "not-found");
    if (req.method !== "POST") return refuse(res, 405, "method-not-allowed", { allow: "POST" });
    if (!authorized(req)) return refuse(res, 401, "unauthorized", { "www-authenticate": "Bearer" });
    const type = String(req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") return refuse(res, 415, "content-type-not-json");
    const raw = await readBody(req);
    if (raw === null) {
      res.on("finish", () => req.destroy());
      return send(res, 413, { error: "body-too-large" }, { connection: "close" });
    }
    let body: unknown;
    try {
      body = strictJsonParse(raw.toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid-json" });
    }
    if (path === "/record") {
      const r = o.recorder.record(body as never);
      return send(res, statusOf(r), r);
    }
    if (path === "/gap") {
      const r = o.recorder.reportGap(body as never);
      return send(res, statusOf(r), r);
    }
    const b = body as Record<string, unknown> | null;
    if (typeof b !== "object" || b === null || typeof b["entry_hash"] !== "string" || typeof b["max_ms"] !== "number") {
      return send(res, 400, { error: "invalid-await-request" });
    }
    const r = await o.recorder.awaitWitness(b["entry_hash"], b["max_ms"]);
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
