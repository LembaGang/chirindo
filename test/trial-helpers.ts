// Shared helpers for the trial recorder tests (test/trial-*.test.ts).

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { makeTmpDir } from "./helpers.js";
import { runInit, loadFullIdentity, type LoadedFullIdentity } from "../src/vendor/recorder/index.js";
import type { RecordInput, TrialOrder } from "../src/trial/index.js";

export const ROOT = resolve(import.meta.dirname, "..");
const CLI_ENTRY = join(ROOT, "src", "cli.ts");
// tsx registered in-process with --import, not tsx's CLI: the CLI runs the
// program in a second child, which child.kill() would leave running on Windows.
const TSX_LOADER = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

export function newDataDir(prefix = "chirindo-trial-"): { dir: string; identity: LoadedFullIdentity } {
  const dir = makeTmpDir(prefix);
  const r = runInit({ dir });
  if (r.kind !== "created") throw new Error("init returned " + r.kind);
  return { dir, identity: loadFullIdentity(r.identityPath, r.privateKeyPath) };
}

// A loopback URL on which nothing listens.
export async function closedPortUrl(): Promise<string> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return `http://127.0.0.1:${port}`;
}

export function readNdjson(path: string): Record<string, unknown>[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

export function walkFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  if (!statSync(dir).isDirectory()) return [dir];
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walkFiles(p));
    else out.push(p);
  }
  return out;
}

export function sha256Tagged(s: string): string {
  return "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");
}

export function sampleOrder(ref = "T-1001"): TrialOrder {
  return {
    merchant_id: "shop.example",
    merchant_order_id: ref,
    currency: "USD",
    total_minor: "4800",
    items: [{ sku: "JACKET-M", quantity: 1, unit_price_minor: "4800", name: "Jacket, size M", refundable: true }],
  };
}

export function sampleInput(ref = "T-1001", seq?: number): RecordInput {
  return { order_ref: ref, order: sampleOrder(ref), ...(seq !== undefined ? { call_seq: seq } : {}) };
}

export function p95(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)]!;
}

export async function waitFor(cond: () => boolean, maxMs: number, stepMs = 25): Promise<boolean> {
  const t0 = Date.now();
  while (Date.now() - t0 < maxMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return cond();
}

// The CLI as one long-running child process.
export interface CliChild {
  child: ChildProcessWithoutNullStreams;
  stdout: () => string;
  stderr: () => string;
  exited: Promise<number | null>;
}

export function startCli(args: string[]): CliChild {
  const child = spawn(process.execPath, ["--import", TSX_LOADER, CLI_ENTRY, ...args], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: ROOT,
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (c: Buffer) => (out += c.toString("utf8")));
  child.stderr.on("data", (c: Buffer) => (err += c.toString("utf8")));
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
  return { child, stdout: () => out, stderr: () => err, exited };
}

// The `{"listening": url}` line, or null if none appeared within maxMs or the
// child exited first.
export async function listeningUrl(c: CliChild, maxMs = 20_000): Promise<string | null> {
  let gone = false;
  void c.exited.then(() => (gone = true));
  await waitFor(() => gone || /\{"listening":"[^"]+"\}/.test(c.stdout()), maxMs, 50);
  const m = /\{"listening":"([^"]+)"\}/.exec(c.stdout());
  return m === null ? null : m[1]!;
}

export interface HttpReply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

// node:http, not fetch, so that the Host header can be set.
export function httpCall(
  url: string,
  opts: { method?: string; path: string; headers?: Record<string, string>; body?: string | Buffer },
): Promise<HttpReply> {
  const u = new URL(url);
  return new Promise((done, fail) => {
    const req = request(
      { host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port), method: opts.method ?? "POST", path: opts.path, headers: opts.headers ?? {} },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => done({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", fail);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}
