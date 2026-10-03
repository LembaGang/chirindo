// Witness client — the client side of WITNESS_SPEC v0.3 (sections 2 to 5).
//
// A witness is an independent party that records signed checkpoints and signs
// a receipt saying when it saw each one. The chain alone cannot detect a cut-off
// tail (the verifier has no expected length) or a rewrite by the key holder
// (they can re-sign); comparing the chain with witnessed checkpoints can, for
// history up to the last witnessed checkpoint. This module builds nothing
// cryptographic of its own: JCS, hashing and signing come from the vendored
// recorder; the witness receipt signature is plain Ed25519 over the JCS bytes of
// the receipt minus `signature` (for a flat all-string object JCS equals the
// worker's sorted-keys JSON.stringify, spec section 4).

import {
  createPublicKey,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
  base64UrlDecode,
  base64UrlNoPad,
  contentOf,
  entryHashOfCanonical,
  jcsBytes,
  publicKeyBase64Url,
  readChainFile,
  strictJsonParse,
  type SignedCheckpoint,
} from "./vendor/recorder/index.js";

export const WITNESS_RECEIPT_TYPE = "witness.checkpoint/1";
export const DEFAULT_WITNESS_NAME = "headlessoracle.com";
// Spec section 5 step 4: the key id assumed for a pinned key that names none.
export const DEFAULT_WITNESS_KEY_ID = "key_2026_v1";
export const WITNESS_POST_TIMEOUT_MS = 10_000;
const WITNESS_GET_TIMEOUT_MS = 10_000;
// A witness that keeps returning next_after forever must not hang a verifier.
const MAX_GET_PAGES = 10_000;

// The sidecar is NOT `.jsonl`: examples/observe-only-agent/verify-latest.mjs
// takes the last sorted `*.jsonl` in the sessions dir as the chain.
export function sidecarPathFor(chainPath: string): string {
  return chainPath + ".witness.ndjson";
}

export type WitnessReceipt = Record<string, string>;

export interface SidecarLine {
  checkpoint: SignedCheckpoint;
  witness_receipt: WitnessReceipt | null;
  witness_error: string | null;
}

// A witness signing key as the verifier holds it.
export interface WitnessPub {
  pubObj: KeyObject;
  hex: string; // lowercase hex of the raw 32-byte key
  id: string; // the key id receipts must name in public_key_id
}

// Where and how to witness a checkpoint (checkpoint command and proxy).
export interface WitnessTarget {
  baseUrl: string;
  name: string; // expected `witness` member of every receipt
  pinned?: WitnessPub; // absent => fetch from <base>/v5/keys per receipt
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function witnessPubFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`Ed25519 key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

// `--witness-key <hex|jwk-file>`: 64 hex chars is the raw key; anything else is
// a path to a JWK file ({kty:"OKP", crv:"Ed25519", x, kid?}). Throws on any
// malformed input — a pin that cannot be read must never degrade to "no pin".
export function parseWitnessKeyArg(arg: string): { raw: Buffer; jwkKid?: string } {
  if (/^[0-9a-fA-F]{64}$/.test(arg)) {
    return { raw: Buffer.from(arg, "hex") };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(arg, "utf8"));
  } catch (e) {
    throw new Error(
      `--witness-key is neither 64 hex chars nor a readable JWK file (${(e as Error).message})`,
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("--witness-key JWK file is not a JSON object");
  }
  const jwk = parsed as Record<string, unknown>;
  const x = jwk["x"];
  if (
    jwk["kty"] !== "OKP" ||
    jwk["crv"] !== "Ed25519" ||
    typeof x !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(x)
  ) {
    throw new Error('--witness-key JWK must be {"kty":"OKP","crv":"Ed25519","x":<43 base64url chars>}');
  }
  const raw = base64UrlDecode(x);
  if (raw.length !== 32 || base64UrlNoPad(raw) !== x) {
    throw new Error("--witness-key JWK x is not a canonical 32-byte base64url value");
  }
  const kid = jwk["kid"];
  return typeof kid === "string" ? { raw, jwkKid: kid } : { raw };
}

// http is allowed only for loopback hosts (spec section 5 step 3); everything
// else must be https. Returns the base with trailing slashes removed.
export function checkWitnessBaseUrl(base: string): string {
  let u: URL;
  try {
    u = new URL(base);
  } catch {
    throw new Error(`witness URL is not a valid URL: ${base}`);
  }
  const loopback =
    u.hostname === "localhost" ||
    u.hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error(`witness URL must be https:// (http only for loopback): ${base}`);
  }
  return base.replace(/\/+$/, "");
}

function errMessage(e: unknown): string {
  const err = e as { name?: string; message?: string; cause?: { message?: string } };
  if (err?.name === "TimeoutError" || err?.name === "AbortError") return "timeout";
  return err?.cause?.message ?? err?.message ?? String(e);
}

// Ed25519 over the JCS bytes of the receipt without `signature`; the signature
// is lowercase hex, 128 chars (spec section 4).
export function verifyWitnessSignature(receipt: Record<string, unknown>, pubObj: KeyObject): boolean {
  const sig = receipt["signature"];
  if (typeof sig !== "string" || !/^[0-9a-f]{128}$/.test(sig)) return false;
  const { signature: _sig, ...unsigned } = receipt;
  try {
    return cryptoVerify(null, jcsBytes(unsigned), pubObj, Buffer.from(sig, "hex"));
  } catch {
    return false;
  }
}

// GET <base>/v5/keys and return the raw key whose key_id equals `keyId`.
export async function fetchWitnessKey(
  baseUrl: string,
  keyId: string,
): Promise<{ ok: true; raw: Buffer; url: string } | { ok: false; reason: string }> {
  const url = `${baseUrl}/v5/keys`;
  let body: unknown;
  try {
    const res = await fetch(url, {
      redirect: "error",
      signal: AbortSignal.timeout(WITNESS_GET_TIMEOUT_MS),
    });
    if (res.status !== 200) return { ok: false, reason: `GET ${url} returned ${res.status}` };
    body = await res.json();
  } catch (e) {
    return { ok: false, reason: `GET ${url} failed: ${errMessage(e)}` };
  }
  const list =
    typeof body === "object" && body !== null ? (body as Record<string, unknown>)["keys"] : undefined;
  if (!Array.isArray(list)) return { ok: false, reason: `${url} has no keys[] array` };
  const matches = list.filter(
    (k) => typeof k === "object" && k !== null && (k as Record<string, unknown>)["key_id"] === keyId,
  ) as Record<string, unknown>[];
  if (matches.length !== 1) {
    return { ok: false, reason: `${url} has ${matches.length} entries for key_id ${keyId}` };
  }
  const hex = matches[0]!["public_key"];
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    return { ok: false, reason: `${url} key ${keyId} public_key is not 32 bytes of hex` };
  }
  return { ok: true, raw: Buffer.from(hex, "hex"), url };
}

// ---------------------------------------------------------------------------
// Submitting a checkpoint (spec section 2; acceptance per the client handoff)
// ---------------------------------------------------------------------------

export type WitnessOutcome =
  | { receipt: WitnessReceipt; error: null }
  | { receipt: null; error: string };

function allStrings(o: Record<string, unknown>): o is Record<string, string> {
  return Object.values(o).every((v) => typeof v === "string");
}

// POST the checkpoint and accept the reply only if (a) the status is 200/201,
// (b) the signature verifies under the witness key, and (c) it is a
// witness.checkpoint/1 receipt from the expected witness for exactly this
// checkpoint's (kid, session_id, count, last_entry_hash). On a 200 the witness
// returns the FIRST receipt it stored for this head, so checkpoint_ts and
// checkpoint_sha256 may differ from the request; that is accepted. Anything
// else becomes an error code, never a receipt.
export async function witnessCheckpoint(
  cp: SignedCheckpoint,
  gatePub: KeyObject,
  target: WitnessTarget,
  timeoutMs = WITNESS_POST_TIMEOUT_MS,
): Promise<WitnessOutcome> {
  const url = `${target.baseUrl}/v1/witness/checkpoints`;
  const body = JSON.stringify({
    checkpoint: cp,
    public_key_jwk: { kty: "OKP", crv: "Ed25519", x: publicKeyBase64Url(gatePub) },
  });
  let status: number;
  let text: string;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    status = res.status;
    text = await res.text();
  } catch (e) {
    return { receipt: null, error: errMessage(e) === "timeout" ? "witness_timeout" : "witness_unreachable" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  const obj =
    typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  if (status !== 200 && status !== 201) {
    // The server's `error` member is its code (spec section 2). Only a short
    // identifier is copied into the sidecar, so a hostile body cannot inject
    // arbitrary text into evidence files or logs.
    const code = obj?.["error"];
    return {
      receipt: null,
      error: typeof code === "string" && /^[A-Za-z0-9_]{1,64}$/.test(code) ? code : `http_${status}`,
    };
  }
  if (obj === null || !allStrings(obj)) return { receipt: null, error: "bad_witness_response" };

  let pubObj: KeyObject;
  if (target.pinned !== undefined) {
    pubObj = target.pinned.pubObj;
  } else {
    const fetched = await fetchWitnessKey(target.baseUrl, obj["public_key_id"] ?? "");
    if (!fetched.ok) return { receipt: null, error: "witness_key_unavailable" };
    pubObj = witnessPubFromRaw(fetched.raw);
  }
  if (!verifyWitnessSignature(obj, pubObj)) return { receipt: null, error: "bad_witness_signature" };
  if (
    obj["type"] !== WITNESS_RECEIPT_TYPE ||
    obj["witness"] !== target.name ||
    obj["kid"] !== cp.kid ||
    obj["session_id"] !== cp.session_id ||
    obj["last_entry_hash"] !== cp.last_entry_hash ||
    obj["count"] !== String(cp.count)
  ) {
    return { receipt: null, error: "witness_receipt_mismatch" };
  }
  return { receipt: obj, error: null };
}

// ---------------------------------------------------------------------------
// Collecting receipts (spec section 5 step 3)
// ---------------------------------------------------------------------------

export type Collected = { ok: true; receipts: unknown[] } | { ok: false; reason: string };

export async function collectReceiptsFromWitness(
  baseUrl: string,
  kid: string,
  sessionId: string,
): Promise<Collected> {
  const receipts: unknown[] = [];
  let after: string | undefined;
  for (let page = 0; page < MAX_GET_PAGES; page++) {
    const q = new URLSearchParams({ kid, session_id: sessionId });
    if (after !== undefined) q.set("after", after);
    const url = `${baseUrl}/v1/witness/checkpoints?${q.toString()}`;
    let body: unknown;
    try {
      const res = await fetch(url, {
        redirect: "error",
        signal: AbortSignal.timeout(WITNESS_GET_TIMEOUT_MS),
      });
      if (res.status !== 200) return { ok: false, reason: `GET ${url} returned ${res.status}` };
      body = await res.json();
    } catch (e) {
      return { ok: false, reason: `GET ${url} failed: ${errMessage(e)}` };
    }
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: `GET ${url} did not return a JSON object` };
    }
    const b = body as Record<string, unknown>;
    if (!Array.isArray(b["receipts"])) return { ok: false, reason: `GET ${url} has no receipts[] array` };
    receipts.push(...(b["receipts"] as unknown[]));
    const next = b["next_after"];
    if (next === undefined) return { ok: true, receipts };
    if (typeof next !== "string" || !/^\d+:sha256:[0-9a-f]{64}$/.test(next) || next === after) {
      return { ok: false, reason: `GET ${url} returned a malformed next_after` };
    }
    after = next;
  }
  return { ok: false, reason: `more than ${MAX_GET_PAGES} pages of receipts` };
}

// Parse a sidecar. Throws on a malformed line: callers fail closed on it.
export function readSidecar(path: string): SidecarLine[] {
  const lines: SidecarLine[] = [];
  const text = readFileSync(path, "utf8").split(/\r?\n/);
  for (let i = 0; i < text.length; i++) {
    const t = text[i]!.trim();
    if (t.length === 0) continue;
    let parsed: unknown;
    try {
      parsed = strictJsonParse(t);
    } catch (e) {
      throw new Error(`sidecar line ${i + 1}: ${(e as Error).message}`);
    }
    const o = parsed as Record<string, unknown> | null;
    if (
      typeof o !== "object" ||
      o === null ||
      typeof o["checkpoint"] !== "object" ||
      o["checkpoint"] === null ||
      !("witness_receipt" in o) ||
      (o["witness_receipt"] !== null && typeof o["witness_receipt"] !== "object") ||
      !("witness_error" in o) ||
      (o["witness_error"] !== null && typeof o["witness_error"] !== "string")
    ) {
      throw new Error(`sidecar line ${i + 1}: not a {checkpoint, witness_receipt, witness_error} object`);
    }
    lines.push(o as unknown as SidecarLine);
  }
  return lines;
}

export function collectReceiptsFromSidecar(path: string): Collected {
  if (!existsSync(path)) return { ok: false, reason: `sidecar ${path} not found` };
  try {
    return {
      ok: true,
      receipts: readSidecar(path)
        .map((l) => l.witness_receipt)
        .filter((r) => r !== null),
    };
  } catch (e) {
    return { ok: false, reason: `sidecar ${path} is malformed: ${(e as Error).message}` };
  }
}

// ---------------------------------------------------------------------------
// Checking receipts against the chain (spec section 5 steps 5 to 8)
// ---------------------------------------------------------------------------

export type WitnessCheck =
  | { kind: "pass"; throughCount: number; receivedAt: string; unprotected: number }
  | { kind: "none" }
  | { kind: "tampered"; line: string }
  | { kind: "unverifiable"; line: string };

export interface ChainHead {
  kid: string;
  sessionId: string;
  // entryHashes[i] is the entry_hash of record i.
  entryHashes: string[];
}

export function checkReceipts(
  receiptsIn: unknown[],
  chain: ChainHead,
  wk: WitnessPub,
  witnessName: string,
): WitnessCheck {
  if (receiptsIn.length === 0) return { kind: "none" };
  const receipts: { r: Record<string, unknown>; count: number; hash: string }[] = [];
  for (const r of receiptsIn) {
    if (typeof r !== "object" || r === null || Array.isArray(r)) {
      return { kind: "unverifiable", line: "UNVERIFIABLE — witness receipts unavailable: a receipt is not a JSON object" };
    }
    const o = r as Record<string, unknown>;
    const c = o["count"];
    if (typeof c !== "string" || !/^(0|[1-9][0-9]*)$/.test(c) || !Number.isSafeInteger(Number(c))) {
      return { kind: "unverifiable", line: "UNVERIFIABLE — witness receipts unavailable: a receipt has no decimal count" };
    }
    receipts.push({ r: o, count: Number(c), hash: String(o["last_entry_hash"]) });
  }
  receipts.sort((a, b) => a.count - b.count || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));

  // Step 5: every receipt must be authentic before any is compared with the
  // chain. The key-id check comes before the signature, so a receipt signed
  // under a key we were not given reads UNVERIFIABLE, not TAMPERED.
  for (const { r, count } of receipts) {
    if (r["public_key_id"] !== wk.id) {
      return { kind: "unverifiable", line: `UNVERIFIABLE — witness key mismatch at count ${count}` };
    }
    if (
      !verifyWitnessSignature(r, wk.pubObj) ||
      r["kid"] !== chain.kid ||
      r["session_id"] !== chain.sessionId ||
      r["type"] !== WITNESS_RECEIPT_TYPE ||
      r["witness"] !== witnessName ||
      (r["fork"] !== "true" && r["fork"] !== "false")
    ) {
      return { kind: "tampered", line: `TAMPERED — witness receipt at count ${count} invalid` };
    }
  }

  // Step 6, ascending count: fork, then shortfall, then hash mismatch. The
  // first failure is the lowest failing count.
  let i = 0;
  while (i < receipts.length) {
    const count = receipts[i]!.count;
    const group = [];
    while (i < receipts.length && receipts[i]!.count === count) group.push(receipts[i++]!);
    if (new Set(group.map((g) => g.hash)).size > 1 || group.some((g) => g.r["fork"] === "true")) {
      return { kind: "tampered", line: `TAMPERED — witnessed count ${count}: fork` };
    }
    if (count > chain.entryHashes.length) {
      return {
        kind: "tampered",
        line: `TAMPERED — witnessed count ${count} is beyond the chain (${chain.entryHashes.length} records)`,
      };
    }
    if (count < 1 || chain.entryHashes[count - 1] !== group[0]!.hash) {
      return { kind: "tampered", line: `TAMPERED — witnessed count ${count}: last_entry_hash mismatch` };
    }
  }

  const last = receipts[receipts.length - 1]!;
  const first = receipts.find((x) => x.count === last.count)!;
  return {
    kind: "pass",
    throughCount: last.count,
    receivedAt: String(first.r["received_at"]),
    unprotected: chain.entryHashes.length - last.count,
  };
}

// ---------------------------------------------------------------------------
// The whole witness layer of `chirindo verify` (spec section 5 steps 2 to 8),
// run only after the existing verifier returned VALID (step 1, in the CLI).
// ---------------------------------------------------------------------------

export interface WitnessVerifyInput {
  chainPath: string;
  validText: string; // the existing verifier's VALID output, printed unchanged
  validExit: number; // and its exit code (1 for DELIVERY UNPROVEN)
  witnessName: string;
  baseUrl?: string; // --witness
  sidecarPath?: string; // --witness-file
  pinned?: WitnessPub; // --witness-key (required with --witness-file)
}

export async function verifyAgainstWitness(
  input: WitnessVerifyInput,
): Promise<{ text: string; code: number }> {
  const { records } = readChainFile(input.chainPath);
  const kid = records[0]!.kid;
  const sessionId = records[0]!.session_id;
  const entryHashes = records.map((r) => entryHashOfCanonical(jcsBytes(contentOf(r))));
  const fromSidecar = input.baseUrl === undefined;
  const noWitness = `NO WITNESS: chain VALID, no witness receipts for kid ${kid} session ${sessionId}`;

  const collected = fromSidecar
    ? collectReceiptsFromSidecar(input.sidecarPath!)
    : await collectReceiptsFromWitness(input.baseUrl!, kid, sessionId);
  if (!collected.ok) {
    return { text: `UNVERIFIABLE — witness receipts unavailable: ${collected.reason}`, code: 1 };
  }
  if (collected.receipts.length === 0) return { text: noWitness, code: 1 };

  // Step 4: an unpinned key is fetched for the receipts' public_key_id and
  // used, but the result can never exit 0 — the fetch is trust in transport.
  let wk = input.pinned;
  let unpinnedNote: string | undefined;
  if (wk === undefined) {
    const keyId = collected.receipts
      .map((r) =>
        typeof r === "object" && r !== null ? (r as Record<string, unknown>)["public_key_id"] : undefined,
      )
      .find((v): v is string => typeof v === "string");
    if (keyId === undefined) {
      return {
        text: "UNVERIFIABLE — witness receipts unavailable: no receipt names a public_key_id",
        code: 1,
      };
    }
    const fetched = await fetchWitnessKey(input.baseUrl!, keyId);
    if (!fetched.ok) {
      return { text: `UNVERIFIABLE — witness receipts unavailable: ${fetched.reason}`, code: 1 };
    }
    wk = { pubObj: witnessPubFromRaw(fetched.raw), hex: fetched.raw.toString("hex"), id: keyId };
    unpinnedNote = `witness key ${wk.hex} fetched from ${fetched.url}, NOT pinned`;
  }

  const check = checkReceipts(collected.receipts, { kid, sessionId, entryHashes }, wk, input.witnessName);
  const out: string[] = [];
  let code: number;
  if (check.kind === "pass") {
    out.push(
      input.validText,
      `WITNESSED through count ${check.throughCount}, received_at ${check.receivedAt}, witness key ${wk.hex}`,
      `${check.unprotected} records after the last witnessed checkpoint are not witness-protected` +
        (fromSidecar ? " (sidecar supplied by the operator)" : ""),
    );
    code = input.validExit;
  } else if (check.kind === "none") {
    out.push(noWitness);
    code = 1;
  } else {
    out.push(check.line);
    code = 1;
  }
  if (unpinnedNote !== undefined) {
    out.push(unpinnedNote);
    code = 1;
  }
  return { text: out.join("\n"), code };
}
