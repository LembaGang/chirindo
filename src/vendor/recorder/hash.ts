import { createHash } from "node:crypto";
import { jcsBytes } from "./canonicalize.js";
import { RECORD_VERSION } from "./record.js";

export function sha256Hex(bytes: Buffer | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// args_hash for tool-call arguments.
//
// Byte-format change: as of this commit, args_hash is SHA-256 over the
// RFC 8785 JCS canonical bytes of the arguments value — NOT over a raw
// JSON.stringify output. JSON.stringify object-key order is not stable
// across an MCP client, a gate (Chirindo), and a recorder/verifier; under
// the prior scheme the same logical arguments could hash to different bytes
// at different stages, silently breaking recomputability (the core property
// of an evidence chain — an independent party given the same arguments must
// derive the same hash). JCS yields one canonical byte sequence regardless
// of key order, so the hash is stable end-to-end. We reuse the exact JCS
// routine used for record signing — one canonicalization path everywhere,
// no second implementation.
//
// This is a deliberate, versioned change with no backward compatibility:
// there are no external consumers of the prior format, no published vectors,
// and any spike .gate/sessions receipts are throwaway artifacts.
export function argsHash(args: unknown): string {
  return "sha256:" + sha256Hex(jcsBytes(args));
}

// Convenience for adapters whose payload carries arguments as a JSON-encoded
// string (e.g. Cursor's beforeMCPExecution `tool_input` field). Parses the
// string, then canonicalizes the resulting value with JCS. If parsing fails
// — i.e. the payload is not valid JSON — falls back to hashing the raw UTF-8
// bytes so observe-only callers still produce a stable hash for whatever
// they saw on the wire.
export function argsHashFromJsonString(toolInputJson: string): string {
  try {
    return argsHash(JSON.parse(toolInputJson));
  } catch {
    return "sha256:" + sha256Hex(Buffer.from(toolInputJson, "utf8"));
  }
}

// result_hash for the MCP tool result (the `result` field of a JSON-RPC
// response — typically `{ content, isError }`).
//
// Same canonicalization-bug class as args_hash: a verifier given the same
// result value must derive byte-identical bytes regardless of how the
// downstream server happened to serialize it. JSON.stringify is non-canonical
// (key order, whitespace, number formatting all vary by serializer). JCS
// yields one canonical byte sequence, so result_hash recomputes byte-for-byte
// from the parsed value. Versioned change, no backwards compatibility needed
// — there are no external consumers of the prior format.
export function resultHash(result: unknown): string {
  return "sha256:" + sha256Hex(jcsBytes(result));
}

// Convenience for callers whose payload is a JSON-encoded result string
// (e.g. Cursor's afterMCPExecution `result_json` field). Parses, then JCS-
// canonicalizes. Falls back to raw UTF-8 bytes only if parsing fails — the
// observe-only-with-best-effort posture mirroring argsHashFromJsonString.
export function resultHashFromJsonString(resultJson: string): string {
  try {
    return resultHash(JSON.parse(resultJson));
  } catch {
    return "sha256:" + sha256Hex(Buffer.from(resultJson, "utf8"));
  }
}

// entry_hash = "sha256:" + lowercase hex of SHA-256 over the JCS canonical
// bytes of the record content (everything except `sig`).
export function entryHashOfCanonical(canonicalBytes: Buffer): string {
  return "sha256:" + sha256Hex(canonicalBytes);
}

// The JCS-canonical object hashed to produce the genesis prev_hash.
// Domain-separated, unambiguous: field boundaries are explicit in JSON.
export interface GenesisInput {
  v: typeof RECORD_VERSION;
  session_id: string;
  marker: "genesis";
}

// Genesis prev_hash for seq=0 records — amended schema:
//   prev_hash[0] = "sha256:" + hex(SHA-256(JCS({v, session_id, marker:"genesis"})))
// Uses the SAME RFC 8785 JCS routine as record content, so the field boundaries
// cannot collide across (v, session_id) pairs — the earlier separator-less
// concatenation permitted splicing (e.g. v="x/0" + sid="123" colliding with
// v="x/01" + sid="23").
export function genesisInput(sessionId: string): GenesisInput {
  return { v: RECORD_VERSION, session_id: sessionId, marker: "genesis" };
}

export function genesisPrevHash(sessionId: string): string {
  return "sha256:" + sha256Hex(jcsBytes(genesisInput(sessionId)));
}
