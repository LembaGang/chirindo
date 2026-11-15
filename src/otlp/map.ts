// B-481: the mapping from one OTLP span to one chirindo `tool_call` event, as
// SPEC_2026-11-13_B481_one-line-install_rev2.md section 3 defines it:
//
//   - every span in a request maps, in wire order (resourceSpans, then
//     scopeSpans, then spans); none is skipped for its content;
//   - tool_name is the `gen_ai.tool.name` attribute when the span's
//     `gen_ai.operation.name` attribute is "execute_tool", else
//     "otel.span:" + the span's name;
//   - outcome is "errored" when the span's status code is 2 (STATUS_CODE_ERROR),
//     else "executed" (printed to people as "no error reported");
//   - decision "observed", decision_source "n/a", no result_hash; the record's
//     gate is null (observe-only), the values chirindo verify accepted in T0 F1;
//   - args_hash is "sha256:" + hex(sha256(JCS(canonical span))), where the
//     canonical span is an OTLP/JSON trace request holding exactly this one span
//     with its resource and scope. Its JCS bytes are what a receiver keeps on
//     the user's disk beside the chain, so anyone can recompute args_hash.
//
// Canonical span rules (so the same span gives the same bytes whether it came
// as protobuf or JSON, and whatever order its attributes arrived in):
//   - OTLP/JSON field names; ids lowercase hex; 64-bit integers decimal strings;
//     enums, flags and counts JSON numbers; bytesValue standard base64;
//     doubleValue a JSON number (JCS writes -0 as 0, so the sign of a zero is
//     not kept), or "NaN", "Infinity", "-Infinity";
//   - a field holding its proto3 default ("", 0, "0", an empty list, an empty
//     message) is left out, except inside AnyValue, whose one member is always
//     kept (an empty string is a value) and whose empty form is {};
//   - every `attributes` list is sorted by key (UTF-16 code units, the order JCS
//     uses for member names) and, where a key repeats, by the JCS text of the
//     value; events, links, array values and kvlist values keep their wire order.

import { jcs, jcsBytes } from "../vendor/recorder/canonicalize.js";
import { sha256Hex } from "../vendor/recorder/hash.js";
import type { ToolCallEvent } from "../vendor/recorder/record.js";
import {
  decodeTraceRequest,
  type DecodedTraceRequest,
  type OtlpAnyValue,
  type OtlpKeyValue,
  type OtlpResourceSpans,
  type OtlpScopeSpans,
  type OtlpSpan,
} from "./decode.js";

export const OTLP_SPAN_TOOL_PREFIX = "otel.span:";
export const GEN_AI_OPERATION_NAME = "gen_ai.operation.name";
export const GEN_AI_TOOL_NAME = "gen_ai.tool.name";
export const EXECUTE_TOOL = "execute_tool";
export const STATUS_CODE_ERROR = 2;
// The record-level gate a receiver writes beside every mapped event.
export const RECEIVER_GATE = null;

export interface MappedSpan {
  // The span's position in the request, counted across all resourceSpans and
  // scopeSpans in wire order, from 0.
  index: number;
  // JCS bytes of the canonical span: the exact preimage of event.args_hash.
  canonical: Buffer;
  event: ToolCallEvent;
}

type C = Record<string, unknown>;

function canonAny(v: OtlpAnyValue): C {
  if (v.stringValue !== undefined) return { stringValue: v.stringValue };
  if (v.boolValue !== undefined) return { boolValue: v.boolValue };
  if (v.intValue !== undefined) return { intValue: v.intValue };
  if (v.doubleValue !== undefined) {
    const d = v.doubleValue;
    return { doubleValue: Number.isNaN(d) ? "NaN" : d === Infinity ? "Infinity" : d === -Infinity ? "-Infinity" : d };
  }
  if (v.arrayValue !== undefined) {
    const values = v.arrayValue.values.map(canonAny);
    return { arrayValue: values.length ? { values } : {} };
  }
  if (v.kvlistValue !== undefined) {
    const values = v.kvlistValue.values.map(canonKv);
    return { kvlistValue: values.length ? { values } : {} };
  }
  if (v.bytesValue !== undefined) return { bytesValue: v.bytesValue };
  return {};
}
function canonKv(kv: OtlpKeyValue): C {
  return { key: kv.key, value: canonAny(kv.value) };
}
// Sorted by key, then (for a key that repeats) by the JCS text of the value,
// so the order the attributes arrived in never changes the bytes.
function putAttrs(o: C, attrs: OtlpKeyValue[]): void {
  if (!attrs.length) return;
  const rows = attrs.map((kv) => ({ key: kv.key, v: canonAny(kv.value), j: jcs(canonAny(kv.value)) }));
  rows.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.j < b.j ? -1 : a.j > b.j ? 1 : 0));
  o.attributes = rows.map((r) => ({ key: r.key, value: r.v }));
}
function putStr(o: C, k: string, v: string): void {
  if (v !== "") o[k] = v;
}
function putNum(o: C, k: string, v: number): void {
  if (v !== 0) o[k] = v;
}
function putU64(o: C, k: string, v: string): void {
  if (v !== "0") o[k] = v;
}

function canonSpanBody(s: OtlpSpan): C {
  const o: C = {};
  putStr(o, "traceId", s.traceId);
  putStr(o, "spanId", s.spanId);
  putStr(o, "traceState", s.traceState);
  putStr(o, "parentSpanId", s.parentSpanId);
  putNum(o, "flags", s.flags);
  putStr(o, "name", s.name);
  putNum(o, "kind", s.kind);
  putU64(o, "startTimeUnixNano", s.startTimeUnixNano);
  putU64(o, "endTimeUnixNano", s.endTimeUnixNano);
  putAttrs(o, s.attributes);
  putNum(o, "droppedAttributesCount", s.droppedAttributesCount);
  if (s.events.length) {
    o.events = s.events.map((e) => {
      const x: C = {};
      putU64(x, "timeUnixNano", e.timeUnixNano);
      putStr(x, "name", e.name);
      putAttrs(x, e.attributes);
      putNum(x, "droppedAttributesCount", e.droppedAttributesCount);
      return x;
    });
  }
  putNum(o, "droppedEventsCount", s.droppedEventsCount);
  if (s.links.length) {
    o.links = s.links.map((l) => {
      const x: C = {};
      putStr(x, "traceId", l.traceId);
      putStr(x, "spanId", l.spanId);
      putStr(x, "traceState", l.traceState);
      putAttrs(x, l.attributes);
      putNum(x, "droppedAttributesCount", l.droppedAttributesCount);
      putNum(x, "flags", l.flags);
      return x;
    });
  }
  putNum(o, "droppedLinksCount", s.droppedLinksCount);
  const status: C = {};
  putStr(status, "message", s.status.message);
  putNum(status, "code", s.status.code);
  if (Object.keys(status).length) o.status = status;
  return o;
}

// The canonical span: an OTLP/JSON trace request with one resourceSpans, one
// scopeSpans and the one span.
export function canonicalSpan(rs: OtlpResourceSpans, ss: OtlpScopeSpans, span: OtlpSpan): C {
  const resource: C = {};
  putAttrs(resource, rs.resource.attributes);
  putNum(resource, "droppedAttributesCount", rs.resource.droppedAttributesCount);
  const scope: C = {};
  putStr(scope, "name", ss.scope.name);
  putStr(scope, "version", ss.scope.version);
  putAttrs(scope, ss.scope.attributes);
  putNum(scope, "droppedAttributesCount", ss.scope.droppedAttributesCount);
  const scopeSpans: C = {};
  if (Object.keys(scope).length) scopeSpans.scope = scope;
  scopeSpans.spans = [canonSpanBody(span)];
  putStr(scopeSpans, "schemaUrl", ss.schemaUrl);
  const resourceSpans: C = {};
  if (Object.keys(resource).length) resourceSpans.resource = resource;
  resourceSpans.scopeSpans = [scopeSpans];
  putStr(resourceSpans, "schemaUrl", rs.schemaUrl);
  return { resourceSpans: [resourceSpans] };
}

export function canonicalSpanBytes(rs: OtlpResourceSpans, ss: OtlpScopeSpans, span: OtlpSpan): Buffer {
  return jcsBytes(canonicalSpan(rs, ss, span));
}

// The one value of `key` among the span's attributes; undefined when the key is
// absent or repeats (OTLP: "Attribute keys MUST be unique").
function onlyAttr(attrs: OtlpKeyValue[], key: string): OtlpAnyValue | undefined {
  let found: OtlpAnyValue | undefined;
  let n = 0;
  for (const kv of attrs) {
    if (kv.key === key) {
      found = kv.value;
      n++;
    }
  }
  return n === 1 ? found : undefined;
}

export function spanToolName(span: OtlpSpan): string {
  const op = onlyAttr(span.attributes, GEN_AI_OPERATION_NAME);
  if (op?.stringValue === EXECUTE_TOOL) {
    const tool = onlyAttr(span.attributes, GEN_AI_TOOL_NAME)?.stringValue;
    if (tool !== undefined && tool !== "") return tool;
  }
  return OTLP_SPAN_TOOL_PREFIX + span.name;
}

export function spanOutcome(span: OtlpSpan): "executed" | "errored" {
  return span.status.code === STATUS_CODE_ERROR ? "errored" : "executed";
}

export function mapSpan(rs: OtlpResourceSpans, ss: OtlpScopeSpans, span: OtlpSpan, index: number): MappedSpan {
  const canonical = canonicalSpanBytes(rs, ss, span);
  const event: ToolCallEvent = {
    type: "tool_call",
    outcome: spanOutcome(span),
    tool_name: spanToolName(span),
    args_hash: "sha256:" + sha256Hex(canonical),
    decision: "observed",
    decision_source: "n/a",
  };
  return { index, canonical, event };
}

export function mapTraceRequest(req: DecodedTraceRequest): MappedSpan[] {
  const out: MappedSpan[] = [];
  for (const rs of req.resourceSpans) {
    for (const ss of rs.scopeSpans) {
      for (const span of ss.spans) out.push(mapSpan(rs, ss, span, out.length));
    }
  }
  return out;
}

// Decode and map one /v1/traces body. Throws OtlpDecodeError (decode.ts) when
// the request is refused; then no span of it is mapped.
export function mapTraceBody(
  body: Uint8Array,
  contentType: string | undefined,
  contentEncoding?: string | undefined,
): { request: DecodedTraceRequest; spans: MappedSpan[] } {
  const request = decodeTraceRequest(body, contentType, contentEncoding);
  return { request, spans: mapTraceRequest(request) };
}
