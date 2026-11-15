// B-481 N1: decode an OTLP/HTTP trace export body (protobuf or JSON, optionally
// gzip) into one in-memory model, with no dependency beyond Node itself.
//
// The model is OTLP/JSON in shape (field names lowerCamelCase, trace and span ids
// as lowercase hex, 64-bit integers as decimal strings, enums as numbers), with
// every field present at its proto3 default when the sender left it out, so the
// canonical span (map.ts) can omit defaults uniformly whichever format arrived.
//
// Field numbers and wire types are those of opentelemetry-proto v1.11.1
// (collector/trace/v1/trace_service.proto, trace/v1/trace.proto,
// common/v1/common.proto, resource/v1/resource.proto).
//
// Fail-closed: anything this module cannot represent exactly throws
// OtlpDecodeError with a closed reason, and the caller refuses the whole request.
// Fields with numbers or JSON names this module does not know are skipped and
// counted in `unknownFields` (OTLP/JSON receivers "MUST ignore message fields
// with unknown names"); they are not part of the canonical span. The two
// profiles-only dictionary fields of common.proto v1.11.1 (AnyValue 8
// string_value_strindex, KeyValue 3 key_strindex) are counted the same way.
// Stricter than Google's protobuf runtime, on purpose (fail-closed): a known
// field with another wire type, an unknown group (wire types 3 and 4) and a
// varint beyond 64 bits refuse the request.

import { gunzipSync } from "node:zlib";
import { StrictJsonParseError, strictJsonParse } from "../vendor/recorder/strict-json.js";

// The receiver's request cap (SPEC B-481 rev 2 s3: "Up to 16 MiB"), applied to
// the body as received and again to the body after gzip.
export const OTLP_MAX_BODY_BYTES = 16 * 1024 * 1024;
// Deepest AnyValue nesting accepted (array or kvlist inside a value).
export const OTLP_MAX_VALUE_DEPTH = 64;

export type OtlpDecodeReason =
  | "unsupported_content_type"
  | "unsupported_content_encoding"
  | "too_large"
  | "gzip_invalid"
  | "protobuf_invalid"
  | "json_invalid"
  | "utf8_invalid"
  | "depth_exceeded"
  | "trace_id_invalid"
  | "span_id_invalid"
  | "parent_span_id_invalid";

export class OtlpDecodeError extends Error {
  constructor(
    readonly reason: OtlpDecodeReason,
    readonly detail: string,
  ) {
    super(`${reason}: ${detail}`);
    this.name = "OtlpDecodeError";
  }
}

export interface OtlpAnyValue {
  stringValue?: string;
  boolValue?: boolean;
  intValue?: string;
  doubleValue?: number;
  arrayValue?: { values: OtlpAnyValue[] };
  kvlistValue?: { values: OtlpKeyValue[] };
  bytesValue?: string;
}
export interface OtlpKeyValue {
  key: string;
  value: OtlpAnyValue;
}
export interface OtlpResource {
  attributes: OtlpKeyValue[];
  droppedAttributesCount: number;
}
export interface OtlpScope {
  name: string;
  version: string;
  attributes: OtlpKeyValue[];
  droppedAttributesCount: number;
}
export interface OtlpStatus {
  message: string;
  code: number;
}
export interface OtlpEvent {
  timeUnixNano: string;
  name: string;
  attributes: OtlpKeyValue[];
  droppedAttributesCount: number;
}
export interface OtlpLink {
  traceId: string;
  spanId: string;
  traceState: string;
  attributes: OtlpKeyValue[];
  droppedAttributesCount: number;
  flags: number;
}
export interface OtlpSpan {
  traceId: string;
  spanId: string;
  traceState: string;
  parentSpanId: string;
  flags: number;
  name: string;
  kind: number;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtlpKeyValue[];
  droppedAttributesCount: number;
  events: OtlpEvent[];
  droppedEventsCount: number;
  links: OtlpLink[];
  droppedLinksCount: number;
  status: OtlpStatus;
}
export interface OtlpScopeSpans {
  scope: OtlpScope;
  spans: OtlpSpan[];
  schemaUrl: string;
}
export interface OtlpResourceSpans {
  resource: OtlpResource;
  scopeSpans: OtlpScopeSpans[];
  schemaUrl: string;
}
export interface DecodedTraceRequest {
  format: "protobuf" | "json";
  resourceSpans: OtlpResourceSpans[];
  spanCount: number;
  unknownFields: number;
}

// ---------------------------------------------------------------- the entry

// Decode one /v1/traces request body. `contentType` and `contentEncoding` are
// the request's header values as received (undefined when absent).
export function decodeTraceRequest(
  body: Uint8Array,
  contentType: string | undefined,
  contentEncoding?: string | undefined,
): DecodedTraceRequest {
  const type = mediaType(contentType);
  if (type !== "application/x-protobuf" && type !== "application/json") {
    throw new OtlpDecodeError("unsupported_content_type", `content-type ${JSON.stringify(contentType ?? null)}`);
  }
  if (body.length > OTLP_MAX_BODY_BYTES) {
    throw new OtlpDecodeError("too_large", `body ${body.length} bytes, cap ${OTLP_MAX_BODY_BYTES}`);
  }
  const bytes = decodeContentEncoding(body, contentEncoding);
  const req = type === "application/x-protobuf" ? decodeTraceProtobuf(bytes) : decodeTraceJson(bytes);
  validateIds(req);
  return req;
}

function mediaType(v: string | undefined): string {
  if (v === undefined) return "";
  return (v.split(";")[0] ?? "").trim().toLowerCase();
}

function decodeContentEncoding(body: Uint8Array, enc: string | undefined): Buffer {
  const e = (enc ?? "").trim().toLowerCase();
  const buf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (e === "" || e === "identity") return buf;
  if (e !== "gzip") throw new OtlpDecodeError("unsupported_content_encoding", `content-encoding ${JSON.stringify(enc)}`);
  try {
    return gunzipSync(buf, { maxOutputLength: OTLP_MAX_BODY_BYTES });
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_BUFFER_TOO_LARGE" || err instanceof RangeError) {
      throw new OtlpDecodeError("too_large", `gzip body inflates past ${OTLP_MAX_BODY_BYTES} bytes`);
    }
    throw new OtlpDecodeError("gzip_invalid", (err as Error).message);
  }
}

// trace.proto: a trace id "is a 16-byte array. An ID with all zeroes OR of
// length other than 16 bytes is considered invalid"; a span id the same at 8
// bytes; parent_span_id is empty for a root span, else a span id.
function validateIds(req: DecodedTraceRequest): void {
  let n = 0;
  for (const rs of req.resourceSpans) {
    for (const ss of rs.scopeSpans) {
      for (const s of ss.spans) {
        if (!/^[0-9a-f]{32}$/.test(s.traceId) || /^0+$/.test(s.traceId)) {
          throw new OtlpDecodeError("trace_id_invalid", `span ${n}: trace id ${JSON.stringify(s.traceId)}`);
        }
        if (!/^[0-9a-f]{16}$/.test(s.spanId) || /^0+$/.test(s.spanId)) {
          throw new OtlpDecodeError("span_id_invalid", `span ${n}: span id ${JSON.stringify(s.spanId)}`);
        }
        if (s.parentSpanId !== "" && (!/^[0-9a-f]{16}$/.test(s.parentSpanId) || /^0+$/.test(s.parentSpanId))) {
          throw new OtlpDecodeError("parent_span_id_invalid", `span ${n}: parent span id ${JSON.stringify(s.parentSpanId)}`);
        }
        n++;
      }
    }
  }
}

// ---------------------------------------------------------------- defaults

const newResource = (): OtlpResource => ({ attributes: [], droppedAttributesCount: 0 });
const newScope = (): OtlpScope => ({ name: "", version: "", attributes: [], droppedAttributesCount: 0 });
const newStatus = (): OtlpStatus => ({ message: "", code: 0 });
const newEvent = (): OtlpEvent => ({ timeUnixNano: "0", name: "", attributes: [], droppedAttributesCount: 0 });
const newLink = (): OtlpLink => ({ traceId: "", spanId: "", traceState: "", attributes: [], droppedAttributesCount: 0, flags: 0 });
const newSpan = (): OtlpSpan => ({
  traceId: "", spanId: "", traceState: "", parentSpanId: "", flags: 0, name: "", kind: 0,
  startTimeUnixNano: "0", endTimeUnixNano: "0", attributes: [], droppedAttributesCount: 0,
  events: [], droppedEventsCount: 0, links: [], droppedLinksCount: 0, status: newStatus(),
});
const newScopeSpans = (): OtlpScopeSpans => ({ scope: newScope(), spans: [], schemaUrl: "" });
const newResourceSpans = (): OtlpResourceSpans => ({ resource: newResource(), scopeSpans: [], schemaUrl: "" });

function countSpans(rss: OtlpResourceSpans[]): number {
  let n = 0;
  for (const rs of rss) for (const ss of rs.scopeSpans) n += ss.spans.length;
  return n;
}

// ---------------------------------------------------------------- protobuf

const VARINT = 0, I64 = 1, LEN = 2, I32 = 5;
type Wire = { f: number; wt: number; n: bigint; b: Buffer; at: number };
interface PbState { unknown: number }

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function pbString(b: Buffer, at: number): string {
  try {
    return utf8.decode(b);
  } catch {
    throw new OtlpDecodeError("utf8_invalid", `string field at byte ${at} is not valid UTF-8`);
  }
}

function* pbFields(buf: Buffer, base: number): Generator<Wire> {
  let p = 0;
  while (p < buf.length) {
    const at = base + p;
    const [key, p1] = pbVarint(buf, p, base);
    p = p1;
    const f = Number(key >> 3n);
    const wt = Number(key & 7n);
    if (f === 0 || key >> 3n > 536870911n) throw new OtlpDecodeError("protobuf_invalid", `field number out of range at byte ${at}`);
    if (wt === VARINT) {
      const [n, q] = pbVarint(buf, p, base);
      p = q;
      yield { f, wt, n, b: EMPTY, at };
    } else if (wt === I64) {
      pbNeed(buf, p, 8, base);
      yield { f, wt, n: buf.readBigUInt64LE(p), b: buf.subarray(p, p + 8), at };
      p += 8;
    } else if (wt === LEN) {
      const [len, q] = pbVarint(buf, p, base);
      if (len > BigInt(buf.length - q)) throw new OtlpDecodeError("protobuf_invalid", `length past the end at byte ${base + p}`);
      const l = Number(len);
      yield { f, wt, n: len, b: buf.subarray(q, q + l), at: base + q };
      p = q + l;
    } else if (wt === I32) {
      pbNeed(buf, p, 4, base);
      yield { f, wt, n: BigInt(buf.readUInt32LE(p)), b: buf.subarray(p, p + 4), at };
      p += 4;
    } else {
      throw new OtlpDecodeError("protobuf_invalid", `wire type ${wt} at byte ${at}`);
    }
  }
}
const EMPTY = Buffer.alloc(0);

function pbNeed(buf: Buffer, p: number, n: number, base: number): void {
  if (p + n > buf.length) throw new OtlpDecodeError("protobuf_invalid", `truncated at byte ${base + p}`);
}

function pbVarint(buf: Buffer, p: number, base: number): [bigint, number] {
  let r = 0n;
  for (let i = 0; i < 10; i++) {
    pbNeed(buf, p, 1, base);
    const byte = buf[p++]!;
    if (i === 9 && byte > 1) throw new OtlpDecodeError("protobuf_invalid", `varint over 64 bits at byte ${base + p - 1}`);
    r |= BigInt(byte & 0x7f) << BigInt(7 * i);
    if ((byte & 0x80) === 0) return [r, p];
  }
  throw new OtlpDecodeError("protobuf_invalid", `varint longer than 10 bytes at byte ${base + p}`);
}

function want(w: Wire, wt: number, what: string): void {
  if (w.wt !== wt) throw new OtlpDecodeError("protobuf_invalid", `${what}: wire type ${w.wt}, expected ${wt}, at byte ${w.at}`);
}
const u32 = (n: bigint): number => Number(BigInt.asUintN(32, n));
const i32 = (n: bigint): number => Number(BigInt.asIntN(32, n));

export function decodeTraceProtobuf(buf: Buffer): DecodedTraceRequest {
  const st: PbState = { unknown: 0 };
  const resourceSpans: OtlpResourceSpans[] = [];
  for (const w of pbFields(buf, 0)) {
    if (w.f === 1) {
      want(w, LEN, "resource_spans");
      const rs = newResourceSpans();
      pbResourceSpans(w.b, w.at, st, rs);
      resourceSpans.push(rs);
    } else st.unknown++;
  }
  return { format: "protobuf", resourceSpans, spanCount: countSpans(resourceSpans), unknownFields: st.unknown };
}

function pbResourceSpans(b: Buffer, base: number, st: PbState, o: OtlpResourceSpans): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "resource"); pbResource(w.b, w.at, st, o.resource); }
    else if (w.f === 2) { want(w, LEN, "scope_spans"); const ss = newScopeSpans(); pbScopeSpans(w.b, w.at, st, ss); o.scopeSpans.push(ss); }
    else if (w.f === 3) { want(w, LEN, "schema_url"); o.schemaUrl = pbString(w.b, w.at); }
    else st.unknown++;
  }
}
function pbResource(b: Buffer, base: number, st: PbState, o: OtlpResource): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "attributes"); o.attributes.push(pbKeyValue(w.b, w.at, st, 0)); }
    else if (w.f === 2) { want(w, VARINT, "dropped_attributes_count"); o.droppedAttributesCount = u32(w.n); }
    else st.unknown++;
  }
}
function pbScopeSpans(b: Buffer, base: number, st: PbState, o: OtlpScopeSpans): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "scope"); pbScope(w.b, w.at, st, o.scope); }
    else if (w.f === 2) { want(w, LEN, "spans"); const s = newSpan(); pbSpan(w.b, w.at, st, s); o.spans.push(s); }
    else if (w.f === 3) { want(w, LEN, "schema_url"); o.schemaUrl = pbString(w.b, w.at); }
    else st.unknown++;
  }
}
function pbScope(b: Buffer, base: number, st: PbState, o: OtlpScope): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "name"); o.name = pbString(w.b, w.at); }
    else if (w.f === 2) { want(w, LEN, "version"); o.version = pbString(w.b, w.at); }
    else if (w.f === 3) { want(w, LEN, "attributes"); o.attributes.push(pbKeyValue(w.b, w.at, st, 0)); }
    else if (w.f === 4) { want(w, VARINT, "dropped_attributes_count"); o.droppedAttributesCount = u32(w.n); }
    else st.unknown++;
  }
}
function pbSpan(b: Buffer, base: number, st: PbState, o: OtlpSpan): void {
  for (const w of pbFields(b, base)) {
    switch (w.f) {
      case 1: want(w, LEN, "trace_id"); o.traceId = w.b.toString("hex"); break;
      case 2: want(w, LEN, "span_id"); o.spanId = w.b.toString("hex"); break;
      case 3: want(w, LEN, "trace_state"); o.traceState = pbString(w.b, w.at); break;
      case 4: want(w, LEN, "parent_span_id"); o.parentSpanId = w.b.toString("hex"); break;
      case 5: want(w, LEN, "name"); o.name = pbString(w.b, w.at); break;
      case 6: want(w, VARINT, "kind"); o.kind = i32(w.n); break;
      case 7: want(w, I64, "start_time_unix_nano"); o.startTimeUnixNano = w.n.toString(); break;
      case 8: want(w, I64, "end_time_unix_nano"); o.endTimeUnixNano = w.n.toString(); break;
      case 9: want(w, LEN, "attributes"); o.attributes.push(pbKeyValue(w.b, w.at, st, 0)); break;
      case 10: want(w, VARINT, "dropped_attributes_count"); o.droppedAttributesCount = u32(w.n); break;
      case 11: { want(w, LEN, "events"); const e = newEvent(); pbEvent(w.b, w.at, st, e); o.events.push(e); break; }
      case 12: want(w, VARINT, "dropped_events_count"); o.droppedEventsCount = u32(w.n); break;
      case 13: { want(w, LEN, "links"); const l = newLink(); pbLink(w.b, w.at, st, l); o.links.push(l); break; }
      case 14: want(w, VARINT, "dropped_links_count"); o.droppedLinksCount = u32(w.n); break;
      case 15: want(w, LEN, "status"); pbStatus(w.b, w.at, st, o.status); break;
      case 16: want(w, I32, "flags"); o.flags = Number(w.n); break;
      default: st.unknown++;
    }
  }
}
function pbEvent(b: Buffer, base: number, st: PbState, o: OtlpEvent): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, I64, "time_unix_nano"); o.timeUnixNano = w.n.toString(); }
    else if (w.f === 2) { want(w, LEN, "name"); o.name = pbString(w.b, w.at); }
    else if (w.f === 3) { want(w, LEN, "attributes"); o.attributes.push(pbKeyValue(w.b, w.at, st, 0)); }
    else if (w.f === 4) { want(w, VARINT, "dropped_attributes_count"); o.droppedAttributesCount = u32(w.n); }
    else st.unknown++;
  }
}
function pbLink(b: Buffer, base: number, st: PbState, o: OtlpLink): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "trace_id"); o.traceId = w.b.toString("hex"); }
    else if (w.f === 2) { want(w, LEN, "span_id"); o.spanId = w.b.toString("hex"); }
    else if (w.f === 3) { want(w, LEN, "trace_state"); o.traceState = pbString(w.b, w.at); }
    else if (w.f === 4) { want(w, LEN, "attributes"); o.attributes.push(pbKeyValue(w.b, w.at, st, 0)); }
    else if (w.f === 5) { want(w, VARINT, "dropped_attributes_count"); o.droppedAttributesCount = u32(w.n); }
    else if (w.f === 6) { want(w, I32, "flags"); o.flags = Number(w.n); }
    else st.unknown++;
  }
}
function pbStatus(b: Buffer, base: number, st: PbState, o: OtlpStatus): void {
  for (const w of pbFields(b, base)) {
    if (w.f === 2) { want(w, LEN, "message"); o.message = pbString(w.b, w.at); }
    else if (w.f === 3) { want(w, VARINT, "code"); o.code = i32(w.n); }
    else st.unknown++;
  }
}
function pbKeyValue(b: Buffer, base: number, st: PbState, depth: number): OtlpKeyValue {
  const o: OtlpKeyValue = { key: "", value: {} };
  for (const w of pbFields(b, base)) {
    if (w.f === 1) { want(w, LEN, "key"); o.key = pbString(w.b, w.at); }
    else if (w.f === 2) { want(w, LEN, "value"); pbAnyValue(w.b, w.at, st, depth + 1, o.value); }
    else st.unknown++; // includes 3 key_strindex (profiles only): counted, the key is kept as sent
  }
  return o;
}
// AnyValue is a oneof: a later member replaces an earlier one; the same message
// member seen twice merges (its repeated values concatenate), as protobuf does.
function pbAnyValue(b: Buffer, base: number, st: PbState, depth: number, o: OtlpAnyValue): void {
  if (depth > OTLP_MAX_VALUE_DEPTH) throw new OtlpDecodeError("depth_exceeded", `value nested deeper than ${OTLP_MAX_VALUE_DEPTH} at byte ${base}`);
  for (const w of pbFields(b, base)) {
    switch (w.f) {
      case 1: want(w, LEN, "string_value"); setOneof(o, { stringValue: pbString(w.b, w.at) }); break;
      case 2: want(w, VARINT, "bool_value"); setOneof(o, { boolValue: w.n !== 0n }); break;
      case 3: want(w, VARINT, "int_value"); setOneof(o, { intValue: BigInt.asIntN(64, w.n).toString() }); break;
      case 4: want(w, I64, "double_value"); setOneof(o, { doubleValue: w.b.readDoubleLE(0) }); break;
      case 5: {
        want(w, LEN, "array_value");
        const arr = o.arrayValue ?? { values: [] };
        for (const x of pbFields(w.b, w.at)) {
          if (x.f === 1) { want(x, LEN, "values"); const v: OtlpAnyValue = {}; pbAnyValue(x.b, x.at, st, depth + 1, v); arr.values.push(v); }
          else st.unknown++;
        }
        setOneof(o, { arrayValue: arr });
        break;
      }
      case 6: {
        want(w, LEN, "kvlist_value");
        const kv = o.kvlistValue ?? { values: [] };
        for (const x of pbFields(w.b, w.at)) {
          if (x.f === 1) { want(x, LEN, "values"); kv.values.push(pbKeyValue(x.b, x.at, st, depth)); }
          else st.unknown++;
        }
        setOneof(o, { kvlistValue: kv });
        break;
      }
      case 7: want(w, LEN, "bytes_value"); setOneof(o, { bytesValue: w.b.toString("base64") }); break;
      // string_value_strindex (v1.10.0+, profiles only: "process the data as if
      // this value were absent or empty"): it takes the oneof, so the value is
      // empty here; counted as unknown so the receiver can say so.
      case 8: want(w, VARINT, "string_value_strindex"); setOneof(o, {}); st.unknown++; break;
      default: st.unknown++;
    }
  }
}
function setOneof(o: OtlpAnyValue, v: OtlpAnyValue): void {
  delete o.stringValue; delete o.boolValue; delete o.intValue; delete o.doubleValue;
  delete o.arrayValue; delete o.kvlistValue; delete o.bytesValue;
  Object.assign(o, v);
}

// ---------------------------------------------------------------- JSON

interface JState { unknown: number }
type J = Record<string, unknown>;

export function decodeTraceJson(bytes: Buffer): DecodedTraceRequest {
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    throw new OtlpDecodeError("utf8_invalid", "JSON body is not valid UTF-8");
  }
  let root: unknown;
  try {
    root = strictJsonParse(text);
  } catch (err) {
    if (err instanceof StrictJsonParseError) throw new OtlpDecodeError("json_invalid", `strict JSON: ${err.message}`);
    throw new OtlpDecodeError("json_invalid", (err as Error).message);
  }
  const st: JState = { unknown: 0 };
  if (root === null || typeof root !== "object" || Array.isArray(root)) jFail("request", "expected a JSON object");
  const o = jObj(root, "request");
  const resourceSpans: OtlpResourceSpans[] = [];
  for (const [k, v] of Object.entries(o)) {
    if (k === "resourceSpans") for (const [i, x] of jArr(v, k).entries()) resourceSpans.push(jResourceSpans(x, `${k}[${i}]`, st));
    else st.unknown++;
  }
  return { format: "json", resourceSpans, spanCount: countSpans(resourceSpans), unknownFields: st.unknown };
}

function jFail(path: string, what: string): never {
  throw new OtlpDecodeError("json_invalid", `${path}: ${what}`);
}
function jObj(v: unknown, path: string): J {
  if (v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) jFail(path, "expected an object");
  return v as J;
}
function jArr(v: unknown, path: string): unknown[] {
  if (v === null) return [];
  if (!Array.isArray(v)) jFail(path, "expected an array");
  return v;
}
// A JSON string may escape a lone surrogate ("\ud800"), which is not Unicode
// text: protobuf could not carry it and RFC 8785 (I-JSON) forbids it.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function jStr(v: unknown, path: string): string {
  if (v === null) return "";
  if (typeof v !== "string") jFail(path, "expected a string");
  if (LONE_SURROGATE.test(v)) throw new OtlpDecodeError("utf8_invalid", `${path}: a lone surrogate is not Unicode text`);
  return v;
}
function jBool(v: unknown, path: string): boolean {
  if (v === null) return false;
  if (typeof v !== "boolean") jFail(path, "expected true or false");
  return v;
}
function jHex(v: unknown, path: string): string {
  const s = jStr(v, path);
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) jFail(path, "expected hex");
  return s.toLowerCase();
}
function jBase64(v: unknown, path: string): string {
  const s = jStr(v, path);
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(std) || (std.includes("=") && std.length % 4 !== 0) || std.length % 4 === 1) jFail(path, "expected base64");
  return Buffer.from(std, "base64").toString("base64");
}
// An integer field given as a JSON number (a safe integer: strict parse refused
// any other) or as a decimal string; checked against [min, max].
function jInt(v: unknown, path: string, min: bigint, max: bigint): bigint {
  if (v === null) return 0n;
  let n: bigint;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) jFail(path, "expected an integer");
    n = BigInt(v);
  } else if (typeof v === "string") {
    if (!/^-?(?:0|[1-9][0-9]*)$/.test(v)) jFail(path, "expected a decimal integer string");
    n = BigInt(v);
  } else jFail(path, "expected an integer");
  if (n < min || n > max) jFail(path, "integer out of range");
  return n;
}
const U64 = (1n << 64n) - 1n, I64MIN = -(1n << 63n), I64MAX = (1n << 63n) - 1n;
const U32 = (1n << 32n) - 1n, I32MIN = -(1n << 31n), I32MAX = (1n << 31n) - 1n;
const jU64 = (v: unknown, p: string): string => jInt(v, p, 0n, U64).toString();
const jI64 = (v: unknown, p: string): string => jInt(v, p, I64MIN, I64MAX).toString();
const jU32 = (v: unknown, p: string): number => Number(jInt(v, p, 0n, U32));
// OTLP/JSON: "Values of enum fields MUST be encoded as integer values".
function jEnum(v: unknown, path: string): number {
  if (v === null) return 0;
  if (typeof v !== "number") jFail(path, "expected an enum as an integer");
  return Number(jInt(v, path, I32MIN, I32MAX));
}
function jDouble(v: unknown, path: string): number {
  if (typeof v === "number") return v;
  if (v === "NaN") return NaN;
  if (v === "Infinity") return Infinity;
  if (v === "-Infinity") return -Infinity;
  if (typeof v === "string" && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(v)) return Number(v);
  return jFail(path, "expected a number");
}

function jResourceSpans(v: unknown, path: string, st: JState): OtlpResourceSpans {
  const o = newResourceSpans();
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "resource") jResource(x, p, st, o.resource);
    else if (k === "scopeSpans") for (const [i, y] of jArr(x, p).entries()) o.scopeSpans.push(jScopeSpans(y, `${p}[${i}]`, st));
    else if (k === "schemaUrl") o.schemaUrl = jStr(x, p);
    else st.unknown++;
  }
  return o;
}
function jResource(v: unknown, path: string, st: JState, o: OtlpResource): void {
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "attributes") o.attributes.push(...jKeyValues(x, p, st, 0));
    else if (k === "droppedAttributesCount") o.droppedAttributesCount = jU32(x, p);
    else st.unknown++;
  }
}
function jScopeSpans(v: unknown, path: string, st: JState): OtlpScopeSpans {
  const o = newScopeSpans();
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "scope") jScope(x, p, st, o.scope);
    else if (k === "spans") for (const [i, y] of jArr(x, p).entries()) o.spans.push(jSpan(y, `${p}[${i}]`, st));
    else if (k === "schemaUrl") o.schemaUrl = jStr(x, p);
    else st.unknown++;
  }
  return o;
}
function jScope(v: unknown, path: string, st: JState, o: OtlpScope): void {
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "name") o.name = jStr(x, p);
    else if (k === "version") o.version = jStr(x, p);
    else if (k === "attributes") o.attributes.push(...jKeyValues(x, p, st, 0));
    else if (k === "droppedAttributesCount") o.droppedAttributesCount = jU32(x, p);
    else st.unknown++;
  }
}
function jSpan(v: unknown, path: string, st: JState): OtlpSpan {
  const o = newSpan();
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    switch (k) {
      case "traceId": o.traceId = jHex(x, p); break;
      case "spanId": o.spanId = jHex(x, p); break;
      case "traceState": o.traceState = jStr(x, p); break;
      case "parentSpanId": o.parentSpanId = jHex(x, p); break;
      case "flags": o.flags = jU32(x, p); break;
      case "name": o.name = jStr(x, p); break;
      case "kind": o.kind = jEnum(x, p); break;
      case "startTimeUnixNano": o.startTimeUnixNano = jU64(x, p); break;
      case "endTimeUnixNano": o.endTimeUnixNano = jU64(x, p); break;
      case "attributes": o.attributes.push(...jKeyValues(x, p, st, 0)); break;
      case "droppedAttributesCount": o.droppedAttributesCount = jU32(x, p); break;
      case "events": for (const [i, y] of jArr(x, p).entries()) o.events.push(jEvent(y, `${p}[${i}]`, st)); break;
      case "droppedEventsCount": o.droppedEventsCount = jU32(x, p); break;
      case "links": for (const [i, y] of jArr(x, p).entries()) o.links.push(jLink(y, `${p}[${i}]`, st)); break;
      case "droppedLinksCount": o.droppedLinksCount = jU32(x, p); break;
      case "status": jStatus(x, p, st, o.status); break;
      default: st.unknown++;
    }
  }
  return o;
}
function jEvent(v: unknown, path: string, st: JState): OtlpEvent {
  const o = newEvent();
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "timeUnixNano") o.timeUnixNano = jU64(x, p);
    else if (k === "name") o.name = jStr(x, p);
    else if (k === "attributes") o.attributes.push(...jKeyValues(x, p, st, 0));
    else if (k === "droppedAttributesCount") o.droppedAttributesCount = jU32(x, p);
    else st.unknown++;
  }
  return o;
}
function jLink(v: unknown, path: string, st: JState): OtlpLink {
  const o = newLink();
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "traceId") o.traceId = jHex(x, p);
    else if (k === "spanId") o.spanId = jHex(x, p);
    else if (k === "traceState") o.traceState = jStr(x, p);
    else if (k === "attributes") o.attributes.push(...jKeyValues(x, p, st, 0));
    else if (k === "droppedAttributesCount") o.droppedAttributesCount = jU32(x, p);
    else if (k === "flags") o.flags = jU32(x, p);
    else st.unknown++;
  }
  return o;
}
function jStatus(v: unknown, path: string, st: JState, o: OtlpStatus): void {
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "message") o.message = jStr(x, p);
    else if (k === "code") o.code = jEnum(x, p);
    else st.unknown++;
  }
}
function jKeyValues(v: unknown, path: string, st: JState, depth: number): OtlpKeyValue[] {
  return jArr(v, path).map((x, i) => jKeyValue(x, `${path}[${i}]`, st, depth));
}
function jKeyValue(v: unknown, path: string, st: JState, depth: number): OtlpKeyValue {
  const o: OtlpKeyValue = { key: "", value: {} };
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (k === "key") o.key = jStr(x, p);
    else if (k === "value") o.value = jAnyValue(x, p, st, depth + 1);
    else st.unknown++;
  }
  return o;
}
// A JSON AnyValue names at most one member; two members is ambiguous and refused.
function jAnyValue(v: unknown, path: string, st: JState, depth: number): OtlpAnyValue {
  if (depth > OTLP_MAX_VALUE_DEPTH) throw new OtlpDecodeError("depth_exceeded", `${path}: value nested deeper than ${OTLP_MAX_VALUE_DEPTH}`);
  const o: OtlpAnyValue = {};
  let members = 0;
  for (const [k, x] of Object.entries(jObj(v, path))) {
    const p = `${path}.${k}`;
    if (x === null) continue;
    switch (k) {
      case "stringValue": o.stringValue = jStr(x, p); break;
      case "boolValue": o.boolValue = jBool(x, p); break;
      case "intValue": o.intValue = jI64(x, p); break;
      case "doubleValue": o.doubleValue = jDouble(x, p); break;
      case "bytesValue": o.bytesValue = jBase64(x, p); break;
      case "arrayValue": {
        const values: OtlpAnyValue[] = [];
        for (const [kk, y] of Object.entries(jObj(x, p))) {
          if (kk === "values") for (const [i, z] of jArr(y, `${p}.values`).entries()) values.push(jAnyValue(z, `${p}.values[${i}]`, st, depth + 1));
          else st.unknown++;
        }
        o.arrayValue = { values };
        break;
      }
      case "kvlistValue": {
        const values: OtlpKeyValue[] = [];
        for (const [kk, y] of Object.entries(jObj(x, p))) {
          if (kk === "values") values.push(...jKeyValues(y, `${p}.values`, st, depth));
          else st.unknown++;
        }
        o.kvlistValue = { values };
        break;
      }
      default: st.unknown++; continue;
    }
    members++;
  }
  if (members > 1) jFail(path, "more than one value member");
  return o;
}
