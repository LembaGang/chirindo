// B-481 T1, N1: decoding OTLP/HTTP trace bodies (protobuf, JSON, gzip).
// Vectors: test/fixtures/otlp (generate.mjs; sha256 pinned in vectors.json).
// Every test calls src/otlp first, so before the code exists each one fails
// with "B481-T1 not implemented" and nothing else.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  OTLP_MAX_BODY_BYTES,
  OTLP_MAX_VALUE_DEPTH,
  OtlpDecodeError,
  decodeTraceJson,
  decodeTraceProtobuf,
  decodeTraceRequest,
  type OtlpDecodeReason,
} from "../src/otlp/index.js";

const DIR = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "otlp");
const vec = (name: string): Buffer => readFileSync(join(DIR, name));
const PB = "application/x-protobuf";
const JSON_CT = "application/json";
const hex = (label: string, n: number): string => createHash("sha256").update(label).digest().subarray(0, n).toString("hex");

function refused(fn: () => unknown): OtlpDecodeError {
  try {
    fn();
  } catch (e) {
    if (e instanceof OtlpDecodeError) return e;
    throw e;
  }
  throw new Error("expected the request to be refused with an OtlpDecodeError; it was accepted");
}
function expectRefused(fn: () => unknown, reason: OtlpDecodeReason): void {
  expect(refused(fn).reason).toBe(reason);
}

describe("decodeTraceRequest: content type and encoding", () => {
  it("decodes application/x-protobuf: 7 spans, 1 with status ERROR, nothing unknown", () => {
    const r = decodeTraceRequest(vec("t0-shape.pb"), PB);
    expect(r.format).toBe("protobuf");
    expect(r.spanCount).toBe(7);
    expect(r.unknownFields).toBe(0);
    const spans = r.resourceSpans.flatMap((rs) => rs.scopeSpans.flatMap((ss) => ss.spans));
    expect(spans.filter((s) => s.status.code === 2).length).toBe(1);
  });

  it("decodes application/json to the same model as the protobuf body", () => {
    const p = decodeTraceRequest(vec("t0-shape.pb"), PB);
    const j = decodeTraceRequest(vec("t0-shape.json"), JSON_CT);
    expect(j.format).toBe("json");
    expect(j.spanCount).toBe(7);
    const strip = (x: typeof p) => x.resourceSpans.map((rs) => rs.scopeSpans.map((ss) => ss.spans.map((s) => [s.traceId, s.spanId, s.name, s.kind, s.flags, s.startTimeUnixNano, s.endTimeUnixNano, s.status.code, s.status.message])));
    expect(strip(j)).toEqual(strip(p));
  });

  it("takes the media type case-insensitively and ignores parameters", () => {
    expect(decodeTraceRequest(vec("t0-shape.pb"), "Application/X-Protobuf; charset=binary").spanCount).toBe(7);
    expect(decodeTraceRequest(vec("t0-shape.json"), "application/json; charset=utf-8").spanCount).toBe(7);
  });

  it("refuses a missing or other content type", () => {
    expectRefused(() => decodeTraceRequest(vec("t0-shape.pb"), undefined), "unsupported_content_type");
    expectRefused(() => decodeTraceRequest(vec("t0-shape.pb"), "text/plain"), "unsupported_content_type");
    expectRefused(() => decodeTraceRequest(vec("t0-shape.pb"), "application/grpc"), "unsupported_content_type");
  });

  it("inflates Content-Encoding gzip (the committed vector) to the same spans", () => {
    const r = decodeTraceRequest(vec("t0-shape.pb.gz"), PB, "gzip");
    expect(r.spanCount).toBe(7);
    expect(decodeTraceRequest(vec("t0-shape.pb.gz"), PB, " GZIP ").spanCount).toBe(7);
  });

  it("inflates gzip made on this machine too, so the platform's zlib is exercised", () => {
    const gz = gzipSync(vec("t0-shape.json"));
    expect(decodeTraceRequest(gz, JSON_CT, "gzip").spanCount).toBe(7);
  });

  it("treats identity and an empty Content-Encoding as none", () => {
    expect(decodeTraceRequest(vec("t0-shape.pb"), PB, "identity").spanCount).toBe(7);
    expect(decodeTraceRequest(vec("t0-shape.pb"), PB, "").spanCount).toBe(7);
  });

  it("refuses any other Content-Encoding", () => {
    expectRefused(() => decodeTraceRequest(vec("t0-shape.pb"), PB, "br"), "unsupported_content_encoding");
    expectRefused(() => decodeTraceRequest(vec("t0-shape.pb"), PB, "deflate"), "unsupported_content_encoding");
  });

  it("refuses a body that says gzip and is not", () => {
    expectRefused(() => decodeTraceRequest(vec("neg-not-gzip.pb.gz"), PB, "gzip"), "gzip_invalid");
  });

  it("refuses a body over 16 MiB as received, before decoding", () => {
    expect(OTLP_MAX_BODY_BYTES).toBe(16 * 1024 * 1024);
    expectRefused(() => decodeTraceRequest(Buffer.alloc(OTLP_MAX_BODY_BYTES + 1), PB), "too_large");
  });

  // A request of exactly n bytes: the T0-shaped body plus one unknown
  // length-delimited field (number 99) of zero bytes as padding.
  function sized(n: number): Buffer {
    const base = vec("t0-shape.pb");
    const pad = n - base.length - 2 - 4;
    const len = Buffer.from([0x80 | (pad & 0x7f), 0x80 | ((pad >> 7) & 0x7f), 0x80 | ((pad >> 14) & 0x7f), (pad >> 21) & 0x7f]);
    return Buffer.concat([base, Buffer.from([0x9a, 0x06]), len, Buffer.alloc(pad)]);
  }

  it("accepts a body of exactly 16 MiB as received, and refuses 16 MiB + 1", () => {
    const exact = sized(OTLP_MAX_BODY_BYTES);
    expect(exact.length).toBe(16 * 1024 * 1024);
    const r = decodeTraceRequest(exact, PB);
    expect(r.spanCount).toBe(7);
    expect(r.unknownFields).toBe(1);
    expectRefused(() => decodeTraceRequest(sized(OTLP_MAX_BODY_BYTES + 1), PB), "too_large");
  });

  it("accepts gzip inflating to exactly 16 MiB, and refuses 16 MiB + 1", () => {
    const exact = gzipSync(sized(OTLP_MAX_BODY_BYTES));
    expect(decodeTraceRequest(exact, PB, "gzip").spanCount).toBe(7);
    expectRefused(() => decodeTraceRequest(gzipSync(sized(OTLP_MAX_BODY_BYTES + 1)), PB, "gzip"), "too_large");
  });

  it("refuses gzip that inflates past 16 MiB (the committed bomb: 16 MiB + 1 zero bytes)", () => {
    expectRefused(() => decodeTraceRequest(vec("bomb.pb.gz"), PB, "gzip"), "too_large");
  });

  it("accepts an empty body and an empty JSON object as a request with no spans", () => {
    expect(decodeTraceRequest(vec("empty.pb"), PB).spanCount).toBe(0);
    expect(decodeTraceRequest(vec("empty.json"), JSON_CT).spanCount).toBe(0);
  });
});

describe("decodeTraceProtobuf: the wire format", () => {
  it("reads the first span's fields as OTLP/JSON values (hex ids, decimal 64-bit times)", () => {
    const r = decodeTraceProtobuf(vec("t0-shape.pb"));
    const rs = r.resourceSpans[0]!;
    const ss = rs.scopeSpans[0]!;
    const s = ss.spans[0]!;
    expect(rs.resource.attributes.map((a) => a.key)).toEqual(["service.name", "telemetry.sdk.language", "telemetry.sdk.name", "telemetry.sdk.version"]);
    expect(ss.scope).toEqual({ name: "b481", version: "1.0.0", attributes: [], droppedAttributesCount: 0 });
    expect(s.traceId).toBe(hex("b481-t1 trace t0-shape", 16));
    expect(s.spanId).toBe(hex("b481-t1 span t0-shape 0", 8));
    expect(s.parentSpanId).toBe("");
    expect(s.name).toBe("execute_tool lookup");
    expect(s.kind).toBe(1);
    expect(s.flags).toBe(257);
    expect(s.startTimeUnixNano).toBe("1794755843144000000");
    expect(s.endTimeUnixNano).toBe("1794755843144496800");
    expect(s.attributes).toEqual([
      { key: "gen_ai.operation.name", value: { stringValue: "execute_tool" } },
      { key: "gen_ai.tool.name", value: { stringValue: "lookup" } },
      { key: "b481.i", value: { intValue: "0" } },
    ]);
    expect(s.status).toEqual({ message: "", code: 0 });
    expect(r.resourceSpans[0]!.scopeSpans[0]!.spans[3]!.status).toEqual({ message: "b481 planned failure", code: 2 });
  });

  it("reads every AnyValue type, events, links, dropped counts and schema URLs", () => {
    const r = decodeTraceProtobuf(vec("mixed.pb"));
    expect(r.spanCount).toBe(8);
    const s = r.resourceSpans[0]!.scopeSpans[0]!.spans[4]!;
    const a = Object.fromEntries(s.attributes.map((kv) => [kv.key, kv.value]));
    expect(a["a.empty_string"]).toEqual({ stringValue: "" });
    expect(a["b.bool_false"]).toEqual({ boolValue: false });
    expect(a["c.int_negative"]).toEqual({ intValue: "-42" });
    expect(a["c.int_max"]).toEqual({ intValue: "9223372036854775807" });
    expect(a["d.double"]).toEqual({ doubleValue: 3.25 });
    expect(Number.isNaN(a["d.double_nan"]?.doubleValue)).toBe(true);
    expect(a["e.array"]).toEqual({ arrayValue: { values: [{ stringValue: "x" }, { intValue: "1" }, { arrayValue: { values: [{ boolValue: true }] } }, {}] } });
    expect(a["e.array_empty"]).toEqual({ arrayValue: { values: [] } });
    expect(a["f.kvlist"]).toEqual({ kvlistValue: { values: [{ key: "zz", value: { stringValue: "kept in wire order" } }, { key: "aa", value: { doubleValue: -0.5 } }] } });
    expect(a["g.bytes"]).toEqual({ bytesValue: Buffer.from([0, 1, 2, 250, 251, 252]).toString("base64") });
    expect(a["h.empty_value"]).toEqual({});
    expect(a["i.unicode"]).toEqual({ stringValue: "naïve € 😀" });
    expect(s.droppedAttributesCount).toBe(2);
    expect(s.events.map((e) => e.name)).toEqual(["second by wire order", "first by time"]);
    expect(s.droppedEventsCount).toBe(1);
    expect(s.links).toHaveLength(1);
    expect(s.links[0]!.flags).toBe(256);
    expect(s.links[0]!.traceState).toBe("x=y");
    expect(s.droppedLinksCount).toBe(3);
    expect(s.status).toEqual({ message: "not a defined code", code: 3 });
    expect(r.resourceSpans[0]!.schemaUrl).toBe("https://opentelemetry.io/schemas/1.37.0");
    expect(r.resourceSpans[0]!.scopeSpans[0]!.schemaUrl).toBe("https://opentelemetry.io/schemas/1.36.0");
    expect(r.resourceSpans[0]!.scopeSpans[0]!.spans[3]!.parentSpanId).toBe(hex("b481-t1 span mixed 0", 8));
  });

  it("follows protobuf for a repeated oneof member (the later wins) and a repeated message (merged)", () => {
    const s = decodeTraceProtobuf(vec("quirks.pb")).resourceSpans[0]!.scopeSpans[0]!.spans[0]!;
    expect(s.attributes).toEqual([{ key: "two.members", value: { intValue: "12" } }]);
    expect(s.status).toEqual({ message: "message from the first status field", code: 2 });
  });

  it("skips and counts fields it does not know, protobuf and JSON alike", () => {
    expect(decodeTraceProtobuf(vec("unknown-fields.pb")).unknownFields).toBe(3);
    expect(decodeTraceJson(vec("unknown-fields.json")).unknownFields).toBe(3);
  });

  it("counts an unknown field inside an ArrayValue and inside a KeyValueList", () => {
    const r = decodeTraceProtobuf(vec("unknown-in-values.pb"));
    expect(r.unknownFields).toBe(2);
    const a = r.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes;
    expect(a).toEqual([
      { key: "arr", value: { arrayValue: { values: [{ stringValue: "x" }] } } },
      { key: "kvl", value: { kvlistValue: { values: [{ key: "a", value: { stringValue: "b" } }] } } },
    ]);
  });

  it("reads string_value_strindex as taking the oneof (the value is empty) and counts both strindex fields", () => {
    const r = decodeTraceProtobuf(vec("strindex.pb"));
    expect(r.unknownFields).toBe(2);
    expect(r.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes).toEqual([
      { key: "s", value: {} },
      { key: "k", value: { stringValue: "v" } },
    ]);
  });

  it("reads span flags as unsigned 32 bits (0xffffffff), protobuf and JSON alike", () => {
    expect(decodeTraceProtobuf(vec("flags-max.pb")).resourceSpans[0]!.scopeSpans[0]!.spans[0]!.flags).toBe(4294967295);
    expect(decodeTraceJson(vec("flags-max.json")).resourceSpans[0]!.scopeSpans[0]!.spans[0]!.flags).toBe(4294967295);
  });

  it("accepts link ids of any length (L7 covers a span's own ids only)", () => {
    const l = decodeTraceRequest(vec("link-ids-odd.pb"), PB).resourceSpans[0]!.scopeSpans[0]!.spans[0]!.links[0]!;
    expect([l.traceId, l.spanId]).toEqual(["010203", "04"]);
  });

  it("accepts kvlist values nested 64 deep, protobuf and JSON alike (65 is a negative vector)", () => {
    expect(decodeTraceProtobuf(vec("deep-kv-64.pb")).spanCount).toBe(1);
    expect(decodeTraceJson(vec("deep-kv-64.json")).spanCount).toBe(1);
  });

  it(`accepts values nested ${OTLP_MAX_VALUE_DEPTH} deep and refuses ${OTLP_MAX_VALUE_DEPTH + 1}`, () => {
    expect(OTLP_MAX_VALUE_DEPTH).toBe(64);
    expect(decodeTraceProtobuf(vec("deep-64.pb")).spanCount).toBe(1);
    expect(decodeTraceJson(vec("deep-64.json")).spanCount).toBe(1);
    expectRefused(() => decodeTraceProtobuf(vec("neg-deep-65.pb")), "depth_exceeded");
    expectRefused(() => decodeTraceJson(vec("neg-deep-65.json")), "depth_exceeded");
  });

  const pbNegatives: Array<[string, OtlpDecodeReason]> = [
    ["neg-truncated.pb", "protobuf_invalid"],
    ["neg-wire-type.pb", "protobuf_invalid"],
    ["neg-group.pb", "protobuf_invalid"],
    ["neg-varint-11.pb", "protobuf_invalid"],
    ["neg-utf8.pb", "utf8_invalid"],
    ["neg-trace-id-short.pb", "trace_id_invalid"],
    ["neg-trace-id-zero.pb", "trace_id_invalid"],
    ["neg-span-id-missing.pb", "span_id_invalid"],
    ["neg-parent-short.pb", "parent_span_id_invalid"],
    ["neg-span-id-zero.pb", "span_id_invalid"],
    ["neg-parent-zero.pb", "parent_span_id_invalid"],
    ["neg-varint-10th-byte.pb", "protobuf_invalid"],
    ["neg-field-zero.pb", "protobuf_invalid"],
    ["neg-deep-kv-65.pb", "depth_exceeded"],
  ];
  for (const [name, reason] of pbNegatives) {
    it(`refuses ${name} with ${reason}`, () => {
      expectRefused(() => decodeTraceRequest(vec(name), PB), reason);
    });
  }
});

describe("decodeTraceJson: OTLP/JSON", () => {
  it("normalises upper-case hex ids and numeric strings, and reads null as the default", () => {
    const body = JSON.stringify({
      resourceSpans: [{ resource: null, scopeSpans: [{ scope: { name: "s" }, spans: [{
        traceId: "ABCDEF0123456789ABCDEF0123456789", spanId: "0123456789ABCDEF", parentSpanId: null,
        name: "n", kind: 2, flags: "1", startTimeUnixNano: "10", endTimeUnixNano: 20,
        attributes: [{ key: "d", value: { doubleValue: "Infinity" } }, { key: "e", value: { doubleValue: "1.5e3" } }, { key: "n", value: null }],
        status: { code: 2, message: null },
      }] }] }],
    });
    const s = decodeTraceJson(Buffer.from(body)).resourceSpans[0]!.scopeSpans[0]!.spans[0]!;
    expect(s.traceId).toBe("abcdef0123456789abcdef0123456789");
    expect(s.spanId).toBe("0123456789abcdef");
    expect(s.parentSpanId).toBe("");
    expect(s.flags).toBe(1);
    expect(s.endTimeUnixNano).toBe("20");
    expect(s.attributes).toEqual([{ key: "d", value: { doubleValue: Infinity } }, { key: "e", value: { doubleValue: 1500 } }, { key: "n", value: {} }]);
    expect(s.status).toEqual({ message: "", code: 2 });
  });

  it("accepts URL-safe base64 for bytesValue and writes it back as standard base64", () => {
    const body = JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{
      traceId: "11".repeat(16), spanId: "22".repeat(8), attributes: [{ key: "b", value: { bytesValue: "-_8=" } }],
    }] }] }] });
    const s = decodeTraceJson(Buffer.from(body)).resourceSpans[0]!.scopeSpans[0]!.spans[0]!;
    expect(s.attributes[0]!.value).toEqual({ bytesValue: "+/8=" });
  });

  const jsonNegatives: Array<[string, OtlpDecodeReason]> = [
    ["neg-dup-member.json", "json_invalid"],
    ["neg-unsafe-int.json", "json_invalid"],
    ["neg-enum-string.json", "json_invalid"],
    ["neg-two-members.json", "json_invalid"],
    ["neg-bad-hex.json", "json_invalid"],
    ["neg-not-json.json", "json_invalid"],
    ["neg-utf8.json", "utf8_invalid"],
    ["neg-lone-surrogate.json", "utf8_invalid"],
    ["neg-null-root.json", "json_invalid"],
    ["neg-deep-kv-65.json", "depth_exceeded"],
  ];
  for (const [name, reason] of jsonNegatives) {
    it(`refuses ${name} with ${reason}`, () => {
      expectRefused(() => decodeTraceRequest(vec(name), JSON_CT), reason);
    });
  }

  it("refuses wrong JSON types, out-of-range integers and bad base64", () => {
    const span = (extra: Record<string, unknown>) => Buffer.from(JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: "11".repeat(16), spanId: "22".repeat(8), ...extra }] }] }] }));
    expectRefused(() => decodeTraceJson(Buffer.from('{"resourceSpans": {}}')), "json_invalid");
    expectRefused(() => decodeTraceJson(Buffer.from("[]")), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ name: 5 })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ flags: -1 })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ startTimeUnixNano: "18446744073709551616" })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ startTimeUnixNano: "+5" })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ attributes: [{ key: "k", value: { intValue: "9223372036854775808" } }] })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ attributes: [{ key: "k", value: { bytesValue: "a$==" } }] })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ attributes: [{ key: "k", value: { boolValue: "true" } }] })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ traceId: "abc" })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ kind: "3" })), "json_invalid");
    expectRefused(() => decodeTraceJson(span({ status: { code: "2" } })), "json_invalid");
    expectRefused(() => decodeTraceJson(Buffer.from('"text"')), "json_invalid");
  });

  it("refuses a lone low or high surrogate in a JSON string and accepts a surrogate pair, in keys and values", () => {
    const span = (attrs: unknown) => Buffer.from(JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: "11".repeat(16), spanId: "22".repeat(8), attributes: attrs }] }] }] }));
    expectRefused(() => decodeTraceJson(span([{ key: "k", value: { stringValue: "\udc00" } }])), "utf8_invalid");
    expectRefused(() => decodeTraceJson(span([{ key: "k", value: { stringValue: "a\udc00b" } }])), "utf8_invalid");
    expectRefused(() => decodeTraceJson(span([{ key: "a\udc00b", value: { stringValue: "v" } }])), "utf8_invalid");
    expectRefused(() => decodeTraceJson(span([{ key: "k", value: { stringValue: "x\ud800" } }])), "utf8_invalid");
    const ok = decodeTraceJson(span([{ key: "k\ud83d\ude00", value: { stringValue: "\ud83d\ude00" } }])).resourceSpans[0]!.scopeSpans[0]!.spans[0]!;
    expect(ok.attributes).toEqual([{ key: "k\u{1F600}", value: { stringValue: "\u{1F600}" } }]);
  });

  it("refuses a JSON trace id that is valid hex of the wrong length", () => {
    const body = Buffer.from(JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: "11".repeat(8), spanId: "22".repeat(8) }] }] }] }));
    expectRefused(() => decodeTraceRequest(body, JSON_CT), "trace_id_invalid");
  });
});
