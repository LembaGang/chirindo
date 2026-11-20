// B-481 T1: the span to record mapping (SPEC B-481 rev 2 section 3).
// The canonical spans below are written out by hand from the rules in
// src/otlp/map.ts's header, not printed by the code, and their sha256 is
// computed here with node:crypto, so the expected values do not come from the
// code under test.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { requestCommitment } from "../src/vendor/recorder/request.js";
import {
  OTLP_SPAN_TOOL_PREFIX,
  OtlpDecodeError,
  RECEIVER_GATE,
  decodeTraceJson,
  decodeTraceProtobuf,
  mapTraceBody,
  mapTraceRequest,
  type DecodedTraceRequest,
} from "../src/otlp/index.js";

const DIR = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "otlp");
const vec = (name: string): Buffer => readFileSync(join(DIR, name));
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const hex = (label: string, n: number): string => createHash("sha256").update(label).digest().subarray(0, n).toString("hex");
const PB = "application/x-protobuf";

const RESOURCE =
  '"resource":{"attributes":[' +
  '{"key":"service.name","value":{"stringValue":"b481-t1-vector"}},' +
  '{"key":"telemetry.sdk.language","value":{"stringValue":"nodejs"}},' +
  '{"key":"telemetry.sdk.name","value":{"stringValue":"opentelemetry"}},' +
  '{"key":"telemetry.sdk.version","value":{"stringValue":"2.2.0"}}]}';
function t0Canonical(i: number, status: string): string {
  const start = 1794755843144000000n + BigInt(i) * 1000000n;
  return (
    '{"resourceSpans":[{' + RESOURCE + ',"scopeSpans":[{"scope":{"name":"b481","version":"1.0.0"},"spans":[{' +
    '"attributes":[' +
    `{"key":"b481.i","value":{"intValue":"${i}"}},` +
    '{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},' +
    '{"key":"gen_ai.tool.name","value":{"stringValue":"lookup"}}],' +
    `"endTimeUnixNano":"${start + 496800n}","flags":257,"kind":1,"name":"execute_tool lookup",` +
    `"spanId":"${hex(`b481-t1 span t0-shape ${i}`, 8)}","startTimeUnixNano":"${start}",` +
    status +
    `"traceId":"${hex("b481-t1 trace t0-shape", 16)}"}]}]}]}`
  );
}

describe("mapping: one span, one tool_call record", () => {
  it("maps the 7 spans of the T0-shaped request to 7 events in wire order, span 3 errored", () => {
    const { spans } = mapTraceBody(vec("t0-shape.pb"), PB);
    expect(spans.map((s) => s.index)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(spans.map((s) => s.event.tool_name)).toEqual(Array(7).fill("lookup"));
    expect(spans.map((s) => s.event.outcome)).toEqual(["executed", "executed", "executed", "errored", "executed", "executed", "executed"]);
  });

  it("writes type tool_call, decision observed, decision_source n/a, no result_hash; the gate is null", () => {
    const { spans } = mapTraceBody(vec("t0-shape.pb"), PB);
    for (const s of spans) {
      expect(Object.keys(s.event).sort()).toEqual(["args_hash", "decision", "decision_source", "outcome", "tool_name", "type"]);
      expect(s.event.type).toBe("tool_call");
      expect(s.event.decision).toBe("observed");
      expect(s.event.decision_source).toBe("n/a");
    }
    expect(RECEIVER_GATE).toBeNull();
  });

  it("builds span 0's canonical span exactly as written by hand, and args_hash is its sha256", () => {
    const { spans } = mapTraceBody(vec("t0-shape.pb"), PB);
    const want = t0Canonical(0, "");
    expect(spans[0]!.canonical.toString("utf8")).toBe(want);
    expect(spans[0]!.event.args_hash).toBe("sha256:" + sha(want));
  });

  it("puts status ERROR in span 3's canonical span as code 2 with its message", () => {
    const { spans } = mapTraceBody(vec("t0-shape.pb"), PB);
    const want = t0Canonical(3, '"status":{"code":2,"message":"b481 planned failure"},');
    expect(spans[3]!.canonical.toString("utf8")).toBe(want);
    expect(spans[3]!.event.args_hash).toBe("sha256:" + sha(want));
  });

  it("gives the same canonical bytes for protobuf, gzip and JSON (attributes reversed, defaults written out)", () => {
    const p = mapTraceBody(vec("t0-shape.pb"), PB).spans;
    const g = mapTraceBody(vec("t0-shape.pb.gz"), PB, "gzip").spans;
    const j = mapTraceBody(vec("t0-shape.json"), "application/json").spans;
    expect(g.map((s) => s.canonical.toString("hex"))).toEqual(p.map((s) => s.canonical.toString("hex")));
    expect(j.map((s) => s.canonical.toString("hex"))).toEqual(p.map((s) => s.canonical.toString("hex")));
    const pm = mapTraceBody(vec("mixed.pb"), PB).spans.map((s) => s.event);
    const jm = mapTraceBody(vec("mixed.json"), "application/json").spans.map((s) => s.event);
    expect(jm).toEqual(pm);
  });

  it("leaves fields it does not know out of the canonical span", () => {
    const t0 = mapTraceBody(vec("t0-shape.pb"), PB).spans[0]!;
    expect(mapTraceBody(vec("unknown-fields.pb"), PB).spans[0]!.event.args_hash).toBe(t0.event.args_hash);
    expect(mapTraceBody(vec("unknown-fields.json"), "application/json").spans[0]!.event.args_hash).toBe(t0.event.args_hash);
  });

  it("names a span by gen_ai.tool.name only when gen_ai.operation.name is execute_tool and each appears once", () => {
    const { spans } = mapTraceBody(vec("mixed.pb"), PB);
    expect(spans.map((s) => s.event.tool_name)).toEqual([
      "otel.span:GET /items",
      "otel.span:execute_tool",
      "otel.span:execute_tool twice",
      "search",
      "otel.span:every value type",
      "otel.span:chat gpt-x",
      OTLP_SPAN_TOOL_PREFIX,
      "fetch",
    ]);
  });

  it("maps status ERROR to errored and every other code (UNSET, OK, an undefined 3) to executed", () => {
    const { spans } = mapTraceBody(vec("mixed.pb"), PB);
    expect(spans.map((s) => s.event.outcome)).toEqual(["executed", "executed", "executed", "executed", "executed", "executed", "errored", "errored"]);
    expect(mapTraceBody(vec("quirks.pb"), PB).spans[0]!.event.outcome).toBe("errored");
  });

  it("counts spans across resourceSpans and scopeSpans in wire order", () => {
    const req = decodeTraceProtobuf(vec("mixed.pb"));
    expect(mapTraceRequest(req).map((s) => s.index)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it("maps a request with no spans to no events", () => {
    expect(mapTraceBody(vec("empty.pb"), PB).spans).toEqual([]);
  });

  it("maps nothing when the request is refused", () => {
    let caught: unknown;
    try {
      mapTraceBody(vec("neg-trace-id-zero.pb"), PB);
    } catch (e) {
      caught = e;
    }
    if (caught !== undefined && !(caught instanceof OtlpDecodeError)) throw caught;
    expect(caught).toBeInstanceOf(OtlpDecodeError);
    expect((caught as OtlpDecodeError).reason).toBe("trace_id_invalid");
  });
});

describe("the canonical span", () => {
  const one = (span: Record<string, unknown>, extra: Record<string, unknown> = {}): DecodedTraceRequest =>
    decodeTraceJson(Buffer.from(JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: "11".repeat(16), spanId: "22".repeat(8), ...span }] }], ...extra }] })));
  const canon = (r: DecodedTraceRequest): string => mapTraceRequest(r)[0]!.canonical.toString("utf8");
  const IDS = '"spanId":"2222222222222222","traceId":"11111111111111111111111111111111"';

  it("is a bare span with only its ids when everything else is at its default", () => {
    expect(canon(one({}))).toBe('{"resourceSpans":[{"scopeSpans":[{"spans":[{' + IDS + "}]}]}]}");
    expect(canon(one({ name: "", kind: 0, flags: 0, startTimeUnixNano: "0", attributes: [], events: [], links: [], status: {}, droppedAttributesCount: 0 }, { resource: {}, schemaUrl: "" })))
      .toBe('{"resourceSpans":[{"scopeSpans":[{"spans":[{' + IDS + "}]}]}]}");
  });

  it("sorts attributes by key, and a repeated key by its value, whatever the arrival order", () => {
    const a = canon(one({ attributes: [{ key: "b", value: { stringValue: "2" } }, { key: "a", value: { intValue: "1" } }, { key: "b", value: { stringValue: "1" } }] }));
    const b = canon(one({ attributes: [{ key: "b", value: { stringValue: "1" } }, { key: "b", value: { stringValue: "2" } }, { key: "a", value: { intValue: "1" } }] }));
    expect(a).toBe(b);
    expect(a).toContain('"attributes":[{"key":"a","value":{"intValue":"1"}},{"key":"b","value":{"stringValue":"1"}},{"key":"b","value":{"stringValue":"2"}}]');
  });

  it("keeps an AnyValue's member even at its default, and writes the empty value as {}", () => {
    const c = canon(one({ attributes: [
      { key: "s", value: { stringValue: "" } }, { key: "i", value: { intValue: "0" } }, { key: "f", value: { boolValue: false } },
      { key: "d", value: { doubleValue: 0 } }, { key: "e", value: {} }, { key: "a", value: { arrayValue: {} } }, { key: "k", value: { kvlistValue: { values: [] } } },
    ] }));
    expect(c).toContain('"attributes":[{"key":"a","value":{"arrayValue":{}}},{"key":"d","value":{"doubleValue":0}},{"key":"e","value":{}},{"key":"f","value":{"boolValue":false}},{"key":"i","value":{"intValue":"0"}},{"key":"k","value":{"kvlistValue":{}}},{"key":"s","value":{"stringValue":""}}]');
  });

  it("writes NaN and the infinities as strings and keeps kvlist and array order", () => {
    const c = canon(one({ attributes: [{ key: "x", value: { arrayValue: { values: [{ doubleValue: "NaN" }, { doubleValue: "-Infinity" }, { kvlistValue: { values: [{ key: "z", value: { boolValue: true } }, { key: "a", value: { stringValue: "y" } }] } }] } } }] }));
    expect(c).toContain('{"key":"x","value":{"arrayValue":{"values":[{"doubleValue":"NaN"},{"doubleValue":"-Infinity"},{"kvlistValue":{"values":[{"key":"z","value":{"boolValue":true}},{"key":"a","value":{"stringValue":"y"}}]}}]}}}');
  });

  it("holds resource, scope, schema URLs, events and links in OTLP/JSON form", () => {
    const c = canon(one(
      { events: [{ timeUnixNano: "5", name: "e", attributes: [{ key: "q", value: { stringValue: "r" } }] }, {}], links: [{ traceId: "33".repeat(16), spanId: "44".repeat(8), flags: 256 }], droppedLinksCount: 1 },
      { resource: { attributes: [{ key: "service.name", value: { stringValue: "svc" } }], droppedAttributesCount: 2 }, schemaUrl: "https://x/1" },
    ));
    expect(c).toBe(
      '{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"svc"}}],"droppedAttributesCount":2},' +
      '"schemaUrl":"https://x/1","scopeSpans":[{"spans":[{"droppedLinksCount":1,' +
      '"events":[{"attributes":[{"key":"q","value":{"stringValue":"r"}}],"name":"e","timeUnixNano":"5"},{}],' +
      '"links":[{"flags":256,"spanId":"4444444444444444","traceId":"33333333333333333333333333333333"}],' + IDS + "}]}]}]}",
    );
  });

  it("sorts event and link attributes too, whatever their arrival order", () => {
    const ev = (attrs: Array<[string, string]>) => ({ events: [{ name: "e", attributes: attrs.map(([key, v]) => ({ key, value: { stringValue: v } })) }], links: [{ traceId: "33".repeat(16), spanId: "44".repeat(8), attributes: attrs.map(([key, v]) => ({ key, value: { stringValue: v } })) }] });
    const a = canon(one(ev([["b", "2"], ["a", "1"]])));
    const b = canon(one(ev([["a", "1"], ["b", "2"]])));
    expect(a).toBe(b);
    expect(a).toContain('"events":[{"attributes":[{"key":"a","value":{"stringValue":"1"}},{"key":"b","value":{"stringValue":"2"}}],"name":"e"}]');
    expect(a).toContain('"links":[{"attributes":[{"key":"a","value":{"stringValue":"1"}},{"key":"b","value":{"stringValue":"2"}}],');
  });

  it("writes flags 0xffffffff as 4294967295 from protobuf and from JSON", () => {
    const p = mapTraceBody(vec("flags-max.pb"), PB).spans[0]!;
    const j = mapTraceBody(vec("flags-max.json"), "application/json").spans[0]!;
    expect(p.canonical.toString("utf8")).toContain('"flags":4294967295,');
    expect(j.canonical.toString("hex")).toBe(p.canonical.toString("hex"));
  });

  it("writes a double -0 as 0, as JCS does (so -0 and 0 give one canonical span)", () => {
    const neg = canon(one({ attributes: [{ key: "z", value: { doubleValue: -0 } }] }));
    const pos = canon(one({ attributes: [{ key: "z", value: { doubleValue: 0 } }] }));
    expect(neg).toBe(pos);
    expect(neg).toContain('{"key":"z","value":{"doubleValue":0}}');
  });

  it("feeds request_commitment through the existing tool_call descriptor (tool and args_hash only)", () => {
    const { spans } = mapTraceBody(vec("t0-shape.pb"), PB);
    const e = spans[0]!.event;
    const want = "sha256:" + sha(`{"args_hash":"${e.args_hash}","class":"tool_call","tool":"lookup"}`);
    expect(requestCommitment(e)).toBe(want);
  });
});
