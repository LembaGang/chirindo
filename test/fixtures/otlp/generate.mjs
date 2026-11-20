#!/usr/bin/env node
// B-481 T1: the OTLP trace test vectors, generated deterministically with no
// dependency. The protobuf encoder here is written separately from the decoder
// under test (src/otlp/decode.ts), so the tests compare two implementations.
//
//   node test/fixtures/otlp/generate.mjs --check <dir>   compare with <dir>, write nothing
//   node test/fixtures/otlp/generate.mjs --write <dir>   write the vectors into <dir>
//
// buildVectors() returns every vector that is a pure function of this file:
// name -> Buffer. The two gzip vectors (t0-shape.pb.gz, bomb.pb.gz) are not
// rebuilt by it: gzip output depends on the zlib build and on the platform (the
// gzip header's OS byte), so they are committed bytes, pinned by sha256 in
// vectors.json, and checked by what they inflate to (gzipSources()).
//
// Ids are the first bytes of sha256 over a label; times are fixed; the span
// shapes follow what T0 F2 saw the stock SDKs send (7 spans "execute_tool
// lookup", gen_ai.operation.name, gen_ai.tool.name, an int attribute, kind 1,
// flags 257, one span with status ERROR).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const id = (label, n) => createHash("sha256").update(label).digest().subarray(0, n);

// ---------------------------------------------------------------- protobuf encoder
function varint(x) {
  let n = BigInt.asUintN(64, BigInt(x));
  const out = [];
  do {
    let b = Number(n & 0x7fn);
    n >>= 7n;
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return Buffer.from(out);
}
const tag = (f, wt) => varint((BigInt(f) << 3n) | BigInt(wt));
const fVarint = (f, x) => Buffer.concat([tag(f, 0), varint(x)]);
const fLen = (f, buf) => Buffer.concat([tag(f, 2), varint(buf.length), buf]);
const fStr = (f, s) => fLen(f, Buffer.from(s, "utf8"));
const fFixed64 = (f, x) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(x)); return Buffer.concat([tag(f, 1), b]); };
const fFixed32 = (f, x) => { const b = Buffer.alloc(4); b.writeUInt32LE(x); return Buffer.concat([tag(f, 5), b]); };
const fDouble = (f, x) => { const b = Buffer.alloc(8); b.writeDoubleLE(x); return Buffer.concat([tag(f, 1), b]); };
const cat = (...parts) => Buffer.concat(parts.flat().filter(Boolean));

// values: { s } string, { b } bool, { i } int64 (bigint), { d } double,
// { a: [values] } array, { k: [[key, value]] } kvlist, { y: Buffer } bytes, {} empty
function pbAny(v) {
  if ("s" in v) return fStr(1, v.s);
  if ("b" in v) return fVarint(2, v.b ? 1 : 0);
  if ("i" in v) return fVarint(3, v.i);
  if ("d" in v) return fDouble(4, v.d);
  if ("a" in v) return fLen(5, cat(v.a.map((x) => fLen(1, pbAny(x)))));
  if ("k" in v) return fLen(6, cat(v.k.map(([key, x]) => fLen(1, pbKv(key, x)))));
  if ("y" in v) return fLen(7, v.y);
  return Buffer.alloc(0);
}
const pbKv = (key, v) => cat(fStr(1, key), fLen(2, pbAny(v)));
const pbAttrs = (f, attrs) => (attrs ?? []).map(([k, v]) => fLen(f, pbKv(k, v)));

function pbSpan(s) {
  return cat(
    s.traceId && fLen(1, s.traceId),
    s.spanId && fLen(2, s.spanId),
    s.traceState && fStr(3, s.traceState),
    s.parentSpanId && fLen(4, s.parentSpanId),
    fStr(5, s.name),
    s.kind && fVarint(6, s.kind),
    fFixed64(7, s.start),
    fFixed64(8, s.end),
    pbAttrs(9, s.attrs),
    s.droppedAttributes && fVarint(10, s.droppedAttributes),
    (s.events ?? []).map((e) => fLen(11, cat(fFixed64(1, e.time), fStr(2, e.name), pbAttrs(3, e.attrs)))),
    s.droppedEvents && fVarint(12, s.droppedEvents),
    (s.links ?? []).map((l) => fLen(13, cat(fLen(1, l.traceId), fLen(2, l.spanId), l.traceState && fStr(3, l.traceState), pbAttrs(4, l.attrs), l.flags && fFixed32(6, l.flags)))),
    s.droppedLinks && fVarint(14, s.droppedLinks),
    s.status && fLen(15, cat(s.status.message && fStr(2, s.status.message), s.status.code && fVarint(3, s.status.code))),
    s.flags && fFixed32(16, s.flags),
    s.extraPb,
  );
}
function pbRequest(req) {
  return cat(req.map((rs) => fLen(1, cat(
    fLen(1, cat(pbAttrs(1, rs.resource), rs.extraResourcePb)),
    rs.scopes.map((ss) => fLen(2, cat(
      fLen(1, cat(fStr(1, ss.name), ss.version && fStr(2, ss.version), pbAttrs(3, ss.attrs))),
      ss.spans.map((s) => fLen(2, pbSpan(s))),
      ss.schemaUrl && fStr(3, ss.schemaUrl),
    ))),
    rs.schemaUrl && fStr(3, rs.schemaUrl),
  ))));
}

// ---------------------------------------------------------------- JSON encoder
// The same request as OTLP/JSON. `shuffle` reverses every attribute list and
// writes some fields at their default explicitly, so the JSON bytes differ from
// any canonical form while meaning the same request.
function jAny(v) {
  if ("s" in v) return { stringValue: v.s };
  if ("b" in v) return { boolValue: v.b };
  if ("i" in v) return { intValue: v.i.toString() };
  if ("d" in v) return { doubleValue: Number.isNaN(v.d) ? "NaN" : v.d };
  if ("a" in v) return { arrayValue: { values: v.a.map(jAny) } };
  if ("k" in v) return { kvlistValue: { values: v.k.map(([key, x]) => ({ key, value: jAny(x) })) } };
  if ("y" in v) return { bytesValue: v.y.toString("base64") };
  return {};
}
function jAttrs(attrs, shuffle) {
  const a = (attrs ?? []).map(([key, v]) => ({ key, value: jAny(v) }));
  return shuffle ? a.reverse() : a;
}
function jSpan(s, shuffle) {
  const o = {
    traceId: s.traceId.toString("hex"),
    spanId: s.spanId.toString("hex"),
    parentSpanId: s.parentSpanId ? s.parentSpanId.toString("hex") : (shuffle ? "" : undefined),
    traceState: s.traceState,
    flags: s.flags,
    name: s.name,
    kind: s.kind,
    startTimeUnixNano: s.start.toString(),
    endTimeUnixNano: s.end.toString(),
    attributes: jAttrs(s.attrs, shuffle),
    droppedAttributesCount: s.droppedAttributes ?? (shuffle ? 0 : undefined),
    events: s.events?.map((e) => ({ timeUnixNano: e.time.toString(), name: e.name, attributes: jAttrs(e.attrs, shuffle) })),
    droppedEventsCount: s.droppedEvents,
    links: s.links?.map((l) => ({ traceId: l.traceId.toString("hex"), spanId: l.spanId.toString("hex"), traceState: l.traceState, attributes: jAttrs(l.attrs, shuffle), flags: l.flags })),
    droppedLinksCount: s.droppedLinks,
    status: s.status ? { message: s.status.message, code: s.status.code } : (shuffle ? {} : undefined),
    ...(s.extraJson ?? {}),
  };
  return o;
}
function jRequest(req, shuffle) {
  return {
    resourceSpans: req.map((rs) => ({
      resource: { attributes: jAttrs(rs.resource, shuffle), ...(shuffle ? { droppedAttributesCount: 0 } : {}) },
      scopeSpans: rs.scopes.map((ss) => ({
        scope: { name: ss.name, version: ss.version, attributes: ss.attrs ? jAttrs(ss.attrs, shuffle) : undefined },
        spans: ss.spans.map((s) => jSpan(s, shuffle)),
        schemaUrl: ss.schemaUrl ?? (shuffle ? "" : undefined),
      })),
      schemaUrl: rs.schemaUrl,
      ...(rs.extraJson ?? {}),
    })),
  };
}
const jsonBytes = (o) => Buffer.from(JSON.stringify(o, null, 2) + "\n", "utf8");

// ---------------------------------------------------------------- the requests
const T0 = 1794755843144000000n;
const RESOURCE = [
  ["service.name", { s: "b481-t1-vector" }],
  ["telemetry.sdk.language", { s: "nodejs" }],
  ["telemetry.sdk.name", { s: "opentelemetry" }],
  ["telemetry.sdk.version", { s: "2.2.0" }],
];
function t0Shape() {
  const traceId = id("b481-t1 trace t0-shape", 16);
  const spans = [];
  for (let i = 0; i < 7; i++) {
    spans.push({
      traceId,
      spanId: id(`b481-t1 span t0-shape ${i}`, 8),
      name: "execute_tool lookup",
      kind: 1,
      flags: 257,
      start: T0 + BigInt(i) * 1000000n,
      end: T0 + BigInt(i) * 1000000n + 496800n,
      attrs: [
        ["gen_ai.operation.name", { s: "execute_tool" }],
        ["gen_ai.tool.name", { s: "lookup" }],
        ["b481.i", { i: BigInt(i) }],
      ],
      status: i === 3 ? { code: 2, message: "b481 planned failure" } : undefined,
    });
  }
  return [{ resource: RESOURCE, scopes: [{ name: "b481", version: "1.0.0", spans }] }];
}

function mixed() {
  const tA = id("b481-t1 trace mixed A", 16);
  const tB = id("b481-t1 trace mixed B", 16);
  const sp = (n) => id(`b481-t1 span mixed ${n}`, 8);
  const base = (n, extra) => ({ traceId: tA, spanId: sp(n), start: T0 + BigInt(n) * 10n, end: T0 + BigInt(n) * 10n + 5n, ...extra });
  const allValues = [
    ["z.last", { s: "sorted last" }],
    ["a.empty_string", { s: "" }],
    ["b.bool_false", { b: false }],
    ["c.int_negative", { i: -42n }],
    ["c.int_max", { i: 9223372036854775807n }],
    ["d.double", { d: 3.25 }],
    ["d.double_nan", { d: NaN }],
    ["e.array", { a: [{ s: "x" }, { i: 1n }, { a: [{ b: true }] }, {}] }],
    ["e.array_empty", { a: [] }],
    ["f.kvlist", { k: [["zz", { s: "kept in wire order" }], ["aa", { d: -0.5 }]] }],
    ["g.bytes", { y: Buffer.from([0, 1, 2, 250, 251, 252]) }],
    ["h.empty_value", {}],
    ["i.unicode", { s: "naïve € 😀" }],
  ];
  return [
    {
      resource: [["service.name", { s: "b481-t1-mixed" }], ["host.name", { s: "vector-host" }]],
      schemaUrl: "https://opentelemetry.io/schemas/1.37.0",
      scopes: [
        {
          name: "scope-one",
          version: "0.1.0",
          attrs: [["scope.attr", { s: "one" }]],
          schemaUrl: "https://opentelemetry.io/schemas/1.36.0",
          spans: [
            // 0: a plain span with no gen_ai attributes -> otel.span:<name>
            base(0, { name: "GET /items", kind: 3, attrs: [["http.request.method", { s: "GET" }]] }),
            // 1: execute_tool without gen_ai.tool.name -> otel.span:<name>
            base(1, { name: "execute_tool", kind: 1, attrs: [["gen_ai.operation.name", { s: "execute_tool" }]] }),
            // 2: gen_ai.tool.name twice -> otel.span:<name>
            base(2, { name: "execute_tool twice", attrs: [["gen_ai.operation.name", { s: "execute_tool" }], ["gen_ai.tool.name", { s: "a" }], ["gen_ai.tool.name", { s: "b" }]] }),
            // 3: a tool name with status OK -> executed
            base(3, { name: "execute_tool search", parentSpanId: sp(0), traceState: "vendor=value", attrs: [["gen_ai.tool.name", { s: "search" }], ["gen_ai.operation.name", { s: "execute_tool" }]], status: { code: 1 } }),
            // 4: status code 3 (not defined) -> executed; every value type; events; links; dropped counts
            base(4, {
              name: "every value type",
              kind: 2,
              flags: 1,
              attrs: allValues,
              droppedAttributes: 2,
              events: [{ time: T0 + 41n, name: "second by wire order", attrs: [["k", { s: "v" }]] }, { time: T0 + 40n, name: "first by time" }],
              droppedEvents: 1,
              links: [{ traceId: tB, spanId: sp(9), traceState: "x=y", attrs: [["link.attr", { i: 7n }]], flags: 256 }],
              droppedLinks: 3,
              status: { code: 3, message: "not a defined code" },
            }),
          ],
        },
        {
          name: "scope-two",
          spans: [
            // 5: gen_ai.operation.name other than execute_tool -> otel.span:<name>
            base(5, { name: "chat gpt-x", attrs: [["gen_ai.operation.name", { s: "chat" }], ["gen_ai.tool.name", { s: "ignored" }]] }),
            // 6: execute_tool with an empty tool name -> otel.span:<name>
            base(6, { name: "", attrs: [["gen_ai.operation.name", { s: "execute_tool" }], ["gen_ai.tool.name", { s: "" }]], status: { code: 2 } }),
          ],
        },
      ],
    },
    {
      resource: [],
      scopes: [{ name: "", spans: [base(7, { traceId: tB, name: "execute_tool fetch", attrs: [["gen_ai.operation.name", { s: "execute_tool" }], ["gen_ai.tool.name", { s: "fetch" }]], status: { code: 2, message: "boom" } })] }],
    },
  ];
}

// A request with fields this decoder does not know (counted, not hashed).
function unknownFields() {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  r[0].scopes[0].spans[0].extraPb = cat(fVarint(99, 5), fStr(100, "future"));
  r[0].scopes[0].spans[0].extraJson = { futureField: 5, futureText: "future" };
  r[0].extraResourcePb = fLen(3, fStr(2, "service"));
  r[0].extraJson = { futureResourceSpansField: true };
  return r;
}

function nest(levels) {
  let v = { s: "bottom" };
  for (let i = 1; i < levels; i++) v = { a: [v] };
  return v;
}
function nestKv(levels) {
  let v = { s: "bottom" };
  for (let i = 1; i < levels; i++) v = { k: [["k", v]] };
  return v;
}
function deepKv(levels) {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  r[0].scopes[0].spans[0].attrs = [["deep", nestKv(levels)]];
  return r;
}
// One span with flags 0xffffffff (all 32 bits; read unsigned).
function flagsMax() {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  r[0].scopes[0].spans[0].flags = 0xffffffff;
  return r;
}
// Link ids of 3 and 1 bytes: L7 covers a span's own ids only, so this is accepted.
function linkOdd() {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  r[0].scopes[0].spans[0].links = [{ traceId: Buffer.from([1, 2, 3]), spanId: Buffer.from([4]) }];
  return r;
}
// Unknown fields inside an ArrayValue and a KeyValueList (each counted once).
function unknownInValues() {
  const traceId = id("b481-t1 trace unknown-in-values", 16);
  const arr = fLen(5, cat(fLen(1, fStr(1, "x")), fVarint(9, 1)));
  const kvl = fLen(6, cat(fLen(1, pbKv("a", { s: "b" })), fVarint(9, 1)));
  const spanBody = cat(fLen(1, traceId), fLen(2, id("b481-t1 span unknown-in-values 0", 8)), fStr(5, "u"),
    fFixed64(7, T0), fFixed64(8, T0 + 1n),
    fLen(9, cat(fStr(1, "arr"), fLen(2, arr))), fLen(9, cat(fStr(1, "kvl"), fLen(2, kvl))));
  return fLen(1, cat(fLen(2, cat(fLen(1, fStr(1, "q")), fLen(2, spanBody)))));
}
// AnyValue string_value (1) then string_value_strindex (8, opentelemetry-proto
// v1.10.0+, profiles only): the strindex member replaces the oneof, so the value
// is empty; and a KeyValue with key_strindex (3) beside its key (counted, key kept).
function strindex() {
  const traceId = id("b481-t1 trace strindex", 16);
  const spanBody = cat(fLen(1, traceId), fLen(2, id("b481-t1 span strindex 0", 8)), fStr(5, "p"),
    fFixed64(7, T0), fFixed64(8, T0 + 1n),
    fLen(9, cat(fStr(1, "s"), fLen(2, cat(fStr(1, "dropped by strindex"), fVarint(8, 3))))),
    fLen(9, cat(fStr(1, "k"), fVarint(3, 4), fLen(2, fStr(1, "v")))));
  return fLen(1, cat(fLen(2, cat(fLen(1, fStr(1, "q")), fLen(2, spanBody)))));
}
function deep(levels) {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  r[0].scopes[0].spans[0].attrs = [["deep", nest(levels)]];
  return r;
}
function mutate(fn) {
  const r = t0Shape();
  r[0].scopes[0].spans = r[0].scopes[0].spans.slice(0, 1);
  fn(r[0].scopes[0].spans[0]);
  return pbRequest(r);
}

// Protobuf quirks: an AnyValue holding two oneof members (the later one wins),
// and a Status sent as two fields (protobuf merges them).
function quirks() {
  const traceId = id("b481-t1 trace quirks", 16);
  const spanBody = cat(
    fLen(1, traceId), fLen(2, id("b481-t1 span quirks 0", 8)), fStr(5, "quirks"),
    fFixed64(7, T0), fFixed64(8, T0 + 1n),
    fLen(9, cat(fStr(1, "two.members"), fLen(2, cat(fStr(1, "first"), fVarint(3, 12))))),
    fLen(15, fStr(2, "message from the first status field")),
    fLen(15, fVarint(3, 2)),
  );
  return fLen(1, cat(fLen(1, Buffer.alloc(0)), fLen(2, cat(fLen(1, fStr(1, "q")), fLen(2, spanBody)))));
}

export function buildVectors() {
  const v = {};
  v["t0-shape.pb"] = pbRequest(t0Shape());
  v["t0-shape.json"] = jsonBytes(jRequest(t0Shape(), true));
  v["mixed.pb"] = pbRequest(mixed());
  v["mixed.json"] = jsonBytes(jRequest(mixed(), true));
  v["unknown-fields.pb"] = pbRequest(unknownFields());
  v["unknown-fields.json"] = jsonBytes(jRequest(unknownFields(), false));
  v["deep-64.pb"] = pbRequest(deep(64));
  v["deep-64.json"] = jsonBytes(jRequest(deep(64), false));
  v["quirks.pb"] = quirks();
  v["empty.pb"] = Buffer.alloc(0);
  v["empty.json"] = jsonBytes({});
  v["deep-kv-64.pb"] = pbRequest(deepKv(64));
  v["deep-kv-64.json"] = jsonBytes(jRequest(deepKv(64), false));
  v["flags-max.pb"] = pbRequest(flagsMax());
  v["flags-max.json"] = jsonBytes(jRequest(flagsMax(), false));
  v["link-ids-odd.pb"] = pbRequest(linkOdd());
  v["unknown-in-values.pb"] = unknownInValues();
  v["strindex.pb"] = strindex();
  // negatives
  const t0 = v["t0-shape.pb"];
  v["neg-truncated.pb"] = t0.subarray(0, t0.length - 1);
  v["neg-wire-type.pb"] = mutate((s) => { s.extraPb = fVarint(5, 1); });
  v["neg-trace-id-short.pb"] = mutate((s) => { s.traceId = s.traceId.subarray(0, 15); });
  v["neg-trace-id-zero.pb"] = mutate((s) => { s.traceId = Buffer.alloc(16); });
  v["neg-span-id-missing.pb"] = mutate((s) => { s.spanId = undefined; });
  v["neg-parent-short.pb"] = mutate((s) => { s.parentSpanId = Buffer.from([1, 2, 3, 4]); });
  v["neg-utf8.pb"] = mutate((s) => { s.extraPb = fLen(3, Buffer.from([0x61, 0xff, 0x62])); });
  v["neg-deep-65.pb"] = pbRequest(deep(65));
  v["neg-group.pb"] = cat(tag(1, 3), tag(1, 4));
  v["neg-varint-11.pb"] = cat(tag(1, 0), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]));
  v["neg-not-gzip.pb.gz"] = Buffer.from("this is not gzip\n", "utf8");
  const j = (o) => jsonBytes(o);
  const js = () => jRequest([{ ...t0Shape()[0], scopes: [{ ...t0Shape()[0].scopes[0], spans: t0Shape()[0].scopes[0].spans.slice(0, 1) }] }], false);
  v["neg-dup-member.json"] = Buffer.from('{"resourceSpans":[],"resourceSpans":[]}\n', "utf8");
  v["neg-unsafe-int.json"] = Buffer.from(j(js()).toString("utf8").replace(`"startTimeUnixNano": "${T0}"`, `"startTimeUnixNano": ${T0}`), "utf8");
  v["neg-enum-string.json"] = Buffer.from(j(js()).toString("utf8").replace('"kind": 1', '"kind": "SPAN_KIND_INTERNAL"'), "utf8");
  v["neg-two-members.json"] = Buffer.from(j(js()).toString("utf8").replace('"stringValue": "lookup"', '"stringValue": "lookup", "intValue": "1"'), "utf8");
  v["neg-bad-hex.json"] = Buffer.from(j(js()).toString("utf8").replace(/"traceId": "[0-9a-f]{32}"/, '"traceId": "zz' + "0".repeat(30) + '"'), "utf8");
  v["neg-utf8.json"] = Buffer.concat([Buffer.from('{"resourceSpans":[{"schemaUrl":"', "utf8"), Buffer.from([0xc3, 0x28]), Buffer.from('"}]}\n', "utf8")]);
  v["neg-deep-65.json"] = jsonBytes(jRequest(deep(65), false));
  v["neg-not-json.json"] = Buffer.from("{\"resourceSpans\": [\n", "utf8");
  v["neg-span-id-zero.pb"] = mutate((s) => { s.spanId = Buffer.alloc(8); });
  v["neg-parent-zero.pb"] = mutate((s) => { s.parentSpanId = Buffer.alloc(8); });
  v["neg-varint-10th-byte.pb"] = mutate((s) => { s.extraPb = cat(tag(6, 0), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02])); });
  v["neg-field-zero.pb"] = mutate((s) => { s.extraPb = Buffer.from([0x00, 0x01]); });
  v["neg-deep-kv-65.pb"] = pbRequest(deepKv(65));
  v["neg-deep-kv-65.json"] = jsonBytes(jRequest(deepKv(65), false));
  v["neg-lone-surrogate.json"] = Buffer.from(j(js()).toString("utf8").replace('"name": "execute_tool lookup"', '"name": "\\ud800"'), "utf8");
  v["neg-null-root.json"] = Buffer.from("null\n", "utf8");
  return v;
}

// What each committed gzip vector must inflate to.
export function gzipSources() {
  return {
    "t0-shape.pb.gz": pbRequest(t0Shape()),
    "bomb.pb.gz": Buffer.alloc(16 * 1024 * 1024 + 1),
  };
}

const norm = (p) => (process.platform === "win32" ? resolve(p).toLowerCase() : resolve(p));
if (process.argv[1] && norm(fileURLToPath(import.meta.url)) === norm(process.argv[1])) {
  const [mode, dir] = process.argv.slice(2);
  if ((mode !== "--check" && mode !== "--write") || !dir) {
    console.error("usage: node generate.mjs --check <dir> | --write <dir>");
    process.exit(2);
  }
  const v = buildVectors();
  let bad = 0;
  for (const [name, buf] of Object.entries(v)) {
    const sha = createHash("sha256").update(buf).digest("hex");
    if (mode === "--write") {
      writeFileSync(join(dir, name), buf);
      console.log(`GEN WROTE ${name} ${buf.length} ${sha}`);
    } else {
      const p = join(dir, name);
      const same = existsSync(p) && Buffer.compare(readFileSync(p), buf) === 0;
      if (!same) bad++;
      console.log(`GEN ${same ? "SAME" : "DIFFERENT"} ${name} ${buf.length} ${sha}`);
    }
  }
  console.log(`GEN SUMMARY ${Object.keys(v).length} vectors, ${bad} different`);
  process.exit(bad ? 1 : 0);
}
