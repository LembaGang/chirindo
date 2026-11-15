// B-481 T1: the committed OTLP trace vectors (test/fixtures/otlp/vectors.json).
// Each vector's bytes are pinned by sha256, rebuilt by generate.mjs (a separate
// encoder, no dependency) where they are a pure function of it, and decoded and
// mapped by src/otlp to the records the manifest pins; each negative vector is
// refused with the reason the manifest names.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { requestCommitment } from "../src/vendor/recorder/request.js";
import { OtlpDecodeError, mapTraceBody } from "../src/otlp/index.js";

const DIR = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "otlp");
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

interface Row {
  file: string;
  bytes: number;
  sha256: string;
  content_type: string;
  content_encoding: string | null;
  spans?: number;
  unknown_fields?: number;
  records?: Array<{ tool_name: string; outcome: string; args_hash: string; request_commitment: string }>;
  refused?: string;
}
const manifest = JSON.parse(readFileSync(join(DIR, "vectors.json"), "utf8")) as { vectors: Row[] };
const rows = manifest.vectors;

function run(row: Row, body: Buffer): { refused?: string; out?: ReturnType<typeof mapTraceBody> } {
  try {
    return { out: mapTraceBody(body, row.content_type, row.content_encoding ?? undefined) };
  } catch (e) {
    if (e instanceof OtlpDecodeError) return { refused: e.reason };
    throw e;
  }
}

describe("the vector set", () => {
  it("lists every file in the folder except the generator and itself, 47 in all, 19 accepted", () => {
    const files = readdirSync(DIR).filter((f) => f !== "generate.mjs" && f !== "vectors.json").sort();
    expect(rows.map((r) => r.file)).toEqual(files);
    expect(rows).toHaveLength(47);
    const accepted = rows.filter((r) => r.refused === undefined);
    expect(accepted).toHaveLength(19);
    expect(accepted.every((r) => run(r, readFileSync(join(DIR, r.file))).out !== undefined)).toBe(true);
  });

  it("is rebuilt byte for byte by generate.mjs, and the gzip vectors inflate to what it says", async () => {
    const gen = (await import(pathToFileURL(join(DIR, "generate.mjs")).href)) as {
      buildVectors: () => Record<string, Buffer>;
      gzipSources: () => Record<string, Buffer>;
    };
    const built = gen.buildVectors();
    const gz = gen.gzipSources();
    expect(Object.keys(built).length + Object.keys(gz).length).toBe(rows.length);
    for (const [name, buf] of Object.entries(built)) {
      expect(sha(readFileSync(join(DIR, name))), name).toBe(sha(buf));
    }
    for (const [name, src] of Object.entries(gz)) {
      expect(sha(gunzipSync(readFileSync(join(DIR, name)))), name).toBe(sha(src));
    }
    const t0 = mapTraceBody(built["t0-shape.pb"]!, "application/x-protobuf").spans;
    expect(t0).toHaveLength(7);
  });
});

for (const row of rows) {
  describe(`vector ${row.file}`, () => {
    it(row.refused !== undefined ? `is refused with ${row.refused}` : `maps to ${row.spans} records as pinned`, () => {
      const body = readFileSync(join(DIR, row.file));
      const r = run(row, body);
      expect(body.length).toBe(row.bytes);
      expect(sha(body)).toBe(row.sha256);
      if (row.refused !== undefined) {
        expect(r.refused).toBe(row.refused);
        return;
      }
      expect(r.refused).toBeUndefined();
      const out = r.out!;
      expect(out.spans).toHaveLength(row.spans!);
      expect(out.request.unknownFields).toBe(row.unknown_fields);
      expect(out.spans.map((s) => ({
        tool_name: s.event.tool_name,
        outcome: s.event.outcome,
        args_hash: s.event.args_hash,
        request_commitment: requestCommitment(s.event),
      }))).toEqual(row.records);
      for (const s of out.spans) expect("sha256:" + sha(s.canonical)).toBe(s.event.args_hash);
    });
  });
}
