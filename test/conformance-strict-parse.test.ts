// Conformance: the frozen corpus's strict_parse vectors must fail closed.
//
// Each vector's `input` is raw JSON text fed verbatim to the strict-ingest
// gate; `expected_reason` is the StrictJsonParseError.reason it must reject
// with BEFORE any hash is produced. Driving the vectors straight from
// vectors-v1.json (not a local copy) means the gate and the frozen corpus
// cannot silently drift: if either changes, this test breaks.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  StrictJsonParseError,
  strictJsonParse,
} from "../src/vendor/recorder/index.js";

interface StrictParseVector {
  name: string;
  input: string;
  expected_reason: string;
  note?: string;
}

const CORPUS = join(
  import.meta.dirname,
  "..",
  "conformance",
  "vectors-v1.json",
);

const vectors: StrictParseVector[] = JSON.parse(
  readFileSync(CORPUS, "utf8"),
).strict_parse;

describe("conformance strict_parse vectors — gate fails closed", () => {
  it("the corpus actually carries the two REJECT vectors", () => {
    expect(vectors.map((v) => v.name)).toEqual([
      "SP1_unsafe_integer_REJECT",
      "SP2_duplicate_member_REJECT",
    ]);
  });

  for (const v of vectors) {
    it(`${v.name} -> REJECT (${v.expected_reason})`, () => {
      let thrown: unknown;
      try {
        strictJsonParse(v.input);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(StrictJsonParseError);
      expect((thrown as StrictJsonParseError).reason).toBe(v.expected_reason);
    });
  }
});
