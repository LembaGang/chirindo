// src/member-names.ts: the fold the gate uses for member names, and the reader
// that finds a tools/call in a line as a case-insensitive decoder would.
//
// test/fixtures/go-json-fold.txt lists, for every code point whose fold under
// Go's encoding/json member-name matching is not itself, that fold (its header
// says how Go 1.24.7 wrote it). Two code points are the same to Go exactly
// when their folds are equal, so checking each listed code point against its
// fold covers every pair Go matches.

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ENVELOPE_MEMBERS,
  TOOLS_CALL_PARAMS_MEMBERS,
  caseVariant,
  foldCollision,
  foldName,
  toolsCallClaims,
} from "../src/member-names.js";

const GO_FOLD = join(resolve(import.meta.dirname, ".."), "test", "fixtures", "go-json-fold.txt");

describe("foldName", () => {
  it("folds every code point Go's encoding/json folds onto another to the same name as that one", () => {
    const pairs = readFileSync(GO_FOLD, "utf8")
      .split("\n")
      .filter((l) => l.length > 0 && !l.startsWith("#"))
      .map((l) => l.split(" ").map((h) => parseInt(h, 16)) as [number, number]);
    expect(pairs).toHaveLength(1454);
    const apart = pairs.filter(
      ([cp, fold]) => foldName(String.fromCodePoint(cp)) !== foldName(String.fromCodePoint(fold)),
    );
    expect(apart.map(([cp, fold]) => `${cp.toString(16)}->${fold.toString(16)}`)).toEqual([]);
  });

  it("matches the protocol names in any case, with U+017F for s and U+212A for k", () => {
    for (const v of ["Method", "METHOD", "mEtHoD"]) expect(foldName(v)).toBe(foldName("method"));
    expect(foldName("paramſ")).toBe(foldName("params"));
    expect(foldName("Key")).toBe(foldName("key"));
    expect(foldName("JSONRPC")).toBe(foldName("jsonrpc"));
    expect(foldName("_META")).toBe(foldName("_meta"));
    expect(foldName("method")).not.toBe(foldName("methods"));
  });

  it("folds U+0130 and U+0131 to i as well (Go does not; Java's equalsIgnoreCase does)", () => {
    expect(foldName("İd")).toBe(foldName("id"));
    expect(foldName("ıd")).toBe(foldName("id"));
  });
});

describe("caseVariant and foldCollision", () => {
  it("finds a member that is a protocol name in another case, never the exact name", () => {
    expect(caseVariant(["jsonrpc", "id", "Method", "params"], ENVELOPE_MEMBERS)).toEqual({
      key: "Method",
      of: "method",
    });
    expect(caseVariant(["jsonrpc", "id", "method", "params", "result"], ENVELOPE_MEMBERS)).toBeNull();
    expect(caseVariant(["name", "nAme"], TOOLS_CALL_PARAMS_MEMBERS)).toEqual({ key: "nAme", of: "name" });
  });

  it("finds two names that differ only in case", () => {
    expect(foldCollision(["a", "b", "A"])).toEqual(["a", "A"]);
    expect(foldCollision(["uri", "URI"])).toEqual(["uri", "URI"]);
    expect(foldCollision(["a", "b", "c"])).toBeNull();
  });
});

describe("toolsCallClaims", () => {
  it("reads the top-level members from the text, so a member a later duplicate overwrote still counts", () => {
    expect(toolsCallClaims('{"method":"tools/call"}')).toEqual([true]);
    expect(toolsCallClaims('{"Method":"tools/call"}')).toEqual([true]);
    expect(toolsCallClaims('{"method":"ping","METHOD":"tools/call"}')).toEqual([true]);
    expect(toolsCallClaims('{"method":"tools/call","method":"ping"}')).toEqual([true]);
    expect(toolsCallClaims('{ "id" : 1 , "metho\\u0064" : "tools\\/call" }')).toEqual([true]);
    expect(toolsCallClaims('{"method":"ping"}')).toEqual([false]);
    expect(toolsCallClaims('{"method":"TOOLS/CALL"}')).toEqual([false]);
    expect(toolsCallClaims('{"x":{"method":"tools/call"},"method":5}')).toEqual([false]);
    expect(toolsCallClaims('{"params":{"a":"}\\"{["},"method":"tools/call"}')).toEqual([true]);
    expect(toolsCallClaims("{}")).toEqual([false]);
  });

  it("answers per element for a top-level array, and with an empty list for any other value", () => {
    expect(
      toolsCallClaims('[{"method":"tools/call"}, 5, {"method":"ping"}, [{"method":"tools/call"}], {"Method":"tools/call"}]'),
    ).toEqual([true, false, false, false, true]);
    expect(toolsCallClaims("[]")).toEqual([]);
    expect(toolsCallClaims('"tools/call"')).toEqual([]);
    expect(toolsCallClaims("null")).toEqual([]);
  });
});
