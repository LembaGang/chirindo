// Receipt result_hash is RFC 8785 JCS over the MCP tool result value — NOT
// SHA-256 of the raw JSON-RPC response bytes. Same canonicalization-bug
// class as args_hash: without JCS, two byte-different but value-identical
// downstream responses (e.g. differing key order in `{ content, isError }`)
// produce different result_hashes, breaking an independent verifier's
// ability to recompute the hash from the parsed result. The recorder's
// `resultHash` helper is the single canonicalization path; this test pins
// that property.
//
// Two assertions, parallel to receipt-args-canonical.test.ts:
//   1. buildEvent produces the same result_hash for two key orderings of
//      a semantically-identical result object.
//   2. A receipt written by appendReceipt recomputes byte-identically via
//      the recorder's `resultHash` helper given the raw result value —
//      the recomputability property an independent verifier relies on.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  parseChainJsonl,
  resultHash,
} from "../src/vendor/recorder/index.js";
import { appendReceipt, buildEvent } from "../src/receipt.js";
import {
  cleanupTmpDir,
  initIdentity,
  makeTmpDir,
} from "./helpers.js";

describe("receipt result_hash — JCS canonicalization (recomputable)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("buildEvent yields the same result_hash regardless of result key order", async () => {
    const identity = await initIdentity(tmp);
    // Same semantic content, different key orderings — these are the two
    // shapes a JSON serializer (downstream MCP server, recorder, verifier)
    // could produce for the same result value. JCS must collapse them.
    const a = {
      content: [{ type: "text", text: "echo: hello" }],
      isError: false,
    };
    const b = {
      isError: false,
      content: [{ text: "echo: hello", type: "text" }],
    };
    const eventA = buildEvent({
      chainPath: "",
      sessionId: "x",
      identity,
      server: "fs",
      toolName: "echo",
      toolArgs: { text: "hello" },
      toolResult: a,
      decision: { kind: "allow" },
    });
    const eventB = buildEvent({
      chainPath: "",
      sessionId: "x",
      identity,
      server: "fs",
      toolName: "echo",
      toolArgs: { text: "hello" },
      toolResult: b,
      decision: { kind: "allow" },
    });
    expect(eventA.result_hash).toBe(eventB.result_hash);
    // And matches the recorder's helper — same canonicalization path
    // everywhere (the source-of-truth property).
    expect(eventA.result_hash).toBe(resultHash(a));
  });

  it("a gate-written receipt's result_hash recomputes via the recorder's resultHash", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const result = {
      content: [{ type: "text", text: "ok" }],
      isError: false,
    };
    appendReceipt({
      chainPath,
      sessionId: "sess-canon-result",
      identity,
      server: "fs",
      toolName: "echo",
      toolArgs: { text: "ok" },
      toolResult: result,
      decision: { kind: "allow" },
    });
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const written = file.records[0]!;
    if (written.event.type !== "mcp_call") throw new Error("expected mcp_call");
    // Independent recompute: given the raw result, a verifier derives the
    // same bytes the gate wrote — byte-for-byte.
    expect(written.event.result_hash).toBe(resultHash(result));
    // Key reorder still recomputes — the whole point of JCS.
    expect(written.event.result_hash).toBe(
      resultHash({
        isError: false,
        content: [{ text: "ok", type: "text" }],
      }),
    );
  });

  it("deny-path receipt has no result_hash (no downstream response was generated)", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain-deny.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-deny",
      identity,
      server: "fs",
      toolName: "delete",
      toolArgs: { path: "/etc" },
      decision: { kind: "deny", reason: "policy" },
    });
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const written = file.records[0]!;
    if (written.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(written.event.result_hash).toBeUndefined();
  });
});
