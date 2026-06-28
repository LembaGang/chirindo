// Receipt args_hash is RFC 8785 JCS over the arguments value — NOT
// JSON.stringify. The property under test is key-order independence: the
// same logical arguments object hashed at the gate must equal the same
// arguments hashed independently by any verifier. Without this property the
// recomputability of every gate receipt is silently broken when JSON
// serializers disagree on key order.
//
// Two assertions here:
//   1. The same arguments in two key orders produce the same args_hash via
//      buildEvent — the gate's hot path.
//   2. A receipt written to disk by appendReceipt recomputes byte-identically
//      via the recorder's argsHash helper (the same call a verifier would
//      make if given the raw arguments).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { argsHash, parseChainJsonl } from "../src/vendor/recorder/index.js";
import { appendReceipt, buildEvent } from "../src/receipt.js";
import {
  cleanupTmpDir,
  initIdentity,
  makeTmpDir,
} from "./helpers.js";

describe("receipt args_hash — JCS canonicalization (recomputable)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("buildEvent yields the same args_hash regardless of arguments' key order", async () => {
    const identity = await initIdentity(tmp);
    const a = { path: "/etc", recursive: true, depth: 5 };
    const b = { recursive: true, depth: 5, path: "/etc" };
    const eventA = buildEvent({
      chainPath: "", // unused by buildEvent
      sessionId: "x",
      identity,
      server: "fs",
      toolName: "list",
      toolArgs: a,
      decision: { kind: "allow" },
    });
    const eventB = buildEvent({
      chainPath: "",
      sessionId: "x",
      identity,
      server: "fs",
      toolName: "list",
      toolArgs: b,
      decision: { kind: "allow" },
    });
    expect(eventA.args_hash).toBe(eventB.args_hash);
    // And matches the recorder's helper — same canonicalization path
    // everywhere (the source-of-truth property).
    expect(eventA.args_hash).toBe(argsHash(a));
  });

  it("a gate-written receipt's args_hash recomputes via the recorder's argsHash", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const args = { query: "foo", limit: 10 };
    appendReceipt({
      chainPath,
      sessionId: "sess-canon",
      identity,
      server: "fs",
      toolName: "search",
      toolArgs: args,
      decision: { kind: "allow" },
    });
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const written = file.records[0]!;
    if (written.event.type !== "mcp_call") throw new Error("expected mcp_call");
    // Independent recompute: a verifier given the raw arguments derives the
    // same bytes the gate wrote — byte-for-byte.
    expect(written.event.args_hash).toBe(argsHash(args));
    // Key reorder still recomputes — the whole point of JCS.
    expect(written.event.args_hash).toBe(argsHash({ limit: 10, query: "foo" }));
  });
});
