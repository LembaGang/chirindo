// kid = RFC 7638 thumbprint (spec G).
//
// New identities emit kid == the bare thumbprint, so a consumer can cross-check
// kid against the JWK by construction. Legacy "ed25519/<fp>" kids still verify
// read-only, and a chain that SPANS the migration (record 0 legacy /0, record 1
// thumbprint /1, same key) still verifies — kidMatchesKey accepts either scheme.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appendRecordLine,
  defaultIssuer,
  genesisPrevHash,
  jcsBytes,
  kidMatchesKey,
  legacyKid,
  loadFullIdentity,
  makeKid,
  parseChainJsonl,
  requestCommitment,
  rfc7638Thumbprint,
  runVerify,
  signEd25519,
  writeIdentity,
  type McpCallEvent,
  type RecordContent,
  type SignedRecord,
} from "../src/vendor/recorder/index.js";
import { generateKeyPair } from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "legacy-v0");

describe("kid = RFC 7638 thumbprint (spec G)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("new identities emit kid == the bare thumbprint (no ed25519/ prefix)", async () => {
    const identity = await initIdentity(tmp);
    const tp = rfc7638Thumbprint(identity.publicKey);
    expect(identity.kid).toBe(tp);
    expect(identity.kid.startsWith("ed25519/")).toBe(false);
    // makeKid agrees with the thumbprint.
    expect(makeKid(identity.publicKey)).toBe(tp);
  });

  it("kidMatchesKey accepts both schemes and rejects a foreign kid", () => {
    const { publicKey } = generateKeyPair();
    const other = generateKeyPair().publicKey;
    expect(kidMatchesKey(publicKey, rfc7638Thumbprint(publicKey))).toBe(true);
    expect(kidMatchesKey(publicKey, legacyKid(publicKey))).toBe(true);
    expect(kidMatchesKey(publicKey, rfc7638Thumbprint(other))).toBe(false);
    expect(kidMatchesKey(publicKey, "ed25519/deadbeef1234")).toBe(false);
  });

  it("the legacy /0 fixture uses an ed25519/ kid and still verifies VALID", () => {
    const rec = parseChainJsonl(
      readFileSync(join(FIXTURE_DIR, "chain.jsonl"), "utf8"),
    ).records[0]!;
    expect(rec.kid.startsWith("ed25519/")).toBe(true);
    const result = runVerify({
      chainPath: join(FIXTURE_DIR, "chain.jsonl"),
      identityPath: join(FIXTURE_DIR, "identity.json"),
    });
    expect(result.kind).toBe("valid");
  });

  it("a mixed-scheme chain (legacy /0 then thumbprint /1, same key) verifies", () => {
    // Same key signs both records; only the kid representation and record
    // version differ across the migration boundary.
    const { privateKey, publicKey } = generateKeyPair();
    writeIdentity(tmp, privateKey, publicKey); // identity.json kid == thumbprint
    const identity = loadFullIdentity(
      join(tmp, "identity.json"),
      join(tmp, "private-key.pem"),
    );
    const chainPath = join(tmp, "chain.jsonl");
    const sessionId = "sess-mixed-scheme";

    // Record 0: hand-built v0 with the LEGACY kid, signed by the same key.
    const event0: McpCallEvent = {
      type: "mcp_call",
      outcome: "executed",
      server: "files",
      tool_name: "echo",
      args_hash: "sha256:" + "0".repeat(64),
      decision: "allow",
      decision_source: "config",
    };
    const content0: RecordContent = {
      v: "evidence.action/0",
      seq: 0,
      session_id: sessionId,
      ts: "2026-01-01T09:00:00.000Z",
      agent: { vendor: "chirindo", version: "0.0.1" },
      event: event0,
      request_commitment: requestCommitment(event0),
      gate: null,
      prev_hash: genesisPrevHash(sessionId, "evidence.action/0"),
      kid: legacyKid(publicKey),
    };
    const sig0 = signEd25519(privateKey, jcsBytes(content0));
    const record0: SignedRecord = { ...content0, sig: sig0 };
    appendRecordLine(chainPath, record0);

    // Record 1: a normal v1 receipt appended by the current code path, which
    // links to record 0 and stamps the THUMBPRINT kid + key binding.
    appendReceipt({
      chainPath,
      sessionId,
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      decision: { kind: "allow" },
      ts: "2026-01-01T09:00:01.000Z",
    });

    // Sanity: the two records really do use different kid schemes + versions.
    const recs = parseChainJsonl(readFileSync(chainPath, "utf8")).records;
    expect(recs[0]!.v).toBe("evidence.action/0");
    expect(recs[0]!.kid.startsWith("ed25519/")).toBe(true);
    expect(recs[1]!.v).toBe("evidence.action/1");
    expect(recs[1]!.kid).toBe(rfc7638Thumbprint(publicKey));
    expect(recs[1]!.kid.startsWith("ed25519/")).toBe(false);

    // The chain verifies despite spanning the kid-scheme migration.
    const result = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(result.kind).toBe("valid");
    if (result.kind === "valid") expect(result.count).toBe(2);
  });
});

// `defaultIssuer` is imported for parity with the production record shape but
// the mixed-scheme record 0 is v0 (no iss); silence unused-import lints by
// referencing it in a trivial assertion.
describe("defaultIssuer sanity", () => {
  it("derives the jwks_uri origin", () => {
    expect(defaultIssuer("tp", "https://a.example/jwks.json")).toBe(
      "https://a.example",
    );
  });
});
