// Each check in check.mjs, shown failing on a one-byte change to the file it
// reads, and the committed files shown passing. Run from the repo root:
//
//   node --test examples/ordering-evidence/test/
//
// The file name deliberately does not match vitest's default include
// (*.test.*, *.spec.*), so the root `npm test` does not pick it up.
// Node built-ins only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const EXAMPLE = join(dirname(fileURLToPath(import.meta.url)), "..");
const CHECK = join(EXAMPLE, "check.mjs");

function freshCopy() {
  const root = mkdtempSync(join(tmpdir(), "ordering-evidence-"));
  for (const d of ["case-a", "case-b", "keys"]) cpSync(join(EXAMPLE, d), join(root, d), { recursive: true });
  return root;
}

function caseFile(root, c, key) {
  const manifest = JSON.parse(readFileSync(join(root, c, "case.json"), "utf8"));
  return join(root, c, key.split(".").reduce((o, k) => o[k], manifest));
}

// Change exactly one byte. `anchor` is either a string (the byte right after
// its first occurrence changes) or a function (text) => byte offset. The byte
// becomes `to` (or "e" if it already is `to`). Asserts the file length is
// unchanged and exactly one byte differs.
function flipAfter(path, anchor, to) {
  const before = readFileSync(path);
  let at;
  if (typeof anchor === "function") {
    at = anchor(before.toString("utf8"));
  } else {
    const i = before.indexOf(anchor);
    assert.ok(i >= 0, `anchor ${anchor} not found in ${path}`);
    at = i + Buffer.byteLength(anchor);
  }
  assert.ok(at >= 0 && at < before.length, `no offset to change in ${path}`);
  const after = Buffer.from(before);
  const replacement = after[at] === to.charCodeAt(0) ? "e" : to;
  after[at] = replacement.charCodeAt(0);
  writeFileSync(path, after);
  let diff = 0;
  for (let k = 0; k < before.length; k++) if (before[k] !== after[k]) diff++;
  assert.equal(after.length, before.length);
  assert.equal(diff, 1);
}

// Each case is checked on its own (--case), so a change to one case's files is
// judged by that case's checks and not masked by the other case.
function run(root, c) {
  const r = spawnSync(process.execPath, [CHECK, "--root", root, "--case", c.slice("case-".length)], { encoding: "utf8" });
  return { code: r.status, out: r.stdout + r.stderr };
}

function expectFail(out, checkId) {
  const line = out.split(/\r?\n/).find((l) => l.includes(` ${checkId}:`));
  assert.ok(line, `no output line for ${checkId}\n${out}`);
  assert.match(line, /^FAIL /, `expected ${checkId} to FAIL\n${out}`);
}

for (const c of ["case-a", "case-b"]) {
  test(`green: committed ${c} files, every check passes`, () => {
    const root = freshCopy();
    try {
      const { code, out } = run(root, c);
      assert.equal(code, 0, out);
      assert.doesNotMatch(out, /^FAIL /m, out);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

// transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s):
// nonce is the 6th 32-byte word after the 4-byte selector. Offset of its last
// hex digit inside the saved transaction file.
function nonceInInput(text) {
  const input = JSON.parse(text).input;
  const nonceHex = input.slice(10 + 5 * 64, 10 + 6 * 64);
  return text.indexOf(input) + 10 + 5 * 64 + nonceHex.length - 1;
}

// Last hex digit of the AuthorizationUsed log's nonce topic (topics[2]).
function nonceInLog(text) {
  const rcpt = JSON.parse(text);
  const log = rcpt.logs.find((l) => l.topics[0] === AUTHORIZATION_USED_TOPIC);
  const topic = log.topics[2];
  const i = text.indexOf(`"${topic}"`, text.indexOf(AUTHORIZATION_USED_TOPIC));
  return i + topic.length;
}

const AUTHORIZATION_USED_TOPIC = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5";

const cases = [
  { name: "receipt: one byte of the record's tool_name", c: "case-b", file: "hash_chain", anchor: '"tool_name":"mock_swa', to: "q", check: "b.receipt-signature" },
  { name: "hash chain: one byte of the record's prev_hash", c: "case-b", file: "hash_chain", anchor: '"prev_hash":"sha256:', to: "0", check: "b.hash-chain-links" },
  { name: "inclusion: one byte of the checkpoint's last_entry_hash", c: "case-b", file: "witness_sidecar", anchor: '"last_entry_hash":"sha256:', to: "0", check: "b.inclusion" },
  { name: "checkpoint: one byte of the checkpoint's ts", c: "case-b", file: "witness_sidecar", anchor: '"ts":"20', to: "3", check: "b.checkpoint-signature" },
  { name: "witness receipt: one byte of received_at", c: "case-b", file: "witness_sidecar", anchor: '"received_at":"20', to: "3", check: "b.witness-signature" },
  { name: "Case A receipt: one byte of the record's tool_name", c: "case-a", file: "hash_chain", anchor: '"tool_name":"mock_swa', to: "q", check: "a.receipt-signature" },
  { name: "Case A witness receipt: one byte of received_at", c: "case-a", file: "witness_sidecar", anchor: '"received_at":"20', to: "3", check: "a.witness-signature" },
  { name: "transaction input: one byte of the input", c: "case-a", file: "transaction.tx_file", anchor: nonceInInput, to: "f", check: "a.tx-nonce" },
  { name: "log: one byte of the AuthorizationUsed nonce topic", c: "case-a", file: "transaction.receipt_file", anchor: nonceInLog, to: "f", check: "a.log-nonce" },
  { name: "pre-seal transaction: one byte of its input", c: "case-a", file: "transaction.preseal.tx_file", anchor: nonceInInput, to: "f", check: "a.preseal-agrees" },
  { name: "pre-seal receipt: one byte of its AuthorizationUsed nonce topic", c: "case-a", file: "transaction.preseal.receipt_file", anchor: nonceInLog, to: "f", check: "a.preseal-agrees" },
];

for (const t of cases) {
  test(`red: ${t.name} -> ${t.check} FAIL`, () => {
    const root = freshCopy();
    try {
      flipAfter(caseFile(root, t.c, t.file), t.anchor, t.to);
      const { code, out } = run(root, t.c);
      assert.equal(code, 1, out);
      expectFail(out, t.check);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
