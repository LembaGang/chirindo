// jcs-json members (spec 4.1 and D.1): the bytes are checked strictly, the
// value is JSON.parse's, and the digest is SHA-256 over RFC 8785 (npm
// canonicalize 2.1.0). And the strict reading of the other members.

import assert from "node:assert/strict";
import { test } from "node:test";
import canonicalize from "canonicalize";
import { jcsJsonDigest } from "../lib/bundle.mjs";
import { parseChirindoLog } from "../lib/records.mjs";

const digest = (s) => jcsJsonDigest(Buffer.from(s, "utf8")).digest;

test("RFC 8785 number serialization (the numbers example of its section 3.2.2.3)", () => {
  assert.equal(canonicalize(JSON.parse("[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]")), "[333333333.3333333,1e+30,4.5,0.002,1e-27]");
  assert.equal(canonicalize({ b: 1e21, a: -0, c: 1e-7 }), '{"a":0,"b":1e+21,"c":1e-7}');
});

test("Case A's arguments hash to the record's args_hash, in every spelling of the same values", () => {
  const want = "sha256:7abf24ca72b407e2510f88c812b28f00845a4700f1263024cd0408a57732a659";
  assert.equal(digest('{"amount_in":0.25,"pair":"ETH/USDC","slippage_bps":50}'), want);
  assert.equal(digest('{"amount_in":2.5e-1,"pair":"ETH/USDC","slippage_bps":50}'), want);
  assert.equal(digest(' { "slippage_bps" : 50, "pair":"\\u0045TH/USDC", "amount_in":0.250 }\n'), want);
  assert.notEqual(digest('{"amount_in":0.26,"pair":"ETH/USDC","slippage_bps":50}'), want);
});

test("an integer above 2^53 is read as JSON.parse reads it, as the gate hashes it", () => {
  assert.equal(digest('{"n":9007199254740993}'), digest('{"n":9007199254740992}'));
});

test("the strict checks of the bytes: duplicate names, a lone surrogate, a byte order mark, bad UTF-8", () => {
  assert.throws(() => digest('{"a":1,"a":1}'), /duplicate/);
  assert.throws(() => digest('{"a":"\\ud800"}'), /surrogate/);
  assert.throws(() => jcsJsonDigest(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")])));
  assert.throws(() => jcsJsonDigest(Buffer.from([0x7b, 0xff, 0x7d])), /UTF-8/);
});

test("a log record is read strictly: an unsafe integer or a fraction is refused", () => {
  assert.throws(() => parseChirindoLog(Buffer.from('{"seq":0.5}\n')), /fraction/);
  const parsed = parseChirindoLog(Buffer.from('{"seq":9007199254740993}\n'));
  assert.equal(typeof parsed.records[0].seq, "bigint");
});
