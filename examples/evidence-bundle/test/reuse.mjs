// The code this folder reuses from examples/ordering-evidence-h4, unchanged,
// and the places where the spec's rule differs from it and this folder uses
// its own (spec D.1 and 4.1).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { txSerialization as h4TxSerialization, address } from "../../ordering-evidence-h4/lib/evm.mjs";
import { parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";
import { statedAddress, UsageError } from "../lib/cli.mjs";
import { txHashOf, txSerialization } from "../lib/tx.mjs";
import { REPO_ROOT } from "../lib/we1.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");
const tx = () => parseStrictJson(readFileSync(path.join(REPO_ROOT, "examples/ordering-evidence/case-a/rpc/transaction.sealed.json")));

test("the reused lib files are the committed ones", () => {
  assert.equal(sha(readFileSync(path.join(REPO_ROOT, "examples/ordering-evidence-h4/lib/formats.mjs"))), "c2586d58f689ae5e5456a988194d25ed5b3fe8fc254955cc95acdecf68b91da7");
  assert.equal(sha(readFileSync(path.join(REPO_ROOT, "examples/ordering-evidence-h4/lib/evm.mjs"))), "7253bb406e796ef8f01e2ad89b82ab62eeb9459ea81db710718ba4dc66a30a80");
});

test("spec D.1: a typed transaction with v or yParity alone recomputes, where the reused serializer needs both", () => {
  const full = tx();
  assert.equal(txHashOf(txSerialization(full)), full.hash);
  for (const drop of ["v", "yParity"]) {
    const t = { ...tx() };
    delete t[drop];
    assert.equal(txHashOf(txSerialization(t)), full.hash, `without ${drop}`);
    assert.throws(() => h4TxSerialization(t), /both v and yParity/);
  }
  const disagree = { ...tx(), v: "0x0" };
  assert.throws(() => txSerialization(disagree), /v and yParity differ/);
});

test("spec 4.1: the stated account is refused written all in upper case; lowercase and EIP-55 are read", () => {
  assert.equal(statedAddress("0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673"), "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673");
  assert.equal(statedAddress("0xe65e3de1493171dcf0a706a3f407d7ddb38c5673"), "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673");
  assert.throws(() => statedAddress("0xE65E3DE1493171DCF0A706A3F407D7DDB38C5673"), UsageError);
  // The reused address reader refuses it in a member too.
  assert.throws(() => address("0xE65E3DE1493171DCF0A706A3F407D7DDB38C5673", "x"));
});
