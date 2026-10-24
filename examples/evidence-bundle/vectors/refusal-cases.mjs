// The bundles of test/refusals.mjs: one per class of the shape this build
// refuses, each built so that every check that runs before the refusing
// property passes, and one FAILS twin for each decoded-shape path whose member
// checks can fail in code that WE-1, the vectors and the sweep do not reach.
// Every key here is a throwaway test key (vectors/synth.mjs).

import { encodeFunctionData } from "viem";
import { jcsSha256, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { ENTRYPOINTS, headerHash } from "../../ordering-evidence-h4/lib/evm.mjs";
import { member } from "../lib/we1.mjs";
import { byId, r15, setBytes, textOf, PAY_CONTRACT, we1 } from "./make-vectors.mjs";
import {
  annexBLog,
  authorization,
  callData,
  checkpoint,
  chirindoLog,
  eip3009Logs,
  gateReceipt,
  instruction,
  issuerProfile,
  json,
  jwksOf,
  placeInBlock,
  pretty,
  q,
  ROUTER_ABI,
  sidecarLine,
  signedTx,
  singleAccountTrie,
  testAccount,
  testAddress,
  testEd,
  testSecp,
  testValue,
} from "./synth.mjs";

export const T0 = 1792000000n;
const JSONL = "application/x-ndjson";
const TIME = "2026-10-20T10:00:00Z";
export const add = (doc, m) => {
  const x = member({ source: "examples/evidence-bundle/vectors/refusal-cases.mjs", fetched_at: TIME, capture: "reconstructed-from examples/evidence-bundle/vectors/synth.mjs", media_type: "application/json", ...m });
  if (m.issuer_profile) x.issuer_profile = m.issuer_profile;
  doc.members.push(x);
};

export const payerPk = testSecp("payer");
export const payer = testAccount("payer");
export const facilitatorPk = testSecp("facilitator");
export const payee = testAddress("payee");

// WE-1's stated inputs, for the cases that keep WE-1's payment.
export const A_STATED = ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"];

export function we1Parts() {
  const doc = we1();
  const logA = JSON.parse(textOf(byId(doc, "log-a")).trim());
  const blk = JSON.parse(textOf(byId(doc, "blk-a")));
  return { doc, logA, hA: jcsSha256(withoutMember(logA, "sig")).slice(7), blk, argsDigest: logA.event.args_hash };
}

// The test payer and a payment's hash as the stated inputs.
export const stated = (txHash) => ["--authorizer", payer.address, "--tx", txHash];

// Puts a payment (transaction, receipt, block) in place of WE-1's.
export function usePayment(doc, p, carriedAs, chainId = 84532) {
  setBytes(doc, "tx-a", pretty(p.tx));
  setBytes(doc, "rc-a", pretty(p.receipt));
  setBytes(doc, "blk-a", pretty(p.block));
  doc.subject.chain_id = `eip155:${chainId}`;
  doc.subject.tx_hash = p.tx.hash;
  doc.subject.carried_as = carriedAs;
}

// A synthetic EIP-3009 payment of the test payer, signed by test keys.
export async function eipPayment(blk, o = {}) {
  const chainId = o.chainId ?? 84532;
  const a = await authorization({
    token: PAY_CONTRACT,
    chainId,
    from: payer.address,
    to: payee,
    value: o.value ?? 10000n,
    validAfter: T0 - 600n,
    validBefore: o.validBefore ?? T0 + 600n,
    nonce: o.nonce,
    signerPk: o.signerPk ?? payerPk,
    receive: o.kind === "receive9",
  });
  const input = callData(o.kind ?? "twa9", a) + (o.trailer ?? "");
  const tx = await signedTx({ type: o.type ?? "0x2", chainId, senderPk: o.senderPk ?? facilitatorPk, to: PAY_CONTRACT, input, authorizationList: o.authorizationList });
  const logs = eip3009Logs(PAY_CONTRACT, { ...a, from: a.from.toLowerCase(), to: a.to.toLowerCase() });
  return { a, logs, ...placeInBlock({ tx, logs, baseBlock: blk, timestamp: T0, parentHash: o.parentHash, stateRoot: o.stateRoot, number: o.number }) };
}

// One hex digit of the transaction's input changed, the member digest recomputed.
function editTxInput(doc) {
  const tx = JSON.parse(textOf(byId(doc, "tx-a")));
  const last = tx.input.slice(-1);
  tx.input = tx.input.slice(0, -1) + (last === "0" ? "1" : "0");
  setBytes(doc, "tx-a", pretty(tx));
}

// A test-key log added beside log-a, with its operator key.
export function addTestLog(doc, { label, sessionId, ...o }) {
  const k = testEd(label);
  const log = chirindoLog({ k, sessionId, ...o });
  add(doc, { id: `log-${label}`, role: "gate-log", profile: "chirindo-evidence.action/1", bytes: log.bytes, media_type: JSONL });
  add(doc, { id: `opkey-${label}`, role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  return { k, log };
}

async function t01() {
  const { doc, logA } = we1Parts();
  const ins = instruction({ principal: testEd("principal"), agentKid: logA.kid, payee: payee.toLowerCase(), token: PAY_CONTRACT });
  add(doc, { id: "ins-t", role: "instruction", profile: "signed-instruction-ed25519/0.2", bytes: json(ins) });
  return { doc, args: A_STATED, ins };
}

// Each case: id; code (the refusal expected), fails (the check or binding
// whose FAIL gives the verdict FAILS) or, for a case of a shape judged since,
// judged (the verdict and states it gives, as test/refusals.mjs reads them);
// build() -> { doc, args }.
const OFFLINE = ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"];
const UNSUPPORTED_CALL = { verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unsupported-call"], checks: [["M5.call", "tx-a", "PASS"]], bindings: { "B-PAY": ["UNSUPPORTED-PATH", "unsupported-call"] }, limitsHave: ["L20"], decision: "allow" };
export const CASES = [
  {
    id: "T-01",
    judged: { verdict: OFFLINE, bindings: { "B-INS": ["UNBOUND-OUTSIDE", null] }, checks: [["M6.instruction", "ins-t", "PASS"]], instructions: { "ins-t": ["UNBOUND-OUTSIDE", ["payees"], null] }, limitsHave: ["L12", "L13", "L18"] },
    build: t01,
  },
  {
    id: "T-02",
    judged: { verdict: OFFLINE, checks: [["M8.result", "result-t", "PASS"], ["M8.arguments", "args-a", "PASS"]], bindings: { "B-PAY": ["BOUND", null], "B-INS": ["ABSENT", null] } },
    build: async () => {
      const { doc, argsDigest } = we1Parts();
      const value = { note: "TEST FIXTURE result", ok: true };
      addTestLog(doc, { label: "t02", sessionId: "test-t02", argsHash: argsDigest, resultHash: jcsSha256(value) });
      add(doc, { id: "result-t", role: "action-result", profile: "jcs-json", bytes: json(value) });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-03",
    judged: { verdict: OFFLINE, bindings: { "B-GRC": ["ABSENT", null], "B-PAY": ["BOUND", null] }, checks: [["M9.issuer-profile", "profile-t", "PASS"], ["M7.signer-key", "receipt-t", "PASS"], ["M2.log", "log-t03", "PASS"]], gateReceipts: { "receipt-t": ["SUPPLIED", null, ["context-receipt"], false] }, flagsHave: ["context-receipt", "test-profile"], limitsHave: ["L16"], decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      const gr = await gateReceipt(testSecp("issuer"));
      const k = testEd("t03");
      add(doc, { id: "log-t03", role: "gate-log", profile: "jcs-sha256-chain/0.1", bytes: annexBLog({ k, sessionId: "test-t03", receiptUid: gr.uid }).bytes, media_type: JSONL });
      add(doc, { id: "opkey-t03", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
      add(doc, { id: "profile-t", role: "issuer-profile", profile: "chirindo-h4-issuer-profile/1", bytes: json(issuerProfile(testAccount("issuer").address)) });
      add(doc, { id: "receipt-t", role: "gate-receipt", profile: "eip712-gate-receipt/0.1", issuer_profile: "profile-t", bytes: json(gr.sealed) });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-04",
    judged: { verdict: OFFLINE, checks: [["M3.checkpoint", "cp-a", "PASS"], ["M3.signature", "cp-a", "PASS"], ["M3.history", "cp-a", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      const line = JSON.parse(textOf(byId(doc, "sidecar-a")).trim());
      add(doc, { id: "cp-a", role: "checkpoint", profile: "witness-spec-0.5-checkpoint", bytes: json(line.checkpoint) });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-05",
    judged: { verdict: OFFLINE, checks: [["M4.witness-receipt", "wr-a", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      const line = JSON.parse(textOf(byId(doc, "sidecar-a")).trim());
      add(doc, { id: "wr-a", role: "witness-receipt", profile: "witness.checkpoint/1", bytes: json(line.witness_receipt) });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-06",
    judged: { verdict: OFFLINE, checks: [["M5.parent-block", "parent-t", "PASS"], ["M5.block-hash", "blk-a", "PASS"]], bindings: { "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const parent = { ...blk, number: q(49999999n), timestamp: q(T0 - 2n), transactions: [testValue("parent tx")] };
      delete parent.hash;
      parent.hash = headerHash(parent).recomputed;
      const p = await eipPayment(blk, { nonce: "0x" + hA, parentHash: parent.hash, number: 50000000n });
      usePayment(doc, p, "eip3009-nonce");
      add(doc, { id: "parent-t", role: "payment-parent-block", profile: "eth-rpc-json", bytes: pretty(parent) });
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-07",
    judged: { verdict: OFFLINE, checks: [["M5.account-proof", "proof-t", "PASS"]], bindings: { "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const trie = singleAccountTrie({ address: payer.address, balance: 50000n });
      const p = await eipPayment(blk, { nonce: "0x" + hA, stateRoot: trie.root });
      usePayment(doc, p, "eip3009-nonce");
      add(doc, { id: "proof-t", role: "account-proof", profile: "eth-proof-json", bytes: pretty({ block_hash: p.block.hash, result: trie.result }) });
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-08",
    judged: { verdict: OFFLINE, checks: [["M5.block-transactions", "btx-t", undefined]], bindings: { "B-PAY": ["BOUND", null] }, flagsHave: ["carried-transactions-mismatch"], decision: "allow" },
    build: async () => {
      const { doc, blk } = we1Parts();
      add(doc, { id: "btx-t", role: "payment-block-transactions", profile: "eth-raw-transactions", bytes: pretty({ block_hash: blk.hash, transactions: ["0x02c0"] }) });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-09",
    judged: { verdict: OFFLINE, checks: [["M1.member", "sup-t", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      add(doc, { id: "sup-t", role: "supporting", profile: "opaque", bytes: Buffer.from("TEST FIXTURE supporting document\n", "utf8"), media_type: "text/plain" });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-10",
    judged: { verdict: OFFLINE, checks: [["M2.log", "log-t10", "PASS"], ["M2.log", "log-a", "PASS"]], bindings: { "B-LOG": ["BOUND", null], "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null], "B-KEY": ["KEY-ONLY", null] }, decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      const k = testEd("t10");
      add(doc, { id: "log-t10", role: "gate-log", profile: "jcs-sha256-chain/0.1", bytes: annexBLog({ k, sessionId: "test-t10", n: 2 }).bytes, media_type: JSONL });
      add(doc, { id: "opkey-t10", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
      return { doc, args: A_STATED };
    },
  },
  ...[false, true].map((twin) => ({
    id: twin ? "T-11F" : "T-11",
    ...(twin ? { fails: "M9.operator-key" } : { judged: { verdict: OFFLINE, checks: [["M9.operator-key", "opkey-a", "PASS"], ["M2.log", "log-a", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" } }),
    build: async () => {
      const { doc } = we1Parts();
      const jwk = JSON.parse(textOf(byId(doc, "opkey-a"))).keys[0];
      if (twin) jwk.x = jwk.x.slice(0, 5) + (jwk.x[5] === "A" ? "B" : "A") + jwk.x.slice(6);
      setBytes(doc, "opkey-a", json(jwk));
      byId(doc, "opkey-a").profile = "jwk-okp-ed25519";
      return { doc, args: A_STATED };
    },
  })),
  {
    id: "T-12",
    code: "legacy-shape",
    build: async () => {
      const doc = r15();
      const w = we1();
      doc.members.unshift(byId(w, "log-a"), byId(w, "opkey-a"));
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-12F",
    fails: "M2.log",
    build: async () => {
      const doc = r15();
      const lines = textOf(byId(doc, "log-l")).split("\n");
      const r1 = JSON.parse(lines[1]);
      const ph = r1.prev_hash;
      r1.prev_hash = ph.slice(0, 20) + (ph[20] === "0" ? "1" : "0") + ph.slice(21);
      lines[1] = JSON.stringify(r1);
      setBytes(doc, "log-l", Buffer.from(lines.join("\n"), "utf8"));
      return { doc, args: A_STATED };
    },
  },
  ...[false, true].map((twin) => ({
    id: twin ? "T-13F" : "T-13",
    ...(twin ? { fails: "M2.log" } : { judged: { verdict: OFFLINE, checks: [["M2.log", "log-t13", "PASS"], ["M2.log", "log-a", "PASS"]], bindings: { "B-KEY": ["KEY-ONLY", null], "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" } }),
    build: async () => {
      const { doc, argsDigest } = we1Parts();
      addTestLog(doc, { label: twin ? "t13f" : "t13", sessionId: "test-t13", argsHash: argsDigest, jwksUri: `${twin ? "http" : "https"}://test-operator.invalid/.well-known/jwks.json` });
      return { doc, args: A_STATED };
    },
  })),
  {
    id: "T-14",
    judged: { verdict: OFFLINE, checks: [["M2.prefix", "log-a", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc } = we1Parts();
      doc.members.splice(1, 0, { ...byId(doc, "log-a"), id: "log-a2" });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-14F",
    fails: "M2.prefix",
    build: async () => {
      const { doc, argsDigest } = we1Parts();
      const { k } = addTestLog(doc, { label: "t14f", sessionId: "test-t14f", argsHash: argsDigest, n: 2 });
      const other = chirindoLog({ k, sessionId: "test-t14f", argsHash: argsDigest, n: 1, t0: Date.parse("2026-10-20T11:00:00.000Z") });
      add(doc, { id: "log-t14f-copy", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: other.bytes, media_type: JSONL });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-15",
    judged: { verdict: OFFLINE, checks: [["M3.history", "sidecar-t15", "PASS"]], bindings: { "B-CKP": ["BOUND", null], "B-WIT": ["SUPPLIED", null], "B-PAY": ["BOUND", null] }, decision: "allow" },
    build: async () => {
      const { doc, argsDigest } = we1Parts();
      const k = testEd("t15");
      const full = chirindoLog({ k, sessionId: "test-t15", argsHash: argsDigest, n: 2 });
      add(doc, { id: "log-t15", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: Buffer.from(JSON.stringify(full.records[0]) + "\n", "utf8"), media_type: JSONL });
      add(doc, { id: "opkey-t15", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
      add(doc, { id: "sidecar-t15", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: sidecarLine(checkpoint({ k, sessionId: "test-t15", count: 2, lastEntryHash: full.hashes[1] })), media_type: JSONL });
      return { doc, args: A_STATED };
    },
  },
  {
    id: "T-15F",
    fails: "M3.history",
    build: async () => {
      const { doc, argsDigest } = we1Parts();
      const { k } = addTestLog(doc, { label: "t15f", sessionId: "test-t15f", argsHash: argsDigest, n: 1 });
      add(doc, { id: "sidecar-t15f", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: sidecarLine(checkpoint({ k, sessionId: "test-t15f", count: 1, lastEntryHash: "sha256:" + testValue("not the log's entry hash").slice(2) })), media_type: JSONL });
      return { doc, args: A_STATED };
    },
  },
  ...[
    ["T-16", 8453],
    ["T-17", 1],
  ].map(([id, chainId]) => ({
    id,
    code: "chain",
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA, chainId });
      usePayment(doc, p, "eip3009-nonce", chainId);
      return { doc, args: stated(p.tx.hash) };
    },
  })),
  ...[
    ["T-18", "0x0"],
    ["T-19", "0x1"],
  ].flatMap(([id, type]) =>
    [false, true].map((twin) => ({
      id: twin ? `${id}F` : id,
      ...(twin ? { fails: "M5.transaction" } : { judged: { verdict: OFFLINE, checks: [["M5.transaction", "tx-a", "PASS"], ["M5.sender", "tx-a", "PASS"], ["M5.authorization", "tx-a", "PASS"]], bindings: { "B-PAY": ["BOUND", null] }, decision: "allow" } }),
      build: async () => {
        const { doc, blk, hA } = we1Parts();
        const p = await eipPayment(blk, { nonce: "0x" + hA, type });
        usePayment(doc, p, "eip3009-nonce");
        if (twin) editTxInput(doc);
        return { doc, args: stated(p.tx.hash) };
      },
    })),
  ),
  {
    id: "T-20",
    judged: { verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unsupported-type"], checks: [["M5.support", null, "NOT-EVALUATED"]], bindings: { "B-PAY": ["UNSUPPORTED-PATH", "unsupported-type"] }, decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA });
      // An unsupported type: M5.support is NOT EVALUATED, so no signature is read.
      const tx = { ...p.tx, type: "0x3", maxFeePerBlobGas: "0x1", blobVersionedHashes: [testValue("blob")], hash: testValue("a type 0x3 transaction") };
      const placed = placeInBlock({ tx, logs: p.logs, baseBlock: blk, timestamp: T0 });
      usePayment(doc, placed, "eip3009-nonce");
      return { doc, args: stated(placed.tx.hash) };
    },
  },
  {
    id: "T-21",
    fails: "M5.chain",
    build: async () => {
      const { doc, blk } = we1Parts();
      // A deposit as Base serves it: no chainId member, v 0x0, at index 0 of
      // WE-1's block. The values WE-1's block does not give are TEST
      // placeholders (this build makes no network read).
      const tx = {
        blockHash: blk.hash,
        blockNumber: blk.number,
        blockTimestamp: blk.timestamp,
        depositReceiptVersion: "0x1",
        from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
        gas: "0xf4240",
        gasPrice: "0x0",
        hash: blk.transactions[0],
        input: "0x098999be" + testValue("placeholder L1 attributes").slice(2),
        mint: "0x0",
        nonce: "0x1",
        r: "0x0",
        s: "0x0",
        sourceHash: testValue("placeholder sourceHash"),
        to: "0x4200000000000000000000000000000000000015",
        transactionIndex: "0x0",
        type: "0x7e",
        v: "0x0",
        value: "0x0",
        yParity: "0x0",
      };
      const receipt = { type: "0x7e", status: "0x1", cumulativeGasUsed: "0xab9e", logs: [], logsBloom: "0x" + "00".repeat(256), transactionHash: tx.hash, transactionIndex: "0x0", blockHash: blk.hash, blockNumber: blk.number, gasUsed: "0xab9e", effectiveGasPrice: "0x0", from: tx.from, to: tx.to, contractAddress: null, depositNonce: "0x1", depositReceiptVersion: "0x1" };
      setBytes(doc, "tx-a", pretty(tx));
      setBytes(doc, "rc-a", pretty(receipt));
      doc.subject.tx_hash = tx.hash;
      doc.subject.carried_as = "none";
      return { doc, args: stated(tx.hash) };
    },
  },
  ...[false, true].map((twin) => ({
    id: twin ? "T-22F" : "T-22",
    ...(twin ? { fails: "M5.transaction" } : { judged: { verdict: ["PAYMENT-NOT-VERIFIED", "V3", "account-has-code"], checks: [["M5.transaction", "tx-a", "PASS"], ["M5.sender", "tx-a", "PASS"]], bindings: { "B-PAY": ["NOT-EVALUATED", "account-has-code"] }, limitsHave: ["L23"], decision: "allow" } }),
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const tuple = await payer.signAuthorization({ address: testAddress("delegate contract"), chainId: 84532, nonce: 8 });
      const p = await eipPayment(blk, { nonce: "0x" + hA, type: "0x4", senderPk: payerPk, authorizationList: [tuple] });
      usePayment(doc, p, "eip3009-nonce");
      if (twin) editTxInput(doc);
      return { doc, args: stated(p.tx.hash) };
    },
  })),
  ...[
    ["T-23", "receive9"],
    ["T-24", "twaBytes64"],
    ["T-25", "twaBytes65"],
  ].map(([id, kind]) => ({
    id,
    ...(kind === "twaBytes65" ? { judged: { verdict: OFFLINE, checks: [["M5.call", "tx-a", "PASS"], ["M5.token-domain", null, "PASS"], ["M5.authorization", "tx-a", "PASS"], ["M5.token-logs", "rc-a", "PASS"], ["M5.validity-window", null, "PASS"]], bindings: { "B-PAY": ["BOUND", null] }, decision: "allow" } } : { judged: UNSUPPORTED_CALL }),
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA, kind });
      usePayment(doc, p, "eip3009-nonce");
      return { doc, args: stated(p.tx.hash) };
    },
  })),
  {
    id: "T-25F",
    fails: "M5.token-logs",
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA, kind: "twaBytes65" });
      p.receipt.logs[1].data = "0x" + (10001n).toString(16).padStart(64, "0");
      usePayment(doc, p, "eip3009-nonce");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-26",
    judged: UNSUPPORTED_CALL,
    build: async () => {
      const { doc, blk } = we1Parts();
      const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: payerPk, to: [...ENTRYPOINTS][1], input: callData("handleOps", null, { beneficiary: payer.address }) });
      const p = placeInBlock({ tx, logs: [], baseBlock: blk, timestamp: T0 });
      usePayment(doc, p, "none");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-27",
    judged: UNSUPPORTED_CALL,
    build: async () => {
      const { doc, blk } = we1Parts();
      const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: payerPk, to: null, input: "0x6080604052600080fd" });
      const p = placeInBlock({ tx, logs: [], baseBlock: blk, timestamp: T0 });
      usePayment(doc, p, "none");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  ...[false, true].map((twin) => ({
    id: twin ? "T-33" : "T-28",
    ...(twin ? { fails: "M5.transaction" } : { judged: { verdict: OFFLINE, checks: [["M5.call", "tx-a", "PASS"], ["M5.sender", "tx-a", "PASS"]], bindings: { "B-PAY": ["BOUND", null], "B-INS": ["ABSENT", null] }, limitsHave: ["L21"], decision: "allow" } }),
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: payerPk, to: testAddress("test contract"), value: 1n, input: encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: ["0x" + hA] }) });
      const p = placeInBlock({ tx, logs: [], baseBlock: blk, timestamp: T0 });
      usePayment(doc, p, "calldata");
      if (twin) editTxInput(doc);
      return { doc, args: stated(p.tx.hash) };
    },
  })),
  {
    id: "T-29",
    judged: { verdict: OFFLINE, bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, flagsHave: ["trailer"], decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: testValue("T-29 nonce"), trailer: hA + "80218021802180218021802180218021" });
      usePayment(doc, p, "calldata");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-30",
    judged: { verdict: ["PAYMENT-NOT-VERIFIED", "V3", "contract-signer"], checks: [["M5.authorization", "tx-a", "NOT-EVALUATED"]], bindings: { "B-PAY": ["NOT-EVALUATED", "contract-signer"] }, limitsHave: ["L23"], decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA, signerPk: testSecp("an account other than from") });
      usePayment(doc, p, "eip3009-nonce");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-31",
    judged: { verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unread-carrier"], bindings: { "B-PAY": ["NOT-EVALUATED", "unread-carrier"] }, decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: testValue("T-31 nonce"), validBefore: BigInt("0x" + hA) });
      usePayment(doc, p, "none");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-32",
    judged: { verdict: ["DOES-NOT-CONNECT", "V2"], bindings: { "B-PAY": ["NO-PAYMENT", null] }, decision: "allow" },
    build: async () => {
      const { doc, blk, hA } = we1Parts();
      const p = await eipPayment(blk, { nonce: "0x" + hA, value: 0n });
      usePayment(doc, p, "eip3009-nonce");
      return { doc, args: stated(p.tx.hash) };
    },
  },
  {
    id: "T-34",
    fails: "M6.instruction",
    build: async () => {
      const { doc, args, ins } = await t01();
      ins.sig = ins.sig.slice(0, 10) + (ins.sig[10] === "A" ? "B" : "A") + ins.sig.slice(11);
      setBytes(doc, "ins-t", json(ins));
      return { doc, args };
    },
  },
  {
    id: "T-35",
    fails: "M1.member",
    build: async () => {
      const { doc, args, ins } = await t01();
      ins.text = ins.text.replace("pay", "Pay");
      byId(doc, "ins-t").bytes_b64 = json(ins).toString("base64");
      return { doc, args };
    },
  },
  {
    id: "T-36",
    fails: "B-LOG",
    build: async () => {
      const { doc } = we1Parts();
      doc.subject.cites.seq = 1;
      return { doc, args: A_STATED };
    },
  },
];
