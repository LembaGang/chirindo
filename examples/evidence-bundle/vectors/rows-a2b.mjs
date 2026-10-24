// The vectors of the payment shapes judged after the first build (spec D.5,
// offline): each a recipe built at run time, on WE-1's document, from the
// repository's own bytes and from throwaway test keys (vectors/synth.mjs).
// Nothing these keys sign is evidence of anything, and no transaction here was
// broadcast. vectors/make-vectors.mjs lists them after the evidence side's
// rows (vectors/rows-a2.mjs), in the order the shape was widened. S_t is the
// test payer, the stated account; F_t the test facilitator; C_t a test
// contract address; H the cited record's entry hash as 32 raw bytes.

import { encodeFunctionData, keccak256, toHex, toRlp } from "viem";
import { headerHash } from "../../ordering-evidence-h4/lib/evm.mjs";
import { txSerialization } from "../lib/tx.mjs";
import { jcsSha256, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { caseB, setBytes } from "./make-vectors.mjs";
import { add, eipPayment, facilitatorPk, payee, payer, payerPk, stated, T0, usePayment, we1Parts } from "./refusal-cases.mjs";
import { addReceipts, annexBCase, PERMIT, pinsFor, withPins } from "./rows-a2.mjs";
import { authorization, callData, chirindoLog, eip3009Logs, gateReceipt, instruction, json, jwksOf, placeInBlock, pretty, q, ROUTER_ABI, signedTx, singleAccountTrie, testAccount, testAddress, testEd, testSecp, testValue } from "./synth.mjs";

const F_T = testAccount("facilitator").address;
const C_T = testAddress("test contract");
const SYNTH = "synthetic: test keys of vectors/synth.mjs on WE-1's document, citing WE-1's record";
const v = (id, description, change, args, build, base = SYNTH) => ({ id, description, recipe: { base, change }, args, build });
const STATED = ["--authorizer", "<the test payer>", "--tx", "<the payment>"];

// A call to C_t that carries H as testPull's argument, sent by `senderPk` with
// `value` wei, of `type`, with the receipt's `logs`, in place of WE-1's payment.
async function calldataCase({ senderPk = payerPk, value = 0n, type = "0x2", logs = [], input, to = C_T, carriedAs = "calldata", authorizationList } = {}) {
  const { doc, blk, hA } = we1Parts();
  const data = typeof input === "function" ? input("0x" + hA) : input ?? encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: ["0x" + hA] });
  const tx = await signedTx({ type, chainId: 84532, senderPk, to, value, input: data, authorizationList });
  const p = placeInBlock({ tx, logs, baseBlock: blk, timestamp: T0 });
  usePayment(doc, p, carriedAs);
  return { doc, p, hA, blk, argv: stated(p.tx.hash) };
}

// Rows that need no widening: run on the shape of A2a's build, before any
// widening of this part, as regression rows.
export const ROWS_B0 = [
  ...[
    ["S-03", "F_t", F_T],
    ["S-04", "S_t", payer.address],
  ].map(([id, who, a]) =>
    v(id, `S-01 with subject.expected_authorizer ${who}: FAILS (M0.bundle)`, `F_t sends value 0 to C_t, calldata holds H; carried_as calldata; subject.expected_authorizer ${who}`, STATED, async () => {
      const c = await calldataCase({ senderPk: facilitatorPk });
      c.doc.subject.expected_authorizer = a;
      return c;
    }),
  ),
  v("S-19a", "a payment block of 17 header fields (through withdrawalsRoot): M5.block-hash PASS", "an EIP-3009 payment of the test payer whose nonce is H, in a block whose header ends at withdrawalsRoot, its hash recomputed", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const base = { ...blk };
    for (const f of ["blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"]) delete base[f];
    const p = await eipPayment(base, { nonce: "0x" + hA });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-19b", "a payment block with blobGasUsed absent and excessBlobGas present: FAILS (M5.block-hash)", "S-19a's payment in a block whose header has excessBlobGas without blobGasUsed; its hash the one recomputed with blobGasUsed present", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const p = await eipPayment(blk, { nonce: "0x" + hA });
    const block = { ...p.block };
    delete block.blobGasUsed;
    // The gap makes the header unreadable: the hash stays the one of the full header.
    usePayment(doc, p, "eip3009-nonce");
    setBytes(doc, "blk-a", pretty(block));
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-97", "WE-1 stated with a test contract address C_t: DOES-NOT-CONNECT", "WE-1 with --authorizer C_t (a test contract address whose code the bundle does not carry)", ["--authorizer", "<C_t>", "--tx", "<WE-1's transaction>"], async () => {
    const { doc } = we1Parts();
    return { doc, argv: ["--authorizer", C_T.toLowerCase(), "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"] };
  }),
];

// Wb-04: transactions of type 0x3 (UNSUPPORTED-PATH unsupported-type).
const T0S = Number(T0);
export const ROWS_WB04 = [
  v("S-86", "an unsupported transaction type (0x3) with an expired cited gate receipt: times reported, not judged", "a test-key Annex B log whose record names a test issuer's gate receipt (gr-t; evaluatedAt 1200 s and expiresAt 600 s before the block's timestamp) under its issuer profile (ip-t), pinned with permit [allow] and refuse [deny]; the test payer's EIP-3009 payment whose nonce is the record's entry hash, as a transaction of type 0x3 (its hash a test value; M5.support NOT-EVALUATED, so no signature is read)", withPins(STATED), async () => {
    const gr = await gateReceipt(testSecp("issuer"), { evaluatedAt: T0S - 1200, expiresAt: T0S - 600 });
    const c = await annexBCase({ log: { receiptUid: gr.uid } });
    const bytes = addReceipts(c.doc, [{ id: "gr-t", gr }]);
    const tx = { ...c.p.tx, type: "0x3", maxFeePerBlobGas: "0x1", blobVersionedHashes: [testValue("blob")], hash: testValue("S-86 a type 0x3 transaction") };
    const p = placeInBlock({ tx, logs: c.p.logs, baseBlock: c.p.block, timestamp: T0 });
    usePayment(c.doc, p, "eip3009-nonce");
    return { doc: c.doc, pins: pinsFor([{ bytes, ...PERMIT }]), argv: withPins(stated(p.tx.hash)) };
  }),
];

// Wb-06: the calls rule 2 does not read (UNSUPPORTED-PATH unsupported-call).
export const ROWS_WB06 = [
  v("S-108", "a contract creation from S_t whose input holds H: UNSUPPORTED-PATH unsupported-call", "S_t sends a contract creation (no to) whose input is init code followed by H; carried_as calldata", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: payerPk, to: null, input: "0x6080604052600080fd" + hA });
    const p = placeInBlock({ tx, logs: [], baseBlock: blk, timestamp: T0 });
    usePayment(doc, p, "calldata");
    return { doc, argv: stated(p.tx.hash) };
  }),
];

// Wb-07: the calldata path (rules 5, 10c, 10d), the outflow reading and B-INS
// on that path. Each event's first topic is the keccak-256 of its signature.
const S_T = payer.address;
// The Base Sepolia test token the shipped pins name (pins/pins.json).
const K = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const JSONL = "application/x-ndjson";
const LOG_T0 = Number(T0 - 3600n) * 1000;
const topic = (sig) => keccak256(toHex(sig));
const pad32 = (a) => "0x" + a.toLowerCase().slice(2).padStart(64, "0");
const word = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");
const cat = (...ws) => "0x" + ws.map((w) => w.slice(2)).join("");
const NFT = testAddress("test NFT contract").toLowerCase();
const UNPINNED = testAddress("a token the pins do not name").toLowerCase();
const PULL = (token = K, amount = 10000, to = C_T) => ({ address: token, topics: [topic("Transfer(address,address,uint256)"), pad32(S_T), pad32(to)], data: word(amount) });
const LOGS = {
  approval: { address: K, topics: [topic("Approval(address,address,uint256)"), pad32(S_T), pad32(C_T)], data: word(10000) },
  approvalForAll: { address: NFT, topics: [topic("ApprovalForAll(address,address,bool)"), pad32(S_T), pad32(C_T)], data: word(1) },
  erc721: { address: NFT, topics: [topic("Transfer(address,address,uint256)"), pad32(S_T), pad32(C_T), word(1)], data: "0x" },
  transferSingle: { address: NFT, topics: [topic("TransferSingle(address,address,address,uint256,uint256)"), pad32(C_T), pad32(S_T), pad32(C_T)], data: cat(word(1), word(5)) },
  transferBatch: { address: NFT, topics: [topic("TransferBatch(address,address,address,uint256[],uint256[])"), pad32(C_T), pad32(S_T), pad32(C_T)], data: cat(word(64), word(128), word(1), word(1), word(1), word(5)) },
  unindexed: { address: K, topics: [topic("Transfer(address,address,uint256)")], data: cat(pad32(S_T), pad32(C_T), word(10000)) },
  erc6909Transfer: { address: NFT, topics: [topic("Transfer(address,address,address,uint256,uint256)"), pad32(S_T), pad32(C_T), word(1)], data: cat(pad32(C_T), word(10000)) },
  operatorSet: { address: NFT, topics: [topic("OperatorSet(address,address,bool)"), pad32(S_T), pad32(C_T)], data: word(1) },
  erc6909Approval: { address: NFT, topics: [topic("Approval(address,address,uint256,uint256)"), pad32(S_T), pad32(C_T), word(1)], data: word(10000) },
  permit2Approval: { address: testAddress("test Permit2").toLowerCase(), topics: [topic("Approval(address,address,address,uint160,uint48)"), pad32(S_T), pad32(K), pad32(C_T)], data: cat(word(10000), word(T0 + 600n)) },
  permit2Permit: { address: testAddress("test Permit2").toLowerCase(), topics: [topic("Permit(address,address,address,uint160,uint48,uint48)"), pad32(S_T), pad32(K), pad32(C_T)], data: cat(word(10000), word(T0 + 600n), word(0)) },
  merchantEvent: { address: C_T.toLowerCase(), topics: [topic("TestPaid(address,uint256)"), pad32(S_T)], data: word(1) },
  unindexedOther: { address: K, topics: [topic("Transfer(address,address,uint256)")], data: cat(pad32(F_T), pad32(C_T), word(5)) },
};

// A test-key chirindo log (log-t, opkey-t) whose record 0 is cited, with its
// arguments (args-t) carried; unless `noInstruction`, an Annex A instruction
// (ins-t; asset native, max_amount 10^16, payees [C_t], with `constraints`)
// whose digest the arguments cite. The payment: S_t (or `senderPk`) sends
// `value` wei to C_t, H as testPull's argument; the receipt's logs are `logs`.
async function outflowCase({ constraints = {}, noInstruction = false, senderPk = payerPk, value = 1n, logs = [] } = {}) {
  const { doc, blk } = we1Parts();
  doc.members = doc.members.filter((m) => ["tx-a", "rc-a", "blk-a"].includes(m.id));
  const k = testEd("a2 operator");
  const ins = noInstruction ? null : instruction({ principal: testEd("principal"), agentKid: k.kid, payee: C_T.toLowerCase(), token: "native", constraints: { max_amount: "10000000000000000", ...constraints } });
  const args = ins ? { note: "TEST FIXTURE arguments", instruction_sha256: jcsSha256(ins) } : { note: "TEST FIXTURE arguments" };
  const l = chirindoLog({ k, sessionId: "test-a2b", argsHash: jcsSha256(args), t0: LOG_T0 });
  add(doc, { id: "log-t", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: l.bytes, media_type: JSONL });
  add(doc, { id: "opkey-t", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  add(doc, { id: "args-t", role: "action-arguments", profile: "jcs-json", bytes: json(args) });
  if (ins) add(doc, { id: "ins-t", role: "instruction", profile: "signed-instruction-ed25519/0.2", bytes: json(ins) });
  doc.subject.cites = { log: "log-t", seq: 0 };
  const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk, to: C_T, value, input: encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: ["0x" + l.hashes[0].slice(7)] }) });
  const p = placeInBlock({ tx, logs, baseBlock: blk, timestamp: T0 });
  usePayment(doc, p, "calldata");
  return { doc, argv: stated(p.tx.hash) };
}

const R3 = "a test-key chirindo log whose cited record's arguments (args-t) cite an Annex A instruction (ins-t; asset native, max_amount 10^16, payees [C_t]); S_t sends 1 wei to C_t with H as testPull's argument; carried_as calldata";
const pull = (what) => `${R3}; the receipt holds ${what}`;
const A0 = "F_t sends value 0 to C_t with H as testPull's argument; carried_as calldata";
export const ROWS_WB07 = [
  v("S-01", "A0: a relayer's calldata carries H, value 0: UNSUPPORTED-PATH other-sender", A0, STATED, () => calldataCase({ senderPk: facilitatorPk })),
  v("S-02", "A1b: S-01 with 1 wei", `${A0}, with 1 wei`, STATED, () => calldataCase({ senderPk: facilitatorPk, value: 1n })),
  v("S-05", "A2: S-01 with a zero-amount Transfer-shaped log from an arbitrary contract", `${A0}; the receipt holds a Transfer-shaped log from a test contract with from S_t and amount word 0`, STATED, () => calldataCase({ senderPk: facilitatorPk, logs: [PULL(testAddress("arbitrary contract").toLowerCase(), 0)] })),
  v("S-06", "A2b: S-01 with a Transfer-shaped log whose data is 0x", `${A0}; the receipt holds a Transfer-shaped log from a test contract with from S_t and data 0x`, STATED, () => calldataCase({ senderPk: facilitatorPk, logs: [{ ...PULL(testAddress("arbitrary contract").toLowerCase(), 0), data: "0x" }] })),
  v("S-09", "S-01 with no account stated: authorizer-not-stated", `${A0}; no --authorizer`, ["--tx", "<the payment>"], async () => {
    const c = await calldataCase({ senderPk: facilitatorPk });
    return { ...c, argv: ["--tx", c.p.tx.hash] };
  }),
  v("S-11", "S_t sends value 0 to itself with H as its input: no-counted-movement", "S_t sends value 0 to S_t, input H (32 bytes); carried_as calldata", STATED, () => calldataCase({ to: S_T, input: (h) => h })),
  v("S-13", "S_t sends 1 wei to itself with H as its input: no-counted-movement", "S_t sends 1 wei to S_t, input H (32 bytes); carried_as calldata", STATED, () => calldataCase({ to: S_T, value: 1n, input: (h) => h })),
  v("S-20", "1 wei with H in calldata, a pull of 10000 of the pinned token: B-INS EXCEEDS (asset)", pull("a Transfer of 10000 of the pinned token from S_t to C_t"), STATED, () => outflowCase({ logs: [PULL()] })),
  v("S-21", "S-20 with the pulled token a contract the pins do not name: unread-outflow", pull("a Transfer of 10000 from S_t to C_t by a token the pins do not name"), STATED, () => outflowCase({ logs: [PULL(UNPINNED)] })),
  ...[
    ["S-22", "an ERC-20 Approval S_t grants", "approval"],
    ["S-23", "an ApprovalForAll S_t grants", "approvalForAll"],
    ["S-24", "an ERC-721 Transfer from S_t", "erc721"],
    ["S-25", "an ERC-1155 TransferSingle from S_t", "transferSingle"],
    ["S-26", "an ERC-1155 TransferBatch from S_t", "transferBatch"],
    ["S-31", "a Transfer with nothing indexed, S_t in data", "unindexed"],
    ["S-32", "an ERC-6909 Transfer from S_t", "erc6909Transfer"],
    ["S-33", "an ERC-6909 OperatorSet by S_t", "operatorSet"],
    ["S-34", "an ERC-6909 Approval by S_t", "erc6909Approval"],
    ["S-35", "a Permit2 Approval by S_t", "permit2Approval"],
    ["S-36", "a Permit2 Permit by S_t", "permit2Permit"],
  ].map(([id, what, k]) => v(id, `S-20 with the pull replaced by ${what}: unread-outflow`, pull(`${what} in place of the pull`), STATED, () => outflowCase({ logs: [LOGS[k]] }))),
  v("S-27", "S-20 with a pull of 0 of the pinned token: reported, not compared; B-INS BOUND", pull("a Transfer of 0 of the pinned token from S_t to C_t"), STATED, () => outflowCase({ logs: [PULL(K, 0)] })),
  v("S-28", "S-20 with no instruction, the pinned token's pull: B-INS ABSENT", `${pull("a Transfer of 10000 of the pinned token from S_t to C_t")}; no instruction, the arguments without instruction_sha256`, STATED, () => outflowCase({ noInstruction: true, logs: [PULL()] })),
  v("S-29", "S-20 with no instruction, an unpinned token's pull: unread-outflow", `${pull("a Transfer of 10000 from S_t by a token the pins do not name")}; no instruction, the arguments without instruction_sha256`, STATED, () => outflowCase({ noInstruction: true, logs: [PULL(UNPINNED)] })),
  v("S-30", "S-20 sent by F_t: UNSUPPORTED-PATH other-sender", `${pull("a Transfer of 10000 of the pinned token from S_t to C_t")}, sent by F_t`, STATED, () => outflowCase({ senderPk: facilitatorPk, logs: [PULL()] })),
  v("S-37", "S-20 inside its instruction plus a merchant's event naming S_t and an unindexed Transfer not naming it: not read", pull("no pull; a test contract's own event with S_t as a topic, and a Transfer with nothing indexed between two other accounts"), STATED, () => outflowCase({ logs: [LOGS.merchantEvent, LOGS.unindexedOther] })),
  v("S-38", "a native value above max_amount with an unread Approval beside it: EXCEEDS (max_amount, unread-outflow)", `${R3.replace("max_amount 10^16", "max_amount 1").replace("sends 1 wei", "sends 2 wei")}; the receipt holds an ERC-20 Approval S_t grants`, STATED, () => outflowCase({ constraints: { max_amount: "1" }, value: 2n, logs: [LOGS.approval] })),
  v("S-39", "a pinned token's transfer from S_t to S_t beside the native payment: reported, not compared", pull("a Transfer of 10000 of the pinned token from S_t to S_t"), STATED, () => outflowCase({ logs: [PULL(K, 10000, S_T)] })),
  v("S-92", "a type 0x04 calldata payment from S_t with a tuple whose authority is S_t: account-has-code", "S_t sends 1 wei to C_t with H as testPull's argument in a type 0x4 transaction whose authorizationList holds a tuple S_t signed; carried_as calldata", STATED, async () =>
    calldataCase({ value: 1n, type: "0x4", authorizationList: [await payer.signAuthorization({ address: testAddress("delegate contract"), chainId: 84532, nonce: 8 })] }),
  ),
  v("S-98", "a calldata payment from S_t without H: DOES-NOT-CONNECT", "S_t sends 1 wei to C_t with another test value as testPull's argument; carried_as none", STATED, () => calldataCase({ value: 1n, input: encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: [testValue("S-98 another reference")] }), carriedAs: "none" })),
];

// Wb-08: bytes after a recognised call's arguments (rule 4's carrier in bytes
// the sender alone signed; rules 10a and 10b; the flag trailer).

// An EIP-3009 authorization of S_t (value 10000 to the test payee, its nonce a
// test value), sent by F_t with 1 wei and `trailer` (hex) after its arguments.
async function suffixPayment(blk, trailer) {
  const a = await authorization({ token: K, chainId: 84532, from: payer.address, to: payee, value: 10000n, validAfter: T0 - 600n, validBefore: T0 + 600n, nonce: testValue("S-07 nonce"), signerPk: payerPk });
  const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: facilitatorPk, to: K, value: 1n, input: callData("twa9", a) + trailer.replace(/^0x/, "") });
  return placeInBlock({ tx, logs: eip3009Logs(K, { ...a, from: a.from.toLowerCase(), to: a.to.toLowerCase() }), baseBlock: blk, timestamp: T0 });
}
async function a3(argvOf) {
  const { doc, blk, hA } = we1Parts();
  const p = await suffixPayment(blk, hA);
  usePayment(doc, p, "calldata");
  return { doc, argv: argvOf(p.tx.hash) };
}
const A3 = "A3: S_t's EIP-3009 authorization (value 10000 to the test payee, its nonce a test value), sent by F_t with 1 wei and H after its arguments; WE-1's ALLOW record cited; carried_as calldata";
// WE-1's document with Case B's log and sidecar beside Case A's (repository
// bytes), and Case B's DENY record's entry hash.
function withCaseB() {
  const parts = we1Parts();
  parts.doc.members.push(...caseB());
  const rec = JSON.parse(Buffer.from(parts.doc.members.find((m) => m.id === "log-b").bytes_b64, "base64").toString("utf8").trim());
  return { ...parts, hB: jcsSha256(withoutMember(rec, "sig")).slice(7) };
}
export const ROWS_WB08 = [
  v("S-07", "A3: H only in the facilitator's suffix, S_t stated: CARRIED-BY-OTHER with a payer", A3, STATED, () => a3(stated)),
  v("S-08", "A3 with F_t stated: CARRIED-BY-OTHER, no payer", `${A3}; --authorizer F_t`, ["--authorizer", "<F_t>", "--tx", "<the payment>"], () => a3((h) => ["--authorizer", F_T, "--tx", h])),
  v("S-10", "A3 with no account stated: authorizer-not-stated", `${A3}; no --authorizer`, ["--tx", "<the payment>"], () => a3((h) => ["--tx", h])),
  v("S-63", "A3 with a cited Annex A instruction whose max_amount is below 10000", "a test-key chirindo log whose cited record's arguments (args-t) cite an Annex A instruction (ins-t; asset the pinned token, max_amount 9999, payees [the test payee]); A3's payment with that record's entry hash after the arguments; carried_as calldata", STATED, async () => {
    const { doc, blk } = we1Parts();
    doc.members = doc.members.filter((m) => ["tx-a", "rc-a", "blk-a"].includes(m.id));
    const k = testEd("a2 operator");
    const ins = instruction({ principal: testEd("principal"), agentKid: k.kid, payee: payee.toLowerCase(), token: K, constraints: { max_amount: "9999" } });
    const args = { note: "TEST FIXTURE arguments", instruction_sha256: jcsSha256(ins) };
    const l = chirindoLog({ k, sessionId: "test-a2b", argsHash: jcsSha256(args), t0: LOG_T0 });
    add(doc, { id: "log-t", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: l.bytes, media_type: JSONL });
    add(doc, { id: "opkey-t", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
    add(doc, { id: "args-t", role: "action-arguments", profile: "jcs-json", bytes: json(args) });
    add(doc, { id: "ins-t", role: "instruction", profile: "signed-instruction-ed25519/0.2", bytes: json(ins) });
    doc.subject.cites = { log: "log-t", seq: 0 };
    const p = await suffixPayment(blk, l.hashes[0].slice(7));
    usePayment(doc, p, "calldata");
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-75", "S_t sends its own payment: nonce the cited ALLOW record's H, a DENY record's hash after the arguments: refuse", "WE-1 with Case B's log and sidecar added; S_t's EIP-3009 authorization whose nonce is Case A's entry hash, sent by S_t with Case B's DENY record's entry hash after the arguments; carried_as eip3009-nonce", STATED, async () => {
    const { doc, blk, hA, hB } = withCaseB();
    const p = await eipPayment(blk, { nonce: "0x" + hA, senderPk: payerPk, trailer: hB });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-76", "S-75 with the DENY hash only in F_t's suffix: other-entry-hash, the cited record's decision", "as S-75, sent by F_t", STATED, async () => {
    const { doc, blk, hA, hB } = withCaseB();
    const p = await eipPayment(blk, { nonce: "0x" + hA, trailer: hB });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
];

// Wb-09: an authorization that does not recover to its from (M5.authorization
// NOT-EVALUATED contract-signer).
export const ROWS_WB09 = [
  v("S-91", "an EIP-3009 authorization whose signature recovers to another account: contract-signer", "an EIP-3009 payment of the test payer whose nonce is H, its authorization signed by another test key; carried_as eip3009-nonce", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const p = await eipPayment(blk, { nonce: "0x" + hA, signerPk: testSecp("S-91 a key other than from's") });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
];

// Wb-10: H found only where it does not bind (rule 6: NOT-EVALUATED
// unread-carrier, the claim reported, not compared), and a raw match with a
// text match beside it.
const asText = (s) => Buffer.from(s, "latin1").toString("hex");
const mixed = (h) => h.replace(/[a-f]/g, (c, i) => (i % 2 ? c.toUpperCase() : c));
// An EIP-3009 authorization of S_t to `to` (value `value`, its nonce `nonce`,
// valid before `validBefore`), sent by F_t with `trailer` (hex) after its arguments.
async function authPayment(blk, { to = payee, value = 10000n, nonce, validBefore = T0 + 600n, trailer = "" }) {
  const a = await authorization({ token: K, chainId: 84532, from: payer.address, to, value, validAfter: T0 - 600n, validBefore, nonce, signerPk: payerPk });
  const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: facilitatorPk, to: K, input: callData("twa9", a) + trailer.replace(/^0x/, "") });
  return placeInBlock({ tx, logs: eip3009Logs(K, { ...a, from: a.from.toLowerCase(), to: a.to.toLowerCase() }), baseBlock: blk, timestamp: T0 });
}
// S_t's call to C_t (1 wei, testPull of a test value, so no raw H in its input).
const OTHER_REF = () => encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: [testValue("a reference other than H")] });
const UNREAD = [
  ["H in a storage key of the access list", (h) => ({ accessList: [{ address: C_T, storageKeys: [h] }] })],
  ["H as authorizationList[0].s (type 0x04; the tuple signed by another test key, its s replaced)", async (h) => ({ type: "0x4", authorizationList: [{ ...(await testAccount("another tuple key").signAuthorization({ address: testAddress("delegate contract"), chainId: 84532, nonce: 8 })), s: h }] })],
  ["H as text in the calldata, lower case, without 0x", (h) => ({ input: OTHER_REF() + asText(h.slice(2)) })],
  ["H as text in the calldata, lower case, with 0x", (h) => ({ input: OTHER_REF() + asText(h) })],
  ["H as text in the calldata, upper case, without 0x", (h) => ({ input: OTHER_REF() + asText(h.slice(2).toUpperCase()) })],
  ["H as text in the calldata, upper case, with 0x", (h) => ({ input: OTHER_REF() + asText("0x" + h.slice(2).toUpperCase()) })],
  ["H as text in the calldata, mixed case, without 0x", (h) => ({ input: OTHER_REF() + asText(mixed(h.slice(2))) })],
  ["H as text in the calldata, mixed case, with 0x", (h) => ({ input: OTHER_REF() + asText("0x" + mixed(h.slice(2))) })],
];
const EIP_UNREAD = [
  ["H as text in F_t's suffix", (h) => ({ nonce: testValue("S-56 nonce"), trailer: asText(h.slice(2)) })],
  ["H as raw bytes in validBefore", (h) => ({ nonce: testValue("S-59 nonce"), validBefore: BigInt(h) })],
];
export const ROWS_WB10 = [
  ...UNREAD.flatMap(([what, opts], k) =>
    ["none", "calldata"].map((claim, j) =>
      v(`S-${40 + 2 * k + j}`, `from S_t, ${what}, claim ${claim}: unread-carrier`, `S_t sends 1 wei to C_t with no raw H in its input; ${what}; carried_as ${claim}`, STATED, async () => {
        const { doc, blk, hA } = we1Parts();
        const o = await opts("0x" + hA);
        const tx = await signedTx({ type: o.type ?? "0x2", chainId: 84532, senderPk: payerPk, to: C_T, value: 1n, input: o.input ?? OTHER_REF(), authorizationList: o.authorizationList, accessList: o.accessList });
        const p = placeInBlock({ tx, logs: [], baseBlock: blk, timestamp: T0 });
        usePayment(doc, p, claim);
        return { doc, argv: stated(p.tx.hash) };
      }),
    ),
  ),
  ...EIP_UNREAD.flatMap(([what, opts], k) =>
    ["none", "calldata", "eip3009-nonce"].map((claim, j) =>
      v(`S-${56 + 3 * k + j}`, `EIP-3009, ${what}, claim ${claim}: unread-carrier`, `S_t's EIP-3009 authorization of 10000 to the test payee sent by F_t, no raw H in its input; ${what}; carried_as ${claim}`, STATED, async () => {
        const { doc, blk, hA } = we1Parts();
        const p = await authPayment(blk, opts("0x" + hA));
        usePayment(doc, p, claim);
        return { doc, argv: stated(p.tx.hash) };
      }),
    ),
  ),
  v("S-62", "raw H in the calldata with H as text beside it: the raw match binds, hash-as-ascii-hex", "S_t sends 1 wei to C_t with H as testPull's argument and H as text after it; carried_as calldata; no instruction", STATED, () => calldataCase({ value: 1n, input: (h) => encodeFunctionData({ abi: ROUTER_ABI, functionName: "testPull", args: [h] }) + asText(h.slice(2)) })),
];

// Wb-11: an authorization that moves nothing out of its payer (NO-PAYMENT).
export const ROWS_WB11 = [
  v("S-12", "an EIP-3009 authorization of 0 whose nonce is H: NO-PAYMENT", "S_t's EIP-3009 authorization of value 0 to the test payee whose nonce is H, sent by F_t; carried_as eip3009-nonce", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const p = await authPayment(blk, { value: 0n, nonce: "0x" + hA });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-14", "an EIP-3009 authorization from S_t to S_t whose nonce is H: NO-PAYMENT", "S_t's EIP-3009 authorization of 10000 to S_t whose nonce is H, sent by F_t; carried_as eip3009-nonce", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const p = await authPayment(blk, { to: payer.address, nonce: "0x" + hA });
    usePayment(doc, p, "eip3009-nonce");
    return { doc, argv: stated(p.tx.hash) };
  }),
  v("S-15", "S-14 with H only in F_t's suffix: CARRIED-BY-OTHER, no payer", "S_t's EIP-3009 authorization of 10000 to S_t, its nonce a test value, sent by F_t with H after its arguments; carried_as calldata", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const p = await authPayment(blk, { to: payer.address, nonce: testValue("S-15 nonce"), trailer: hA });
    usePayment(doc, p, "calldata");
    return { doc, argv: stated(p.tx.hash) };
  }),
];

// Wb-12: the payment block's parent (M5.parent-block).
// A parent block of WE-1's block's shape (number N-1, its own timestamp, one
// test transaction hash), its header hash recomputed.
function parentOf(blk, extra = {}) {
  const parent = { ...blk, number: q(49999999n), timestamp: q(T0 - 2n), transactions: [testValue("parent tx")], ...extra };
  delete parent.hash;
  parent.hash = headerHash(parent).recomputed;
  return parent;
}
export const ROWS_WB12 = [
  v("S-95", "a parent block whose hash is not the payment block's parentHash: FAILS (M5.parent-block)", "an EIP-3009 payment of the test payer whose nonce is H, in a block N whose parentHash is a test value; a payment-parent-block member (parent-t) of number N-1 whose header hash recomputes", STATED, async () => {
    const { doc, blk, hA } = we1Parts();
    const parent = parentOf(blk);
    const p = await eipPayment(blk, { nonce: "0x" + hA, parentHash: testValue("S-95 a hash other than the parent's"), number: 50000000n });
    usePayment(doc, p, "eip3009-nonce");
    add(doc, { id: "parent-t", role: "payment-parent-block", profile: "eth-rpc-json", bytes: pretty(parent) });
    return { doc, argv: stated(p.tx.hash) };
  }),
];

// Wb-13: account proofs (M5.account-proof; rule 10e reading carried proofs).
// A one-account state trie of S_t (an EIP-1186 proof of one leaf), and an
// EIP-3009 payment of S_t whose nonce is H, in a block whose stateRoot is
// `stateRoot` (WE-1's block's when absent).
async function proofCase({ stateRoot, parentHash } = {}) {
  const { doc, blk, hA } = we1Parts();
  const p = await eipPayment(blk, { nonce: "0x" + hA, stateRoot, parentHash, number: 50000000n });
  usePayment(doc, p, "eip3009-nonce");
  return { doc, blk, p, argv: stated(p.tx.hash) };
}
export const ROWS_WB13 = [
  v("S-93", "an account proof that does not verify under its header's stateRoot: FAILS (M5.account-proof)", "an EIP-3009 payment of the test payer whose nonce is H, in a block whose stateRoot is WE-1's block's; an account-proof member (proof-t) of S_t's account in a one-account test trie, naming the payment block", STATED, async () => {
    const c = await proofCase();
    const trie = singleAccountTrie({ address: payer.address, balance: 50000n });
    add(c.doc, { id: "proof-t", role: "account-proof", profile: "eth-proof-json", bytes: pretty({ block_hash: c.p.block.hash, result: trie.result }) });
    return c;
  }),
  v("S-94", "an account proof whose block_hash names no carried header: FAILS (M5.account-proof)", "as T-07, the proof's block_hash a test value", STATED, async () => {
    const trie = singleAccountTrie({ address: payer.address, balance: 50000n });
    const c = await proofCase({ stateRoot: trie.root });
    add(c.doc, { id: "proof-t", role: "account-proof", profile: "eth-proof-json", bytes: pretty({ block_hash: testValue("S-94 a block no member carries"), result: trie.result }) });
    return c;
  }),
  v("S-96", "an account proof of S_t at block N-1 showing code: account-has-code", "an EIP-3009 payment of the test payer whose nonce is H, in block N; its parent (parent-t, block N-1) carried, its stateRoot the root of a one-account test trie in which S_t has a code hash other than the empty one; the proof of S_t (proof-t) naming the parent", STATED, async () => {
    const { blk } = we1Parts();
    const trie = singleAccountTrie({ address: payer.address, codeHash: keccak256(toHex("TEST FIXTURE code")) });
    const parent = parentOf(blk, { stateRoot: trie.root });
    const c = await proofCase({ parentHash: parent.hash });
    add(c.doc, { id: "parent-t", role: "payment-parent-block", profile: "eth-rpc-json", bytes: pretty(parent) });
    add(c.doc, { id: "proof-t", role: "account-proof", profile: "eth-proof-json", bytes: pretty({ block_hash: parent.hash, result: trie.result }) });
    return c;
  }),
];

// Wb-14: the payment block's raw transactions (M5.block-transactions; rule
// 10e's scan of the entries before the payment's).
// An EIP-3009 payment of S_t whose nonce is H, sent by F_t, the last entry of
// block N, whose other entries are `earlier` (raw bytes) and whose
// transactionsRoot is their trie root; the block's raw transactions carried as
// btx-t, as `list` changes them, under `blockHash` (the payment block's when absent).
async function rawTxCase({ earlier, list = (raws) => raws, blockHash } = {}) {
  const { doc, blk, hA } = we1Parts();
  const a = await authorization({ token: K, chainId: 84532, from: payer.address, to: payee, value: 10000n, validAfter: T0 - 600n, validBefore: T0 + 600n, nonce: "0x" + hA, signerPk: payerPk });
  const tx = await signedTx({ type: "0x2", chainId: 84532, senderPk: facilitatorPk, to: K, input: callData("twa9", a) });
  const raws = [...(await earlier()), txSerialization(tx).signedHex];
  const p = placeInBlock({ tx, logs: eip3009Logs(K, { ...a, from: a.from.toLowerCase(), to: a.to.toLowerCase() }), baseBlock: blk, timestamp: T0, rawTransactions: raws });
  usePayment(doc, p, "eip3009-nonce");
  add(doc, { id: "btx-t", role: "payment-block-transactions", profile: "eth-raw-transactions", bytes: pretty({ block_hash: blockHash ?? p.block.hash, transactions: list(raws) }) });
  return { doc, argv: stated(p.tx.hash) };
}
// A raw transaction of `type` from another test sender (0x4: its
// authorizationList holds `tuples`).
const rawOf = async (label, type = "0x2", tuples) => txSerialization(await signedTx({ type, chainId: 84532, senderPk: testSecp(label), to: testAddress("a contract of the test block"), input: "0x", authorizationList: tuples })).signedHex;
// An entry of `type` that is not one this version decodes or knows (test bytes).
const opaqueEntry = (type, label) => type + toRlp([testValue(label)]).slice(2);
const flip = (hex, at) => hex.slice(0, at) + (hex[at] === "0" ? "1" : "0") + hex.slice(at + 1);
const BTX = "an EIP-3009 payment of the test payer whose nonce is H, sent by F_t, the last entry of a test block N whose transactionsRoot is the trie root of its raw entries; btx-t carries the block's raw transactions";
export const ROWS_WB14 = [
  v("S-99", "an earlier type 0x04 entry with a tuple whose authority is S_t: account-has-code", `${BTX}; entry 0 a type 0x04 transaction of another test sender whose authorizationList holds a tuple S_t signed`, STATED, () =>
    rawTxCase({ earlier: async () => [await rawOf("earlier 7702 sender", "0x4", [await payer.signAuthorization({ address: testAddress("delegate contract"), chainId: 84532, nonce: 3 })])] }),
  ),
  v("S-100", "a carried list with one byte of one entry changed: carried-transactions-mismatch, not used", `${BTX}; one hex digit of entry 0 (a type 0x2 transaction of another test sender) changed in btx-t`, STATED, () => rawTxCase({ earlier: async () => [await rawOf("earlier sender")], list: (r) => [flip(r[0], 40), ...r.slice(1)] })),
  v("S-101", "a carried list with two entries swapped: carried-transactions-mismatch, not used", `${BTX}; its two entries swapped in btx-t`, STATED, () => rawTxCase({ earlier: async () => [await rawOf("earlier sender")], list: (r) => [r[1], r[0]] })),
  v("S-102", "a carried list with an entry left out: carried-transactions-mismatch, not used", `${BTX}; entry 0 left out of btx-t`, STATED, () => rawTxCase({ earlier: async () => [await rawOf("earlier sender")], list: (r) => r.slice(1) })),
  v("S-103", "a carried list under the block_hash of another block: carried-transactions-mismatch, not used", `${BTX}; btx-t's block_hash a test value`, STATED, () => rawTxCase({ earlier: async () => [await rawOf("earlier sender")], blockHash: testValue("S-103 another block") })),
  v("S-104", "an earlier type 0x04 entry that does not decode, under a matching root: prerequisite-failed:O7.account-code", `${BTX}; entry 0 the bytes 0x04c0 (type 0x04, an empty RLP list)`, STATED, () => rawTxCase({ earlier: async () => ["0x04c0"] })),
  v("S-105", "a first entry of the deposit type 0x7e: read as bytes only", `${BTX}; entry 0 test bytes of type 0x7e`, STATED, () => rawTxCase({ earlier: async () => [opaqueEntry("0x7e", "S-105 deposit bytes")] })),
  v("S-106", "an earlier entry of type 0x03: prerequisite-failed:O7.account-code", `${BTX}; entry 0 test bytes of type 0x03`, STATED, () => rawTxCase({ earlier: async () => [opaqueEntry("0x03", "S-106 blob transaction bytes")] })),
  v("S-107", "an earlier entry of type 0x05: prerequisite-failed:O7.account-code", `${BTX}; entry 0 test bytes of type 0x05`, STATED, () => rawTxCase({ earlier: async () => [opaqueEntry("0x05", "S-107 bytes of a type this version does not know")] })),
];
