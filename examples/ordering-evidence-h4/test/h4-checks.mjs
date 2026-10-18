// node --test --test-reporter=tap examples/ordering-evidence-h4/test/h4-checks.mjs
//
// Every case here is built from the TEST FIXTURES (fixtures/make-fixtures.mjs:
// throwaway keys from public seed strings, a STUB witness key, chain id 31337)
// or from public vectors in test/vectors. None of it is evidence. The --online
// checks are served by a stand-in fetch; nothing here reads the network.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, symlinkSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { domainSeparator, encodeAbiParameters, keccak256, serializeTransaction, toHex } from "viem";
import { privateKeyToAccount, sign as secpSign } from "viem/accounts";
import { authorizerAddress, checkCase, diskIo, formatRows, rpcEndpoints } from "../lib/check.mjs";
import { headerHash, parseErc8021, txSerialization, recoverSigner } from "../lib/evm.mjs";
import { sign as edSign } from "node:crypto";
import { KEYS, OTHER_STUB_WITNESS, STUB_WITNESS, TEST_KEYS_URL, TEST_TOKEN, buildCase, compact, testAddress, testKeyDocument, testPins, testProfile, writeFiles } from "../fixtures/make-fixtures.mjs";
import { jcs, okpThumbprint, sha256Hex } from "../lib/formats.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const CASE_FILES = [
  "case.json", "issuer/profile.json", "receipts/source.json", "receipts/destination.json",
  "requests/source.json", "requests/destination.json", "log/entries.jsonl", "log/public-key-jwk.json", "log/checkpoint.json",
  "witness/receipt.json", "chain/transaction.json", "chain/receipt.json", "chain/block.json", "chain/target-abi.json", "chain/token-domain.json",
];
const PIN_FILES = ["pins.json", "v5-keys.response.json"];

const addrOf = (k) => privateKeyToAccount(k).address.toLowerCase();
// The account each fixture's trade comes from, as its verifier states it (--authorizer).
const AUTHORIZER = { calldata: addrOf(KEYS.trader), eip3009: addrOf(KEYS.payer) };
const as = (kind, extra = {}) => ({ authorizer: AUTHORIZER[kind], ...extra });
const mem = (caseFiles, pinFiles) => ({ readCase: (r) => caseFiles.get(r) ?? null, readPin: (r) => pinFiles.get(r) ?? null });
const run = (caseFiles, pinFiles = testPins(), opts = {}) => checkCase(mem(caseFiles, pinFiles), opts);
// Test pins that accept the case's own (edited) issuer profile.
const pinsFor = (files) => testPins({ profiles: [files.get("issuer/profile.json")] });
const row = (out, id) => out.rows.find((x) => x.id === id);
const fails = (out) => out.rows.filter((x) => x.status === "FAIL");
const J = (files, rel) => JSON.parse(files.get(rel).toString("utf8"));
const put = (files, rel, v) => files.set(rel, Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8"));
const edit = (files, rel, fn) => {
  const x = J(files, rel);
  fn(x);
  put(files, rel, x);
  return files;
};
const topicAddr = (a) => "0x" + "0".repeat(24) + a.slice(2).toLowerCase();
const TRANSFER = keccak256(toHex("Transfer(address,address,uint256)"));

// A stand-in for the network: Headless Oracle's witness list (in `pages` pages),
// the test issuer's key document and two JSON-RPC endpoints, answering from the
// case's own chain files. `change(url, method, result)` alters one endpoint's answer.
const RPC = ["https://rpc-a.invalid", "https://rpc-b.invalid"];
function standIn(files, { list, pages = 1, keyDoc = testKeyDocument(), finalized = "0x2000000", token = {}, change } = {}) {
  const tx = J(files, "chain/transaction.json");
  const rc = J(files, "chain/receipt.json");
  const blk = J(files, "chain/block.json");
  const w = J(files, "witness/receipt.json");
  const str = (x) => encodeAbiParameters([{ type: "string" }], [x]);
  return async (url, init) => {
    const reply = (obj) => new Response(Buffer.from(JSON.stringify(obj)), { status: 200 });
    if (url.startsWith("https://api.headlessoracle.com/v1/witness/checkpoints?")) {
      const k = Number(new URL(url).searchParams.get("after") ?? 0);
      const last = k + 1 >= pages;
      return reply({ kid: w.kid, session_id: w.session_id, receipts: last ? list ?? [w] : [], ...(last ? {} : { next_after: String(k + 1) }) });
    }
    if (url === TEST_KEYS_URL) return reply(keyDoc);
    const body = JSON.parse(init.body);
    let result;
    if (body.method === "eth_call") {
      const t = { name: TEST_TOKEN.name, version: TEST_TOKEN.version, ...token };
      const sep = t.separator ?? domainSeparator({ domain: { name: t.name, version: t.version, chainId: Number(BigInt(tx.chainId)), verifyingContract: tx.to } });
      result = { "0x06fdde03": str(t.name), "0x54fd4d50": str(t.version), "0x3644e515": sep }[body.params[0].data];
    } else result = { eth_getTransactionByHash: tx, eth_getTransactionReceipt: rc, eth_getBlockByNumber: body.params[0] === "finalized" ? { number: finalized } : blk }[body.method];
    if (change) result = change(url, body.method, structuredClone(result));
    return reply({ jsonrpc: "2.0", id: 1, result });
  };
}
const online = (files, opts = {}, served = {}, pins = testPins()) => run(files, pins, { online: true, fetchImpl: standIn(files, served), rpcUrls: RPC, ...opts });

function fromDisk(dir, names) {
  const m = new Map();
  for (const n of names) {
    try {
      m.set(n, readFileSync(path.join(dir, n)));
    } catch {}
  }
  return m;
}

test("the committed fixtures are the generator's output, byte for byte", async () => {
  for (const kind of ["calldata", "eip3009"]) {
    const built = await buildCase(kind);
    const disk = fromDisk(path.join(ROOT, "fixtures", kind), CASE_FILES);
    assert.deepEqual([...disk.keys()].sort(), [...built.keys()].sort(), `${kind}: file list`);
    for (const [rel, buf] of built) assert.ok(disk.get(rel).equals(buf), `${kind}/${rel} differs from the generator's output`);
  }
  const pins = testPins();
  const disk = fromDisk(path.join(ROOT, "fixtures", "test-pins"), PIN_FILES);
  for (const [rel, buf] of pins) assert.ok(disk.get(rel).equals(buf), `test-pins/${rel} differs`);
});

test("the command runs however its folder is reached (here through a symlink or junction): exit codes 1, 2, 3 and 4, and a RESULT line on an input that crashed rev 2", async (t) => {
  const tmp = mkdtempSync(path.join(tmpdir(), "h4-cli-"));
  const link = path.join(tmp, "h4link");
  // A junction on Windows (no privilege needed); a symlink elsewhere.
  symlinkSync(ROOT, link, "junction");
  t.after(() => {
    // Remove the link itself first, and the temporary folder only once the
    // link is gone, so nothing can reach the checker's own folder.
    try {
      rmdirSync(link);
    } catch {
      try {
        unlinkSync(link);
      } catch {}
    }
    let gone = false;
    try {
      lstatSync(link);
    } catch {
      gone = true;
    }
    if (gone) rmSync(tmp, { recursive: true, force: true });
  });
  const cli = (args) => spawnSync(process.execPath, [path.join(link, "check-h4.mjs"), ...args], { encoding: "utf8" });
  const pins = ["--pins", path.join(link, "fixtures", "test-pins")];
  const trader = privateKeyToAccount(KEYS.trader).address;
  const offline = cli([path.join(link, "fixtures", "calldata"), ...pins, "--authorizer", trader]);
  assert.equal(offline.status, 4, `exit ${offline.status}\n${offline.stdout}${offline.stderr}`);
  assert.match(offline.stdout, /^RESULT: NOT VERIFIED OFFLINE: no check failed, but the chain data .* this is not a pass/m);
  assert.match(offline.stdout, /^PASS g\.binding: BOUND: /m);
  const real = cli([path.join(link, "fixtures", "calldata"), "--authorizer", trader]);
  assert.equal(real.status, 1, `exit ${real.status}\n${real.stdout}${real.stderr}`);
  assert.match(real.stdout, /^RESULT: FAIL /m);
  const usage = cli([]);
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /^usage: node check-h4.mjs <case-dir> \[--authorizer <address>\]/m);
  // --authorizer: all lower case, all upper case and the EIP-55 form are read
  // as the same address; mixed case that is not the checksum, a value that is
  // not an address and a second --authorizer are usage errors (exit 2).
  const calldataCase = path.join(link, "fixtures", "calldata");
  for (const form of [trader.toLowerCase(), "0x" + trader.slice(2).toUpperCase()]) {
    const x = cli([calldataCase, ...pins, "--authorizer", form]);
    assert.equal(x.status, 4, `${form}: exit ${x.status}\n${x.stdout}${x.stderr}`);
    assert.match(x.stdout, /^PASS g\.binding: BOUND: /m);
  }
  const k = trader.search(/[a-f][^a-f]*$/i);
  const badCase = trader.slice(0, k) + (trader[k] === trader[k].toLowerCase() ? trader[k].toUpperCase() : trader[k].toLowerCase()) + trader.slice(k + 1);
  const wantCase = trader[k] === trader[k].toUpperCase() ? "upper" : "lower";
  const relayer = privateKeyToAccount(KEYS.relayer).address;
  const usageErrors = [
    [["--authorizer", "0x1234"], /^usage error: --authorizer is not a 20-byte hex address \(0x and 40 hex digits\)$/m],
    [["--authorizer", "0X" + trader.slice(2)], /^usage error: --authorizer is not a 20-byte hex address/m],
    [["--authorizer", badCase], new RegExp(`^usage error: --authorizer is in mixed case, so it is read as an EIP-55 checksum, and it is not a valid one: hex digit ${k - 1} of 40 should be ${wantCase} case\\. Give the address all in lower case, all in upper case, or exactly in its EIP-55 form$`, "m")],
    [["--authorizer", trader, "--authorizer", relayer], /^usage error: --authorizer is given 2 times; give it once$/m],
    [["--authorizer", trader, "--authorizer", trader], /^usage error: --authorizer is given 2 times; give it once$/m],
    // --rpc: one endpoint per host; fewer than two distinct hosts is refused.
    [["--authorizer", trader, "--rpc", "https://rpc-a.invalid", "--rpc", "https://rpc-a.invalid/again"], /^usage error: --rpc names 1 distinct host\(s\) \(1 more URL\(s\) on a host already named\): name endpoints on at least two different hosts, run by different operators$/m],
    [["--authorizer", trader, "--rpc", "https://rpc-a.invalid:8545", "--rpc", "http://RPC-A.invalid./x"], /^usage error: --rpc names 1 distinct host\(s\)/m],
    [["--authorizer", trader, "--rpc", "https://rpc-a.invalid"], /^usage error: --rpc names 1 distinct host\(s\): name endpoints/m],
    [["--authorizer", trader, "--rpc", "ftp://rpc-a.invalid", "--rpc", "https://rpc-b.invalid"], /^usage error: --rpc "ftp:\/\/rpc-a\.invalid" is not an http or https URL$/m],
    [["--authorizer", trader, "--rpc", "rpc-a.invalid", "--rpc", "https://rpc-b.invalid"], /^usage error: --rpc "rpc-a\.invalid" is not a URL$/m],
  ];
  for (const [args, re] of usageErrors) {
    const x = cli([calldataCase, ...pins, ...args]);
    assert.equal(x.status, 2, `${args.join(" ")}: exit ${x.status}\n${x.stdout}${x.stderr}`);
    assert.match(x.stderr, re, args.join(" "));
    assert.equal(x.stdout, "");
  }
  const src = await buildCase("eip3009", { chainId: 8453, tokenDomainFile: true });
  const report = path.join(tmp, "trailer-report");
  writeFiles(report, new Map([...src].filter(([key]) => key.startsWith("chain/"))));
  writeFiles(report, new Map([["case.json", Buffer.from(JSON.stringify({ format: "chirindo-h4-case/1", mode: "trailer-report", chain_id: 8453, tx_hash: J(src, "chain/transaction.json").hash }))]]));
  const trailer = cli([report, ...pins]);
  assert.equal(trailer.status, 3, `exit ${trailer.status}\n${trailer.stdout}${trailer.stderr}`);
  assert.match(trailer.stdout, /^RESULT: TRAILER REPORT: /m);
  // A folder in place of requests/source.json: rev 2 stopped with a stack trace.
  const folderCase = path.join(tmp, "folder-case");
  writeFiles(folderCase, new Map([...(await buildCase("calldata"))].filter(([key]) => key !== "requests/source.json")));
  mkdirSync(path.join(folderCase, "requests", "source.json"));
  const folder = cli([folderCase, ...pins, "--authorizer", trader]);
  assert.equal(folder.status, 1, `exit ${folder.status}\n${folder.stdout}${folder.stderr}`);
  assert.match(folder.stdout, /^FAIL b\.source\.request-hash: /m);
  assert.match(folder.stdout, /^RESULT: FAIL /m);
  assert.equal(folder.stderr, "");
});

test("both fixtures: offline exit 4 with their chain facts NOT VERIFIED OFFLINE; online (stand-in endpoints) exit 0; under Headless Oracle's own pins they fail", async () => {
  for (const kind of ["calldata", "eip3009"]) {
    const io = diskIo(path.join(ROOT, "fixtures", kind), path.join(ROOT, "fixtures", "test-pins"));
    const out = await checkCase(io, as(kind));
    assert.equal(out.exitCode, 4, `${kind}:\n${formatRows(out.rows)}`);
    assert.equal(fails(out).length, 0);
    assert.match(row(out, "g.binding").text, /^BOUND: /);
    assert.match(out.result, /^NOT VERIFIED OFFLINE: .*this is not a pass/);
    assert.match(out.result, /TEST PINS/);
    const facts = kind === "calldata" ? ["f.chain-data", "f.receipt", "f.block", "f.block-hash"] : ["f.chain-data", "f.receipt", "f.block", "f.block-hash", "g.token-logs", "g.validity-window"];
    assert.deepEqual(out.rows.filter((x) => x.status === "NOT VERIFIED OFFLINE").map((x) => x.id), facts);
    const files = fromDisk(path.join(ROOT, "fixtures", kind), CASE_FILES);
    const live = await online(files, as(kind));
    assert.equal(live.exitCode, 0, `${kind} online:\n${formatRows(live.rows)}`);
    assert.match(live.result, /^PASS: every check that applies passed, online, with the authorizer the verifier stated/);
    for (const id of facts) assert.equal(row(live, id).status, "PASS", `${kind} online: ${id}`);
    const real = await checkCase(diskIo(path.join(ROOT, "fixtures", kind), path.join(ROOT, "pins")), as(kind));
    assert.equal(real.exitCode, 1);
    assert.equal(row(real, "a.profile").status, "FAIL");
    assert.equal(row(real, "e.witness-receipt").status, "FAIL");
  }
});

test("exit codes: 1 wins over 4 and 5, 4 over 5; a FLAG line online is exit 5 (a block before the receipts' check time)", async () => {
  const early = await buildCase("calldata", { blockTimestamp: 1792130000 - 100 });
  const flagged = await online(early, as("calldata"));
  assert.deepEqual(flagged.rows.filter((x) => x.status === "FLAG").map((x) => x.id), ["i.source-checked-at", "i.destination-checked-at"]);
  assert.equal(flagged.exitCode, 5, formatRows(flagged.rows));
  assert.match(flagged.result, /^FLAG: no check failed, but 2 FLAG line\(s\) stand against a pass: i\.source-checked-at, i\.destination-checked-at/);
  assert.match(row(flagged, "flag").text, /^2: /);
  const offline = await run(early, testPins(), as("calldata"));
  assert.equal(offline.exitCode, 4);
  const failing = await online(edit(await buildCase("calldata", { blockTimestamp: 1792130000 - 100 }), "chain/receipt.json", (rc) => (rc.status = "0x0")), as("calldata"), {});
  assert.equal(failing.exitCode, 1, formatRows(failing.rows));
});

// Values no signature, hash or comparison covers. A one-byte change to any
// of them leaves the result as it was; README.md lists the same set.
const NOT_COVERED = {
  "receipts/source.json": [/^label$/, /^issued_at$/, /^info_url$/],
  "receipts/destination.json": [/^label$/, /^issued_at$/, /^info_url$/],
  "chain/transaction.json": [/^gasPrice$/],
  "chain/receipt.json": [/^blobGasUsed$/, /^cumulativeGasUsed$/, /^daFootprintGasScalar$/, /^effectiveGasPrice$/, /^gasUsed$/, /^l1[A-Za-z]+$/, /^logsBloom$/, /^logs\.\d+\.logIndex$/],
  "chain/block.json": [/^size$/, /^transactions\.0$/],
  "chain/target-abi.json": [/.*/],
  "pins.json": [/^label$/, /^witness_keys\.fetched_at$/, /^witness_keys\.url$/, /^issuer_profiles\.\d+\.label$/],
};
// The calldata path reads no log, so in the calldata fixture the receipt's one
// log (a Transfer to the trader) is read by no check beyond its place.
const NOT_COVERED_CALLDATA = { "chain/receipt.json": [/^logs\.0\.(address|data|topics\.\d+)$/] };

function leaves(v, p = []) {
  if (v !== null && typeof v === "object") return Object.entries(v).flatMap(([k, x]) => leaves(x, [...p, k]));
  return typeof v === "string" || typeof v === "number" ? [{ path: p, value: v }] : [];
}
function setAt(v, p, x) {
  if (p.length === 0) return x;
  const c = Array.isArray(v) ? [...v] : { ...v };
  c[p[0]] = setAt(v[p[0]], p.slice(1), x);
  return c;
}
// One character of the value's text replaced by another of the same kind, so
// the file stays valid JSON and changes in exactly one byte: the last decimal
// digit if the value has one (a time, a hex string or a number keeps its
// format), otherwise the last character.
function mutate(value) {
  const s = String(value);
  const lastDigit = s.search(/[0-9][^0-9]*$/);
  const k = lastDigit >= 0 ? lastDigit : s.length - 1;
  const c = s[k];
  let d;
  if (/[0-9]/.test(c)) d = String((Number(c) + 1) % 10);
  else if (/[a-f]/.test(c)) d = c === "a" ? "b" : "a";
  else if (/[a-z]/.test(c)) d = c === "z" ? "y" : "z";
  else if (/[A-Z]/.test(c)) d = c === "Z" ? "Y" : "Z";
  else if (c === "_") d = "-";
  else if (c === "-") d = "_";
  else d = c === "x" ? "y" : "x";
  const t = s.slice(0, k) + d + s.slice(k + 1);
  if (typeof value === "number") return Number(t) === value || /^0\d/.test(t) ? null : Number(t);
  return t;
}
// The other one-byte change a reader might try: the last letter of a string
// in the other case (hex, EIP-55 addresses, base64url).
function flipCase(value) {
  if (typeof value !== "string") return null;
  const k = value.search(/[A-Za-z][^A-Za-z]*$/);
  if (k < 0) return null;
  const c = value[k];
  return value.slice(0, k) + (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()) + value.slice(k + 1);
}
function oneByteVariants(rel, buf) {
  const out = [];
  const each = (v, emit) => {
    for (const { path: p, value } of leaves(v)) {
      const m = mutate(value);
      if (m !== null) emit(p, m, "digit or letter");
      const f = flipCase(value);
      if (f !== null) emit(p, f, "letter case");
    }
  };
  if (rel.endsWith(".jsonl")) {
    const lines = buf.toString("utf8").split("\n").slice(0, -1);
    lines.forEach((line, i) => {
      each(JSON.parse(line), (p, m, how) => {
        const nl = [...lines];
        nl[i] = JSON.stringify(setAt(JSON.parse(line), p, m));
        out.push({ where: `line ${i + 1}: ${p.join(".")} (${how})`, path: p.join("."), how, buf: Buffer.from(nl.join("\n") + "\n", "utf8") });
      });
    });
    return out;
  }
  const text = buf.toString("utf8");
  const v = JSON.parse(text);
  const prettyForm = JSON.stringify(v, null, 2) + "\n";
  if (prettyForm !== text) return null; // compact pinned documents: byte flips test them
  each(v, (p, m, how) => out.push({ where: `${p.join(".")} (${how})`, path: p.join("."), how, buf: Buffer.from(JSON.stringify(setAt(v, p, m), null, 2) + "\n", "utf8") }));
  return out;
}
const differsInOneByte = (a, b) => a.length === b.length && [...a].filter((x, i) => x !== b[i]).length === 1;

for (const kind of ["calldata", "eip3009"]) {
  test(`${kind}: a one-byte change to every value a signature, hash or comparison covers fails; the rest is the listed set`, async () => {
    const files = await buildCase(kind);
    const pins = testPins();
    let changed = 0;
    let failed = 0;
    const passedButCovered = [];
    const failedButListed = [];
    const targets = [...[...files.keys()].map((rel) => ["case", rel]), ...[...pins.keys()].map((rel) => ["pins", rel])];
    for (const [side, rel] of targets) {
      const original = side === "case" ? files.get(rel) : pins.get(rel);
      const variants = oneByteVariants(rel, original);
      if (variants === null) continue;
      for (const v of variants) {
        assert.ok(differsInOneByte(original, v.buf), `${rel} ${v.where}: the variant is not a one-byte change`);
        const f2 = new Map(files);
        const p2 = new Map(pins);
        (side === "case" ? f2 : p2).set(rel, v.buf);
        const out = await run(f2, p2, as(kind));
        changed++;
        const listed = [...(NOT_COVERED[rel] ?? []), ...(kind === "calldata" ? NOT_COVERED_CALLDATA[rel] ?? [] : [])].some((re) => re.test(v.path));
        if (out.exitCode === 1) {
          failed++;
          // A case flip may break a listed value's format (a time ending "z"); only
          // digit and letter changes keep it, so only they test the list.
          if (listed && v.how === "digit or letter") failedButListed.push(`${rel} ${v.where}`);
        } else if (!listed) passedButCovered.push(`${rel} ${v.where}: ${out.result}`);
        else assert.equal(out.exitCode, 4, `${rel} ${v.where}: ${out.result}`);
      }
    }
    assert.deepEqual(passedButCovered, [], "a change to a covered value did not fail");
    assert.deepEqual(failedButListed, [], "a value listed as not covered is in fact covered: update the list and README.md");
    assert.ok(changed > 400, `only ${changed} one-byte changes made`);
    console.log(`${kind}: ${changed} one-byte value changes, ${failed} FAIL, ${changed - failed} in the listed not-covered set`);
  });
}

// Members whose absence the checker accepts. Renaming any other member (one
// byte of its name) fails, because the member is then missing or unexpected.
const RENAME_OK = {
  "chain/transaction.json": [/^gasPrice$/, /^blockTimestamp$/],
  "chain/receipt.json": [/^blobGasUsed$/, /^cumulativeGasUsed$/, /^daFootprintGasScalar$/, /^effectiveGasPrice$/, /^gasUsed$/, /^l1[A-Za-z]+$/, /^logsBloom$/, /^logs\.\d+\.blockTimestamp$/],
  "chain/block.json": [/^size$/, /^uncles$/, /^withdrawals$/],
};

for (const kind of ["calldata", "eip3009"]) {
  test(`${kind}: renaming a member (one byte of its name) fails, except the members the checker does not require`, async () => {
    const files = await buildCase(kind);
    const unexpected = [];
    let renamed = 0;
    for (const [rel, buf] of files) {
      // The pinned copy is compared byte for byte (tested below); the target ABI
      // only places the hash in the report: renaming in it can make it
      // unreadable (FAIL) or leave the result as it was.
      if (rel === "issuer/profile.json" || rel === "chain/target-abi.json") continue;
      const lines = rel.endsWith(".jsonl") ? buf.toString("utf8").split("\n").slice(0, -1) : [buf.toString("utf8")];
      for (const [li, text] of lines.entries()) {
        const v = JSON.parse(text);
        const walk = (x, p) => {
          if (x === null || typeof x !== "object" || Array.isArray(x)) {
            if (Array.isArray(x)) x.forEach((y, k) => walk(y, [...p, String(k)]));
            return;
          }
          for (const key of Object.keys(x)) {
            const k = key.search(/[A-Za-z][^A-Za-z]*$/);
            const other = key.slice(0, k) + (key[k] === key[k].toLowerCase() ? key[k].toUpperCase() : key[k].toLowerCase()) + key.slice(k + 1);
            const rename = (o, path) => (path.length === 0 ? Object.fromEntries(Object.entries(o).map(([a, b]) => [a === key ? other : a, b])) : Array.isArray(o) ? o.map((y, i) => (String(i) === path[0] ? rename(y, path.slice(1)) : y)) : { ...o, [path[0]]: rename(o[path[0]], path.slice(1)) });
            const changed = rename(v, p);
            const out = rel.endsWith(".jsonl") ? lines.map((l, i) => (i === li ? JSON.stringify(changed) : l)).join("\n") + "\n" : JSON.stringify(changed, null, 2) + "\n";
            renamed++;
            jobs.push({ rel, path: [...p, key].join("."), buf: Buffer.from(out, "utf8") });
            walk(x[key], [...p, key]);
          }
        };
        const jobs = [];
        walk(v, []);
        for (const j of jobs) {
          assert.ok(differsInOneByte(buf, j.buf), `${rel} ${j.path}: not a one-byte change`);
          const out = await run(new Map(files).set(rel, j.buf), testPins(), as(kind));
          const ok = (RENAME_OK[rel] ?? []).some((re) => re.test(j.path));
          if ((out.exitCode === 1) === ok) unexpected.push(`${rel} ${j.path}: ${out.result}`);
        }
      }
    }
    assert.deepEqual(unexpected, []);
    assert.ok(renamed > 150, `only ${renamed} members renamed`);
    console.log(`${kind}: ${renamed} member renames`);
  });
}

test("chain files may be whole JSON-RPC responses", async () => {
  const files = await buildCase("calldata");
  for (const rel of ["chain/transaction.json", "chain/receipt.json", "chain/block.json"]) files.set(rel, Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, result: J(files, rel) })));
  const out = await run(files, testPins(), as("calldata"));
  assert.equal(out.exitCode, 4, formatRows(out.rows));
  assert.equal(fails(out).length, 0);
  assert.match(row(out, "f.chain-data").text, /the result member of the JSON-RPC response in chain\/transaction.json, chain\/receipt.json, chain\/block.json/);
});

test("a receipt log marked removed fails", async () => {
  const files = edit(await buildCase("eip3009"), "chain/receipt.json", (rc) => (rc.logs[0].removed = true));
  const out = await run(files, testPins(), as("eip3009"));
  assert.equal(out.exitCode, 1);
  assert.match(row(out, "f.receipt").text, /log 0 is not marked removed: false/);
});

test("a one-byte change anywhere in a pinned document fails", async () => {
  const files = await buildCase("eip3009");
  const pins = testPins();
  const targets = [["case", "issuer/profile.json"], ["pins", "v5-keys.response.json"]];
  for (const [side, rel] of targets) {
    const buf = side === "case" ? files.get(rel) : pins.get(rel);
    const positions = new Set([0, buf.length - 1]);
    for (let i = 0; i < buf.length; i += 37) positions.add(i);
    for (const i of positions) {
      const b = Buffer.from(buf);
      b[i] ^= 0x01;
      const f2 = new Map(files);
      const p2 = new Map(pins);
      (side === "case" ? f2 : p2).set(rel, b);
      const out = await run(f2, p2, as("eip3009"));
      assert.equal(out.exitCode, 1, `${rel} byte ${i} flipped, still ${out.result}`);
    }
  }
});

test("the JSON text's form (white space, member order): not covered in parsed JSON members, covered in the pinned documents", async () => {
  const files = await buildCase("calldata");
  const reorder = (v) => (Array.isArray(v) ? v.map(reorder) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reorder(x)])) : v);
  for (const [rel, buf] of files) {
    if (rel === "issuer/profile.json") continue;
    let changed;
    if (rel.endsWith(".jsonl")) changed = Buffer.from(buf.toString("utf8").split("\n").slice(0, -1).map((l) => " " + JSON.stringify(reorder(JSON.parse(l))) + " ").join("\r\n") + "\r\n", "utf8");
    else changed = Buffer.from(JSON.stringify(reorder(JSON.parse(buf.toString("utf8"))), null, "\t"), "utf8");
    assert.notDeepEqual(changed, buf);
    const f2 = new Map(files);
    f2.set(rel, changed);
    const out = await run(f2, testPins(), as("calldata"));
    assert.equal(out.exitCode, 4, `${rel}: white space and member order changed, expected not covered, got ${out.result}`);
    assert.equal(fails(out).length, 0);
  }
  const f3 = new Map(files);
  f3.set("issuer/profile.json", Buffer.from(JSON.stringify(J(files, "issuer/profile.json"), null, 1), "utf8"));
  const reformatted = await run(f3, testPins(), as("calldata"));
  assert.equal(reformatted.exitCode, 1, "the issuer profile is pinned by sha256");
  assert.match(row(reformatted, "a.profile").text, /is not a profile the verifier pinned/);
});

test("the authorizer comes from the verifier: bytes signed only by another account give CARRIED-BY-OTHER, never BOUND", async () => {
  // A relayer sends the trade: with value 0, with 1 wei of its own, and with a
  // zero-amount Transfer-shaped log from a contract of its own in the receipt.
  const relayer = addrOf(KEYS.relayer);
  const relayed = [
    ["value 0", await buildCase("calldata", { sender: "relayer" })],
    ["1 wei", await buildCase("calldata", { sender: "relayer", value: 1n })],
    [
      "a zero-amount Transfer-shaped log",
      edit(await buildCase("calldata", { sender: "relayer" }), "chain/receipt.json", (rc) => rc.logs.push({ ...rc.logs[0], address: testAddress("a contract the relayer deployed").toLowerCase(), topics: [TRANSFER, topicAddr(relayer), topicAddr(testAddress("anyone"))], data: "0x" + "00".repeat(32), logIndex: "0x9" })),
    ],
  ];
  for (const [name, files] of relayed) {
    for (const out of [await run(files, testPins(), as("calldata")), await online(files, as("calldata"))]) {
      assert.equal(out.exitCode, 1, `${name}: ${out.result}`);
      assert.equal(row(out, "g.binding").status, "FAIL");
      assert.match(row(out, "g.binding").text, /^CARRIED-BY-OTHER: .*signed by the transaction's sender 0x[0-9a-f]{6}\.\.\.[0-9a-f]{4} .*the verifier states the authorizer 0x[0-9a-f]{6}\.\.\.[0-9a-f]{4} \(--authorizer\), who did not sign those bytes/, name);
    }
  }
  // A facilitator's suffix carrying the hash after an EIP-3009 authorization the payer signed.
  for (const binding of ["calldata", "eip3009-nonce"]) {
    for (const opts of [as("eip3009"), as("calldata"), {}]) {
      const out = await run(await buildCase("eip3009", { nonceIsEntryHash: false, trailerHash: true, binding }), testPins(), opts);
      assert.equal(out.exitCode, 1);
      assert.match(row(out, "g.binding").text, /^CARRIED-BY-OTHER: .*the payment moves value from 0x[0-9a-f]{6}\.\.\.[0-9a-f]{4}, who signed the authorization and did not sign those bytes/);
      assert.match(row(out, "h.trailer").text, /the destination entry hash is in it/);
    }
  }
  // The fixtures, each with the other fixture's authorizer stated.
  for (const [kind, other] of [["calldata", "eip3009"], ["eip3009", "calldata"]]) {
    const out = await run(await buildCase(kind), testPins(), as(other));
    assert.equal(out.exitCode, 1);
    assert.match(row(out, "g.binding").text, /^CARRIED-BY-OTHER: /);
  }
});

test("without --authorizer the binding line is FLAG, naming the account that signed, and no run passes; a case that names expected_authorizer fails", async () => {
  for (const kind of ["calldata", "eip3009"]) {
    const files = await buildCase(kind);
    const signer = AUTHORIZER[kind];
    for (const [out, code] of [[await run(files), 4], [await online(files), 5]]) {
      assert.equal(out.exitCode, code, `${kind}: ${out.result}`);
      assert.equal(row(out, "g.binding").status, "FLAG");
      assert.ok(row(out, "g.binding").text.startsWith("authorizer not stated by the verifier: "));
      assert.ok(row(out, "g.binding").text.includes(`the account recovered from that signature is ${signer.slice(0, 8)}...${signer.slice(-4)}`));
    }
    const shown = await online(files, { showParties: true });
    assert.ok(row(shown, "g.binding").text.includes(signer));
    const named = edit(await buildCase(kind), "case.json", (c) => (c.expected_authorizer = signer));
    const out = await run(named, testPins(), as(kind));
    assert.equal(out.exitCode, 1);
    assert.match(row(out, "case").text, /names expected_authorizer, which this version does not read: the authorizer comes from the verifier \(--authorizer\), never from the case/);
  }
  const wrongPath = await run(await buildCase("eip3009", { binding: "calldata" }), testPins(), as("eip3009"));
  assert.equal(wrongPath.exitCode, 1);
  assert.match(row(wrongPath, "g.binding").text, /set binding to eip3009-nonce/);
});

test("ABSENT: a calldata trade and an EIP-3009 settlement that do not carry the destination entry hash fail", async () => {
  for (const [kind, o] of [["calldata", { omitHash: true }], ["eip3009", { nonceIsEntryHash: false }]]) {
    const files = await buildCase(kind, o);
    for (const out of [await run(files, testPins(), as(kind)), await run(files), await online(files, as(kind))]) {
      assert.equal(out.exitCode, 1, `${kind}: ${out.result}`);
      assert.equal(row(out, "g.binding").status, "FAIL");
      assert.match(row(out, "g.binding").text, /^ABSENT: the destination entry hash 0x[0-9a-f]{64} is not in the transaction's calldata/);
    }
  }
});

test("EIP-3009 token logs: a Transfer counts only from the pinned token, above zero, from the authorization's signer, tied to it by nonce", async () => {
  const token = TEST_TOKEN.address.toLowerCase();
  const cases = [
    ["a Transfer from another contract", (rc) => (rc.logs[1].address = testAddress("another token contract").toLowerCase()), /holds 0 Transfer logs from the token/],
    ["a Transfer from another account", (rc) => (rc.logs[1].topics[1] = topicAddr(testAddress("another account"))), /holds 0 Transfer logs from the token/],
    ["an AuthorizationUsed log for another nonce", (rc) => (rc.logs[0].topics[2] = "0x" + "ab".repeat(32)), /names another authorizer or nonce/],
    ["no AuthorizationUsed log", (rc) => rc.logs.splice(0, 1), /holds 0 AuthorizationUsed logs/],
    ["an AuthorizationUsed log from another contract", (rc) => (rc.logs[0].address = testAddress("another token contract").toLowerCase()), /holds 0 AuthorizationUsed logs/],
  ];
  for (const [name, fn, re] of cases) {
    const files = edit(await buildCase("eip3009"), "chain/receipt.json", fn);
    for (const out of [await run(files, testPins(), as("eip3009")), await online(files, as("eip3009"))]) {
      assert.equal(out.exitCode, 1, `${name}: ${out.result}`);
      assert.equal(row(out, "g.token-logs").status, "FAIL", name);
      assert.match(row(out, "g.token-logs").text, re, name);
    }
  }
  const zero = await run(await buildCase("eip3009", { authValue: 0n }), testPins(), as("eip3009"));
  assert.equal(zero.exitCode, 1);
  assert.match(row(zero, "g.token-logs").text, /moves 0, and a Transfer of 0 does not count/);
  // A token the pinned profile does not name.
  const files = await buildCase("eip3009", { editProfile: (d) => ((d.tokens[0].address = testAddress("a token nobody pinned").toLowerCase()), d) });
  const unnamed = await run(files, pinsFor(files), as("eip3009"));
  assert.equal(unnamed.exitCode, 1);
  assert.match(row(unnamed, "g.token-domain").text, new RegExp(`calls ${token}, which the pinned profile does not name among its EIP-3009 tokens`));
  const none = await buildCase("eip3009", { editProfile: (d) => (delete d.tokens, d) });
  assert.match(row(await run(none, pinsFor(none), as("eip3009")), "g.token-domain").text, /it names none/);
});

test("chain id: the case must be on the chain the pinned profile names (Base mainnet, 8453, when it names none); trailer-report mode reads 8453 only", async () => {
  const on8453 = await buildCase("calldata", { chainId: 8453 });
  const out = await run(on8453, testPins(), as("calldata"));
  assert.equal(out.exitCode, 1);
  assert.equal(row(out, "a.chain-id").status, "FAIL");
  assert.match(row(out, "a.chain-id").text, /case\.json chain_id 8453 is not the chain the pinned profile names: 31337/);
  const noChain = await buildCase("calldata", { chainId: 8453, editProfile: (d) => (delete d.chain_id, d) });
  const base = await run(noChain, pinsFor(noChain), as("calldata"));
  assert.equal(base.exitCode, 4, formatRows(base.rows));
  assert.match(row(base, "a.chain-id").text, /chain id 8453, the chain the pinned profile names \(Base mainnet, since the profile names no chain_id\)/);
  const local = await buildCase("calldata", { editProfile: (d) => (delete d.chain_id, d) });
  assert.match(row(await run(local, pinsFor(local), as("calldata")), "a.chain-id").text, /chain_id 31337 is not the chain the pinned profile names: 8453 \(Base mainnet, since the profile names no chain_id\)/);
  // A transaction signed for another chain than the one the case and the profile name.
  const elsewhere = edit(await buildCase("calldata", { chainId: 8453 }), "case.json", (c) => (c.chain_id = 31337));
  const signedElsewhere = await run(elsewhere, testPins(), as("calldata"));
  assert.equal(signedElsewhere.exitCode, 1);
  assert.equal(row(signedElsewhere, "a.chain-id").status, "PASS");
  assert.match(row(signedElsewhere, "f.transaction").text, /^transaction chain id 8453 is not the case's chain_id 31337$/);
  const src = await buildCase("eip3009", { tokenDomainFile: true });
  const tr = new Map([...src].filter(([k]) => k.startsWith("chain/")));
  put(tr, "case.json", { format: "chirindo-h4-case/1", mode: "trailer-report", chain_id: 31337, tx_hash: J(src, "chain/transaction.json").hash });
  const trailer = await run(tr);
  assert.equal(trailer.exitCode, 1);
  assert.match(row(trailer, "case").text, /trailer-report mode reads Base mainnet only: case\.json chain_id must be 8453, not 31337/);
});

test("inputs that stopped rev 2 with a stack trace now give a FAIL or INFO line and a RESULT", async () => {
  const files = await buildCase("calldata");
  const io = {
    readCase: (r) => {
      if (r === "requests/source.json") {
        const e = new Error("EISDIR: illegal operation on a directory, read");
        e.code = "EISDIR";
        throw e;
      }
      return files.get(r) ?? null;
    },
    readPin: (r) => testPins().get(r) ?? null,
  };
  const out = await checkCase(io, as("calldata"));
  assert.equal(out.exitCode, 1);
  assert.match(row(out, "b.source.request-hash").text, /EISDIR/);
  // A pinned profile whose request layout gives a field another type than the receipt's.
  const g = await buildCase("calldata", { editProfile: (d) => ((d.request.eip712.types.TestTradeRequest = d.request.eip712.types.TestTradeRequest.map((x) => (x.name === "action" ? { name: "action", type: "uint256" } : x))), d) });
  for (const role of ["source", "destination"]) edit(g, `receipts/${role}.json`, (e) => delete e.layout);
  g.delete("requests/source.json");
  g.delete("requests/destination.json");
  const x = await run(g, pinsFor(g), as("calldata"));
  assert.equal(x.exitCode, 4, formatRows(x.rows));
  assert.match(row(x, "b.source.request-fields").text, /could not be computed under the profile's request layout/);
  assert.equal(x.rows.at(-1).status, "RESULT");
});

test("a receipt signed by a different key fails", async () => {
  const notListed = await run(await buildCase("calldata", { issuerKey: KEYS.otherIssuer }), testPins(), as("calldata"));
  assert.equal(notListed.exitCode, 1);
  assert.match(row(notListed, "b.source.signer-key").text, /is not among the profile's signers/);
  const mismatch = await run(await buildCase("calldata", { issuerKey: KEYS.otherIssuer, claimedSigner: privateKeyToAccount(KEYS.issuer).address }), testPins(), as("calldata"));
  assert.equal(mismatch.exitCode, 1);
  assert.match(row(mismatch, "b.source.signature").text, /not the envelope's signer/);
  // The issuer's own sample-role key, which its key document lists but its profile does not.
  const sample = await run(await buildCase("calldata", { issuerKey: KEYS.sampleIssuer }), testPins(), as("calldata"));
  assert.equal(sample.exitCode, 1);
  assert.match(row(sample, "b.source.signer-key").text, /is not among the profile's signers/);
});

test("a wrong pinned witness key fails", async () => {
  const files = await buildCase("calldata");
  const otherKey = await run(files, testPins({ stub: OTHER_STUB_WITNESS }), as("calldata"));
  assert.equal(otherKey.exitCode, 1);
  assert.match(row(otherKey, "e.witness-receipt").text, /does not verify under the pinned key/);
  const otherId = await run(files, testPins({ stub: OTHER_STUB_WITNESS, keyId: "stub_test_v2" }), as("calldata"));
  assert.equal(otherId.exitCode, 1);
  assert.match(row(otherId, "e.witness-receipt").text, /public_key_id/);
});

test("log rules: each one, broken in an otherwise well-formed and checkpointed log, fails", async () => {
  const cases = [
    ["seq does not start at 0", { editEntries: (es) => es.map((e, k) => ({ ...e, seq: k + 1 })) }, "c.chain", /entry 0 has seq 1/],
    ["an entry with another session_id", { editEntries: (es) => es.map((e, k) => (k === 1 ? { ...e, session_id: "another session" } : e)) }, "c.chain", /session_id "another session"/],
    ["an entry with another v", { editEntries: (es) => es.map((e, k) => (k === 1 ? { ...e, v: "test.h4-log/2" } : e)) }, "c.chain", /v "test.h4-log\/2"/],
    ["one receipt uid in two entries", { editEntries: (es) => es.map((e) => ({ ...e, receipt_uid: es[0].receipt_uid })) }, "c.receipt-uids", /the source receipt's uid appears as receipt_uid in 2 entries/],
    ["the destination uid before the source uid", { editEntries: (es) => [es[1], es[0]].map((e, k) => ({ ...e, seq: k })) }, "c.receipt-uids", /is not before/],
    ["an entry after the checkpoint's count", { extraEntry: true }, "d.checkpoint-covers", /the log holds 3 entries/],
    ["a checkpoint signed for another session_id", { checkpointSessionId: "another session" }, "d.checkpoint-session", /is not the log's/],
    ["a witness receipt for another head", { witnessHead: true }, "e.witness-covers-checkpoint", /count "1" is not the checkpoint's "2"/],
  ];
  for (const [name, o, id, re] of cases) {
    const out = await run(await buildCase("calldata", o), testPins(), as("calldata"));
    assert.equal(out.exitCode, 1, name);
    assert.equal(row(out, id).status, "FAIL", `${name}: ${id}`);
    assert.match(row(out, id).text, re, name);
  }
});

test("EIP-3009 forms: the bytes-signature overload binds; receiveWithAuthorization and a hash in another authorization word are NOT SUPPORTED", async () => {
  const bytes = await run(await buildCase("eip3009", { bytesSignature: true }), testPins(), as("eip3009"));
  assert.equal(bytes.exitCode, 4, formatRows(bytes.rows));
  assert.match(row(bytes, "g.binding").text, /^BOUND: /);
  assert.match(row(bytes, "g.authorization").text, /^transferWithAuthorization\(address,address,uint256,uint256,uint256,bytes32,bytes\)/);
  const receive = await run(await buildCase("eip3009", { receive: true }), testPins(), as("eip3009"));
  assert.equal(receive.exitCode, 1);
  assert.equal(row(receive, "g.authorization").status, "NOT SUPPORTED");
  assert.match(row(receive, "g.binding").text, /no binding established: receiveWithAuthorization/);
  const word = await run(await buildCase("eip3009", { hashAsValidBefore: true }), testPins(), as("eip3009"));
  assert.equal(word.exitCode, 1);
  assert.equal(row(word, "g.authorization-word").status, "NOT SUPPORTED");
  assert.match(row(word, "g.authorization-word").text, /byte offset 132/);
});

test("a witness receipt for another signed checkpoint of the same head binds the head and is reported", async () => {
  const out = await run(await buildCase("calldata", { witnessOtherCheckpoint: true }), testPins(), as("calldata"));
  assert.equal(out.exitCode, 4, formatRows(out.rows));
  assert.equal(fails(out).length, 0);
  assert.equal(row(out, "e.checkpoint-sha256").status, "INFO");
  assert.match(row(out, "e.witness-covers-checkpoint").text, /another signed checkpoint of the same head/);
  assert.match(row(out, "i.checkpoint").text, /the witness's checkpoint_ts/);
});

test("checks that no other check stands in for: each fails on its own", async () => {
  const cases = [
    ["a checkpoint naming another key's kid, signed by the log key and witnessed", "calldata", { checkpointKid: okpThumbprint(OTHER_STUB_WITNESS.x) }, "d.checkpoint-key", /is not the log key's thumbprint/],
    ["a signed, witnessed checkpoint over another last entry hash", "calldata", { checkpointLastHash: "sha256:" + "ab".repeat(32) }, "d.checkpoint-covers", /is not the recomputed entry hash/],
    ["a witness receipt that reports a fork", "calldata", { witnessFork: "true" }, "e.witness-covers-checkpoint", /fork is "true"/],
    ["an authorization signed by a key other than its from", "eip3009", { authSignKey: KEYS.relayer }, "g.authorization", /not the authorization's from/],
    ["an authorization signature in its high-s form", "eip3009", { authHighS: true }, "g.authorization", /high-s/],
    ["an authorization signed for another token contract", "eip3009", { authDomainContract: testAddress("another token contract") }, "g.authorization", /not the authorization's from/],
    ["two AuthorizationUsed logs", "eip3009", { duplicateAuthUsed: true }, "g.token-logs", /holds 2 AuthorizationUsed logs/],
    ["a block time after the authorization's validBefore", "eip3009", { validBefore: 1792130000 + 20 - 1 }, "g.validity-window", /is outside/],
    ["an issuer profile the verifier did not pin", "calldata", { editProfile: (d) => ((d.receipt.eip712.domain.version = "2"), d) }, "a.profile", /is not a profile the verifier pinned/],
    ["a pinned issuer profile that does not list the signer", "calldata", { editProfile: (d) => ((d.signers[0].address = testAddress("a signer nobody uses").toLowerCase()), d), pin: true }, "b.source.signer-key", /is not among the profile's signers/],
  ];
  for (const [name, kind, o, id, re] of cases) {
    const files = await buildCase(kind, o);
    const out = await run(files, o.pin ? pinsFor(files) : testPins(), as(kind));
    assert.equal(out.exitCode, 1, `${name}: ${out.result}`);
    assert.equal(row(out, id)?.status, "FAIL", `${name}: ${id}`);
    assert.match(row(out, id).text, re, name);
  }
  // The transaction's from and the receipt's from both name someone other than the signer.
  const files = await buildCase("calldata");
  const other = testAddress("someone who did not sign").toLowerCase();
  for (const rel of ["chain/transaction.json", "chain/receipt.json"]) edit(files, rel, (x) => (x.from = other));
  const sender = await run(files, testPins(), as("calldata"));
  assert.equal(sender.exitCode, 1);
  assert.match(row(sender, "f.sender").text, /not the transaction's from/);
  // A receipt signature with v 0 or 1, and one in its high-s form (the same signer recovers from it).
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const withSig = async (fn) => run(edit(await buildCase("calldata"), "receipts/source.json", (env) => (env.sig = fn(env.sig))), testPins(), as("calldata"));
  const v01 = await withSig((sig) => sig.slice(0, 130) + (parseInt(sig.slice(130), 16) - 27).toString(16).padStart(2, "0"));
  assert.match(row(v01, "b.source.signature").text, /not 27 or 28/);
  const highS = await withSig((sig) => sig.slice(0, 66) + (N - BigInt("0x" + sig.slice(66, 130))).toString(16).padStart(64, "0") + (55 - parseInt(sig.slice(130), 16)).toString(16));
  assert.equal(highS.exitCode, 1);
  assert.match(row(highS, "b.source.signature").text, /high-s/);
});

test("more checks that no other check stands in for: chain data, keys, envelope data, witness type", async () => {
  // A receipt for another transaction, consistent in itself.
  const otherHash = "0x" + "cd".repeat(32);
  const rcOther = edit(await buildCase("calldata"), "chain/receipt.json", (rc) => {
    rc.transactionHash = otherHash;
    for (const l of rc.logs) l.transactionHash = otherHash;
  });
  assert.match(row(await run(rcOther, testPins(), as("calldata")), "f.receipt").text, /receipt transactionHash differs/);
  // Another block, whose own hash recomputes from its header.
  const blkOther = edit(await buildCase("calldata"), "chain/block.json", (b) => {
    b.number = "0x" + (BigInt(b.number) + 1n).toString(16);
    b.hash = headerHash(b).recomputed;
  });
  assert.match(row(await run(blkOther, testPins(), as("calldata")), "f.block").text, /is not the transaction's block/);
  // Receipt data signed with schema version 2 where the profile says 1.
  assert.match(row(await run(await buildCase("calldata", { formatVersion: 2 }), testPins(), as("calldata")), "b.source.envelope").text, /payload\.formatVersion is 2, not 1/);
  // A pinned profile whose signer is valid only outside the receipt's check time.
  const keyCases = [
    [(k) => (k.valid_from = "2026-12-01T00:00:00.000Z"), /from after the receipt's evaluatedAt/],
    [(k) => (k.valid_until = "2026-02-01T00:00:00.000Z"), /until before the receipt's evaluatedAt/],
  ];
  for (const [fn, re] of keyCases) {
    const files = await buildCase("calldata", { editProfile: (d) => (fn(d.signers[0]), d) });
    const out = await run(files, pinsFor(files), as("calldata"));
    assert.equal(out.exitCode, 1);
    assert.match(row(out, "b.source.signer-key").text, re);
  }
  // A validly signed witness receipt of another type.
  assert.match(row(await run(await buildCase("calldata", { witnessType: "witness.checkpoint/2" }), testPins(), as("calldata")), "e.witness-covers-checkpoint").text, /type is witness\.checkpoint\/2/);
});

test("--online with an EIP-3009 settlement: the pinned token's domain is compared with the token's own, read by eth_call (stand-in fetch)", async () => {
  const files = await buildCase("eip3009");
  const good = await online(files, as("eip3009"));
  assert.equal(good.exitCode, 0, formatRows(good.rows));
  assert.match(row(good, "g.token-domain").text, /named by the pinned profile and read with eth_call \(name, version, DOMAIN_SEPARATOR\)/);
  const badSep = await online(files, as("eip3009"), { token: { separator: "0x" + "ee".repeat(32) } });
  assert.match(row(badSep, "g.token-domain").text, /DOMAIN_SEPARATOR\(\) is not the separator/);
  const otherVersion = await online(files, as("eip3009"), { token: { version: "1" } });
  assert.match(row(otherVersion, "g.token-domain").text, /the pinned profile's domain .* differs from the token's own/);
  const split = await online(files, as("eip3009"), { change: (url, m, r) => (m === "eth_call" && url.startsWith("https://rpc-b.") ? r + "00" : r) });
  assert.match(row(split, "g.token-domain").text, /do not give byte-equal answers for the token's name\(\), version\(\) and DOMAIN_SEPARATOR\(\)/);
  // Ordering mode reads the domain from the pinned profile, never from the case: a
  // chain/token-domain.json naming another domain is not read, and the line says so.
  const withFile = edit(await buildCase("eip3009", { tokenDomainFile: true }), "chain/token-domain.json", (d) => (d.name = "Another Token Name"));
  for (const out of [await run(withFile, testPins(), as("eip3009")), await online(withFile, as("eip3009"))]) {
    assert.equal(fails(out).length, 0, formatRows(out.rows));
    assert.match(row(out, "g.token-domain").text, /; chain\/token-domain\.json is not read in ordering mode$/);
    assert.doesNotMatch(row(out, "g.token-domain").text, /equal to chain\/token-domain\.json/);
  }
});

test("a UserOperation path is NOT SUPPORTED and the ordering check fails", async () => {
  const out = await run(await buildCase("calldata", { useropTarget: true }), testPins(), as("calldata"));
  assert.equal(out.exitCode, 1);
  assert.equal(row(out, "g.userop").status, "NOT SUPPORTED");
  assert.equal(row(out, "g.binding").status, "FAIL");
});

test("a transaction type this checker does not serialize fails as unsupported, never passes", async () => {
  for (const type of ["0x3", "0x7e", "0x5"]) {
    const out = await run(edit(await buildCase("calldata"), "chain/transaction.json", (tx) => (tx.type = type)), testPins(), as("calldata"));
    assert.equal(out.exitCode, 1);
    assert.match(row(out, "f.transaction").text, /unsupported type/);
  }
});

test("trailer-report mode reads a settlement with an ERC-8021 trailer on Base mainnet, claims no entry hash and exits 3", async () => {
  const src = await buildCase("eip3009", { chainId: 8453, tokenDomainFile: true });
  const files = new Map([...src].filter(([k]) => k.startsWith("chain/")));
  put(files, "case.json", { format: "chirindo-h4-case/1", mode: "trailer-report", chain_id: 8453, tx_hash: J(src, "chain/transaction.json").hash });
  const out = await run(files, testPins(), as("eip3009"));
  assert.equal(out.exitCode, 3, formatRows(out.rows));
  assert.match(out.result, /^TRAILER REPORT/);
  assert.match(row(out, "case").text, /--authorizer is not read in trailer-report mode/);
  assert.equal(row(out, "g.authorization").status, "PASS");
  assert.equal(row(out, "g.token-logs").status, "INFO");
  assert.match(row(out, "g.token-logs").text, /reported only: trailer-report mode pins no token/);
  assert.match(row(out, "g.binding").text, /none is claimed/);
  assert.match(row(out, "h.trailer").text, /33 byte\(s\) after the ABI-encoded arguments .*ERC-8021 suffix: schema 2, CBOR \{"w": "test_facil"\}.*no entry hash is read from it/);
  // A chain/token-domain.json for another contract than the one the transaction calls, with
  // an authorization signed under that domain.
  const other = await buildCase("eip3009", { chainId: 8453, tokenDomainFile: true, authDomainContract: testAddress("another token contract") });
  const tr = new Map([...other].filter(([k]) => k.startsWith("chain/")));
  put(tr, "case.json", { format: "chirindo-h4-case/1", mode: "trailer-report", chain_id: 8453, tx_hash: J(other, "chain/transaction.json").hash });
  const wrong = await run(tr);
  assert.equal(wrong.exitCode, 1, formatRows(wrong.rows));
  assert.match(row(wrong, "g.token-domain").text, /^the token domain's verifyingContract is not the contract the transaction calls$/);
});

test("ERC-8021: synthetic suffixes in each layout of the draft ERC, and malformed ones", () => {
  // Made-up codes and values (no real app's, wallet's or facilitator's code)
  // in the layouts of the draft ERC (ethereum/ERCs pull 1209, ERCS/erc-8021.md):
  // schema 0 codes, schema 1 codes with a registry, schema 2 a CBOR map, and an
  // unknown schema id. 0xdddddddd stands for the calldata before the suffix.
  const M = "80218021802180218021802180218021";
  const v0 = parseErc8021("0xdddddddd746573745f617070080080218021802180218021802180218021");
  assert.deepEqual([v0.schemaId, v0.codes, v0.length, v0.codeRegistryAddress], [0, ["test_app"], 26, undefined]);
  const v0b = parseErc8021("0xdddddddd746573745f6170702c746573745f77616c6c6574140080218021802180218021802180218021");
  assert.deepEqual([v0b.schemaId, v0b.codes, v0b.length], [0, ["test_app", "test_wallet"], 38]);
  const v0e = parseErc8021("0xdddddddd000080218021802180218021802180218021");
  assert.deepEqual([v0e.schemaId, v0e.codes, v0e.length], [0, [], 18]);
  const v1 = parseErc8021("0xddddddddcccccccccccccccccccccccccccccccccccccccc7a6902746573745f6170702c746573745f77616c6c6574140180218021802180218021802180218021");
  assert.deepEqual([v1.schemaId, v1.codes, v1.length, v1.codeRegistryChainId, v1.codeRegistryAddress], [1, ["test_app", "test_wallet"], 61, "31337", "0x" + "cc".repeat(20)]);
  const v2 = parseErc8021("0xdddddddda1616168746573745f617070000c0280218021802180218021802180218021");
  assert.deepEqual([v2.schemaId, v2.length, [...v2.cbor.keys()], v2.cbor.get("a")], [2, 31, ["a"], "test_app"]);
  const v2r = parseErc8021(
    "0xdddddddda4616168746573745f61707061776b746573745f77616c6c65746172a16161a26163663078376136396161782a307831313131313131313131313131313131313131313131313131313131313131313131313131313131616da26863616d706169676e6d746573742d63616d706169676e66736f757263656b746573742d736f7572636500840280218021802180218021802180218021",
  );
  assert.deepEqual(
    [v2r.length, [...v2r.cbor.keys()], v2r.cbor.get("a"), v2r.cbor.get("w"), v2r.cbor.get("r").get("a").get("c"), v2r.cbor.get("r").get("a").get("a"), v2r.cbor.get("m").get("campaign"), v2r.cbor.get("m").get("source")],
    [151, ["a", "w", "r", "m"], "test_app", "test_wallet", "0x7a69", "0x" + "11".repeat(20), "test-campaign", "test-source"],
  );
  const v2s = parseErc8021("0xdddddddda3616168746573745f61707061776b746573745f77616c6c65746173826e746573745f736572766963655f316e746573745f736572766963655f32003b0280218021802180218021802180218021");
  assert.deepEqual([v2s.length, v2s.cbor.get("w"), v2s.cbor.get("s")], [78, "test_wallet", ["test_service_1", "test_service_2"]]);
  // A CBOR map longer than 255 bytes (its 2-byte length is 0x0138).
  const v2l = parseErc8021("0xdddddddd" + "a1616da1646e6f7465" + "79012c" + "78".repeat(300) + "0138" + "02" + M);
  assert.deepEqual([v2l.schemaId, v2l.length, v2l.cbor.get("m").get("note")], [2, 331, "x".repeat(300)]);
  const vff = parseErc8021("0xddddddddff80218021802180218021802180218021");
  assert.deepEqual([vff.schemaId, vff.unknown], [255, true]);
  assert.equal(parseErc8021("0xdddddddd"), null);
  assert.equal(parseErc8021("0x" + M), null);
  assert.equal(parseErc8021("0x" + "dd".repeat(40)), null);
  // Malformed suffixes are refused, never read as something else.
  assert.throws(() => parseErc8021("0x6162" + "08" + "00" + M), { message: "ERC-8021 suffix is truncated (codes)" });
  assert.throws(() => parseErc8021("0xdddddddd" + "ff" + "01" + "00" + M), { message: "ERC-8021 codes are not 7-bit ASCII" });
  assert.throws(() => parseErc8021("0xdddddddd" + "cc".repeat(20) + "00" + "74657374" + "04" + "01" + M), { message: "ERC-8021 registry chain id length is 0" });
  assert.throws(() => parseErc8021("0xdddddddd" + "a1616168746573745f617070" + "00" + "000d" + "02" + M), { message: "ERC-8021 CBOR data has bytes after its map" });
  assert.throws(() => parseErc8021("0xdddddddd" + "68746573745f617070" + "0009" + "02" + M), { message: "ERC-8021 CBOR data is not a map" });
});

test("block hash: recomputed from real Base mainnet headers (two blocks, two endpoints at fetch time)", () => {
  for (const n of ["52690283", "52640383"]) {
    const v = JSON.parse(readFileSync(path.join(HERE, "vectors", `base-mainnet-block-${n}.json`), "utf8"));
    const hh = headerHash(v.header);
    assert.equal(hh.fields, 21);
    assert.equal(hh.recomputed, v.header.hash);
    const h2 = { ...v.header, timestamp: "0x" + (BigInt(v.header.timestamp) + 1n).toString(16) };
    assert.notEqual(headerHash(h2).recomputed, v.header.hash);
    const withExtra = headerHash({ ...v.header, newField: "0x1" });
    assert.deepEqual([withExtra.unknown, withExtra.recomputed], [["newField"], v.header.hash]);
    const renamed = { ...v.header, requestsHasH: v.header.requestsHash };
    delete renamed.requestsHash;
    assert.notEqual(headerHash(renamed).recomputed, v.header.hash);
  }
});

test("transaction hash and sender: the checker's serialization equals viem's for every supported type", async () => {
  const key = KEYS.trader;
  const from = privateKeyToAccount(key).address.toLowerCase();
  const to = testAddress("serialization target");
  const base = { nonce: 3, gas: 50000n, to, value: 5n, data: "0x1234" };
  const cases = [
    { type: "legacy", chainId: 8453, gasPrice: 7n, ...base },
    { type: "eip2930", chainId: 8453, gasPrice: 7n, accessList: [{ address: to, storageKeys: ["0x" + "01".repeat(32)] }], ...base },
    { type: "eip1559", chainId: 8453, maxFeePerGas: 9n, maxPriorityFeePerGas: 1n, accessList: [], ...base },
    { type: "eip7702", chainId: 8453, maxFeePerGas: 9n, maxPriorityFeePerGas: 1n, accessList: [], authorizationList: [{ chainId: 8453, address: to, nonce: 4, r: "0x" + "02".repeat(32), s: "0x" + "03".repeat(32), yParity: 1 }], ...base },
  ];
  const q = (v) => "0x" + BigInt(v).toString(16);
  for (const t of cases) {
    const hash = keccak256(serializeTransaction(t));
    const sig = await secpSign({ hash, privateKey: key });
    const signed = serializeTransaction(t, t.type === "legacy" ? { r: sig.r, s: sig.s, v: BigInt(8453 * 2 + 35 + sig.yParity) } : { r: sig.r, s: sig.s, yParity: sig.yParity });
    const rpcTx = {
      type: { legacy: "0x0", eip2930: "0x1", eip1559: "0x2", eip7702: "0x4" }[t.type],
      chainId: q(8453), nonce: q(3), gas: q(50000), to: to.toLowerCase(), value: q(5), input: "0x1234",
      r: q(BigInt(sig.r)), s: q(BigInt(sig.s)),
      v: t.type === "legacy" ? q(8453 * 2 + 35 + sig.yParity) : q(sig.yParity),
      ...(t.type === "legacy" ? { gasPrice: q(7) } : t.type === "eip2930" ? { gasPrice: q(7), accessList: t.accessList, yParity: q(sig.yParity) } : { maxFeePerGas: q(9), maxPriorityFeePerGas: q(1), accessList: [], yParity: q(sig.yParity) }),
      ...(t.type === "eip7702" ? { authorizationList: [{ chainId: q(8453), address: to.toLowerCase(), nonce: q(4), r: q("0x" + "02".repeat(32)), s: q("0x" + "03".repeat(32)), yParity: q(1) }] } : {}),
    };
    const ser = txSerialization(rpcTx);
    assert.equal(keccak256(ser.signedHex), keccak256(signed), `${t.type}: hash`);
    assert.equal(await recoverSigner(keccak256(ser.payloadHex), ser.r, ser.s, ser.yParity), from, `${t.type}: sender`);
  }
});

test("strict readers: a duplicate member, an unsafe integer, non-canonical base64url and upper-case hex each fail", async () => {
  const files = await buildCase("calldata");
  const change = (rel, fn) => {
    const f2 = new Map(files);
    f2.set(rel, Buffer.from(fn(files.get(rel).toString("utf8")), "utf8"));
    return run(f2, testPins(), as("calldata"));
  };
  const dup = await change("log/checkpoint.json", (s) => s.replace('"count": 2,', '"count": 2,\n  "count": 2,'));
  assert.match(row(dup, "d.checkpoint-shape").text, /duplicate member name "count"/);
  const unsafe = await change("log/entries.jsonl", (s) => s.replace('"seq":0', '"seq":9007199254740993'));
  assert.equal(unsafe.exitCode, 1);
  const cp = J(files, "log/checkpoint.json");
  // The last of 86 characters carries 2 bits of the signature and 4 unused
  // bits; setting one unused bit keeps the decoded bytes the same.
  const last = cp.sig.at(-1);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const sameBytes = alphabet[alphabet.indexOf(last) + 1];
  assert.ok(Buffer.from(cp.sig.slice(0, -1) + sameBytes, "base64url").equals(Buffer.from(cp.sig, "base64url")));
  const nonCanon = await change("log/checkpoint.json", (s) => s.replace(cp.sig, cp.sig.slice(0, -1) + sameBytes));
  assert.equal(nonCanon.exitCode, 1);
  assert.match(row(nonCanon, "d.checkpoint-shape").text, /not the canonical base64url form/);
  const w = J(files, "witness/receipt.json");
  const upper = await change("witness/receipt.json", (s) => s.replace(w.signature, w.signature.toUpperCase()));
  assert.match(row(upper, "e.witness-receipt").text, /lowercase hex/);
});

test("--online: the witness list and two endpoints, whose answers must be byte-equal (served here by a stand-in fetch)", async () => {
  const files = await buildCase("calldata");
  const w = J(files, "witness/receipt.json");
  const good = await online(files, as("calldata"));
  assert.equal(good.exitCode, 0, formatRows(good.rows));
  for (const id of ["e.online-witness", "a.online-keys", "f.online-rpc", "f.finality", "f.chain-data", "f.receipt", "f.block", "f.block-hash"]) assert.equal(row(good, id).status, "PASS", id);
  assert.match(row(good, "f.online-rpc").text, /give byte-equal answers for the transaction, its receipt and its block/);
  // The chain files left out: read from the two endpoints, held in memory.
  const bare = new Map([...files].filter(([k]) => !["chain/transaction.json", "chain/receipt.json", "chain/block.json"].includes(k)));
  const fromRpc = await run(bare, testPins(), { ...as("calldata"), online: true, fetchImpl: standIn(files), rpcUrls: RPC });
  assert.equal(fromRpc.exitCode, 0, formatRows(fromRpc.rows));
  assert.match(row(fromRpc, "f.chain-data").text, /byte-equal \(in memory; nothing saved\)/);
  // Endpoints that differ: on a field the checks read, and on one they do not.
  const blockB = (url, m, r) => (m === "eth_getBlockByNumber" && r.hash && url.startsWith("https://rpc-b.") ? { ...r, timestamp: "0x1" } : r);
  const split = await online(files, as("calldata"), { change: blockB });
  assert.equal(split.exitCode, 1);
  assert.match(row(split, "f.chain-data").text, /do not give byte-equal answers \(canonical JSON, RFC 8785\): they differ on block timestamp/);
  const gasPrice = await online(files, as("calldata"), { change: (url, m, r) => (m === "eth_getTransactionByHash" && url.startsWith("https://rpc-b.") ? { ...r, gasPrice: "0x1" } : r) });
  assert.equal(gasPrice.exitCode, 1);
  assert.match(row(gasPrice, "f.chain-data").text, /they differ on transaction gasPrice/);
  const extra = await online(files, as("calldata"), { change: (url, m, r) => (m === "eth_getTransactionReceipt" && url.startsWith("https://rpc-b.") ? { ...r, extraMember: "0x0" } : r) });
  assert.match(row(extra, "f.chain-data").text, /they differ on receipt extraMember/);
  const bothDiffer = await online(files, as("calldata"), { change: (url, m, r) => (m === "eth_getBlockByNumber" && r.hash ? { ...r, timestamp: "0x1" } : r) });
  assert.match(row(bothDiffer, "f.chain-data").text, /the case's chain\/ files differ from .* on block\.timestamp/);
  // Receipts the stand-in witness lists beside the supplied one, signed with the stub key.
  const signed = (fields) => {
    const body = { ...w, ...fields };
    delete body.signature;
    const sorted = Object.fromEntries(Object.keys(body).sort().map((k) => [k, body[k]]));
    return { ...sorted, signature: edSign(null, Buffer.from(jcs(sorted), "utf8"), STUB_WITNESS.key).toString("hex") };
  };
  const listed = (list, extra = {}) => online(files, as("calldata"), { list, ...extra });
  assert.match(row(await listed([]), "e.online-witness").text, /does not list a receipt equal/);
  const other = "sha256:" + "ab".repeat(32);
  assert.match(row(await listed([signed({ count: "1", last_entry_hash: other }), w]), "e.online-witness").text, /history was rewritten/);
  assert.match(row(await listed([w, signed({ last_entry_hash: other })]), "e.online-witness").text, /a fork/);
  const later = await listed([w, signed({ count: "3", last_entry_hash: other })]);
  assert.equal(row(later, "e.online-witness").status, "PASS");
  assert.match(row(later, "e.online-witness").text, /1 later checkpoint\(s\) \(counts 3\) go beyond the supplied log/);
  assert.match(row(await listed([{ ...w, received_at: "2026-10-16T05:53:27.732Z" }]), "e.online-witness").text, /does not verify under the pinned key/);
  assert.match(row(await listed([w, signed({ session_id: "another session" })]), "e.online-witness").text, /is for another kid or session_id/);
  // A list longer than 20 pages (rev 2 stopped at 20).
  const long = await listed([w], { pages: 25 });
  assert.equal(row(long, "e.online-witness").status, "PASS", row(long, "e.online-witness").text);
  assert.match(row(long, "e.online-witness").text, /in 25 page\(s\)/);
});

test("--online: the case's own chain files are compared with the endpoints' answers on the 24 facts the PASS line names, and on no other member", async () => {
  const files = await buildCase("calldata");
  // The endpoints answer with the original chain data; only the case's copy is changed.
  const served = standIn(files);
  const withCase = (rel, fn) => run(edit(new Map(files), rel, fn), testPins(), { ...as("calldata"), online: true, fetchImpl: served, rpcUrls: RPC });
  const PASS_TEXT =
    "https://rpc-a.invalid and https://rpc-b.invalid give byte-equal answers for the transaction, its receipt and its block; the checks below read those answers; " +
    "the case's chain/ files agree with them on 24 facts: the transaction's hash, type, chainId, nonce, from, to, value, input, r, s, blockHash, blockNumber and transactionIndex; " +
    "the receipt's status, transactionHash, blockHash, blockNumber, transactionIndex and logs (each log's address, topics, data and logIndex); " +
    "and the block's number, hash, parentHash and timestamp, and whether its transactions list holds the transaction. The files' other members are not compared";
  const good = await run(files, testPins(), { ...as("calldata"), online: true, fetchImpl: served, rpcUrls: RPC });
  assert.equal(good.exitCode, 0, formatRows(good.rows));
  assert.equal(row(good, "f.online-rpc").text, PASS_TEXT);
  // Each of the 24 facts, changed in the case's file alone: FAIL, naming it
  // (a changed transaction hash is also no longer in the block's list).
  const h32 = "0x" + "ab".repeat(32);
  const a20 = "0x" + "11".repeat(20);
  const [TX, RC, BLK] = ["chain/transaction.json", "chain/receipt.json", "chain/block.json"];
  const facts = [
    [TX, (t) => (t.hash = h32), "tx.hash, block.hasTx"],
    [TX, (t) => (t.type = "0x1"), "tx.type"],
    [TX, (t) => (t.chainId = "0x2105"), "tx.chainId"],
    [TX, (t) => (t.nonce = "0x8"), "tx.nonce"],
    [TX, (t) => (t.from = a20), "tx.from"],
    [TX, (t) => (t.to = a20), "tx.to"],
    [TX, (t) => (t.value = "0x1"), "tx.value"],
    [TX, (t) => (t.input += "00"), "tx.input"],
    [TX, (t) => (t.r = h32), "tx.r"],
    [TX, (t) => (t.s = "0x1"), "tx.s"],
    [TX, (t) => (t.blockHash = h32), "tx.blockHash"],
    [TX, (t) => (t.blockNumber = "0x1"), "tx.blockNumber"],
    [TX, (t) => (t.transactionIndex = "0x2"), "tx.transactionIndex"],
    [RC, (x) => (x.status = "0x0"), "receipt.status"],
    [RC, (x) => (x.transactionHash = h32), "receipt.transactionHash"],
    [RC, (x) => (x.blockHash = h32), "receipt.blockHash"],
    [RC, (x) => (x.blockNumber = "0x1"), "receipt.blockNumber"],
    [RC, (x) => (x.transactionIndex = "0x2"), "receipt.transactionIndex"],
    [RC, (x) => (x.logs[0].data = "0x" + "ff".repeat(32)), "receipt.logs"],
    [BLK, (b) => (b.number = "0x1"), "block.number"],
    [BLK, (b) => (b.hash = h32), "block.hash"],
    [BLK, (b) => (b.parentHash = h32), "block.parentHash"],
    [BLK, (b) => (b.timestamp = "0x1"), "block.timestamp"],
    [BLK, (b) => (b.transactions = [h32]), "block.hasTx"],
  ];
  assert.equal(facts.length, 24);
  for (const [rel, fn, named] of facts) {
    const out = await withCase(rel, fn);
    assert.equal(out.exitCode, 1, `${named}: ${formatRows(out.rows)}`);
    assert.equal(row(out, "f.chain-data").text, `the case's chain/ files differ from https://rpc-a.invalid and https://rpc-b.invalid on ${named}`);
  }
  // Members outside the 24, changed in the case's file alone: not compared, so
  // the run passes on the endpoints' answers, and the PASS line says no more.
  const others = [
    [TX, (t) => (t.gas = "0x33451")],
    [TX, (t) => (t.maxFeePerGas = "0x5b8d81")],
    [TX, (t) => (t.maxPriorityFeePerGas = "0xf4241")],
    [TX, (t) => (t.yParity = "0x1")],
    [TX, (t) => (t.from = privateKeyToAccount(KEYS.trader).address)],
    [RC, (x) => (x.gasUsed = "0x1")],
    [RC, (x) => (x.logs[0].blockHash = h32)],
    [BLK, (b) => (b.stateRoot = h32)],
    [BLK, (b) => (b.size = "0x1")],
  ];
  for (const [rel, fn] of others) {
    const out = await withCase(rel, fn);
    assert.equal(out.exitCode, 0, `${rel}: ${formatRows(out.rows)}`);
    assert.equal(row(out, "f.online-rpc").text, PASS_TEXT);
  }
});

test("--authorizer and --rpc as the library reads them: upper case accepted, a bad checksum refused naming the digit; one endpoint per host, two hosts needed", async () => {
  const files = await buildCase("calldata");
  const trader = privateKeyToAccount(KEYS.trader).address;
  for (const form of [trader, trader.toLowerCase(), "0x" + trader.slice(2).toUpperCase()]) {
    assert.equal(authorizerAddress(form), trader.toLowerCase(), form);
    const out = await run(files, testPins(), { authorizer: form });
    assert.equal(out.exitCode, 4, formatRows(out.rows));
    assert.match(row(out, "g.binding").text, /^BOUND: /);
  }
  // The first letter of the address, its case flipped.
  const k = trader.search(/[a-f]/i);
  const flipped = trader.slice(0, k) + (trader[k] === trader[k].toLowerCase() ? trader[k].toUpperCase() : trader[k].toLowerCase()) + trader.slice(k + 1);
  const badChecksum = { message: `--authorizer is in mixed case, so it is read as an EIP-55 checksum, and it is not a valid one: hex digit ${k - 1} of 40 should be ${trader[k] === trader[k].toUpperCase() ? "upper" : "lower"} case. Give the address all in lower case, all in upper case, or exactly in its EIP-55 form` };
  assert.throws(() => authorizerAddress(flipped), badChecksum);
  await assert.rejects(run(files, testPins(), { authorizer: flipped }), badChecksum);
  for (const bad of ["0X" + trader.slice(2), trader.slice(2), trader + "0", " " + trader, ""]) assert.throws(() => authorizerAddress(bad), { message: "--authorizer is not a 20-byte hex address (0x and 40 hex digits)" });
  assert.deepEqual(rpcEndpoints(["https://a.invalid/x", "https://A.INVALID./y", "http://a.invalid:8545", "https://b.invalid"]), { urls: ["https://a.invalid/x", "https://b.invalid"], dropped: ["https://A.INVALID./y", "http://a.invalid:8545"] });
  const viaRpc = (urls) => run(files, testPins(), { ...as("calldata"), online: true, fetchImpl: standIn(files), rpcUrls: urls });
  const oneHost = await viaRpc(["https://rpc-a.invalid", "https://rpc-a.invalid/again"]);
  assert.equal(oneHost.exitCode, 1, formatRows(oneHost.rows));
  assert.equal(row(oneHost, "f.chain-data").text, "--rpc names 1 distinct host(s) (1 more URL(s) on a host already named): name endpoints on at least two different hosts, run by different operators");
  const twoHosts = await viaRpc(["https://rpc-a.invalid", "https://rpc-a.invalid/again", "https://rpc-b.invalid"]);
  assert.equal(twoHosts.exitCode, 0, formatRows(twoHosts.rows));
  assert.equal(row(twoHosts, "f.online-rpc-hosts").text, "--rpc URL(s) on a host that an earlier --rpc URL names, not used: https://rpc-a.invalid/again");
  assert.match(row(twoHosts, "f.online-rpc").text, /^https:\/\/rpc-a\.invalid and https:\/\/rpc-b\.invalid give byte-equal answers/);
});

test("--online: the issuer's key document is read with the profile's map; a signer it no longer lists is NOT CHECKED; a block above the finalized one is FLAG (exit 5)", async () => {
  const files = await buildCase("calldata");
  const rotated = testKeyDocument();
  rotated.keys = rotated.keys.filter((k) => k.id !== "test-issuer-key-1");
  const out = await online(files, as("calldata"), { keyDoc: rotated, finalized: "0x1f00000" });
  assert.equal(out.exitCode, 5, formatRows(out.rows));
  assert.equal(fails(out).length, 0);
  assert.equal(row(out, "a.online-keys.source").status, "NOT CHECKED");
  assert.equal(row(out, "f.finality").status, "FLAG");
  assert.match(out.result, /^FLAG: no check failed, but 1 FLAG line\(s\) stand against a pass: f\.finality/);
  const edits = [
    [(d) => (d.keys[0].revoked = true), /has revoked true, not false/],
    [(d) => (d.keys[0].role = "sample"), /has role "sample", which the profile does not accept/],
    [(d) => (d.keys[0].valid_until = "2026-02-01T00:00:00.000Z"), /before the receipt's check time/],
    [(d) => (d.formats.check.domain.version = "2"), /differs from the profile's/],
    [(d) => d.keys.push({ ...d.keys[0], id: "a second entry" }), /listed more than once/],
  ];
  for (const [fn, re] of edits) {
    const doc = testKeyDocument();
    fn(doc);
    const x = await online(files, as("calldata"), { keyDoc: doc });
    assert.equal(x.exitCode, 1);
    assert.equal(row(x, "a.online-keys").status, "FAIL");
    assert.match(row(x, "a.online-keys").text, re);
  }
});

test("issuer profiles: pinned by sha256 in pins.json or with --profile-sha256, read strictly, and the profile's envelope map is followed", async () => {
  const files = await buildCase("calldata");
  const own = files.get("issuer/profile.json");
  // No profile pinned: the FAIL line never offers the case's own hash.
  const none = testPins({ profiles: [] });
  const unpinned = row(await run(files, none, as("calldata")), "a.profile");
  assert.equal(unpinned.status, "FAIL");
  assert.match(unpinned.text, /is not a profile the verifier pinned\. Obtain the sha256 of this issuer's published profile from the issuer, out of band, .*never pin a value read from the case itself/);
  assert.ok(!unpinned.text.includes(sha256Hex(own)), unpinned.text);
  // The same profile named for this run instead.
  const named = await run(files, none, as("calldata", { profileSha256: [sha256Hex(own)] }));
  assert.equal(named.exitCode, 4, formatRows(named.rows));
  assert.equal(fails(named).length, 0);
  assert.match(row(named, "a.profile").text, /pinned in --profile-sha256/);
  // Profiles that do not read: each pinned, so only the reader can refuse it.
  const broken = [
    [(d) => (d.receipt.fields.checked_at = "noSuchField"), /receipt\.fields\.checked_at names no field/],
    [(d) => (d.receipt.fields.verdict = "testNotional"), /receipt\.fields\.verdict \(testNotional\) has type uint256/],
    [(d) => (d.envelope.uid = "nowhere"), /envelope\.uid \(nowhere\) is in neither/],
    [(d) => (d.signers = []), /signers is not a non-empty list/],
    [(d) => d.signers.push({ ...d.signers[0] }), /list an address twice/],
    [(d) => ((d.key_document.url = "http://test-issuer.invalid/keys.json"), d), /not an https URL/],
    [(d) => (d.extra = 1), /unexpected member "extra"/],
    [(d) => (d.chain_id = "31337"), /chain_id is not a positive integer/],
    [(d) => (d.tokens = []), /tokens is not a non-empty list/],
    [(d) => (d.tokens[0].decimals = 6), /unexpected member "decimals"/],
    [(d) => d.tokens.push({ ...d.tokens[0] }), /tokens list an address twice/],
    [(d) => (d.tokens[0].address = "0x1234"), /tokens\[0\]\.address is not a 20-byte hex address/],
    [(d) => (d.tokens[0].version = ""), /tokens\[0\] name and version must be non-empty strings/],
  ];
  for (const [fn, re] of broken) {
    const f2 = await buildCase("calldata", { editProfile: (d) => (fn(d), d) });
    const out = await run(f2, pinsFor(f2), as("calldata"));
    assert.equal(out.exitCode, 1);
    assert.match(row(out, "a.profile").text, re);
  }
  // A receipt inside an API response: the profile's unwrap path is read.
  const wrapped = await buildCase("calldata");
  put(wrapped, "receipts/source.json", { status: "ok", result: { receipt: J(wrapped, "receipts/source.json") } });
  const unwrapped = await run(wrapped, testPins(), as("calldata"));
  assert.equal(unwrapped.exitCode, 4, formatRows(unwrapped.rows));
  assert.equal(fails(unwrapped).length, 0);
  assert.match(row(unwrapped, "b.source.envelope").text, /^read result\.receipt of the file/);
  // The fixture's profile is the generator's TEST profile, byte for byte.
  assert.ok(compact(testProfile()).equals(own));
});

test("default output redacts parties, also when a call does not decode or no authorizer is stated; --show-parties prints them", async () => {
  const parties = [KEYS.trader, KEYS.relayer, KEYS.payer, KEYS.facilitator].map(addrOf);
  parties.push(testAddress("test payee").toLowerCase());
  // Every 10-hex-digit run of the digits a redacted address hides (all but
  // the first 6 and the last 4).
  const hiddenRuns = (a) => Array.from({ length: 40 - 10 - 10 + 1 }, (_, k) => a.slice(8 + k, 18 + k));
  const leaked = (text) => parties.filter((a) => hiddenRuns(a).some((w) => text.includes(w)));
  const variants = [
    ["calldata", {}],
    ["calldata", { sender: "relayer" }],
    ["eip3009", {}],
    ["eip3009", { nonceIsEntryHash: false, trailerHash: true }],
    ["eip3009", { truncateInput: 26 }],
  ];
  for (const [kind, o] of variants) {
    const files = await buildCase(kind, o);
    for (const opts of [as(kind), {}]) {
      const out = await run(files, testPins(), opts);
      assert.deepEqual(leaked(formatRows(out.rows)), [], `${kind} ${JSON.stringify(o)} ${JSON.stringify(opts)}: a party's hidden digits appear in the default output`);
      if (o.truncateInput) assert.match(row(out, "g.call").text, /does not decode as transferWithAuthorization/);
    }
  }
  const files = await buildCase("eip3009");
  const payer = AUTHORIZER.eip3009;
  const redacted = formatRows((await run(files, testPins(), as("eip3009"))).rows);
  assert.ok(redacted.includes(`${payer.slice(0, 8)}...${payer.slice(-4)}`));
  const shown = formatRows((await run(files, testPins(), as("eip3009", { showParties: true }))).rows);
  assert.ok(shown.includes(payer));
});
