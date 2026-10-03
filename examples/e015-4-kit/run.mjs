// E015.4 evidence kit: shows, with real bytes, what a hash chain detects on
// its own and what it detects once checkpoints are witnessed.
//
// Run from the repo root (Node >= 20, Windows or Linux):
//
//   npx tsx examples/e015-4-kit/run.mjs
//
// tsx is required: the kit imports the TypeScript sources and the stub witness
// in test/witness-stub.ts, which is not part of the built dist.
//
// The witness here is a LOCAL STUB, not Headless Oracle's witness. Everything
// is deterministic (fixed gate and witness seeds, fixed session id, fixed stub
// clock, one tool call at a time), so RESULTS.md is byte-identical on every
// run. Scratch files go to ./work/ (gitignored; it holds a throwaway private
// key derived from a published seed).

import { spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  ed25519PrivateKeyFromSeed,
  loadFullIdentity,
  publicKeyFromPrivate,
  readChainFile,
  serializeChainJsonl,
  writeIdentity,
} from "../../src/vendor/recorder/index.ts";
import { appendReceipt } from "../../src/receipt.ts";
import { readSidecar, sidecarPathFor } from "../../src/witness.ts";
import { STUB_WITNESS_NAME, startStubWitness } from "../../test/witness-stub.ts";

const KIT = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(KIT, "..", "..");
const WORK = join(KIT, "work");
const GATE_DIR = join(WORK, "gate");
const COPIES = join(WORK, "copies");
const TSX_CLI = join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
const CLI = join(ROOT, "src", "cli.ts");
const FAKE_SERVER = join(ROOT, "scripts", "fake-mcp-server.ts");
const SESSION_ID = "e015-4-kit-0001";
const SERVER_LABEL = "kit-fake-server";
const EVERY = 2;

// Seven tool calls, ALLOW and DENY mixed. `delete` is denied by the policy.
const CALLS = [
  { tool: "echo", args: { text: "alpha" } },
  { tool: "delete", args: { path: "/srv/data/a" } },
  { tool: "echo", args: { text: "beta" } },
  { tool: "echo", args: { text: "gamma" } },
  { tool: "delete", args: { path: "/srv/data/b" } },
  { tool: "echo", args: { text: "delta" } },
  { tool: "echo", args: { text: "epsilon" } },
];
const DENY_REASON = "destructive: blocked by kit policy";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred, what, timeoutMs = 20_000) {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(20);
  }
}

function runCli(args) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [TSX_CLI, CLI, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("exit", (status) => done({ stdout, stderr, status }));
  });
}

// Absolute paths -> "<kit>/...", forward slashes, so the file is identical on
// every machine and OS.
function scrub(s) {
  const variants = [KIT, KIT.replace(/\\/g, "/")];
  for (const v of variants) s = s.split(v).join("<kit>");
  return s.replace(/<kit>[^\s)]*/g, (m) => m.replace(/\\/g, "/"));
}

// ---- 1. throwaway identities + policy ------------------------------------
rmSync(WORK, { recursive: true, force: true });
mkdirSync(COPIES, { recursive: true });
const gatePriv = ed25519PrivateKeyFromSeed(Buffer.alloc(32, 0x01));
writeIdentity(GATE_DIR, gatePriv, publicKeyFromPrivate(gatePriv));
const identityPath = join(GATE_DIR, IDENTITY_FILENAME);
const identity = loadFullIdentity(identityPath, join(GATE_DIR, PRIVATE_KEY_FILENAME));
const policyPath = join(WORK, "policy.json");
writeFileSync(policyPath, JSON.stringify({ deny: [{ tool: "delete", reason: DENY_REASON }] }, null, 2) + "\n");

// ---- 2. stub witness (seed 0x02, "stub.invalid", fixed clock) -------------
const stub = await startStubWitness();
const witnessArgs = ["--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME];

// ---- 3. drive the proxy ---------------------------------------------------
const chainPath = join(GATE_DIR, "sessions", `${SESSION_ID}.jsonl`);
const sidecar = sidecarPathFor(chainPath);
const sidecarLines = () => (existsSync(sidecar) ? readSidecar(sidecar).length : 0);

const proxy = spawn(
  process.execPath,
  [
    TSX_CLI, CLI, "proxy", "--dir", GATE_DIR, "--session-id", SESSION_ID,
    "--policy", policyPath, "--server-label", SERVER_LABEL,
    "--checkpoint-every", String(EVERY), ...witnessArgs,
    "--", "node", TSX_CLI, FAKE_SERVER,
  ],
  { stdio: ["pipe", "pipe", "pipe"] },
);
let proxyStderr = "";
proxy.stderr.on("data", (c) => (proxyStderr += c));
const proxyExit = new Promise((r) => proxy.on("exit", r));
const responses = new Map();
let outBuf = "";
proxy.stdout.on("data", (c) => {
  outBuf += c;
  const lines = outBuf.split("\n");
  outBuf = lines.pop() ?? "";
  for (const l of lines) {
    if (!l.trim()) continue;
    const msg = JSON.parse(l);
    if (msg.id !== undefined) responses.set(msg.id, msg);
  }
});
const send = (msg) => proxy.stdin.write(JSON.stringify(msg) + "\n");

send({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "e015-4-kit", version: "1" } } });
await waitFor(() => responses.has(0), "initialize response");

const results = [];
for (let i = 0; i < CALLS.length; i++) {
  const id = i + 1;
  send({ jsonrpc: "2.0", id, method: "tools/call", params: { name: CALLS[i].tool, arguments: CALLS[i].args } });
  await waitFor(() => responses.has(id), `response to call ${id}`);
  results.push(responses.get(id).result);
  // The next call goes out only after the checkpoint this call triggered is
  // in the sidecar, so the stub stores receipts in the same order every run.
  if (id % EVERY === 0) await waitFor(() => sidecarLines() >= id / EVERY, `checkpoint at count ${id}`);
}
proxy.stdin.end(); // clean shutdown: the proxy checkpoints the head (count 7)
const proxyCode = await proxyExit;
if (proxyCode !== 0) throw new Error(`proxy exited ${proxyCode}\n${proxyStderr}`);

// Once more by hand, so a witnessed checkpoint exists at the final count even
// if the shutdown checkpoint had not been witnessed.
const cpRun = await runCli(["checkpoint", chainPath, "--dir", GATE_DIR, ...witnessArgs]);
if (cpRun.status !== 0) throw new Error(`chirindo checkpoint exited ${cpRun.status}: ${cpRun.stderr}`);

// The witness goes away: every verify below runs offline from the sidecar.
await stub.close();

// ---- 4. six copies --------------------------------------------------------
const original = readChainFile(chainPath).records;
const copyPath = (name) => join(COPIES, `${name}.jsonl`);
const writeCopy = (name, records) =>
  writeFileSync(copyPath(name), serializeChainJsonl({ records, checkpoint: null }), "utf8");
const clone = () => JSON.parse(JSON.stringify(original));

copyFileSync(chainPath, copyPath("intact"));

const edited = clone();
edited[3].event.args_hash = "sha256:" + "0".repeat(64); // not re-signed
writeCopy("edited", edited);

const deleted = clone();
deleted.splice(3, 1);
writeCopy("deleted", deleted);

const reordered = clone();
[reordered[3], reordered[4]] = [reordered[4], reordered[3]];
writeCopy("reordered", reordered);

writeCopy("truncated", clone().slice(0, original.length - 2));

// The key holder rebuilds the whole chain with the same identity, session,
// label, tools, decisions, results and timestamps, changing only the
// arguments of the record at index 3, and re-signs every record.
for (let i = 0; i < original.length; i++) {
  const denied = CALLS[i].tool === "delete";
  appendReceipt({
    chainPath: copyPath("resigned"),
    sessionId: SESSION_ID,
    identity,
    server: SERVER_LABEL,
    toolName: CALLS[i].tool,
    toolArgs: i === 3 ? { text: "rewritten by the key holder" } : CALLS[i].args,
    ...(denied ? {} : { toolResult: results[i] }),
    decision: denied ? { kind: "deny", reason: DENY_REASON } : { kind: "allow" },
    ts: original[i].ts,
  });
}

// ---- 5. verify each copy, without and with the witness --------------------
const CASES = [
  { name: "intact", shows: "untouched session" },
  { name: "edited", shows: "record 3 event.args_hash changed, not re-signed" },
  { name: "deleted", shows: "record 3 removed" },
  { name: "reordered", shows: "records 3 and 4 swapped" },
  { name: "truncated", shows: "last 2 records cut off" },
  { name: "resigned", shows: "key holder rewrote record 3's arguments and re-signed the whole chain" },
];
const EXPECTED = {
  intact: [(o) => o.startsWith("VALID —"), (o) => o.startsWith("VALID —") && o.includes("\nWITNESSED through count 7,")],
  edited: [(o) => o === "TAMPERED — entry 3: request_commitment mismatch", (o) => o === "TAMPERED — entry 3: request_commitment mismatch"],
  deleted: [(o) => o === "TAMPERED — entry 3: sequence gap", (o) => o === "TAMPERED — entry 3: sequence gap"],
  reordered: [(o) => o === "TAMPERED — entry 3: sequence gap", (o) => o === "TAMPERED — entry 3: sequence gap"],
  truncated: [(o) => o.startsWith("VALID —"), (o) => o === "TAMPERED — witnessed count 6 is beyond the chain (5 records)"],
  resigned: [(o) => o.startsWith("VALID —"), (o) => o === "TAMPERED — witnessed count 4: last_entry_hash mismatch"],
};

const rows = [];
let mismatches = 0;
for (const c of CASES) {
  const base = ["verify", copyPath(c.name), "--key", identityPath];
  const plain = await runCli(base);
  const witnessed = await runCli([
    ...base, "--witness-file", sidecar, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
  ]);
  const outs = [plain, witnessed].map((r) => ({ text: scrub(r.stdout.trimEnd()), status: r.status }));
  outs.forEach((o, k) => {
    if (!EXPECTED[c.name][k](o.text)) {
      mismatches++;
      process.stderr.write(`MISMATCH: ${c.name} ${k === 0 ? "without" : "with"} witness:\n${o.text}\n`);
    }
  });
  rows.push({ ...c, outs });
}

// ---- 6. RESULTS.md --------------------------------------------------------
const cell = ({ text, status }) =>
  text.split("\n").map((l) => "`" + l.replace(/\|/g, "\\|") + "`").join("<br>") + `<br>exit ${status}`;
const md = [
  `This is NOT Headless Oracle's witness: these results come from a local stub witness ("witness":"stub.invalid", throwaway key from a fixed seed) implementing WITNESS_SPEC v0.3 sections 2 to 4.`,
  "received_at values come from a fixed test clock and are not real times.",
  "",
  "# E015.4 evidence kit: results",
  "",
  "Generated by `npx tsx examples/e015-4-kit/run.mjs`. Do not edit by hand; rerun the script.",
  "",
  `Session \`${SESSION_ID}\`: ${CALLS.length} tool calls (${CALLS.filter((c) => c.tool === "delete").length} DENY), proxy run with \`--checkpoint-every ${EVERY}\`; witnessed checkpoints at counts ${readSidecar(sidecar).filter((l) => l.witness_receipt).map((l) => l.checkpoint.count).join(", ")}. Each copy is verified twice:`,
  "",
  "- without witness: `chirindo verify <copy> --key <kit>/work/gate/identity.json`",
  `- with witness (offline): the same plus \`--witness-file <kit>/work/gate/sessions/${SESSION_ID}.jsonl.witness.ndjson --witness-key ${stub.publicKeyHex} --witness-name ${STUB_WITNESS_NAME}\``,
  "",
  "| Copy | What was done | Without witness | With witness |",
  "|---|---|---|---|",
  ...rows.map((r) => `| ${r.name} | ${r.shows} | ${cell(r.outs[0])} | ${cell(r.outs[1])} |`),
  "",
  "--witness-file trusts the sidecar the operator supplied; only querying the witness is independent of the operator.",
  "",
].join("\n");
writeFileSync(join(KIT, "RESULTS.md"), md, "utf8");

if (mismatches > 0) {
  process.stderr.write(`${mismatches} outcome(s) differ from the expected table; RESULTS.md written for inspection.\n`);
  process.exit(1);
}
process.stdout.write(`all 12 outcomes match the expected table; wrote ${join(KIT, "RESULTS.md")}\n`);
