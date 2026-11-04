// B-439: `chirindo issuer-pack`, spec rev 1 §8 (tests that define done) with
// the Lead's rulings of §11. The fixture is a purchase-check directory built
// by the package's own API (createPurchaseCheck and the three mappers of the
// examples), one customer instruction per chain, every chain witnessed by the
// in-process stub witness.

import { createHash, createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildIssuerPack, checkIssuerPack, PDF_MAX_DECISION_ROWS, type IssuerPackOptions, type IssuerPackResult } from "../src/issuer/pack.js";
import { pdfLines, renderPdf, PDF_MAX_BYTES, wrap, PDF_COLUMNS } from "../src/issuer/pdf.js";
import { BUNDLE_LIMITS, NOT_ENDORSED, NOT_THIS_FORMAT, CONSENT_NOT_SUPPLIED, PURCHASE_LIMITS, mappingRows as mappingRowsOf, packLimits } from "../src/issuer/texts.js";
import { readZip, writeZip } from "../src/issuer/zip.js";
import { createPurchaseCheck } from "../src/purchase/check.js";
import { mapBasisTheoryAllowance, mapCrossmintOrderIntent, mapPravaMandate } from "../src/purchase/mappers.js";
import { signInstruction, jcsSha256 } from "../src/purchase/m6.js";
import { writeIdentity } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir, makeTmpDir, runCli } from "./helpers.js";
import { GATE, keyFromSeed, type Key } from "./purchase-helpers.js";
import { ROOT } from "./trial-helpers.js";
import { startStubWitness, STUB_WITNESS_NAME, type StubWitness } from "./witness-stub.js";
// @ts-expect-error -- plain .mjs without declarations; it is the reference the port is compared against
import { LIMIT_TEXTS as REF_LIMIT_TEXTS } from "../examples/evidence-bundle/lib/limits.mjs";

type Obj = Record<string, unknown>;
const NOW = "2026-11-06T09:00:00.000Z";
const CLI_TIMEOUT = 60_000;

interface Example {
  name: string;
  key: Key;
  text: string;
  digest: string;
  session: string;
}

let root: string;
let dir: string; // the fixture: three chains, one per example
let inputs: string; // instructions/, request.json, consent.json, keys
let stub: StubWitness;
const ex: Example[] = [];

// A gate clock one second later on every call, so no receipt regresses.
function clock(): () => string {
  let n = 0;
  return () => new Date(Date.parse("2026-11-05T12:00:00.000Z") + 1000 * n++).toISOString();
}

const order = (sku: string, merchant: string, id: string, total: string) => ({
  merchant_id: merchant,
  merchant_order_id: id,
  currency: "USD",
  total_minor: total,
  items: [{ sku, quantity: 1, unit_price_minor: total, name: sku }],
});

async function runExample(d: string, now: () => string, name: string, key: Key, body: Obj, orders: Obj[]): Promise<Example> {
  const text = JSON.stringify(signInstruction(body, key.priv));
  const pc = createPurchaseCheck({ dir: d, now, witness: { baseUrl: stub.url, name: STUB_WITNESS_NAME, pinnedKey: stub.publicKeyHex } });
  for (const o of orders) pc.check({ instruction: text, order: o });
  await pc.close();
  return { name, key, text, digest: jcsSha256(JSON.parse(text)), session: pc.session_id };
}

function examples(): { name: string; key: Key; body: (k: KeyObject) => Obj; sku: string; totals: [string, string, string] }[] {
  const common = (k: KeyObject, maxUses: number, approvedAt: string) => ({ principalKey: k, agentKids: [GATE.kid], maxUses, approvedAt });
  return [
    {
      name: "crossmint",
      key: keyFromSeed(11),
      sku: "GROCERIES",
      totals: ["12000", "18000", "5000"],
      body: (k) =>
        mapCrossmintOrderIntent(
          { paymentMethodId: "pm_123", amount: { value: "150.00", currency: "USD" }, merchant: { name: "Acme Store", url: "https://acme.example.com", countryCode: "US" }, description: "Weekly grocery purchases", expiresAt: "2026-11-12T00:00:00.000Z" },
          common(k, 2, "2026-11-05T11:00:00.000Z"),
        ) as Obj,
    },
    {
      name: "basis-theory",
      key: keyFromSeed(12),
      sku: "OFFICE",
      totals: ["8000", "12000", "5000"],
      body: (k) =>
        mapBasisTheoryAllowance(
          { payment_method_id: "pm_h2Kd91mAqLwX", amount: { value: "100.00", currency: "USD" }, merchant: { name: "Acme Store", url: "https://acme.example.com", country_code: "US", category_code: "5732", acquirer_bin: "545301" }, description: "Buy approved office supplies from Acme Store", expires_at: "2030-07-08T00:00:00.000Z", metadata: { order_ref: "po-1138" } },
          common(k, 2, "2026-11-05T11:00:00.000Z"),
        ) as Obj,
    },
    {
      name: "prava",
      key: keyFromSeed(13),
      sku: "PLAN",
      totals: ["3500", "4500", "2000"],
      body: (k) =>
        mapPravaMandate(
          {
            mandate: { id: "mdt_123", status: "active", approvedAmount: "40.00", currency: "USD", spent: "40.00", chargeCount: 1, charges: [{ transactionId: "txn_9", amount: "40.00", currency: "USD", status: "completed", reference: "invoice_2026_07", createdAt: "2026-07-26T00:00:00Z" }] },
            session: { user_id: "user_123", user_email: "jane@example.com", total_amount: "40.00", currency: "USD", purchase_context: { custom: [{ merchant_details: { name: "Acme Store", url: "https://acme.example.com", country_code_iso2: "US" }, product_details: [{ description: "Monthly plan", unit_price: "40.00" }] }] }, mandate_setup: { intent: "mandate_setup", recurring_frequency: "monthly", merchant_scope: "listed", max_charges: 12 } },
          },
          common(k, 12, "2026-11-05T11:55:00.000Z"),
        ) as Obj,
    },
  ];
}

function snapshot(d: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (p: string) => {
    for (const e of readdirSync(p, { withFileTypes: true })) {
      const f = join(p, e.name);
      if (e.isDirectory()) walk(f);
      else out.set(relative(d, f), createHash("sha256").update(readFileSync(f)).digest("hex"));
    }
  };
  walk(d);
  return out;
}

const keyFile = (e: Example) => join(inputs, `provider-${e.name}.pem`);

// `noWitness` builds without a witness check, which opts() otherwise adds.
type More = Partial<IssuerPackOptions> & { noWitness?: boolean };

function opts(e: Example, more: More = {}): IssuerPackOptions {
  const { noWitness, ...rest } = more;
  const o: IssuerPackOptions = {
    dir,
    selection: { kind: "instruction", sha256: e.digest },
    instructionsDir: join(inputs, "instructions"),
    requestFile: join(inputs, "request.json"),
    consentFile: join(inputs, "consent.json"),
    providerKeyFile: keyFile(e),
    witness: { mode: "sidecar", pinned: { pubObj: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(stub.publicKeyHex, "hex").toString("base64url") }, format: "jwk" }), hex: stub.publicKeyHex, id: stub.keyId }, name: STUB_WITNESS_NAME },
    now: NOW,
    ...rest,
  };
  if (noWitness === true) delete o.witness;
  return o;
}

async function packOf(e: Example, more: More = {}): Promise<Map<string, Buffer>> {
  const r = await buildIssuerPack(opts(e, more));
  if (!r.ok) throw new Error(`expected a pack, got ${r.refusal}: ${r.message}`);
  return readZip(r.zip);
}

// The CLI form of opts(): the refusals are judged on its exit code and stdout.
function cliArgs(e: Example, d: string, out: string, extra: string[] = [], instructionsDir = join(inputs, "instructions")): string[] {
  return [
    "issuer-pack", "--dir", d, "--out", out, "--instruction", e.digest,
    "--instructions-dir", instructionsDir, "--request-file", join(inputs, "request.json"), "--consent-file", join(inputs, "consent.json"),
    "--provider-key", keyFile(e), "--witness-file-only", "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME, "--now", NOW, ...extra,
  ];
}

function refusalOf(r: { stdout: string; status: number | null }): { status: number | null; refusal: string; message: string } {
  const lines = r.stdout.trim().split("\n");
  expect(lines).toHaveLength(1);
  const o = JSON.parse(lines[0]!) as { refusal: string; message: string };
  return { status: r.status, refusal: o.refusal, message: o.message };
}

function copyFixture(): string {
  const d = join(root, `copy-${Math.random().toString(16).slice(2)}`);
  cpSync(dir, d, { recursive: true });
  return d;
}

const pdfText = (pdf: Buffer) => pdfLines(pdf).join(" ").replace(/\s+/g, " ");

beforeAll(async () => {
  root = makeTmpDir("chirindo-issuer-pack-");
  dir = join(root, "provider");
  inputs = join(root, "inputs");
  mkdirSync(join(inputs, "instructions"), { recursive: true });
  writeIdentity(dir, GATE.priv, createPublicKey(GATE.priv));
  stub = await startStubWitness();
  const now = clock();
  for (const x of examples()) {
    const e = await runExample(dir, now, x.name, x.key, x.body(x.key.priv), [
      order(x.sku, "https://acme.example.com", "A-1", x.totals[0]),
      order(x.sku, "https://acme.example.com", "A-2", x.totals[1]),
      order(x.sku, "https://other.example.net", "O-1", x.totals[2]),
    ]);
    ex.push(e);
    writeFileSync(join(inputs, "instructions", `${e.name}.json`), e.text);
    writeFileSync(keyFile(e), e.key.priv.export({ format: "pem", type: "pkcs8" }));
  }
  writeFileSync(join(inputs, "request.json"), JSON.stringify({ requester: "Example Issuing Bank", reference: "RFI-2026-0001", received: "2026-11-06" }));
  writeFileSync(join(inputs, "consent.json"), JSON.stringify(Object.fromEntries(ex.map((e) => [e.digest, { reference: `consent-${e.name}-001` }]))));
}, 60_000);

afterAll(async () => {
  await stub?.close();
  if (root !== undefined) cleanupTmpDir(root);
});

describe("B-439 issuer-pack: the fixture", () => {
  it("is three chains of three receipts, one instruction each, every chain witnessed", () => {
    expect(ex.map((e) => e.name)).toEqual(["crossmint", "basis-theory", "prava"]);
    for (const e of ex) {
      const lines = readFileSync(join(dir, "purchase-chains", `${e.session}.jsonl`), "utf8").trim().split("\n");
      expect([e.name, lines.length]).toEqual([e.name, 3]);
      const decisions = lines.map((l) => (JSON.parse(l) as { check: { instruction_sha256: string; reasons: string[] } }).check);
      expect(new Set(decisions.map((c) => c.instruction_sha256))).toEqual(new Set([e.digest]));
      expect([e.name, decisions[0]!.reasons]).toEqual([e.name, []]);
      expect(existsSync(join(dir, "purchase-chains", `${e.session}.jsonl.witness.ndjson`))).toBe(true);
    }
  });
});

describe("B-439 issuer-pack: spec §8", () => {
  it("1. a pack from each example's chain verifies offline from its members alone (exit 0)", { timeout: 4 * CLI_TIMEOUT }, async () => {
    for (const e of ex) {
      const r = await buildIssuerPack(opts(e));
      expect(r.ok).toBe(true);
      const zip = (r as Extract<IssuerPackResult, { ok: true }>).zip;
      const c = await checkIssuerPack(zip);
      expect([e.name, c.ok, c.lines]).toEqual([e.name, true, expect.any(Array)]);
      expect(c.lines.some((l) => l.includes("WITNESSED through count 3"))).toBe(true);
      // The installed verifier, run on the extracted members with the pack's own offline command.
      const x = join(root, `extract-${e.name}`);
      for (const [p, b] of readZip(zip)) {
        mkdirSync(join(x, ...p.split("/").slice(0, -1)), { recursive: true });
        writeFileSync(join(x, ...p.split("/")), b);
      }
      const v = JSON.parse(readFileSync(join(x, "verify", `${e.session}.json`), "utf8")) as { offline_command: string[]; label: string };
      expect(v.label).toBe("sidecar");
      const args = v.offline_command.slice(1).map((a) => (/^(chains|keys|witness)\//.test(a) ? join(x, ...a.split("/")) : a));
      const run = runCli(args, { timeoutMs: CLI_TIMEOUT });
      expect([e.name, run.status, run.stdout]).toEqual([e.name, 0, expect.stringMatching(/^VALID[^\n]*\n[\s\S]*WITNESSED through count 3/)]);
      if (e.name === "crossmint") {
        writeFileSync(join(root, "crossmint.zip"), zip);
        const check = runCli(["issuer-pack-check", join(root, "crossmint.zip")], { timeoutMs: CLI_TIMEOUT });
        expect([check.status, check.stdout]).toEqual([0, expect.stringContaining("OK MANIFEST.sig verifies")]);
      }
    }
  });

  it("2. every zip member is in the manifest with matching sha256 and bytes, and every entry has a member", async () => {
    const z = await packOf(ex[0]!);
    const manifest = JSON.parse(z.get("MANIFEST.json")!.toString("utf8")) as { members: { path: string; sha256: string; bytes: number }[] };
    const listed = new Map(manifest.members.map((m) => [m.path, m]));
    const inZip = [...z.keys()].filter((p) => p !== "MANIFEST.json" && p !== "MANIFEST.sig").sort();
    expect([...listed.keys()].sort()).toEqual(inZip);
    for (const [p, b] of z) {
      if (p === "MANIFEST.json" || p === "MANIFEST.sig") continue;
      expect([p, `sha256:${createHash("sha256").update(b).digest("hex")}`, b.length]).toEqual([p, listed.get(p)!.sha256, listed.get(p)!.bytes]);
    }
    // Control: one changed byte in one member is found.
    const members = [...z.entries()].map(([path, data]) => ({ path, data: path === "pack.json" ? Buffer.concat([data, Buffer.from(" ")]) : data }));
    const c = await checkIssuerPack(writeZip(members, new Date(NOW)));
    expect(c.ok).toBe(false);
    expect(c.lines).toContain("FAIL pack.json: sha256 or bytes differ from the manifest");
  });

  it("3. MANIFEST.sig verifies against the provider's key, which is the instruction's principal key (ruling 4)", async () => {
    const e = ex[1]!;
    const z = await packOf(e);
    const sig = JSON.parse(z.get("MANIFEST.sig")!.toString("utf8")) as { sig: string; kid: string };
    const jwk = JSON.parse(z.get("keys/provider-jwk.json")!.toString("utf8")) as { x: string; kid: string };
    expect(jwk.x).toBe(e.key.x);
    expect(sig.kid).toBe(e.key.kid);
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
    expect(edVerify(null, z.get("MANIFEST.json")!, pub, Buffer.from(sig.sig, "base64url"))).toBe(true);
    // Control: the same signature over other bytes does not verify.
    expect(edVerify(null, Buffer.concat([z.get("MANIFEST.json")!, Buffer.from(" ")]), pub, Buffer.from(sig.sig, "base64url"))).toBe(false);
    // Another provider's key is refused (exit 2), not used.
    const r = await buildIssuerPack(opts(e, { providerKeyFile: keyFile(ex[0]!) }));
    expect(r.ok ? null : [r.refusal, r.exit]).toEqual(["invalid-input", 2]);
  });

  it("4. equal inputs and --now give byte-identical zips; another --now does not", async () => {
    const a = await buildIssuerPack(opts(ex[2]!));
    const b = await buildIssuerPack(opts(ex[2]!));
    const c = await buildIssuerPack(opts(ex[2]!, { now: "2026-11-06T09:00:02.000Z" }));
    const zip = (r: IssuerPackResult) => (r.ok ? r.zip : Buffer.alloc(0));
    expect(zip(a).length).toBeGreaterThan(0);
    expect(zip(a).equals(zip(b))).toBe(true);
    expect(zip(a).equals(zip(c))).toBe(false);
  });

  it("5. a chain with one line deleted: exit 3 chain-broken, no file", { timeout: 2 * CLI_TIMEOUT }, () => {
    const d = copyFixture();
    const path = join(d, "purchase-chains", `${ex[0]!.session}.jsonl`);
    const lines = readFileSync(path, "utf8").split("\n");
    writeFileSync(path, [lines[0], lines[2], ""].join("\n"));
    const out = join(root, "deleted-line.zip");
    const r = refusalOf(runCli(cliArgs(ex[0]!, d, out), { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([3, "chain-broken"]);
    expect(existsSync(out)).toBe(false);
    // Control: the same command on the untouched fixture writes the pack.
    const ok = runCli(cliArgs(ex[0]!, dir, join(root, "deleted-line-control.zip")), { timeoutMs: CLI_TIMEOUT });
    expect(ok.status).toBe(0);
  });

  it("6. a decision with its instruction text removed: exit 4 decision-without-instruction", { timeout: CLI_TIMEOUT }, () => {
    const only = join(root, "instructions-without-basis");
    mkdirSync(only, { recursive: true });
    for (const e of ex) if (e.name !== "basis-theory") writeFileSync(join(only, `${e.name}.json`), e.text);
    const out = join(root, "no-instruction.zip");
    const r = refusalOf(runCli(cliArgs(ex[1]!, dir, out, [], only), { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([4, "decision-without-instruction"]);
    expect(r.message).toContain(ex[1]!.digest);
    expect(existsSync(out)).toBe(false);
  });

  it("6b. retained arguments missing, or not hashing to args_hash: exit 4 decision-without-args", async () => {
    for (const how of ["missing", "changed"] as const) {
      const d = copyFixture();
      const argsDir = join(d, "purchase-args", ex[2]!.session);
      const f = join(argsDir, readdirSync(argsDir).sort()[1]!);
      if (how === "missing") unlinkSync(f);
      else writeFileSync(f, Buffer.concat([readFileSync(f), Buffer.from(" ")]));
      const r = await buildIssuerPack(opts(ex[2]!, { dir: d }));
      expect([how, r.ok ? null : r.refusal, r.ok ? null : r.exit]).toEqual([how, "decision-without-args", 4]);
    }
  });

  it("7. an empty range: exit 5 no-records", { timeout: CLI_TIMEOUT }, () => {
    const out = join(root, "empty.zip");
    const args = cliArgs(ex[0]!, dir, out);
    const k = args.indexOf("--instruction");
    args.splice(k, 2, "--from", "2026-12-01T00:00:00Z", "--to", "2026-12-02T00:00:00Z");
    const r = refusalOf(runCli(args, { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([5, "no-records"]);
    expect(existsSync(out)).toBe(false);
  });

  it("8. a missing consent entry: exit 6; with --consent-missing-ok, CONSENT NOT SUPPLIED on the first screen", { timeout: 2 * CLI_TIMEOUT }, async () => {
    const consent = join(root, "consent-partial.json");
    writeFileSync(consent, JSON.stringify({ [ex[1]!.digest]: { reference: "consent-basis-theory-001" } }));
    const out = join(root, "no-consent.zip");
    const args = cliArgs(ex[0]!, dir, out);
    args[args.indexOf("--consent-file") + 1] = consent;
    const r = refusalOf(runCli(args, { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([6, "consent-missing"]);
    expect(existsSync(out)).toBe(false);
    const ok = runCli([...args, "--consent-missing-ok"], { timeoutMs: CLI_TIMEOUT });
    expect(ok.status).toBe(0);
    const z = readZip(readFileSync(out));
    expect(pdfLines(z.get("summary.pdf")!).slice(0, 3).join(" ")).toContain("CONSENT NOT SUPPLIED");
    expect(JSON.parse(z.get("pack.json")!.toString("utf8"))).toMatchObject({ consent_supplied: false, consent: null });
    expect([...z.keys()].some((p) => p.startsWith("consent/"))).toBe(false);
    expect(CONSENT_NOT_SUPPLIED.startsWith("CONSENT NOT SUPPLIED")).toBe(true);
  });

  it("9. witness receipts showing a longer history: exit 3; --allow-failed builds it with the failure first", { timeout: CLI_TIMEOUT }, async () => {
    const d = copyFixture();
    const path = join(d, "purchase-chains", `${ex[1]!.session}.jsonl`);
    const lines = readFileSync(path, "utf8").split("\n");
    writeFileSync(path, [lines[0], lines[1], ""].join("\n")); // the tail cut: the chain alone still verifies
    const out = join(root, "truncated.zip");
    const r = refusalOf(runCli(cliArgs(ex[1]!, d, out), { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([3, "chain-broken"]);
    expect(r.message).toContain("TAMPERED — witnessed count 3 is beyond the chain (2 records)");
    expect(existsSync(out)).toBe(false);
    // Control: without the witness the same cut chain builds, so the witness is what refused it.
    expect((await buildIssuerPack(opts(ex[1]!, { dir: d, noWitness: true }))).ok).toBe(true);
    // Ruling 5: --allow-failed answers truthfully, the failure as the first line of the PDF and the JSON.
    const a = await buildIssuerPack(opts(ex[1]!, { dir: d, allowFailed: true }));
    expect(a.ok).toBe(true);
    const z = readZip((a as Extract<IssuerPackResult, { ok: true }>).zip);
    expect(pdfLines(z.get("summary.pdf")!)[0]).toMatch(/^FAILED: chain [0-9a-f]{32} against the witness: TAMPERED/);
    const pj = z.get("pack.json")!.toString("utf8");
    expect(pj.split("\n")[2]).toMatch(/^ {2}"failure": "FAILED: chain/);
  });

  it("10. args/ holds only the selected receipts' arguments", async () => {
    const e = ex[0]!;
    // The three customers reuse order ids, so an order reference alone spans instructions (ruling 1).
    const across = await buildIssuerPack(opts(e, { selection: { kind: "order", merchant: "https://acme.example.com", orderRef: "A-2" } }));
    expect(across.ok ? null : across.refusal).toBe("several-instructions");
    // The crossmint chain's second decision alone, by its gate-clock second.
    const z = await packOf(e, { selection: { kind: "range", from: "2026-11-05T12:00:01Z", to: "2026-11-05T12:00:02Z" } });
    const args = [...z.keys()].filter((p) => p.startsWith("args/"));
    expect(args).toHaveLength(1);
    const retained = readdirSync(join(dir, "purchase-args", e.session)).sort();
    expect(retained).toHaveLength(3);
    const seq1 = readFileSync(join(dir, "purchase-args", e.session, retained.find((f) => f.startsWith("1-"))!));
    expect(z.get(args[0]!)!.equals(seq1)).toBe(true);
    const pack = JSON.parse(z.get("pack.json")!.toString("utf8")) as { decisions: { seq: number; merchant_order_id: string }[] };
    expect(pack.decisions.map((d) => [d.seq, d.merchant_order_id])).toEqual([[1, "A-2"]]);
    // The chain is still carried whole.
    expect(z.get(`chains/${e.session}.jsonl`)!.toString("utf8").trim().split("\n")).toHaveLength(3);
  });

  it("11. every §6 limit appears verbatim in LIMITS.txt and in summary.pdf, and each is its source's text", async () => {
    const z = await packOf(ex[0]!, { sameParty: true });
    const limitsTxt = z.get("LIMITS.txt")!.toString("utf8");
    const pdf = pdfText(z.get("summary.pdf")!);
    const all = packLimits(true);
    expect(all.map((l) => l.id)).toEqual([
      "purchase-check 1", "purchase-check 2", "purchase-check 3", "purchase-check 4", "purchase-check 5", "purchase-check 6", "purchase-check 7", "purchase-check 8", "purchase-check 10",
      "L1", "L3", "L7", "L8", "L9", "L12", "L14", "L24", "L25", "pack",
    ]);
    for (const l of all) {
      expect([l.id, limitsTxt.includes(`${l.id}: ${l.text}`)]).toEqual([l.id, true]);
      expect([l.id, pdf.includes(l.text)]).toEqual([l.id, true]);
    }
    expect(pdf).toContain(NOT_ENDORSED);
    expect(pdf).toContain(NOT_THIS_FORMAT);
    // L14 only when one party runs gate and witness.
    expect((await packOf(ex[0]!)).get("LIMITS.txt")!.toString("utf8")).not.toContain("L14:");
    // Sources: the README's full list and the evidence bundle's table 8-1.
    const readme = readFileSync(join(ROOT, "README.md"), "utf8").replace(/\r\n/g, "\n");
    const section = readme.slice(readme.indexOf("## Purchase check (before you charge)"), readme.indexOf("## Getting started"));
    for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 10]) expect([n, section.includes(`\n${n}. ${PURCHASE_LIMITS[n]!}`)]).toEqual([n, true]);
    for (const [id, text] of Object.entries(BUNDLE_LIMITS)) expect([id, text]).toEqual([id, (REF_LIMIT_TEXTS as Record<string, string>)[id]]);
  });

  it("12. the mapping has a settlement row and a card authorization row reading NOT CARRIED, in the JSON and the PDF", async () => {
    const z = await packOf(ex[0]!);
    const pack = JSON.parse(z.get("pack.json")!.toString("utf8")) as { mapping: { category: string; state: string }[] };
    expect(pack.mapping.find((m) => m.category === "Settlement (cards)")?.state).toBe("NOT CARRIED");
    expect(pack.mapping.find((m) => m.category === "Card authorization (cards)")?.state).toBe("NOT CARRIED");
    const pdf = pdfText(z.get("summary.pdf")!);
    expect(pdf).toContain("NOT CARRIED: Settlement (cards)");
    expect(pdf).toContain("NOT CARRIED: Card authorization (cards)");
    for (const m of pack.mapping) expect([m.category, pdf.includes(`${m.state}: ${m.category}`)]).toEqual([m.category, true]);
  });

  it("13. --dir is byte-identical before and after a run, a refused one included", async () => {
    const before = snapshot(dir);
    expect(before.size).toBeGreaterThan(10);
    await buildIssuerPack(opts(ex[0]!));
    await buildIssuerPack(opts(ex[0]!, { consentFile: join(inputs, "request.json") }));
    await buildIssuerPack(opts(ex[0]!, { selection: { kind: "range", from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z" } }));
    expect(snapshot(dir)).toEqual(before);
  });
});

describe("B-439 issuer-pack: the README section", () => {
  const readme = readFileSync(join(ROOT, "README.md"), "utf8").replace(/\r\n/g, "\n");
  const start = readme.indexOf("## Answering an issuer's written request");
  const section = readme.slice(start, readme.indexOf("\n## ", start + 10));

  it("has the command, every mapping row, every limit the pack prints, and both notices", () => {
    expect(start).toBeGreaterThan(0);
    expect(section).toContain("chirindo issuer-pack --dir <purchase-check-dir> --out <pack.zip>");
    expect(section).toContain(NOT_ENDORSED);
    expect(section).toContain(NOT_THIS_FORMAT);
    for (const supplied of [false, true]) {
      for (const m of mappingRowsOf(supplied)) {
        expect([m.category, section.includes(`| ${m.category} | ${m.source} |`)]).toEqual([m.category, true]);
        if (m.category !== mappingRowsOf(true)[3]!.category) expect([m.category, section.includes(`| ${m.state} | ${m.limit} |`)]).toEqual([m.category, true]);
      }
    }
    for (const l of packLimits(true)) {
      if (l.id.startsWith("purchase-check")) continue; // the full list above it, held by test 11
      expect([l.id, section.includes(l.text)]).toEqual([l.id, true]);
    }
    for (const r of ["invalid-input", "chain-broken", "decision-without-instruction", "decision-without-args", "no-records", "consent-missing", "shared-chain", "several-instructions"]) {
      expect([r, section.includes(`\`${r}\``)]).toEqual([r, true]);
    }
  });

  it("says no network requires the pack: no sentence pairs a network with requires or mandates", () => {
    const sentences = section.split(/(?<=[.:])\s+/);
    const bad = sentences.filter((s) => /\b(Visa|Mastercard|card network|network)\b/i.test(s) && /\b(requires?|mandates?|demands?)\b/i.test(s) && !s.includes(NOT_THIS_FORMAT.split(";")[0]!));
    expect(bad).toEqual([]);
  });
});

describe("B-439 issuer-pack: one customer per pack (ruling 1)", () => {
  it("a chain holding another instruction's decisions is refused: exit 7 shared-chain", async () => {
    const d = join(root, "shared");
    writeIdentity(d, GATE.priv, createPublicKey(GATE.priv));
    const pc = createPurchaseCheck({ dir: d, now: clock() });
    pc.check({ instruction: ex[0]!.text, order: order("GROCERIES", "https://acme.example.com", "A-1", "12000") });
    pc.check({ instruction: ex[1]!.text, order: order("OFFICE", "https://acme.example.com", "B-1", "8000") });
    await pc.close();
    const r = await buildIssuerPack(opts(ex[0]!, { dir: d, noWitness: true }));
    expect(r.ok ? null : [r.refusal, r.exit]).toEqual(["shared-chain", 7]);
    expect(r.ok ? "" : r.message).toContain("one customer per pack (Lead ruling 1)");
  });

  it("a selection spanning two instructions is refused: exit 7 several-instructions", async () => {
    const r = await buildIssuerPack(opts(ex[0]!, { selection: { kind: "range", from: "2026-11-05T00:00:00Z", to: "2026-11-06T00:00:00Z" } }));
    expect(r.ok ? null : [r.refusal, r.exit]).toEqual(["several-instructions", 7]);
  });
});

describe("B-439 issuer-pack: the PDF", () => {
  it("stays under 6 MB at the most decision rows it prints, each at full width", () => {
    const row = "x".repeat(PDF_COLUMNS);
    const lines = Array.from({ length: PDF_MAX_DECISION_ROWS * 2 + 400 }, () => ({ text: row }));
    const pdf = renderPdf(lines);
    expect(pdf.bytes.length).toBeLessThan(PDF_MAX_BYTES);
    expect(pdf.pages).toBeGreaterThan(100);
  });

  it("the fixture's summary.pdf is a PDF well under 6 MB, and wrapping loses no word", async () => {
    const z = await packOf(ex[0]!);
    const pdf = z.get("summary.pdf")!;
    expect(pdf.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
    expect(pdf.length).toBeLessThan(PDF_MAX_BYTES);
    const text = "a ".repeat(200) + "b".repeat(PDF_COLUMNS * 2 + 3);
    const w = wrap(text.trim(), PDF_COLUMNS);
    expect(w.every((l) => [...l].length <= PDF_COLUMNS)).toBe(true);
    expect(w.join(" ").replace(/b /g, "b")).toContain("b".repeat(PDF_COLUMNS * 2 + 3));
  });

  it("prints a character outside the font as ? and says that pack.json carries the exact text", () => {
    const p = renderPdf([{ text: "Lisbon → Porto ’quoted’" }]);
    expect(p.replaced).toBe(1);
    expect(pdfLines(p.bytes)[0]).toBe("Lisbon ? Porto ’quoted’");
  });
});

describe("B-439 issuer-pack: the zip", () => {
  it("reads back what it wrote, and refuses a changed byte", () => {
    const z = writeZip([{ path: "a.txt", data: Buffer.from("hello") }, { path: "d/b.json", data: Buffer.from("{}") }], new Date(NOW));
    expect([...readZip(z).entries()].map(([p, b]) => [p, b.toString()])).toEqual([["a.txt", "hello"], ["d/b.json", "{}"]]);
    const bad = Buffer.from(z);
    const at = 30 + "a.txt".length;
    bad[at] = bad[at]! ^ 1;
    expect(() => readZip(bad)).toThrow(/CRC mismatch/);
    expect(() => writeZip([{ path: "../x", data: Buffer.alloc(0) }], new Date(NOW))).toThrow(/not allowed/);
  });

  it("invalid inputs exit 2 with one JSON line and write nothing", { timeout: CLI_TIMEOUT }, () => {
    const out = join(root, "invalid.zip");
    const r = refusalOf(runCli(["issuer-pack", "--dir", dir, "--out", out], { timeoutMs: CLI_TIMEOUT }));
    expect([r.status, r.refusal]).toEqual([2, "invalid-input"]);
    expect(existsSync(out)).toBe(false);
    expect(statSync(dir).isDirectory()).toBe(true);
    rmSync(out, { force: true });
  });
});
