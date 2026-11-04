// `chirindo issuer-pack` (B-439, spec rev 1 §3 to §9 with the Lead's rulings
// of §11): one zip that answers a written request about one customer's
// purchases, built from a purchase-check directory opened read-only.
//
// Where the spec and the code differ, the code wins:
// - The purchase check retains each receipt's arguments but not the
//   instruction's text (only its digest), so the texts come from
//   --instructions-dir: every *.json there is read as an instruction, and its
//   JCS sha256 is the digest a decision cites.
// - Ruling 4 signs the manifest with the provider's key: --provider-key, which
//   must be the principal key of the instruction (limit 2: the provider signs
//   the instruction).
// - Ruling 3 makes the summary a PDF (summary.pdf); there is no summary.html.
// - No evidence-bundle verifier ships in this package (it is in
//   examples/evidence-bundle), so a stated charge is carried in charge/ and
//   pack.json says that no bundle verdict was computed.

import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GATE_VERSION } from "../version.js";
import {
  buildIdentityFile,
  buildJwk,
  buildJwks,
  contentOf,
  entryHashOfCanonical,
  formatVerifyResult,
  jcs,
  jcsBytes,
  readChainFile,
  readIdentityFile,
  rfc7638Thumbprint,
  runVerify,
  type SignedRecord,
} from "../vendor/recorder/index.js";
import { collectReceiptsFromWitness, sidecarPathFor, verifyAgainstWitness, type WitnessPub } from "../witness.js";
import { isPlainObject, jcsSha256, parseStrictJson, readInstruction } from "../purchase/m6.js";
import { compareInstants, TIME_RE } from "../purchase/time.js";
import { renderPdf, PDF_MAX_BYTES, type PdfLine } from "./pdf.js";
import {
  CONSENT_NOT_SUPPLIED,
  FIRST_SCREEN_LIMITS,
  ISSUER_PACK_VERSION,
  NOT_CONSENT,
  NOT_ENDORSED,
  NOT_THIS_FORMAT,
  RULE_QUOTE,
  mappingRows,
  packLimits,
  type MappingRow,
  type PackLimit,
} from "./texts.js";
import { writeZip } from "./zip.js";

export type Selection =
  | { kind: "range"; from: string; to: string }
  | { kind: "order"; merchant: string; orderRef: string }
  | { kind: "instruction"; sha256: string };

export type WitnessMode =
  | { mode: "online"; baseUrl: string; pinned: WitnessPub; name: string }
  | { mode: "sidecar"; pinned: WitnessPub; name: string };

export interface IssuerPackOptions {
  dir: string;
  selection: Selection;
  instructionsDir: string;
  requestFile: string;
  consentFile: string;
  consentMissingOk?: boolean;
  chargeFile?: string;
  // The gate key: an identity.json (default <dir>/identity.json), or a JWKS URL.
  keyFile?: string;
  jwksUrl?: string;
  witness?: WitnessMode;
  providerKeyFile: string;
  now?: string;
  allowFailed?: boolean;
  sameParty?: boolean;
}

export type Refusal =
  | "invalid-input"
  | "chain-broken"
  | "decision-without-instruction"
  | "decision-without-args"
  | "no-records"
  | "consent-missing"
  | "shared-chain"
  | "several-instructions";

export const REFUSAL_EXIT: Record<Refusal, number> = {
  "invalid-input": 2,
  "chain-broken": 3,
  "decision-without-instruction": 4,
  "decision-without-args": 4,
  "no-records": 5,
  "consent-missing": 6,
  // Ruling 1 (one customer per pack); spec §3 gives these no code, so 7.
  "shared-chain": 7,
  "several-instructions": 7,
};

export type IssuerPackResult =
  | { ok: true; zip: Buffer; manifestSha256: string; members: { path: string; sha256: string; bytes: number }[]; failure: string | null; pdfBytes: number }
  | { ok: false; refusal: Refusal; exit: number; message: string };

class Refused extends Error {
  constructor(readonly refusal: Refusal, message: string) {
    super(message);
  }
}
const refuse = (r: Refusal, m: string): never => {
  throw new Refused(r, m);
};

type Obj = Record<string, unknown>;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SESSION_FILE_RE = /^([0-9a-f]{32})\.jsonl$/;
const hexOf = (h: string) => h.slice("sha256:".length);
const sha256Hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const asJson = (v: unknown) => Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8");
// Decision rows printed in the PDF; the rest are in pack.json, and the PDF says so.
export const PDF_MAX_DECISION_ROWS = 5000;

function readJsonFile(path: string, what: string): { bytes: Buffer; value: unknown } {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    return refuse("invalid-input", `cannot read ${what} ${path} (${(e as NodeJS.ErrnoException).code ?? "unreadable"})`);
  }
  const p = parseStrictJson(bytes.toString("utf8"));
  if (!p.ok) return refuse("invalid-input", `${what} ${path} is not strict JSON (${p.problem})`);
  return { bytes, value: p.value };
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

interface Consent {
  reference: string;
  app_login_id?: string;
}

interface ChainInfo {
  sessionId: string;
  path: string;
  bytes: Buffer;
  records: SignedRecord[];
}

interface Decision {
  at: string;
  session_id: string;
  seq: number;
  entry_hash: string;
  decision: "allow" | "deny";
  reasons: string[];
  instruction_sha256: string;
  merchant_id: string;
  merchant_order_id: string | null;
  checkout_ref: string | null;
  order_sha256: string;
  args_hash: string;
  witness: string;
}

const checkOf = (r: SignedRecord) => (r as unknown as { check?: Obj }).check;

function selected(r: SignedRecord, s: Selection): boolean {
  const c = checkOf(r);
  if (!isPlainObject(c)) return false;
  if (s.kind === "instruction") return c["instruction_sha256"] === s.sha256;
  if (s.kind === "order") return c["merchant_id"] === s.merchant && (c["merchant_order_id"] === s.orderRef || c["checkout_ref"] === s.orderRef);
  const at = c["at"];
  return typeof at === "string" && TIME_RE.test(at) && compareInstants(at, s.from) >= 0 && compareInstants(at, s.to) < 0;
}

// Builds the pack in memory. Never writes under opts.dir; works on copies in
// a temporary directory, removed before it returns.
export async function buildIssuerPack(opts: IssuerPackOptions): Promise<IssuerPackResult> {
  const work = mkdtempSync(join(tmpdir(), "chirindo-issuer-pack-"));
  try {
    return await build(opts, work);
  } catch (e) {
    if (e instanceof Refused) return { ok: false, refusal: e.refusal, exit: REFUSAL_EXIT[e.refusal], message: e.message };
    throw e;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

async function build(opts: IssuerPackOptions, work: string): Promise<IssuerPackResult> {
  // ---- inputs (invalid-input) ---------------------------------------------
  const createdAt = opts.now ?? new Date().toISOString();
  if (!TIME_RE.test(createdAt) || !Number.isFinite(Date.parse(createdAt))) refuse("invalid-input", `--now must be a Z instant (got ${createdAt})`);
  const sel = opts.selection;
  if (sel.kind === "range") {
    for (const t of [sel.from, sel.to]) if (!TIME_RE.test(t) || !Number.isFinite(Date.parse(t))) refuse("invalid-input", `--from and --to must be Z instants (got ${t})`);
    if (compareInstants(sel.from, sel.to) >= 0) refuse("invalid-input", "--from must be before --to (the range is start inclusive, end exclusive)");
  } else if (sel.kind === "instruction") {
    if (!SHA256_RE.test(sel.sha256)) refuse("invalid-input", "--instruction must be sha256: followed by 64 lowercase hex characters");
  } else if (!isStr(sel.merchant) || !isStr(sel.orderRef)) refuse("invalid-input", "--order-ref must be <merchant>:<order_ref>, both non-empty");

  const request = readJsonFile(opts.requestFile, "--request-file");
  const rq = request.value;
  if (!isPlainObject(rq) || !isStr(rq["requester"]) || !isStr(rq["reference"]) || !isStr(rq["received"])) {
    refuse("invalid-input", '--request-file must be a JSON object with non-empty strings "requester", "reference" and "received"');
  }
  const consentDoc = readJsonFile(opts.consentFile, "--consent-file").value;
  if (!isPlainObject(consentDoc)) refuse("invalid-input", "--consent-file must be a JSON object of instruction sha256 to consent entry");
  const consents = new Map<string, Consent>();
  for (const [k, v] of Object.entries(consentDoc as Obj)) {
    if (!SHA256_RE.test(k)) refuse("invalid-input", `--consent-file: key ${JSON.stringify(k)} is not sha256:<64 hex>`);
    if (!isPlainObject(v) || !isStr(v["reference"]) || Object.keys(v).some((m) => m !== "reference" && m !== "app_login_id") || (v["app_login_id"] !== undefined && !isStr(v["app_login_id"]))) {
      refuse("invalid-input", `--consent-file: ${k} must be {"reference": string, "app_login_id"?: string}`);
    }
    consents.set(k, v as unknown as Consent);
  }
  const charge = opts.chargeFile !== undefined ? readJsonFile(opts.chargeFile, "--charge-file") : null;

  let providerKey: KeyObject;
  try {
    providerKey = createPrivateKey(readFileSync(opts.providerKeyFile));
  } catch (e) {
    return refuse("invalid-input", `cannot read --provider-key ${opts.providerKeyFile} as a private key (${(e as Error).message.split("\n")[0]})`);
  }
  if (providerKey.asymmetricKeyType !== "ed25519") refuse("invalid-input", "--provider-key must be an Ed25519 private key");
  const providerPub = createPublicKey(providerKey);
  const providerX = (providerPub.export({ format: "jwk" }) as { x: string }).x;

  const instructions = new Map<string, { file: string; bytes: Buffer; value: Obj }>();
  let names: string[];
  try {
    names = readdirSync(opts.instructionsDir).filter((n) => n.endsWith(".json")).sort();
  } catch (e) {
    return refuse("invalid-input", `cannot read --instructions-dir ${opts.instructionsDir} (${(e as NodeJS.ErrnoException).code ?? "unreadable"})`);
  }
  for (const n of names) {
    const bytes = readFileSync(join(opts.instructionsDir, n));
    const r = readInstruction(bytes.toString("utf8"));
    if (!r.ok || !isPlainObject(r.value)) refuse("invalid-input", `--instructions-dir: ${n} is not an instruction (${r.ok ? "not an object" : r.problem})`);
    instructions.set(jcsSha256((r as { value: unknown }).value), { file: n, bytes, value: (r as { value: Obj }).value });
  }

  const identityPath = opts.keyFile ?? join(opts.dir, "identity.json");
  let gateIdentity;
  try {
    gateIdentity = readIdentityFile(identityPath);
  } catch (e) {
    return refuse("invalid-input", `cannot read the gate identity ${identityPath} (${(e as Error).message})`);
  }
  const gatePub = createPublicKey(gateIdentity.public_key_pem);

  // ---- the chains, read once ------------------------------------------------
  const chainsDir = join(opts.dir, "purchase-chains");
  let files: string[];
  try {
    files = readdirSync(chainsDir).filter((n) => SESSION_FILE_RE.test(n)).sort();
  } catch (e) {
    return refuse("invalid-input", `cannot read ${chainsDir} (${(e as NodeJS.ErrnoException).code ?? "unreadable"}); --dir must be a purchase-check directory`);
  }
  const chains: ChainInfo[] = [];
  for (const n of files) {
    const path = join(chainsDir, n);
    const bytes = readFileSync(path);
    if (bytes.length === 0) continue;
    const copy = join(work, n);
    writeFileSync(copy, bytes);
    let records: SignedRecord[];
    try {
      records = readChainFile(copy).records;
    } catch (e) {
      // Unreadable: it may hold selected decisions, so it is not passed over.
      return refuse("chain-broken", `chain ${path} does not read (${(e as Error).message}); a chain that cannot be read may hold selected decisions`);
    }
    chains.push({ sessionId: SESSION_FILE_RE.exec(n)![1]!, path, bytes, records });
  }

  const picked: { chain: ChainInfo; record: SignedRecord }[] = [];
  for (const c of chains) for (const r of c.records) if (selected(r, sel)) picked.push({ chain: c, record: r });
  if (picked.length === 0) refuse("no-records", `the selection matches no decision in ${chainsDir}`);

  // Ruling 1: one customer per pack, so one instruction and only its chains.
  const cited = [...new Set(picked.map((p) => checkOf(p.record)!["instruction_sha256"] as string))].sort();
  if (cited.length > 1) {
    refuse("several-instructions", `the selection spans ${cited.length} instructions (${cited.join(", ")}); one customer per pack (Lead ruling 1): select one instruction`);
  }
  const digest = cited[0]!;
  const carried = [...new Map(picked.map((p) => [p.chain.sessionId, p.chain])).values()];
  for (const c of carried) {
    const other = c.records.map((r) => checkOf(r)?.["instruction_sha256"]).find((d) => d !== digest);
    if (other !== undefined || c.records.some((r) => !isPlainObject(checkOf(r)))) {
      refuse("shared-chain", `chain ${c.path} also holds decisions under another instruction (${String(other)}); one customer per pack (Lead ruling 1): v1 needs one purchase-check chain per customer instruction, and carries it whole`);
    }
  }

  // ---- verification ------------------------------------------------------------
  const failures: string[] = [];
  const verified = new Map<string, { mode: string; command: string[]; offline: string[]; exit: number; output: string; through: number | null; receivedAt: string | null; receipts: unknown[] | null }>();
  for (const c of carried) {
    const copy = join(work, `${c.sessionId}.jsonl`);
    const sidecar = sidecarPathFor(c.path);
    const hasSidecar = existsSync(sidecar);
    if (hasSidecar) copyFileSync(sidecar, sidecarPathFor(copy));
    const result = opts.jwksUrl !== undefined ? await runVerify({ chainPath: copy, jwksUrl: opts.jwksUrl }) : runVerify({ chainPath: copy, identityPath });
    const f = formatVerifyResult(result);
    const keyArgs = opts.jwksUrl !== undefined ? ["--jwks", opts.jwksUrl] : ["--key", identityPath];
    const command = ["chirindo", "verify", c.path, ...keyArgs];
    const offline = ["chirindo", "verify", `chains/${c.sessionId}.jsonl`, "--key", "keys/gate-identity.json"];
    let output = f.line;
    let exit: number = f.exitCode;
    let through: number | null = null;
    let receivedAt: string | null = null;
    let receipts: unknown[] | null = null;
    let mode = "chain only, no witness";
    if (result.kind !== "valid") {
      failures.push(`chain ${c.sessionId} does not verify: ${f.line.split("\n")[0]}`);
    } else if (opts.witness !== undefined) {
      const w = opts.witness;
      const wArgs = ["--witness-key", "witness/witness-key.jwk", "--witness-name", w.name];
      if (w.mode === "online") {
        mode = "online";
        command.push("--witness", w.baseUrl, "--witness-key", w.pinned.hex, "--witness-name", w.name);
        const got = await collectReceiptsFromWitness(w.baseUrl, c.records[0]!.kid, c.sessionId);
        receipts = got.ok ? got.receipts : null;
      } else {
        mode = "sidecar";
        command.push("--witness-file", sidecar, "--witness-key", w.pinned.hex, "--witness-name", w.name);
      }
      if (hasSidecar) offline.push("--witness-file", `witness/${c.sessionId}.witness.ndjson`, ...wArgs);
      if (w.mode === "sidecar" && !hasSidecar) {
        output = `UNVERIFIABLE — witness receipts unavailable: sidecar ${sidecar} not found`;
        exit = 1;
      } else {
        const wv = await verifyAgainstWitness({
          chainPath: copy,
          validText: f.line,
          validExit: f.exitCode,
          witnessName: w.name,
          pinned: w.pinned,
          ...(w.mode === "online" ? { baseUrl: w.baseUrl } : { sidecarPath: sidecarPathFor(copy) }),
        });
        output = wv.text;
        exit = wv.code;
        if (output.startsWith("TAMPERED")) failures.push(`chain ${c.sessionId} against the witness: ${output.split("\n")[0]}`);
        const m = /^WITNESSED through count (\d+), received_at (\S+),/m.exec(output);
        if (m !== null) {
          through = Number(m[1]);
          receivedAt = m[2]!;
        }
      }
    }
    verified.set(c.sessionId, { mode, command, offline, exit, output, through, receivedAt, receipts });
  }
  if (failures.length > 0 && opts.allowFailed !== true) refuse("chain-broken", failures.join("; ") + " (--allow-failed builds the pack with the failure as its first line)");
  const failure = failures.length > 0 ? `FAILED: ${failures.join("; ")}` : null;

  // ---- the instruction, the arguments, the consent ------------------------------
  const ins = instructions.get(digest);
  if (ins === undefined) {
    refuse("decision-without-instruction", `the selected decisions cite instruction ${digest}, whose text is not in --instructions-dir ${opts.instructionsDir}`);
  }
  const principal = ins!.value["principal"];
  const principalX = isPlainObject(principal) && isPlainObject(principal["public_key_jwk"]) ? principal["public_key_jwk"]["x"] : undefined;
  if (principalX !== providerX) {
    refuse("invalid-input", `--provider-key is not the principal key of instruction ${digest}; the manifest is signed by the provider that signed the instruction (Lead ruling 4)`);
  }

  const args = new Map<string, Buffer>();
  const decisions: Decision[] = [];
  for (const { chain, record } of picked) {
    const c = checkOf(record)!;
    const ev = record.event as unknown as Obj;
    const ah = ev["args_hash"];
    const entryHash = entryHashOfCanonical(jcsBytes(contentOf(record)));
    if (typeof ah !== "string" || !SHA256_RE.test(ah)) refuse("decision-without-args", `chain ${chain.sessionId} record ${record.seq} has no args_hash`);
    const argsPath = join(opts.dir, "purchase-args", chain.sessionId, `${record.seq}-${hexOf(ah as string).slice(0, 32)}.json`);
    let bytes: Buffer;
    try {
      bytes = readFileSync(argsPath);
    } catch {
      return refuse("decision-without-args", `the retained arguments of chain ${chain.sessionId} record ${record.seq} are missing (${argsPath})`);
    }
    if (`sha256:${sha256Hex(bytes)}` !== ah) refuse("decision-without-args", `the retained arguments ${argsPath} do not hash to the receipt's args_hash ${ah}`);
    args.set(hexOf(entryHash), bytes);
    const v = verified.get(chain.sessionId)!;
    const witness =
      opts.witness === undefined
        ? "not checked (no witness given)"
        : v.through !== null && record.seq < v.through
          ? `witnessed: checkpoint count ${v.through}, received_at ${v.receivedAt}`
          : v.through !== null
            ? "after the last witnessed checkpoint: not witness-protected"
            : `not shown: ${v.output.split("\n")[0]}`;
    decisions.push({
      at: c["at"] as string,
      session_id: chain.sessionId,
      seq: record.seq,
      entry_hash: entryHash,
      decision: ev["decision"] === "allow" ? "allow" : "deny",
      reasons: c["reasons"] as string[],
      instruction_sha256: digest,
      merchant_id: c["merchant_id"] as string,
      merchant_order_id: (c["merchant_order_id"] as string | null) ?? null,
      checkout_ref: (c["checkout_ref"] as string | null) ?? null,
      order_sha256: c["order_sha256"] as string,
      args_hash: ah as string,
      witness,
    });
  }
  decisions.sort((a, b) => compareInstants(a.at, b.at) || (a.session_id < b.session_id ? -1 : a.session_id > b.session_id ? 1 : a.seq - b.seq));

  const consent = consents.get(digest) ?? null;
  if (consent === null && opts.consentMissingOk !== true) refuse("consent-missing", `instruction ${digest} has no entry in --consent-file (--consent-missing-ok builds the pack and prints CONSENT NOT SUPPLIED first)`);

  // ---- the members ---------------------------------------------------------------
  const constraints = isPlainObject(ins!.value["constraints"]) ? ins!.value["constraints"] : {};
  const mapping = mappingRows(consent?.app_login_id !== undefined);
  const limits = packLimits(opts.sameParty === true);
  const witnessName = opts.witness?.name ?? null;
  const bundleNote =
    charge === null
      ? "No stated charge was supplied (--charge-file), so no evidence-bundle verdict."
      : "No evidence-bundle verdict was computed: this package carries no evidence-bundle verifier (it is examples/evidence-bundle in the source repository). The stated charge is carried in charge/charge.json as supplied.";

  const members = new Map<string, Buffer>();
  members.set(`instructions/${hexOf(digest)}.json`, ins!.bytes);
  if (consent !== null) members.set(`consent/${hexOf(digest)}.json`, asJson(consent));
  for (const c of carried) {
    members.set(`chains/${c.sessionId}.jsonl`, c.bytes);
    const sc = sidecarPathFor(c.path);
    if (existsSync(sc)) members.set(`witness/${c.sessionId}.witness.ndjson`, readFileSync(sc));
    const v = verified.get(c.sessionId)!;
    if (v.receipts !== null) members.set(`witness/${c.sessionId}.receipts.json`, asJson(v.receipts));
    members.set(`verify/${c.sessionId}.txt`, Buffer.from(`$ ${v.command.join(" ")}\n# ${v.mode}, exit ${v.exit}\n${v.output}\n`, "utf8"));
    members.set(`verify/${c.sessionId}.json`, asJson({ label: v.mode, command: v.command, exit: v.exit, output: v.output, offline_command: v.offline }));
  }
  for (const [h, b] of args) members.set(`args/${h}.json`, b);
  if (opts.witness !== undefined) {
    // A JWK file, the form `chirindo verify --witness-key` reads from a path.
    members.set("witness/witness-key.jwk", asJson({ kty: "OKP", crv: "Ed25519", x: Buffer.from(opts.witness.pinned.hex, "hex").toString("base64url"), kid: opts.witness.pinned.id }));
    members.set("witness/witness-key.json", asJson({ public_key_hex: opts.witness.pinned.hex, public_key_id: opts.witness.pinned.id, witness_name: opts.witness.name }));
  }
  members.set("keys/gate-identity.json", asJson(buildIdentityFile(gatePub)));
  members.set("keys/gate-jwks.json", asJson(buildJwks([buildJwk({ kid: gateIdentity.kid, publicKeyBase64Url: gateIdentity.public_key_b64url })])));
  const providerKid = rfc7638Thumbprint(providerPub);
  members.set("keys/provider-jwk.json", asJson({ kty: "OKP", crv: "Ed25519", x: providerX, kid: providerKid }));
  members.set("request/request.json", request.bytes);
  if (charge !== null) members.set("charge/charge.json", charge.bytes);
  members.set("LIMITS.txt", Buffer.from(limitsText(limits), "utf8"));

  const packJson = {
    v: ISSUER_PACK_VERSION,
    failure,
    consent_supplied: consent !== null,
    notices: { not_endorsed: NOT_ENDORSED, not_this_format: NOT_THIS_FORMAT, not_consent: NOT_CONSENT, rule: RULE_QUOTE },
    request: { ...(rq as Obj), statement_of: "the provider" },
    selection: sel,
    instruction: {
      sha256: digest,
      valid_from: constraints["valid_from"] ?? null,
      valid_until: constraints["valid_until"] ?? null,
      text: typeof ins!.value["text"] === "string" ? ins!.value["text"] : null,
      member: `instructions/${hexOf(digest)}.json`,
    },
    consent: consent === null ? null : { ...consent, statement_of: "the provider" },
    decisions,
    chains: carried.map((c) => {
      const v = verified.get(c.sessionId)!;
      return { session_id: c.sessionId, records: c.records.length, verify: { label: v.mode, exit: v.exit, first_line: v.output.split("\n")[0] ?? "" } };
    }),
    witness_name: witnessName,
    charge_supplied: charge !== null,
    bundle_verdict: null,
    bundle_verdict_note: bundleNote,
    mapping,
    limits,
  };
  members.set("pack.json", asJson(packJson));

  let pdf = renderPdf(summaryLines(packJson, decisions, mapping, limits, consent, failure, false));
  if (pdf.replaced > 0) pdf = renderPdf(summaryLines(packJson, decisions, mapping, limits, consent, failure, true));
  if (pdf.bytes.length >= PDF_MAX_BYTES) refuse("invalid-input", `summary.pdf would be ${pdf.bytes.length} bytes, not under ${PDF_MAX_BYTES}`);
  members.set("summary.pdf", pdf.bytes);

  // ---- manifest, signature, zip ----------------------------------------------------
  const listed = [...members.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, b]) => ({ path, sha256: `sha256:${sha256Hex(b)}`, bytes: b.length }));
  const manifest = {
    v: ISSUER_PACK_VERSION,
    generator: { name: "@headlessoracle/chirindo", version: GATE_VERSION, commit: null, commit_note: "the npm package carries no commit id; its version names the release" },
    created_at: createdAt,
    created_at_clock: opts.now !== undefined ? "--now, as the person running the generator gave it" : "the generator's clock",
    selection: sel,
    instruction_sha256: digest,
    signed_by: { kid: providerKid, role: "provider (the instruction's principal key)" },
    members: listed,
  };
  const manifestBytes = Buffer.from(jcs(manifest), "utf8");
  const sig = edSign(null, manifestBytes, providerKey).toString("base64url");
  const sigBytes = asJson({ alg: "Ed25519", kid: providerKid, key: "keys/provider-jwk.json", signs: "the bytes of MANIFEST.json (its JCS form)", sig });
  const zip = writeZip(
    [{ path: "MANIFEST.json", data: manifestBytes }, { path: "MANIFEST.sig", data: sigBytes }, ...listed.map((m) => ({ path: m.path, data: members.get(m.path)! }))],
    new Date(createdAt),
  );
  return { ok: true, zip, manifestSha256: `sha256:${sha256Hex(manifestBytes)}`, members: listed, failure, pdfBytes: pdf.bytes.length };
}

function limitsText(limits: PackLimit[]): string {
  return limits.map((l) => `${l.id}: ${l.text}`).join("\n\n") + "\n";
}

function summaryLines(
  p: { request: Obj; selection: Selection; instruction: Obj; witness_name: string | null; bundle_verdict_note: string; chains: { session_id: string; records: number; verify: { label: string; exit: number; first_line: string } }[] },
  decisions: Decision[],
  mapping: MappingRow[],
  limits: PackLimit[],
  consent: Consent | null,
  failure: string | null,
  replacedNote: boolean,
): PdfLine[] {
  const L: PdfLine[] = [];
  const h = (t: string) => L.push({ text: "" }, { text: t, bold: true });
  const t = (text: string, indent = 0) => L.push({ text, indent });
  if (failure !== null) L.push({ text: failure, bold: true });
  if (consent === null) L.push({ text: CONSENT_NOT_SUPPLIED, bold: true });
  L.push({ text: "Issuer pack: the provider's answer to a written request", bold: true });
  t(NOT_ENDORSED);
  t(NOT_THIS_FORMAT);
  t(`${RULE_QUOTE.source}, ${RULE_QUOTE.provision}: "${RULE_QUOTE.text}"`);
  t(NOT_CONSENT);
  if (replacedNote) t("Characters the PDF font cannot show are printed as ?; pack.json carries the exact text.");
  h("Read first");
  for (const id of FIRST_SCREEN_LIMITS) {
    const l = limits.find((x) => x.id === id)!;
    t(`${l.id}: ${l.text}`);
  }
  h("The request (the provider's statement)");
  t(`requester: ${String(p.request["requester"])}`);
  t(`reference: ${String(p.request["reference"])}`);
  t(`received: ${String(p.request["received"])}`);
  h("Selection");
  const s = p.selection;
  t(s.kind === "range" ? `gate-clock range from ${s.from} (inclusive) to ${s.to} (exclusive)` : s.kind === "order" ? `merchant ${s.merchant}, order reference ${s.orderRef}` : `every decision under instruction ${s.sha256}`);
  h("The instruction");
  t(`sha256: ${String(p.instruction["sha256"])}`);
  t(`valid_from: ${String(p.instruction["valid_from"])}; valid_until: ${String(p.instruction["valid_until"])}`);
  t(`text: ${String(p.instruction["text"])}`);
  t(consent === null ? "consent reference: NOT SUPPLIED" : `consent reference (the provider's statement): ${consent.reference}`);
  if (consent?.app_login_id !== undefined) t(`APP login ID (the provider's statement): ${consent.app_login_id}`);
  h("Verification of each chain");
  for (const c of p.chains) t(`chain ${c.session_id}, ${c.records} records: ${c.verify.label}, exit ${c.verify.exit}: ${c.verify.first_line}`);
  t(`Settlement verdict: ${p.bundle_verdict_note}`);
  h(`Decisions (${decisions.length})`);
  for (const d of decisions.slice(0, PDF_MAX_DECISION_ROWS)) {
    t(`${d.at}  ${d.decision.toUpperCase()}  ${d.reasons.length === 0 ? "no reasons" : d.reasons.join(" ")}`);
    t(`merchant ${d.merchant_id}, order ${d.merchant_order_id ?? "-"}, checkout ${d.checkout_ref ?? "-"}; chain ${d.session_id} seq ${d.seq}; witness: ${d.witness}`, 2);
  }
  if (decisions.length > PDF_MAX_DECISION_ROWS) t(`The other ${decisions.length - PDF_MAX_DECISION_ROWS} decisions are listed in pack.json.`);
  h("What the pack carries for each category");
  for (const m of mapping) {
    t(`${m.state}: ${m.category} (${m.source})`);
    t(`carries: ${m.carries}. ${m.limit}`, 2);
  }
  h("Limits");
  for (const l of limits) t(`${l.id}: ${l.text}`);
  return L;
}

// ---- checking a pack from its members alone ------------------------------------------

export interface PackCheck {
  ok: boolean;
  lines: string[];
}

// Offline: the zip's members against the manifest, the manifest's signature
// against keys/provider-jwk.json, then `chirindo verify` on each chain with
// keys/gate-identity.json and, when the pack carries them, the witness
// sidecar and key. Reads nothing outside the zip.
export async function checkIssuerPack(zipBytes: Buffer): Promise<PackCheck> {
  const { readZip } = await import("./zip.js");
  const lines: string[] = [];
  let ok = true;
  const bad = (l: string) => {
    ok = false;
    lines.push(`FAIL ${l}`);
  };
  let z: Map<string, Buffer>;
  try {
    z = readZip(zipBytes);
  } catch (e) {
    return { ok: false, lines: [`FAIL ${(e as Error).message}`] };
  }
  const mBytes = z.get("MANIFEST.json");
  const sBytes = z.get("MANIFEST.sig");
  if (mBytes === undefined || sBytes === undefined) return { ok: false, lines: ["FAIL MANIFEST.json or MANIFEST.sig is missing"] };
  let manifest: Obj;
  try {
    manifest = JSON.parse(mBytes.toString("utf8")) as Obj;
    if (jcs(manifest) !== mBytes.toString("utf8")) return { ok: false, lines: ["FAIL MANIFEST.json is not in its JCS form"] };
  } catch (e) {
    return { ok: false, lines: [`FAIL MANIFEST.json does not read (${(e as Error).message})`] };
  }
  const listed = (manifest["members"] as { path: string; sha256: string; bytes: number }[]) ?? [];
  const names = new Set(listed.map((m) => m.path));
  for (const m of listed) {
    const b = z.get(m.path);
    if (b === undefined) bad(`${m.path}: listed in the manifest, not in the zip`);
    else if (`sha256:${sha256Hex(b)}` !== m.sha256 || b.length !== m.bytes) bad(`${m.path}: sha256 or bytes differ from the manifest`);
  }
  for (const p of z.keys()) if (p !== "MANIFEST.json" && p !== "MANIFEST.sig" && !names.has(p)) bad(`${p}: in the zip, not in the manifest`);
  if (ok) lines.push(`OK ${listed.length} members match the manifest`);
  try {
    const sig = JSON.parse(sBytes.toString("utf8")) as Obj;
    const jwk = JSON.parse(z.get("keys/provider-jwk.json")!.toString("utf8")) as Obj;
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk["x"] as string }, format: "jwk" });
    if (edVerify(null, mBytes, pub, Buffer.from(String(sig["sig"]), "base64url"))) lines.push(`OK MANIFEST.sig verifies against keys/provider-jwk.json (kid ${String(jwk["kid"])})`);
    else bad("MANIFEST.sig does not verify against keys/provider-jwk.json");
  } catch (e) {
    bad(`MANIFEST.sig or keys/provider-jwk.json does not read (${(e as Error).message})`);
  }
  const dir = mkdtempSync(join(tmpdir(), "chirindo-issuer-check-"));
  try {
    for (const [p, b] of z) {
      mkdirSync(join(dir, ...p.split("/").slice(0, -1)), { recursive: true });
      writeFileSync(join(dir, ...p.split("/")), b);
    }
    for (const p of [...z.keys()].filter((k) => /^chains\/[0-9a-f]{32}\.jsonl$/.test(k)).sort()) {
      const session = p.slice("chains/".length, -".jsonl".length);
      const chainPath = join(dir, "chains", `${session}.jsonl`);
      const r = runVerify({ chainPath, identityPath: join(dir, "keys", "gate-identity.json") });
      const f = formatVerifyResult(r);
      if (r.kind !== "valid" || f.exitCode !== 0) {
        bad(`chains/${session}.jsonl: ${f.line.split("\n")[0]}`);
        continue;
      }
      const sidecar = `witness/${session}.witness.ndjson`;
      const keyJson = z.get("witness/witness-key.json");
      if (z.has(sidecar) && z.has("witness/witness-key.jwk") && keyJson !== undefined) {
        const { parseWitnessKeyArg, witnessPubFromRaw } = await import("../witness.js");
        const k = JSON.parse(keyJson.toString("utf8")) as Obj;
        const raw = parseWitnessKeyArg(join(dir, "witness", "witness-key.jwk")).raw;
        const wv = await verifyAgainstWitness({
          chainPath,
          validText: f.line,
          validExit: f.exitCode,
          witnessName: String(k["witness_name"]),
          sidecarPath: join(dir, ...sidecar.split("/")),
          pinned: { pubObj: witnessPubFromRaw(raw), hex: raw.toString("hex"), id: String(k["public_key_id"]) },
        });
        if (wv.code !== 0) bad(`chains/${session}.jsonl with ${sidecar}: ${wv.text.split("\n")[0]}`);
        else lines.push(`OK chains/${session}.jsonl: ${wv.text.split("\n").join(" | ")}`);
      } else lines.push(`OK chains/${session}.jsonl: ${f.line.split("\n")[0]} (no witness sidecar in the pack)`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { ok, lines };
}
