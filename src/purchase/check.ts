// createPurchaseCheck: the before-purchase instruction check with its record
// (B-432, design rev 3 §4 and §5 with the T0 and T1 rulings). A provider's
// code calls check() before it mints a credential or charges. The answer is
// allow or deny with the reasons, and each decision made on a well-formed
// request is a signed, hash-chained receipt (appendReceipt's format, so
// `chirindo verify` reads it) written BEFORE the answer is returned.
//
// Files under the data directory:
//   purchase-chains/.lock                       the pid of the process holding the dir
//   purchase-chains/<session_id>.jsonl          one chain per process session
//   purchase-chains/<session_id>.jsonl.witness.ndjson   its witness sidecar
//   purchase-args/<session_id>/<seq>-<32 hex>.json      each receipt's arguments, as JCS bytes
// Never dir/chains or dir/args, which are the trial recorder's.

import { randomBytes } from "node:crypto";
import { closeSync, openSync, readdirSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync, writeSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { ProxyCheckpointer } from "../checkpoint.js";
import { appendReceipt } from "../receipt.js";
import { ensureDir, ensureFile, lockIsLive } from "../trial/files.js";
import type { TrialWitnessOptions } from "../trial/types.js";
import {
  DEFAULT_WITNESS_KEY_ID,
  checkWitnessBaseUrl,
  isWitnessAccountKey,
  parseWitnessKeyArg,
  witnessPubFromRaw,
  type WitnessTarget,
} from "../witness.js";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  argsHash,
  contentOf,
  entryHashOfCanonical,
  formatVerifyResult,
  genesisPrevHash,
  jcsBytes,
  loadFullIdentity,
  readChainFile,
  rfc7638Thumbprint,
  runVerify,
  type LoadedFullIdentity,
  type SignedRecord,
} from "../vendor/recorder/index.js";
import { cardLimitsOf, checkOptions, judgeInput, judgeLimits, type CardLimitRow, type Prepared } from "./limits.js";
import { isPlainObject, jcsSha256 } from "./m6.js";
import { PURCHASE_CHECK_VERSION, type PurchaseCheckMember } from "./member.js";
import { compareInstants } from "./time.js";

const TOOL_NAME = "check";
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
// The verifier's timestamp rule (cli/verify.ts): a record more than 5 s
// earlier than one before it is a regression, so it is never written.
const MAX_SKEW_MS = 5_000;
const CLOSE_WITNESS_WAIT_MS = 5_000;

export interface PurchaseCheckOptions {
  // The data directory; `chirindo init --dir <dir>` creates its identity.
  dir: string;
  // The `server` member of every receipt. Default "purchase-check".
  serverLabel?: string;
  // https URL of the operator's published JWKS, stamped into every receipt.
  jwksUri?: string;
  // Checkpoints of the chain head go to this witness, asynchronously; a
  // witness failure is a sidecar line and never changes an answer.
  witness?: TrialWitnessOptions;
  // The gate clock, for tests. A clock that throws or answers no ISO UTC
  // calendar instant makes every answer deny record-failed (T0 ruling 4).
  now?: () => string;
}

export interface CheckInput {
  // The instruction's JSON text, so duplicate members are detectable.
  instruction: string;
  order: unknown;
}

export interface CheckResult {
  decision: "allow" | "deny";
  reasons: string[];
  exceeded: string[];
  card_limits: CardLimitRow[];
  // The M6 digest; the JCS digest of the parsed instruction on a step 2 deny;
  // null when the input was refused at step 1 or no decision could be made.
  instruction_sha256: string | null;
  // The time of the decision; for a repeat, the time of the allow it returns;
  // null when the gate clock failed.
  at: string | null;
  // The receipt of this decision (for a repeat, the earlier allow's); null
  // when nothing was written (step 1, record-failed).
  receipt: { seq: number; entry_hash: string } | null;
  // True when this is an earlier allow returned again: not a second purchase.
  repeat: boolean;
}

export interface PurchaseCheck {
  readonly session_id: string;
  readonly dir: string;
  // Synchronous; never throws.
  check(input: CheckInput): CheckResult;
  // Final witness checkpoint (at most 5 s), then the lock is released.
  close(): Promise<void>;
}

// Internal: options after validation, with the tests' fault injection.
export interface ResolvedPurchaseOptions {
  dir: string;
  serverLabel: string;
  jwksUri?: string;
  witness?: WitnessTarget;
  now: () => string;
  log: (line: string) => void;
  appendEntry?: typeof appendReceipt;
  writeArgs?: (path: string, bytes: Buffer) => void;
  truncateChain?: (path: string, length: number) => void;
}

function fail(msg: string): never {
  throw new Error(`createPurchaseCheck: ${msg}`);
}

// Validates the options and opens the check. Throws on invalid options, a
// missing or legacy identity, a held or stale lock, or a chain that does not
// verify; nothing after it throws.
export function createPurchaseCheck(options: PurchaseCheckOptions): PurchaseCheck {
  if (typeof options !== "object" || options === null) fail("options must be an object");
  const { dir, serverLabel = "purchase-check", jwksUri, witness, now } = options;
  if (typeof dir !== "string" || dir === "") fail("dir must be a non-empty string");
  if (typeof serverLabel !== "string" || serverLabel === "") fail("serverLabel must be a non-empty string");
  if (jwksUri !== undefined) {
    let u: URL;
    try {
      u = new URL(jwksUri);
    } catch {
      fail("jwksUri is not a valid URL");
    }
    if (u.protocol !== "https:") fail("jwksUri must be an https:// URL");
  }
  if (now !== undefined && typeof now !== "function") fail("now must be a function");
  return openPurchaseCheck({
    dir: isAbsolute(dir) ? dir : resolve(process.cwd(), dir),
    serverLabel,
    ...(jwksUri !== undefined ? { jwksUri } : {}),
    ...(witness !== undefined ? { witness: witnessTarget(witness) } : {}),
    now: now ?? (() => new Date().toISOString()),
    log: (l) => process.stderr.write(l + "\n"),
  });
}

// The trial recorder's witness options, read the same way.
function witnessTarget(w: TrialWitnessOptions): WitnessTarget {
  if (typeof w !== "object" || w === null) fail("witness must be an object");
  if (typeof w.name !== "string" || w.name === "") fail("witness.name must be a non-empty string");
  let baseUrl: string;
  try {
    baseUrl = checkWitnessBaseUrl(String(w.baseUrl));
  } catch (e) {
    fail(`witness.baseUrl: ${(e as Error).message}`);
  }
  const target: WitnessTarget = { baseUrl, name: w.name };
  if (w.pinnedKey !== undefined) {
    try {
      const parsed = parseWitnessKeyArg(String(w.pinnedKey));
      target.pinned = { pubObj: witnessPubFromRaw(parsed.raw), hex: parsed.raw.toString("hex"), id: parsed.jwkKid ?? DEFAULT_WITNESS_KEY_ID };
    } catch (e) {
      fail(`witness.pinnedKey: ${(e as Error).message.replace(/^--witness-key /, "")}`);
    }
  }
  if (w.accountKeyFile !== undefined) {
    const path = String(w.accountKeyFile);
    if (/ho_live_[0-9a-f]{16}/.test(path)) fail("witness.accountKeyFile takes the path of a file holding the key, not the key itself");
    let key: string;
    try {
      key = readFileSync(path, "utf8").trim();
    } catch (e) {
      fail(`cannot read witness.accountKeyFile ${path} (${(e as NodeJS.ErrnoException).code ?? "unreadable"})`);
    }
    if (!isWitnessAccountKey(key)) fail(`witness.accountKeyFile ${path} does not hold ho_live_ followed by 64 lowercase hex characters`);
    target.accountKey = key;
  }
  return target;
}

// The exclusive lock: created with "wx", or refused, naming the pid and the
// path. A stale lock is never reclaimed (T0 ruling 5): the operator removes it
// after checking that no process holds the dir.
function takeLock(dir: string, lockPath: string): void {
  let fd: number;
  try {
    fd = openSync(lockPath, "wx", 0o600);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "error";
    if (code !== "EEXIST") fail(`cannot create lock ${lockPath} (${code})`);
    let held = "";
    try {
      held = readFileSync(lockPath, "utf8").trim();
    } catch {
      /* named as unreadable below */
    }
    if (!/^[1-9][0-9]{0,9}$/.test(held)) {
      fail(`lock ${lockPath} holds no process id; check that no process holds ${dir}, then remove the file`);
    }
    if (lockIsLive(lockPath)) fail(`${dir} is in use: lock ${lockPath} names process ${held}, which is running`);
    fail(`stale lock ${lockPath} names process ${held}, which is not running; check that no process holds ${dir}, then remove the file`);
  }
  try {
    writeSync(fd, String(process.pid));
  } catch (e) {
    closeSync(fd);
    rmSync(lockPath, { force: true });
    fail(`cannot write lock ${lockPath} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }
  closeSync(fd);
}

interface Allowed {
  order_sha256: string;
  seq: number;
  entry_hash: string;
  at: string;
}

const keyOf = (digest: string, order: Obj): string =>
  JSON.stringify([digest, order["merchant_id"], order["merchant_order_id"] ?? null, order["checkout_ref"] ?? null]);

type Obj = Record<string, unknown>;
const isStr = (v: unknown): v is string => typeof v === "string";
const nullOrStr = (v: unknown) => v === null || isStr(v);
const strList = (v: unknown) => Array.isArray(v) && v.every(isStr);
const MEMBER_KEYS = ["v", "instruction_sha256", "order_sha256", "merchant_id", "merchant_order_id", "checkout_ref", "at", "reasons", "exceeded"];

// What makes a verified record unusable for the rebuild, or null.
function recordProblem(r: SignedRecord, sessionId: string): string | null {
  if (r.session_id !== sessionId) return "session_id is not the file's";
  const e = r.event as unknown as Obj;
  if (e["type"] !== "mcp_call" || e["tool_name"] !== TOOL_NAME) return "not a purchase-check record";
  if (e["decision"] !== "allow" && e["decision"] !== "deny") return "event.decision is neither allow nor deny";
  const c = (r as unknown as Obj)["check"];
  if (!isPlainObject(c)) return "no check member";
  const keys = Object.keys(c);
  if (keys.length !== MEMBER_KEYS.length || !MEMBER_KEYS.every((k) => keys.includes(k))) return "check does not have exactly its members";
  if (c["v"] !== PURCHASE_CHECK_VERSION) return `check.v is not ${PURCHASE_CHECK_VERSION}`;
  if (!isStr(c["instruction_sha256"]) || !SHA256_RE.test(c["instruction_sha256"])) return "check.instruction_sha256 is malformed";
  if (!isStr(c["order_sha256"]) || !SHA256_RE.test(c["order_sha256"])) return "check.order_sha256 is malformed";
  if (!isStr(c["merchant_id"]) || !nullOrStr(c["merchant_order_id"]) || !nullOrStr(c["checkout_ref"])) return "check's key parts are malformed";
  if (c["at"] !== r.ts) return "check.at is not the receipt's ts";
  if (!strList(c["reasons"]) || !strList(c["exceeded"])) return "check.reasons or check.exceeded is not a list of strings";
  if ((e["decision"] === "allow") !== ((c["reasons"] as string[]).length === 0)) return "the decision and check.reasons disagree";
  return null;
}

// Internal: opens a check from validated options.
export function openPurchaseCheck(o: ResolvedPurchaseOptions): PurchaseCheck {
  const identityPath = join(o.dir, IDENTITY_FILENAME);
  let identity: LoadedFullIdentity;
  try {
    identity = loadFullIdentity(identityPath, join(o.dir, PRIVATE_KEY_FILENAME));
  } catch (e) {
    fail(`cannot load the identity in ${o.dir} (${(e as Error).message}); run 'chirindo init --dir ${o.dir}' first`);
  }
  // A legacy kid, or a kid that is not its key's thumbprint, is refused: the
  // instruction's agent_kid and the bundle's M2 take thumbprint kids only.
  if (identity.kid !== rfc7638Thumbprint(identity.publicKey)) {
    fail(`kid ${identity.kid} is not the RFC 7638 thumbprint of the identity's key; a legacy kid cannot run the purchase check`);
  }
  const chainsDir = join(o.dir, "purchase-chains");
  const argsRoot = join(o.dir, "purchase-args");
  const lockPath = join(chainsDir, ".lock");
  ensureDir(chainsDir);
  ensureDir(argsRoot);
  takeLock(o.dir, lockPath);

  const appendEntry = o.appendEntry ?? appendReceipt;
  const truncateChain = o.truncateChain ?? truncateSync;
  const writeArgs = o.writeArgs ?? ((path: string, bytes: Buffer) => writeFileSync(path, bytes, { mode: 0o600, flag: "w" }));

  // The rebuild (design §4.3), from the signed bytes of every chain here.
  const uses = new Map<string, number>();
  const allowed = new Map<string, Allowed>();
  try {
    for (const name of readdirSync(chainsDir).sort()) {
      const m = /^([0-9a-f]{32})\.jsonl$/.exec(name);
      if (m === null) continue;
      const path = join(chainsDir, name);
      // A torn final line is an append that did not complete; no answer was
      // returned on it (an answer follows its append), so it is cut off.
      const bytes = readFileSync(path);
      if (bytes.length > 0 && bytes[bytes.length - 1] !== 0x0a) {
        const keep = bytes.lastIndexOf(0x0a) + 1;
        truncateChain(path, keep);
        o.log(`[chirindo] purchase-check: ${path}: cut a torn final line of ${bytes.length - keep} bytes (an append that did not complete; no answer was given on it)`);
      }
      if (statSync(path).size === 0) continue;
      let verdict;
      try {
        verdict = runVerify({ chainPath: path, identityPath });
      } catch (e) {
        fail(`chain ${path} does not read: ${(e as Error).message}`);
      }
      if (verdict.kind !== "valid") fail(`chain ${path} does not verify: ${formatVerifyResult(verdict).line.split("\n")[0]}`);
      const file = readChainFile(path);
      if (file.checkpoint !== null) fail(`chain ${path} holds an in-file checkpoint, which the purchase check never writes`);
      for (const r of file.records) {
        const problem = recordProblem(r, m[1]!);
        if (problem !== null) fail(`chain ${path} record ${r.seq}: ${problem}`);
        if (r.event.type !== "mcp_call" || r.event.decision !== "allow") continue;
        const c = (r as unknown as { check: PurchaseCheckMember }).check;
        uses.set(c.instruction_sha256, (uses.get(c.instruction_sha256) ?? 0) + 1);
        const key = JSON.stringify([c.instruction_sha256, c.merchant_id, c.merchant_order_id, c.checkout_ref]);
        if (!allowed.has(key)) {
          allowed.set(key, { order_sha256: c.order_sha256, seq: r.seq, entry_hash: entryHashOfCanonical(jcsBytes(contentOf(r))), at: c.at });
        }
      }
    }
  } catch (e) {
    rmSync(lockPath, { force: true });
    throw e;
  }

  const sessionId = randomBytes(16).toString("hex");
  const chainPath = join(chainsDir, `${sessionId}.jsonl`);
  const argsDir = join(argsRoot, sessionId);
  let head = { seq: 0, prevHash: genesisPrevHash(sessionId) };
  let chainCreated = false;
  let chainBytes = 0;
  let chainBroken = false;
  let lastTsMs: number | null = null;
  let closing: Promise<void> | null = null;
  let closed = false;
  const checkpointer =
    o.witness !== undefined
      ? new ProxyCheckpointer({ chainPath, identity, every: 1, witness: o.witness, log: o.log, now: () => new Date().toISOString() })
      : null;

  const answer = (fields: Partial<CheckResult> & Pick<CheckResult, "decision" | "reasons">): CheckResult => ({
    exceeded: [],
    card_limits: [],
    instruction_sha256: null,
    at: null,
    receipt: null,
    repeat: false,
    ...fields,
  });
  const recordFailed = (at: string | null, more: Partial<CheckResult> = {}): CheckResult =>
    answer({ decision: "deny", ...more, reasons: [...(more.reasons ?? []), "record-failed"], at, receipt: null, repeat: false });

  // A member of the input, read without running a getter or a trap that throws.
  const own = (input: unknown, key: string): unknown => {
    if (typeof input !== "object" || input === null) return undefined;
    try {
      const d = Object.getOwnPropertyDescriptor(input, key);
      return d !== undefined && "value" in d ? d.value : undefined;
    } catch {
      return undefined;
    }
  };

  // Design §4.2 step 5: the receipt, then the answer. Allow is returned only
  // after its append has completed; any failure is deny record-failed with
  // nothing written.
  const write = (
    decision: "allow" | "deny",
    reasons: string[],
    exceeded: string[],
    card_limits: CardLimitRow[],
    digest: string,
    order: Obj,
    at: string,
  ): CheckResult => {
    const decided = { exceeded, card_limits, instruction_sha256: digest };
    if (chainBroken) return recordFailed(at, { reasons, ...decided });
    const args = decision === "allow" ? { order, instruction_sha256: digest } : { order, denied_instruction_sha256: digest };
    const ah = argsHash(args);
    const seq = head.seq;
    const argsPath = join(argsDir, `${seq}-${ah.slice("sha256:".length, "sha256:".length + 32)}.json`);
    try {
      ensureDir(argsDir);
      writeArgs(argsPath, jcsBytes(args));
    } catch {
      try {
        rmSync(argsPath, { force: true });
      } catch {
        /* an orphan: no receipt names it */
      }
      return recordFailed(at, { reasons, ...decided });
    }
    const member: PurchaseCheckMember = {
      v: PURCHASE_CHECK_VERSION,
      instruction_sha256: digest,
      order_sha256: jcsSha256(order),
      merchant_id: order["merchant_id"] as string,
      merchant_order_id: (order["merchant_order_id"] as string | undefined) ?? null,
      checkout_ref: (order["checkout_ref"] as string | undefined) ?? null,
      at,
      reasons,
      exceeded,
    };
    let entry: SignedRecord;
    try {
      if (!chainCreated) {
        ensureFile(chainPath);
        chainBytes = statSync(chainPath).size;
        chainCreated = true;
      }
      entry = appendEntry({
        chainPath,
        sessionId,
        identity,
        server: o.serverLabel,
        toolName: TOOL_NAME,
        toolArgs: args,
        decision: decision === "allow" ? { kind: "allow" } : { kind: "deny", reason: reasons.join(" ") },
        ...(o.jwksUri !== undefined ? { jwksUri: o.jwksUri } : {}),
        ts: at,
        head: { seq, prevHash: head.prevHash },
        check: member,
      });
    } catch {
      try {
        rmSync(argsPath, { force: true });
      } catch {
        /* an orphan: no receipt names it */
      }
      if (chainCreated) {
        try {
          truncateChain(chainPath, chainBytes);
        } catch {
          chainBroken = true;
          o.log(`[chirindo] purchase-check: a failed append could not be cut back; chain ${sessionId} is broken and every later check is denied record-failed`);
        }
      }
      return recordFailed(at, { reasons, ...decided });
    }
    // appendRecordLine writes exactly this line.
    chainBytes += Buffer.byteLength(JSON.stringify(entry) + "\n", "utf8");
    const entryHash = entryHashOfCanonical(jcsBytes(contentOf(entry)));
    head = { seq: seq + 1, prevHash: entryHash };
    lastTsMs = Math.max(lastTsMs ?? -Infinity, Date.parse(at));
    if (decision === "allow") {
      uses.set(digest, (uses.get(digest) ?? 0) + 1);
      allowed.set(keyOf(digest, order), { order_sha256: member.order_sha256, seq, entry_hash: entryHash, at });
    }
    try {
      checkpointer?.afterReceipt(head.seq);
    } catch {
      /* the witness never changes an answer */
    }
    return answer({ decision, reasons, ...decided, at, receipt: { seq, entry_hash: entryHash } });
  };

  const run = (input: unknown): CheckResult => {
    if (closed || closing !== null) return recordFailed(null);
    // The gate clock fails closed (T0 ruling 4).
    let at: string;
    try {
      at = o.now();
      checkOptions({ kid: identity.kid, at, usesSoFar: 0 });
    } catch {
      return recordFailed(null);
    }
    if (lastTsMs !== null && Date.parse(at) + MAX_SKEW_MS < lastTsMs) return recordFailed(at);

    // Steps 1 and 2.
    const r = judgeInput(own(input, "instruction"), own(input, "order"));
    if (!r.ok) {
      const j = r.judgement;
      if (j.step === 1) return answer({ decision: "deny", reasons: j.reasons, at });
      return write("deny", j.reasons, [], [], j.instruction_sha256!, j.order!, at);
    }
    const p: Prepared = r.prepared;

    // Step 2b: the repeat lookup.
    const prior = allowed.get(keyOf(p.digest, p.order));
    if (prior !== undefined) {
      if (prior.order_sha256 !== jcsSha256(p.order)) return write("deny", ["order-ref-reused"], [], [], p.digest, p.order, at);
      const validUntil = (p.instruction["constraints"] as Obj)["valid_until"] as string;
      if (compareInstants(at, validUntil) <= 0) {
        // The card limits depend on the instruction and the order alone, so
        // they are the earlier allow's.
        const { card_limits } = cardLimitsOf(p.instruction, p.order, { kid: identity.kid, authorizedAt: at }, 1);
        return answer({ decision: "allow", reasons: [], card_limits, instruction_sha256: p.digest, at: prior.at, receipt: { seq: prior.seq, entry_hash: prior.entry_hash }, repeat: true });
      }
    }

    // Steps 3 and 4, then 5.
    const j = judgeLimits(p, { kid: identity.kid, at, usesSoFar: uses.get(p.digest) ?? 0 });
    return write(j.reasons.length === 0 ? "allow" : "deny", j.reasons, j.exceeded, j.card_limits, p.digest, p.order, at);
  };

  return {
    session_id: sessionId,
    dir: o.dir,
    check(input) {
      try {
        return run(input);
      } catch {
        return recordFailed(null);
      }
    },
    close() {
      if (closing !== null) return closing;
      closing = (async () => {
        try {
          await checkpointer?.shutdown(head.seq, CLOSE_WITNESS_WAIT_MS);
        } catch {
          /* the witness never blocks a close */
        } finally {
          closed = true;
          try {
            rmSync(lockPath, { force: true });
          } catch {
            /* the directory may be gone */
          }
        }
      })();
      return closing;
    },
  };
}
