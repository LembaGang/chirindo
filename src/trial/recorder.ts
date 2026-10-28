// The Chirindo trial recorder: each agent cart a merchant's checkout service
// records becomes a signed, hash-chained entry (the format appendReceipt
// writes, so `chirindo verify` reads it unchanged), and checkpoints of the
// chain head go to the witness. Nothing here blocks or fails a checkout:
// record() is synchronous and never throws, and every witness failure is a
// sidecar line, a timing line and at most one log line.
//
// Cost does not grow with the chain: the head (seq and the previous entry's
// hash) is kept in memory and passed to appendReceipt, and a checkpoint is
// signed from that head. The chain is never re-read and records are not kept.

import { randomBytes } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { appendReceipt } from "../receipt.js";
import { appendSidecarLine, buildCheckpointFromHead } from "../checkpoint.js";
import {
  DEFAULT_WITNESS_KEY_ID,
  WITNESS_POST_TIMEOUT_MS,
  checkWitnessBaseUrl,
  isWitnessAccountKey,
  parseWitnessKeyArg,
  readSidecar,
  sidecarPathFor,
  upgradeHintLine,
  witnessCheckpoint,
  witnessPubFromRaw,
  type WitnessOutcome,
  type WitnessTarget,
} from "../witness.js";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  argsHash,
  contentOf,
  entryHashOfCanonical,
  genesisPrevHash,
  jcsBytes,
  loadFullIdentity,
  strictJsonParse,
  type LoadedFullIdentity,
  type SignedCheckpoint,
  type SignedRecord,
} from "../vendor/recorder/index.js";
import {
  appendJsonLine,
  chainEnds,
  chainPathOf,
  earlierChains,
  ensureDir,
  ensureFile,
  gapsPathOf,
  lockIsLive,
  lockPathOf,
  removeLock,
  sha256Tagged,
  timingPathOf,
  writeLock,
  writeRetained,
} from "./files.js";
import { checkGapInput, checkRecordInput, gapFieldsOf } from "./rules.js";
import type {
  AwaitResult,
  GapResult,
  RecordRefusal,
  RecordResult,
  TrialRecorder,
  TrialRecorderOptions,
} from "./types.js";

const TOOL_NAME = "record_agent_cart";
const MAX_AWAIT_MS = 3_500;
const REMEMBERED_ENTRIES = 10_000;
const CATCH_UP_CHAINS = 10;
const CATCH_UP_POSTS = 10;
const CATCH_UP_QUIET_MS = 10 * 60_000;
// The witness refused this caller, not this checkpoint: sending more today
// would only be refused again.
const STOP_CODES = new Set(["quota_exceeded", "payment_required", "invalid_key"]);

// Options after validation; the CLI builds these from its own flag parser.
export interface ResolvedTrialOptions {
  dir: string;
  serverLabel: string;
  jwksUri?: string;
  witness?: WitnessTarget;
  log: (line: string) => void;
  now: () => string;
}

function fail(msg: string): never {
  throw new Error(`createTrialRecorder: ${msg}`);
}

// Validates the options and opens the recorder. Throws on invalid options or a
// missing identity; nothing after it throws. Messages name the option, never a
// key's value.
export function createTrialRecorder(options: TrialRecorderOptions): TrialRecorder {
  if (typeof options !== "object" || options === null) fail("options must be an object");
  const { dir, serverLabel, jwksUri, witness, logger, now } = options;
  if (typeof dir !== "string" || dir === "") fail("dir must be a non-empty string");
  if (typeof serverLabel !== "string" || serverLabel === "") fail("serverLabel must be a non-empty string");
  // The same two checks `chirindo proxy --jwks-uri` makes.
  if (jwksUri !== undefined) {
    let u: URL;
    try {
      u = new URL(jwksUri);
    } catch {
      fail("jwksUri is not a valid URL");
    }
    if (u.protocol !== "https:") fail("jwksUri must be an https:// URL");
  }
  if (logger !== undefined && typeof logger !== "function") fail("logger must be a function");
  if (now !== undefined && typeof now !== "function") fail("now must be a function");
  let target: WitnessTarget | undefined;
  if (witness !== undefined) {
    if (typeof witness !== "object" || witness === null) fail("witness must be an object");
    if (typeof witness.name !== "string" || witness.name === "") fail("witness.name must be a non-empty string");
    let baseUrl: string;
    try {
      baseUrl = checkWitnessBaseUrl(String(witness.baseUrl));
    } catch (e) {
      fail(`witness.baseUrl: ${(e as Error).message}`);
    }
    target = { baseUrl, name: witness.name };
    if (witness.pinnedKey !== undefined) {
      try {
        const parsed = parseWitnessKeyArg(String(witness.pinnedKey));
        target.pinned = {
          pubObj: witnessPubFromRaw(parsed.raw),
          hex: parsed.raw.toString("hex"),
          id: parsed.jwkKid ?? DEFAULT_WITNESS_KEY_ID,
        };
      } catch (e) {
        fail(`witness.pinnedKey: ${(e as Error).message.replace(/^--witness-key /, "")}`);
      }
    }
    if (witness.accountKeyFile !== undefined) {
      const path = String(witness.accountKeyFile);
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
  }
  return openTrialRecorder({
    dir: isAbsolute(dir) ? dir : resolve(process.cwd(), dir),
    serverLabel,
    ...(jwksUri !== undefined ? { jwksUri } : {}),
    ...(target !== undefined ? { witness: target } : {}),
    log: logger ?? ((l) => process.stderr.write(l + "\n")),
    now: now ?? (() => new Date().toISOString()),
  });
}

interface Head {
  sessionId: string;
  count: number;
  hash: string;
  sidecar: string;
  own: boolean;
}

interface InFlight {
  head: Head;
  cp: SignedCheckpoint;
  sentAt: string;
  abandoned: boolean;
  settled: Promise<void>;
}

interface Waiter {
  count: number;
  timer: NodeJS.Timeout;
  finish: (r: AwaitResult) => void;
}

function nextUtcMidnight(ms: number): number {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
}

// Internal: opens a recorder from validated options. Throws on a missing
// identity, or a legacy kid with a witness (the witness accepts thumbprint
// kids only).
export function openTrialRecorder(o: ResolvedTrialOptions): TrialRecorder {
  const identity: LoadedFullIdentity = loadFullIdentity(join(o.dir, IDENTITY_FILENAME), join(o.dir, PRIVATE_KEY_FILENAME));
  if (o.witness !== undefined && identity.kid.startsWith("ed25519/")) {
    throw new Error(`createTrialRecorder: legacy kid ${identity.kid} cannot be witnessed; the witness accepts RFC 7638 thumbprint kids only`);
  }
  const sessionId = randomBytes(16).toString("hex");
  const chainPath = chainPathOf(o.dir, sessionId);
  const ownSidecar = sidecarPathFor(chainPath);
  ensureDir(join(o.dir, "chains"));
  ensureDir(join(o.dir, "args"));
  writeLock(o.dir, sessionId);

  let head = { seq: 0, prevHash: genesisPrevHash(sessionId) };
  let chainCreated = false;
  let closing: Promise<void> | null = null;
  let closed = false;
  // entry_hash -> count, the last REMEMBERED_ENTRIES entries.
  const known = new Map<string, number>();
  // Verified, non-fork receipts for this session, in arrival order (counts rise).
  const receipts: { count: number; received_at: string }[] = [];
  const waiters = new Set<Waiter>();

  // Witness driver state.
  let pendingOwn: Head | null = null;
  let lastAttemptedOwn = 0;
  let lastOwnOk = 0;
  const catchUp: Head[] = [];
  let inflight: InFlight | null = null;
  let scheduled = false;
  let stoppedUntil = 0;
  const stop = new AbortController();
  const idleWaiters: (() => void)[] = [];
  const logged = new Set<string>();
  const ensured = new Set<string>();

  const logOnce = (key: string, line: string) => {
    if (logged.has(key)) return;
    logged.add(key);
    o.log(line);
  };
  const stopped = () => Date.now() < stoppedUntil;

  const timingLine = (line: Record<string, unknown>) => {
    try {
      appendJsonLine(timingPathOf(o.dir), line);
    } catch (e) {
      logOnce("timing", `[chirindo] trial-recorder: witness timing line not written (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  };

  const gapLine = (orderRef: string | null, callSeq: number | null, reason: string, paths: string[]): boolean => {
    try {
      appendJsonLine(gapsPathOf(o.dir), {
        ts: o.now(),
        session_id: sessionId,
        order_ref_sha256: orderRef === null ? null : sha256Tagged(orderRef),
        call_seq: callSeq,
        reason,
        paths,
      });
      return true;
    } catch (e) {
      process.stderr.write(`[chirindo] trial-recorder: gap line not written (${(e as NodeJS.ErrnoException).code ?? "error"})\n`);
      return false;
    }
  };

  const refuse = (input: unknown, reason: RecordRefusal, paths: string[]): RecordResult => {
    const f = gapFieldsOf(input);
    gapLine(f.orderRef, f.callSeq, reason, paths);
    return { ok: false, reason, paths, session_id: sessionId };
  };

  const settleWaiters = (pick: (w: Waiter) => AwaitResult | null) => {
    for (const w of [...waiters]) {
      const r = pick(w);
      if (r !== null) w.finish(r);
    }
  };

  const notifyIdle = () => {
    for (const r of idleWaiters.splice(0)) r();
  };

  const schedule = () => {
    if (scheduled || o.witness === undefined) return;
    scheduled = true;
    // After the caller's synchronous work, as the proxy's checkpointer does.
    setImmediate(() => {
      scheduled = false;
      pump();
    });
  };

  const writeSidecar = (path: string, line: Parameters<typeof appendSidecarLine>[1]) => {
    try {
      if (!ensured.has(path)) {
        ensureFile(path);
        ensured.add(path);
      }
      appendSidecarLine(path, line);
    } catch (e) {
      logOnce("sidecar", `[chirindo] trial-recorder: sidecar write failed (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  };

  const finish = (f: InFlight, outcome: WitnessOutcome) => {
    inflight = null;
    const error = outcome.error;
    writeSidecar(f.head.sidecar, { checkpoint: f.cp, witness_receipt: outcome.receipt, witness_error: error });
    timingLine({
      session_id: f.head.sessionId,
      count: f.head.count,
      last_entry_hash: f.head.hash,
      sent_at: f.sentAt,
      replied_at: o.now(),
      outcome: error ?? "ok",
    });
    if (f.head.own && outcome.receipt !== null) {
      lastOwnOk = Math.max(lastOwnOk, f.head.count);
      if (outcome.receipt["fork"] !== "true") {
        const r = { count: f.head.count, received_at: String(outcome.receipt["received_at"]) };
        receipts.push(r);
        settleWaiters((w) => (w.count <= r.count ? { ok: true, received_at: r.received_at, covering_count: r.count } : null));
      }
    }
    if (error !== null) {
      if (STOP_CODES.has(error)) {
        stoppedUntil = nextUtcMidnight(Date.now());
        catchUp.length = 0;
        logOnce(
          `stop:${stoppedUntil}`,
          `[chirindo] trial-recorder: witness refused with ${error}; no checkpoint is sent until 00:00 UTC or a restart (recorded in the sidecar)`,
        );
        settleWaiters(() => ({ ok: false, reason: "stopped" }));
      } else {
        logOnce(`err:${error}`, `[chirindo] trial-recorder: witness failed (${error}); records continue unwitnessed meanwhile (recorded in the sidecar)`);
      }
      if ("upgrade" in outcome && outcome.upgrade !== undefined) logOnce("upgrade", upgradeHintLine(error, outcome.upgrade));
    }
    pump();
  };

  // At most one POST in flight; the newest own head first, then catch-up heads.
  // Heads in between are covered by the later checkpoint.
  const pump = () => {
    if (inflight !== null || closed || o.witness === undefined) return;
    let next: Head | null = null;
    if (!stopped()) {
      if (pendingOwn !== null && pendingOwn.count > lastAttemptedOwn) {
        next = pendingOwn;
        lastAttemptedOwn = next.count;
      } else if (catchUp.length > 0) {
        next = catchUp.shift()!;
      }
    }
    if (next === null) {
      notifyIdle();
      return;
    }
    const h = next;
    let cp: SignedCheckpoint;
    try {
      cp = buildCheckpointFromHead({ sessionId: h.sessionId, count: h.count, lastEntryHash: h.hash }, identity, o.now());
    } catch (e) {
      logOnce("build", `[chirindo] trial-recorder: checkpoint not built: ${(e as Error).message}`);
      pump();
      return;
    }
    const f: InFlight = { head: h, cp, sentAt: o.now(), abandoned: false, settled: Promise.resolve() };
    inflight = f;
    f.settled = witnessCheckpoint(cp, identity.publicKey, o.witness, WITNESS_POST_TIMEOUT_MS, stop.signal)
      .catch((): WitnessOutcome => ({ receipt: null, error: "witness_unreachable" }))
      .then((outcome) => {
        if (!f.abandoned) finish(f, outcome);
      });
  };

  const remember = (hash: string, count: number) => {
    known.set(hash, count);
    if (known.size > REMEMBERED_ENTRIES) {
      known.delete(known.keys().next().value!);
      const oldest: number = known.values().next().value!;
      // A receipt below the oldest remembered count can answer no awaitWitness.
      while (receipts.length > 0 && receipts[0]!.count < oldest) receipts.shift();
    }
  };

  // Earlier sessions under this data directory whose head no receipt covers:
  // rebuilt once and sent through the driver, so a restart leaves no
  // unwitnessed tail. Read from the chain's two ends only.
  const runCatchUp = () => {
    if (o.witness === undefined || closed) return;
    try {
      let queued = 0;
      const cutoff = Date.now() - CATCH_UP_QUIET_MS;
      for (const c of earlierChains(o.dir, sessionId).slice(0, CATCH_UP_CHAINS)) {
        if (queued >= CATCH_UP_POSTS) break;
        if (c.mtimeMs > cutoff || lockIsLive(lockPathOf(o.dir, c.sessionId))) continue;
        try {
          const ends = chainEnds(c.path);
          if (ends === null) continue;
          const first = strictJsonParse(ends.first) as SignedRecord;
          const last = strictJsonParse(ends.last) as SignedRecord;
          if (first.kid !== identity.kid || last.kid !== identity.kid) continue;
          if (first.seq !== 0 || first.session_id !== c.sessionId || last.session_id !== c.sessionId) continue;
          if (!Number.isSafeInteger(last.seq) || last.seq < 0) continue;
          const count = last.seq + 1;
          const sidecar = sidecarPathFor(c.path);
          let covered = false;
          try {
            covered = readSidecar(sidecar).some(
              (l) => l.witness_receipt !== null && l.witness_receipt["session_id"] === c.sessionId && Number(l.witness_receipt["count"]) >= count,
            );
          } catch (e) {
            if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
              o.log(`[chirindo] trial-recorder: catch-up skipped session ${c.sessionId}: malformed sidecar`);
              continue;
            }
          }
          if (covered) continue;
          catchUp.push({ sessionId: c.sessionId, count, hash: entryHashOfCanonical(jcsBytes(contentOf(last))), sidecar, own: false });
          queued++;
        } catch {
          /* unreadable or not a chain: skipped */
        }
      }
      if (queued > 0) pump();
    } catch (e) {
      o.log(`[chirindo] trial-recorder: catch-up not run (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  };
  if (o.witness !== undefined) setImmediate(runCatchUp);

  const recorder: TrialRecorder = {
    session_id: sessionId,
    dir: o.dir,

    record(input) {
      try {
        if (closed || closing !== null) return refuse(input, "internal", []);
        const c = checkRecordInput(input);
        if (!c.ok) return refuse(input, c.reason, c.paths);
        const ah = argsHash(c.args);
        const count = head.seq + 1;
        let retained: string;
        try {
          retained = writeRetained(o.dir, sessionId, count, ah, {
            args_hash: ah,
            order_ref_sha256: sha256Tagged(c.orderRef),
            call_seq: c.callSeq,
            arguments: c.args,
          });
        } catch {
          return refuse(input, "write-failed", []);
        }
        let entry: SignedRecord;
        try {
          if (!chainCreated) {
            ensureFile(chainPath);
            chainCreated = true;
          }
          entry = appendReceipt({
            chainPath,
            sessionId,
            identity,
            server: o.serverLabel,
            toolName: TOOL_NAME,
            toolArgs: c.args,
            decision: { kind: "allow" },
            ...(o.jwksUri !== undefined ? { jwksUri: o.jwksUri } : {}),
            ts: o.now(),
            head: { seq: head.seq, prevHash: head.prevHash },
          });
        } catch {
          try {
            rmSync(retained);
          } catch {
            /* an orphan the assembler ignores */
          }
          return refuse(input, "write-failed", []);
        }
        const entryHash = entryHashOfCanonical(jcsBytes(contentOf(entry)));
        head = { seq: count, prevHash: entryHash };
        remember(entryHash, count);
        if (o.witness !== undefined) {
          pendingOwn = { sessionId, count, hash: entryHash, sidecar: ownSidecar, own: true };
          schedule();
        }
        return { ok: true, entry_hash: entryHash, args_hash: ah, count, session_id: sessionId };
      } catch {
        return refuse(input, "internal", []);
      }
    },

    reportGap(input): GapResult {
      try {
        const g = checkGapInput(input);
        if (!g.ok) return { ok: false, reason: "invalid-input" };
        return gapLine(g.orderRef, g.callSeq, g.reason, []) ? { ok: true } : { ok: false, reason: "write-failed" };
      } catch {
        return { ok: false, reason: "internal" };
      }
    },

    async awaitWitness(entryHash, maxMs) {
      const t0 = Date.now();
      const sentAt = o.now();
      const count = typeof entryHash === "string" ? known.get(entryHash) : undefined;
      const done = (r: AwaitResult): AwaitResult => {
        timingLine({
          session_id: sessionId,
          count: count ?? null,
          last_entry_hash: typeof entryHash === "string" && /^sha256:[0-9a-f]{64}$/.test(entryHash) ? entryHash : null,
          sent_at: sentAt,
          replied_at: o.now(),
          outcome: r.ok ? "ok" : r.reason,
          await: true,
          waited_ms: Date.now() - t0,
        });
        return r;
      };
      try {
        if (o.witness === undefined) return done({ ok: false, reason: "no-witness" });
        if (closed) return done({ ok: false, reason: "closed" });
        if (count === undefined) return done({ ok: false, reason: "unknown-entry" });
        const hit = receipts.find((r) => r.count >= count);
        if (hit !== undefined) return done({ ok: true, received_at: hit.received_at, covering_count: hit.count });
        if (stopped()) return done({ ok: false, reason: "stopped" });
        const limit = typeof maxMs === "number" && Number.isFinite(maxMs) ? Math.min(Math.max(maxMs, 0), MAX_AWAIT_MS) : 0;
        return await new Promise<AwaitResult>((resolveWait) => {
          const w: Waiter = {
            count,
            timer: setTimeout(() => w.finish({ ok: false, reason: "timeout" }), limit),
            finish: (r) => {
              clearTimeout(w.timer);
              waiters.delete(w);
              resolveWait(done(r));
            },
          };
          waiters.add(w);
        });
      } catch {
        return done({ ok: false, reason: "internal" });
      }
    },

    close(timeoutMs = 5_000) {
      if (closing !== null) return closing;
      closing = (async () => {
        try {
          if (o.witness !== undefined) {
            catchUp.length = 0;
            // The final checkpoint of the head, unless it is already witnessed
            // or waiting to be sent.
            if (pendingOwn !== null && lastOwnOk < pendingOwn.count && lastAttemptedOwn >= pendingOwn.count && inflight?.head !== pendingOwn) {
              lastAttemptedOwn = pendingOwn.count - 1;
            }
            pump();
            let timer: NodeJS.Timeout | undefined;
            const idle = new Promise<void>((r) => {
              if (inflight === null) r();
              else idleWaiters.push(r);
            });
            await Promise.race([idle, new Promise<void>((r) => (timer = setTimeout(r, Math.max(0, timeoutMs))))]);
            clearTimeout(timer);
            closed = true;
            stop.abort();
            // What remains is written as witness_timeout, as the proxy's shutdown does.
            const left = inflight as InFlight | null;
            if (left !== null) {
              left.abandoned = true;
              inflight = null;
              writeSidecar(left.head.sidecar, { checkpoint: left.cp, witness_receipt: null, witness_error: "witness_timeout" });
              timingLine({
                session_id: left.head.sessionId,
                count: left.head.count,
                last_entry_hash: left.head.hash,
                sent_at: left.sentAt,
                replied_at: o.now(),
                outcome: "witness_timeout",
              });
              await left.settled;
            }
            const p = pendingOwn as Head | null;
            if (p !== null && p.count > lastAttemptedOwn) {
              try {
                const cp = buildCheckpointFromHead({ sessionId, count: p.count, lastEntryHash: p.hash }, identity, o.now());
                writeSidecar(ownSidecar, { checkpoint: cp, witness_receipt: null, witness_error: "witness_timeout" });
              } catch {
                /* nothing more to record */
              }
            }
          }
        } finally {
          closed = true;
          settleWaiters(() => ({ ok: false, reason: "closed" }));
          notifyIdle();
          removeLock(o.dir, sessionId);
        }
      })();
      return closing;
    },
  };
  return recorder;
}
