// B-481 T3: the receiver's checkpoints and their witness (N3 of
// SPEC_2026-11-13_B481_one-line-install_rev2.md section 3, with the Lead's
// rulings of 18 Nov). Only a checkpoint of the chain head leaves the
// machine, never a record (the founder's ruling of 14 Nov: Headless Oracle
// receives checkpoints only).
//
//   - Witness ON by default: https://api.headlessoracle.com with its key
//     pinned (key_2026_v1); --witness <url> takes another witness and then
//     needs --witness-key (always pinned); --no-witness turns it off. The
//     start prints one line saying what leaves the machine and how to stop it.
//   - Pacing by time. With an account key (--account-key-file, the only
//     source) at most one checkpoint every 120 s while records arrive
//     (--checkpoint-interval 40 to 900 with a key, 40 for the Evidence
//     plans); with no key every 900 s. A checkpoint is due at
//       max(L + interval, min(A + 10 s, P + interval))
//     where L is when the last one was sent, A the last append and P when the
//     head last became unwitnessed after L. So after quiet the head goes 10 s
//     after the last record, but never sooner than one interval after the
//     previous checkpoint (Lead ruling of 18 Nov, departing from the spec's
//     "always one 10 s after quiet": the quota under bursty load; the cost is
//     an unwitnessed tail after quiet of up to one interval).
//   - Failures. 401 invalid_key, 402 payment_required, 403
//     witness_plan_required, 429 quota_exceeded and 503 witness_unavailable
//     stop sending until the next 00:00 UTC (kept in otel/witness-state.json,
//     so a restart keeps it). 429 RATE_LIMITED doubles the interval, up to
//     900 s, until a receipt comes back. A network failure or a timeout, and
//     every other error, is retried at the next slot (L + interval). A 402 is
//     recorded and never answered: nothing here builds a payment.
//   - Never in the agent's way: appended() only notes the time and sets a
//     timer; the SDK's request has its answer before any witness call starts.
//   - Every outcome is one line of <chain>.witness.ndjson (the sidecar that
//     `chirindo verify --witness-file` reads), receipt or error.
//   - At start, earlier sessions of the folder whose head no receipt covers
//     are sent first (at most CATCH_UP_MAX, one at a time), so a restart
//     leaves no unwitnessed tail behind.
//   - At shutdown one last checkpoint of the head, outside the interval,
//     with SHUTDOWN_MS for everything still open; the outcome is printed.
//   - The clock, the timers and the POST are seams: the tests drive them, so
//     no test depends on how fast a machine is.

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { appendSidecarLine, buildCheckpointFromHead } from "../checkpoint.js";
import { chainEnds } from "../trial/files.js";
import {
  DEFAULT_WITNESS_KEY_ID,
  DEFAULT_WITNESS_NAME,
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
  contentOf,
  entryHashOfCanonical,
  jcsBytes,
  publicKeyFromPrivate,
  strictJsonParse,
  type LoadedFullIdentity,
  type SignedCheckpoint,
  type SignedRecord,
} from "../vendor/recorder/index.js";

export const OTEL_WITNESS_DEFAULT_URL = "https://api.headlessoracle.com";
// Headless Oracle's witness key key_2026_v1 (its /v5/keys, also pinned in
// examples/ordering-evidence/keys/witness-key.pin.json).
export const OTEL_WITNESS_PINNED_HEX = "03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178";
export const INTERVAL_KEY_S = 120;
export const INTERVAL_NO_KEY_S = 900;
export const INTERVAL_MIN_S = 40;
export const INTERVAL_MAX_S = 900;
export const IDLE_MS = 10_000;
export const SHUTDOWN_MS = 10_000;
export const RATE_LIMIT_MAX_MS = 900_000;
export const CATCH_UP_MAX = 8;
// The witness refused this caller, not this checkpoint: nothing more today.
export const STOP_CODES = ["invalid_key", "payment_required", "witness_plan_required", "quota_exceeded", "witness_unavailable"] as const;
export const RATE_LIMITED = "RATE_LIMITED";
export const WITNESS_STATE_FILE = "witness-state.json";

export function nextUtcMidnight(ms: number): number {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
}

// ---------------------------------------------------------------------------
// The command's flags
// ---------------------------------------------------------------------------

export interface OtelWitnessFlags {
  noWitness: boolean;
  witness?: string;
  witnessKey?: string;
  witnessName?: string;
  accountKeyFile?: string; // already resolved to an absolute path
  checkpointInterval?: string;
}

export interface OtelWitnessConfig {
  target?: WitnessTarget; // absent: --no-witness
  intervalMs: number;
  keyed: boolean;
  startLine: string;
}

export type OtelWitnessResolved = { ok: true; config: OtelWitnessConfig } | { ok: false; why: string };

export function resolveOtelWitness(f: OtelWitnessFlags, readFile: (path: string) => string = (p) => readFileSync(p, "utf8")): OtelWitnessResolved {
  const no = (why: string): OtelWitnessResolved => ({ ok: false, why });
  if (f.noWitness) {
    const other = [f.witness !== undefined && "--witness", f.witnessKey !== undefined && "--witness-key", f.witnessName !== undefined && "--witness-name", f.accountKeyFile !== undefined && "--account-key-file", f.checkpointInterval !== undefined && "--checkpoint-interval"].filter(Boolean);
    if (other.length > 0) return no(`--no-witness cannot be given with ${other.join(", ")}`);
    return {
      ok: true,
      config: { intervalMs: INTERVAL_NO_KEY_S * 1000, keyed: false, startLine: "[chirindo] otel-receiver: witness off (--no-witness): no checkpoint leaves this machine; these records are not witness-protected" },
    };
  }
  let baseUrl = OTEL_WITNESS_DEFAULT_URL;
  let keyHex = OTEL_WITNESS_PINNED_HEX;
  let keyId = DEFAULT_WITNESS_KEY_ID;
  if (f.witness === undefined) {
    if (f.witnessKey !== undefined || f.witnessName !== undefined) return no("--witness-key and --witness-name need --witness <url> (without it the witness is Headless Oracle's, its key pinned)");
  } else {
    try {
      baseUrl = checkWitnessBaseUrl(f.witness);
    } catch (e) {
      return no((e as Error).message);
    }
    if (f.witnessKey === undefined) return no("--witness needs --witness-key <hex|jwk-file>: the witness key is always pinned");
    try {
      const parsed = parseWitnessKeyArg(f.witnessKey);
      keyHex = parsed.raw.toString("hex");
      keyId = parsed.jwkKid ?? DEFAULT_WITNESS_KEY_ID;
    } catch (e) {
      return no((e as Error).message);
    }
  }
  const name = f.witnessName ?? DEFAULT_WITNESS_NAME;
  if (name === "") return no("--witness-name takes a name");
  let accountKey: string | undefined;
  if (f.accountKeyFile !== undefined) {
    const path = f.accountKeyFile;
    if (/ho_live_[0-9a-f]{16}/.test(path)) return no("--account-key-file takes the path of a file holding the key, not the key itself");
    let text: string;
    try {
      text = readFile(path);
    } catch (e) {
      return no(`cannot read --account-key-file ${path} (${(e as NodeJS.ErrnoException).code ?? "unreadable"})`);
    }
    const key = text.trim();
    if (!isWitnessAccountKey(key)) return no(`--account-key-file ${path} does not hold ho_live_ followed by 64 lowercase hex characters`);
    accountKey = key;
  }
  let intervalS = accountKey !== undefined ? INTERVAL_KEY_S : INTERVAL_NO_KEY_S;
  if (f.checkpointInterval !== undefined) {
    if (accountKey === undefined) return no(`--checkpoint-interval needs --account-key-file: without an account key the interval is ${INTERVAL_NO_KEY_S} s`);
    if (!/^[1-9][0-9]{0,3}$/.test(f.checkpointInterval) || Number(f.checkpointInterval) < INTERVAL_MIN_S || Number(f.checkpointInterval) > INTERVAL_MAX_S) {
      return no(`--checkpoint-interval must be a whole number of seconds from ${INTERVAL_MIN_S} to ${INTERVAL_MAX_S}`);
    }
    intervalS = Number(f.checkpointInterval);
  }
  const pubObj = witnessPubFromRaw(Buffer.from(keyHex, "hex"));
  const target: WitnessTarget = { baseUrl, name, pinned: { pubObj, hex: keyHex, id: keyId }, ...(accountKey !== undefined ? { accountKey } : {}) };
  const startLine =
    `[chirindo] otel-receiver: witness on: ${baseUrl} (key ${keyHex.slice(0, 16)}... pinned) gets a checkpoint of the chain head` +
    ` at most every ${intervalS} s while records arrive, and ${IDLE_MS / 1000} s after they stop but never sooner than ${intervalS} s after the last one, and one at shutdown.` +
    ` What leaves this machine: the chain head hash, the record count, a timestamp and the session id, with this receiver's key id, public key and signature` +
    (accountKey !== undefined ? ", and the account key as the authorization header" : "") +
    `; never a record's content. --no-witness turns this off.`;
  return { ok: true, config: { target, intervalMs: intervalS * 1000, keyed: accountKey !== undefined, startLine } };
}

// ---------------------------------------------------------------------------
// The checkpointer
// ---------------------------------------------------------------------------

export interface OtelTimers {
  set(fn: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

export const realTimers: OtelTimers = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (h) => clearTimeout(h as NodeJS.Timeout),
};

export interface OtelCheckpointerOptions {
  dir: string; // the data directory; the state file is <dir>/otel/witness-state.json
  chainsDir: string;
  chainPath: string;
  sessionId: string;
  identity: LoadedFullIdentity;
  head: () => { count: number; lastEntryHash: string };
  target: WitnessTarget;
  intervalMs: number;
  idleMs?: number;
  shutdownMs?: number;
  log: (line: string) => void;
  clock?: () => number;
  timers?: OtelTimers;
  post?: (cp: SignedCheckpoint, stop: AbortSignal) => Promise<WitnessOutcome>;
}

export interface OtelCheckpointerStatus {
  baseUrl: string;
  intervalMs: number;
  baseIntervalMs: number;
  stoppedUntil: number | null;
  stopReason: string | null;
  lastSentAt: number | null;
  dueAt: number | null;
  witnessedCount: number;
  posts: number;
  inflight: boolean;
  catchUpQueued: number;
}

export interface OtelCheckpointer {
  start(): void;
  appended(): void;
  status(): OtelCheckpointerStatus;
  // Resolves once no witness POST is open.
  settled(): Promise<void>;
  // The last checkpoint and the wait for it, SHUTDOWN_MS in all; resolves
  // with the outcome line (also logged).
  shutdown(): Promise<string>;
}

interface CatchUp {
  sessionId: string;
  count: number;
  hash: string;
  sidecar: string;
}

export function witnessStatePath(dir: string): string {
  return join(dir, "otel", WITNESS_STATE_FILE);
}

export function createOtelCheckpointer(o: OtelCheckpointerOptions): OtelCheckpointer {
  const clock = o.clock ?? Date.now;
  const timers = o.timers ?? realTimers;
  const idle = o.idleMs ?? IDLE_MS;
  const shutdownMs = o.shutdownMs ?? SHUTDOWN_MS;
  const sidecar = sidecarPathFor(o.chainPath);
  const statePath = witnessStatePath(o.dir);
  const stop = new AbortController();
  const gatePub = publicKeyFromPrivate(o.identity.privateKey);
  const post = o.post ?? ((cp: SignedCheckpoint, signal: AbortSignal) => witnessCheckpoint(cp, gatePub, o.target, WITNESS_POST_TIMEOUT_MS, signal));
  const log = (line: string) => {
    try {
      o.log(line);
    } catch {
      /* the caller's logger failed */
    }
  };
  const said = new Set<string>();
  const once = (key: string, line: string) => {
    if (!said.has(key)) {
      said.add(key);
      log(line);
    }
  };

  let interval = o.intervalMs;
  let lastSent: number | null = null; // L
  let dirtySince: number | null = null; // P
  let lastAppend: number | null = null; // A
  let witnessed = { count: 0, hash: "" };
  let stoppedUntil = 0;
  let stopReason: string | null = null;
  let timer: unknown;
  let timerAt: number | null = null;
  let inflight: Promise<void> | null = null;
  let ending = false;
  let posts = 0;
  let upgradeHinted = false;
  const catchUp: CatchUp[] = [];
  let shut: Promise<string> | null = null;

  const stopped = (now: number) => now < stoppedUntil;
  const unwitnessed = () => {
    const h = o.head();
    return h.count > 0 && !(h.count === witnessed.count && h.lastEntryHash === witnessed.hash);
  };
  const dueAt = (): number | null => {
    if (ending) return null;
    const now = clock();
    if (stopped(now)) return unwitnessed() ? stoppedUntil : null;
    if (catchUp.length > 0) return now;
    if (!unwitnessed() || dirtySince === null || lastAppend === null) return null;
    const quiet = Math.min(lastAppend + idle, dirtySince + interval);
    return lastSent === null ? quiet : Math.max(lastSent + interval, quiet);
  };
  const clearTimer = () => {
    if (timer !== undefined) timers.clear(timer);
    timer = undefined;
    timerAt = null;
  };
  const schedule = () => {
    if (inflight !== null || ending) return;
    const d = dueAt();
    if (d === null) return clearTimer();
    if (timer !== undefined && timerAt === d) return;
    clearTimer();
    timerAt = d;
    timer = timers.set(() => {
      timer = undefined;
      timerAt = null;
      pump();
    }, Math.max(0, d - clock()));
  };

  const writeState = () => {
    try {
      mkdirSync(dirname(statePath), { recursive: true, mode: 0o700 });
      const tmp = `${statePath}.part`;
      writeFileSync(tmp, JSON.stringify({ stopped_until: new Date(stoppedUntil).toISOString(), reason: stopReason, at: new Date(clock()).toISOString() }) + "\n", { encoding: "utf8", mode: 0o600 });
      renameSync(tmp, statePath);
    } catch (e) {
      log(`[chirindo] otel-receiver: witness stop not saved to ${statePath} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}); a restart before 00:00 UTC would send again`);
    }
  };

  const record = (path: string, cp: SignedCheckpoint, outcome: WitnessOutcome) => {
    try {
      appendSidecarLine(path, { checkpoint: cp, witness_receipt: outcome.receipt, witness_error: outcome.error });
    } catch (e) {
      log(`[chirindo] otel-receiver: witness outcome not written to ${path} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`);
    }
  };

  // What an error does to the pacing. Returns true for a stop.
  const onError = (error: string, outcome: WitnessOutcome, own: boolean): boolean => {
    if ((STOP_CODES as readonly string[]).includes(error)) {
      stoppedUntil = nextUtcMidnight(clock());
      stopReason = error;
      catchUp.length = 0;
      writeState();
      log(`[chirindo] otel-receiver: witness refused with ${error}: no checkpoint is sent until ${new Date(stoppedUntil).toISOString()} (00:00 UTC); records go on, unwitnessed meanwhile (recorded in ${own ? sidecar : "the session's sidecar"})`);
      if ("upgrade" in outcome && outcome.upgrade !== undefined && !upgradeHinted) {
        upgradeHinted = true;
        log(upgradeHintLine(error, outcome.upgrade));
      }
      return true;
    }
    if (error === RATE_LIMITED) {
      interval = Math.min(interval * 2, Math.max(o.intervalMs, RATE_LIMIT_MAX_MS));
      log(`[chirindo] otel-receiver: witness rate limited (429 RATE_LIMITED): checkpoint interval now ${interval / 1000} s until a receipt comes back`);
      return false;
    }
    once(`err:${error}`, `[chirindo] otel-receiver: witness failed (${error}); tried again at the next slot (${interval / 1000} s); records go on, unwitnessed meanwhile (recorded in the sidecar)`);
    return false;
  };

  const sendCatchUp = (c: CatchUp, now: number) => {
    let cp: SignedCheckpoint;
    try {
      cp = buildCheckpointFromHead({ sessionId: c.sessionId, count: c.count, lastEntryHash: c.hash }, o.identity, new Date(now).toISOString());
    } catch (e) {
      log(`[chirindo] otel-receiver: catch-up checkpoint for session ${c.sessionId} not built: ${(e as Error).message}`);
      return schedule();
    }
    posts += 1;
    inflight = post(cp, stop.signal)
      .catch((): WitnessOutcome => ({ receipt: null, error: "witness_unreachable" }))
      .then((outcome) => {
        record(c.sidecar, cp, outcome);
        if (outcome.error === null) log(`[chirindo] otel-receiver: earlier session ${c.sessionId} witnessed through count ${c.count} (catch-up)`);
        else if (!onError(outcome.error, outcome, false)) catchUp.length = 0; // the rest at the next start
      })
      .catch(() => undefined)
      .finally(() => {
        inflight = null;
        schedule();
      });
  };

  const sendOwn = (now: number) => {
    let cp: SignedCheckpoint;
    const h = o.head();
    try {
      cp = buildCheckpointFromHead({ sessionId: o.sessionId, count: h.count, lastEntryHash: h.lastEntryHash }, o.identity, new Date(now).toISOString());
    } catch (e) {
      log(`[chirindo] otel-receiver: checkpoint not built: ${(e as Error).message}`);
      return;
    }
    lastSent = now;
    dirtySince = null;
    posts += 1;
    const p = post(cp, stop.signal)
      .catch((): WitnessOutcome => ({ receipt: null, error: "witness_unreachable" }))
      .then((outcome) => {
        record(sidecar, cp, outcome);
        if (outcome.error === null) {
          if (cp.count >= witnessed.count) witnessed = { count: cp.count, hash: cp.last_entry_hash };
          interval = o.intervalMs;
          once("first-ok", `[chirindo] otel-receiver: first checkpoint witnessed (count ${cp.count})`);
        } else {
          // Not witnessed: unwitnessed since this send at least.
          dirtySince = dirtySince === null ? lastSent : Math.min(dirtySince, lastSent ?? dirtySince);
          onError(outcome.error, outcome, true);
        }
        return outcome;
      });
    inflight = p
      .then(() => undefined)
      .catch(() => undefined)
      .finally(() => {
        inflight = null;
        schedule();
      });
    return p;
  };

  const pump = () => {
    if (inflight !== null || ending) return;
    const now = clock();
    const d = dueAt();
    if (d === null) return;
    if (d > now) return schedule();
    if (catchUp.length > 0) return sendCatchUp(catchUp.shift()!, now);
    void sendOwn(now);
  };

  const loadState = () => {
    if (!existsSync(statePath)) return;
    try {
      const s = strictJsonParse(readFileSync(statePath, "utf8").trim()) as { stopped_until?: unknown; reason?: unknown };
      const until = typeof s.stopped_until === "string" ? Date.parse(s.stopped_until) : Number.NaN;
      if (Number.isFinite(until) && until > clock()) {
        stoppedUntil = until;
        stopReason = typeof s.reason === "string" && /^[A-Za-z0-9_]{1,64}$/.test(s.reason) ? s.reason : "unknown";
        log(`[chirindo] otel-receiver: witness stopped until ${new Date(until).toISOString()} (${stopReason}, saved in ${statePath}); no checkpoint is sent before then`);
      }
    } catch {
      log(`[chirindo] otel-receiver: ${statePath} is unreadable; ignored`);
    }
  };

  const findCatchUp = () => {
    let names: string[];
    try {
      names = readdirSync(o.chainsDir).filter((n) => /^[0-9a-f]{32}\.jsonl$/.test(n) && n !== `${o.sessionId}.jsonl`).sort();
    } catch {
      return;
    }
    for (const n of names) {
      if (catchUp.length >= CATCH_UP_MAX) {
        log(`[chirindo] otel-receiver: more than ${CATCH_UP_MAX} earlier sessions to catch up; the rest at the next start`);
        break;
      }
      const sid = n.slice(0, -".jsonl".length);
      const path = join(o.chainsDir, n);
      try {
        const ends = chainEnds(path);
        if (ends === null) continue;
        const first = strictJsonParse(ends.first) as SignedRecord;
        const last = strictJsonParse(ends.last) as SignedRecord;
        if (first.kid !== o.identity.kid || last.kid !== o.identity.kid || first.seq !== 0 || first.session_id !== sid || last.session_id !== sid) continue;
        if (!Number.isSafeInteger(last.seq) || last.seq < 0) continue;
        const count = last.seq + 1;
        const side = sidecarPathFor(path);
        let covered = false;
        if (existsSync(side)) {
          try {
            covered = readSidecar(side).some((l) => l.witness_receipt !== null && l.witness_receipt["session_id"] === sid && Number(l.witness_receipt["count"]) >= count);
          } catch {
            log(`[chirindo] otel-receiver: catch-up skipped session ${sid}: its witness sidecar is malformed`);
            continue;
          }
        }
        if (!covered) catchUp.push({ sessionId: sid, count, hash: entryHashOfCanonical(jcsBytes(contentOf(last))), sidecar: side });
      } catch {
        /* unreadable or not a chain: not caught up */
      }
    }
    if (catchUp.length > 0) log(`[chirindo] otel-receiver: ${catchUp.length} earlier session(s) with an unwitnessed head; sent first, one at a time`);
  };

  return {
    start: () => {
      loadState();
      if (!stopped(clock())) findCatchUp();
      schedule();
    },
    appended: () => {
      const now = clock();
      lastAppend = now;
      if (dirtySince === null) dirtySince = now;
      schedule();
    },
    status: () => ({
      baseUrl: o.target.baseUrl,
      intervalMs: interval,
      baseIntervalMs: o.intervalMs,
      stoppedUntil: stoppedUntil > clock() ? stoppedUntil : null,
      stopReason: stoppedUntil > clock() ? stopReason : null,
      lastSentAt: lastSent,
      dueAt: dueAt(),
      witnessedCount: witnessed.count,
      posts,
      inflight: inflight !== null,
      catchUpQueued: catchUp.length,
    }),
    settled: async () => {
      while (inflight !== null) await inflight;
    },
    shutdown: () => (shut ??= shutdownOnce()),
  };

  async function shutdownOnce(): Promise<string> {
    {
      ending = true;
      clearTimer();
      let timedOut = false;
      const deadline = timers.set(() => {
        timedOut = true;
        stop.abort();
      }, shutdownMs);
      let line: string;
      try {
        while (inflight !== null) await inflight;
        if (o.head().count === 0) line = "nothing recorded, nothing sent";
        else if (!unwitnessed()) line = `head already witnessed (count ${witnessed.count}), nothing sent`;
        else if (stopped(clock())) line = `not sent: the witness is stopped until ${new Date(stoppedUntil).toISOString()} (${stopReason}); count ${o.head().count} is not witnessed, ${o.head().count - witnessed.count} record(s) not witness-protected`;
        else if (timedOut) line = `not sent: ${shutdownMs / 1000} s used up by an earlier checkpoint; count ${o.head().count} is not witnessed, ${o.head().count - witnessed.count} record(s) not witness-protected`;
        else {
          const outcome = await sendOwn(clock());
          if (inflight !== null) await inflight;
          if (outcome === undefined) line = "not sent: the checkpoint could not be built";
          else if (outcome.error === null) line = `count ${outcome.receipt["count"]} witnessed, received_at ${outcome.receipt["received_at"]}; 0 records not witness-protected`;
          else line = `count ${o.head().count} NOT witnessed (${outcome.error}); recorded in ${sidecar}; ${o.head().count - witnessed.count} record(s) not witness-protected`;
        }
      } finally {
        timers.clear(deadline);
      }
      const out = `[chirindo] otel-receiver: witness at shutdown: ${line}`;
      log(out);
      return out;
    }
  }
}

// The checkpointer the receiver uses, or none (--no-witness).
export interface OtelWitnessOptions {
  target: WitnessTarget;
  intervalMs: number;
  idleMs?: number;
  shutdownMs?: number;
  clock?: () => number;
  timers?: OtelTimers;
  post?: (cp: SignedCheckpoint, stop: AbortSignal) => Promise<WitnessOutcome>;
}
