// The offline verifier: the checks of spec 4.2, the bindings of 4.3, the
// gating of 4.4, the times and orderings of 4.5, the verdict of 4.6 and the
// output of 4.7, with the limits of section 8.
//
// verifyBundle(bytes, stated, pins) returns { kind: "verdict", output } or,
// for a bundle outside the shape this build judges, { kind: "refused", code,
// checks } (checks: those that ran before the refusal; never written out).
// It throws only on an internal error.

import { createHash } from "node:crypto";
import { isoUtc, isPlainObject, jcs, jcsSha256, parseStrictJson, quantity } from "../../ordering-evidence-h4/lib/formats.mjs";
import { parseErc8021 } from "../../ordering-evidence-h4/lib/evm.mjs";
import { declaredShape, decodedShape } from "./allowlist.mjs";
import { jcsJsonDigest, m0, m1 } from "./bundle.mjs";
import { LIMIT_TEXTS } from "./limits.mjs";
import { analyseSearch, m5, readRpcJson, signerOfMatch } from "./payment.mjs";
import {
  checkpointSigOk,
  inWindow,
  m2ChirindoLog,
  m3Shape,
  m4Shape,
  m9OperatorKey,
  operatorKeysByThumbprint,
  parseChirindoLog,
  parseSidecar,
  receiptSigOk,
  tsMs,
  witnessEntryShape,
  witnessKeyEntries,
} from "./records.mjs";
import { ALLOW_TRIPLE, BINDING_IDS, OUTPUT_TYPE, REFUSE_VALUES, THUMBPRINT_RE, VERDICT_TEXT } from "./table.mjs";
import { eip3009Readable } from "./tx.mjs";

export const VERIFIER = { name: "chirindo examples/evidence-bundle", version: "0.9.0", commit: "unrecorded" };

const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const isStr = (v) => typeof v === "string";
const tryParse = (bytes) => {
  try {
    return { value: parseStrictJson(bytes) };
  } catch (e) {
    return { error: e.message };
  }
};

// Reads, for M1's count rules, what the members' contents show. A member that
// cannot be read is skipped here and left to its own check.
function peekFactory(doc) {
  return (decoded) => {
    const of = (role) => doc.members.filter((m) => m.role === role && decoded.has(m.id));
    const lines = (bytes) => {
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes).split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length);
      } catch {
        return [];
      }
    };
    const objs = (bytes) =>
      lines(bytes)
        .map((l) => tryParse(Buffer.from(l, "utf8")).value)
        .filter(isPlainObject);
    return {
      logKids: () => {
        const s = new Set();
        for (const m of of("gate-log")) for (const o of objs(decoded.get(m.id))) if (o.type !== "checkpoint" && isStr(o.kid)) s.add(o.kid);
        return s;
      },
      receiptKeyIds: () => {
        const s = new Set();
        for (const m of of("witness-sidecar")) for (const o of objs(decoded.get(m.id))) if (isPlainObject(o.witness_receipt) && isStr(o.witness_receipt.public_key_id)) s.add(o.witness_receipt.public_key_id);
        for (const m of of("witness-receipt")) {
          const v = tryParse(decoded.get(m.id)).value;
          if (isPlainObject(v) && isStr(v.public_key_id)) s.add(v.public_key_id);
        }
        return s;
      },
      jcsDigest: (id) => {
        try {
          return jcsJsonDigest(decoded.get(id)).digest;
        } catch {
          return null;
        }
      },
      proofKey: (id) => {
        const v = tryParse(decoded.get(id)).value;
        return isPlainObject(v) && isPlainObject(v.result) && isStr(v.result.address) && isStr(v.block_hash) ? `${v.result.address.toLowerCase()}|${v.block_hash}` : null;
      },
    };
  };
}

function decisionOf(rec) {
  // Spec 4.3, "The cited decision": the three members, read as strings.
  const ev = isPlainObject(rec.event) ? rec.event : {};
  const g = isPlainObject(rec["gate"]) ? rec["gate"] : {};
  const vals = [ev.decision, ev.outcome, g.result].map((x) => (isStr(x) ? x : null));
  if (vals.some((x) => x !== null && REFUSE_VALUES.includes(x))) return { vals, value: "refuse" };
  if (vals.every((x, i) => x === ALLOW_TRIPLE[i])) return { vals, value: "allow" };
  return { vals, value: "not-read" };
}

export async function verifyBundle(bytes, stated, pins) {
  const checks = [];
  const flags = [];
  const add = (id, member, status, reason, detail) => checks.push({ id, member, status, reason, detail: detail ?? "" });
  const flag = (code, detail) => flags.push({ code, detail });
  const base = { bundle_sha256: "sha256:" + sha256Hex(bytes), stated: { authorizer: stated.authorizer ?? null, tx: stated.tx ?? null } };

  // (a1) S1.authorizer, S2.tx, M0, M1.
  const r0 = m0(bytes);
  const doc = r0.doc ?? null;
  const card = doc?.subject.kind === "card-payment";
  if (!card) {
    if (stated.authorizer) add("S1.authorizer", null, "PASS", null, `the account stated: ${stated.authorizer}`);
    else add("S1.authorizer", null, "NOT-EVALUATED", "authorizer-not-stated", "no account was stated");
    if (!stated.tx) add("S2.tx", null, "NOT-EVALUATED", "tx-not-stated", "no transaction was stated");
    else if (!doc) add("S2.tx", null, "NOT-EVALUATED", "prerequisite-failed:M0.bundle", "the bundle's subject could not be read");
    else if (stated.tx === doc.subject.tx_hash) add("S2.tx", null, "PASS", null, "the stated transaction is subject.tx_hash");
    else add("S2.tx", null, "FAIL", null, "the stated transaction is not subject.tx_hash");
  }
  if (!doc) {
    add("M0.bundle", null, "FAIL", null, r0.fail);
    return finish({ base, checks, flags, doc: null, failAt: "M0.bundle" });
  }
  add("M0.bundle", null, "PASS", null, "strict JSON; type, members and subject as section 3 defines them");
  const { rows: m1rows, decoded } = m1(doc, peekFactory(doc));
  checks.push(...m1rows.map((r) => ({ ...r, detail: r.detail ?? "" })));
  const firstFail = () => checks.find((c) => c.status === "FAIL")?.id ?? null;
  if (firstFail()) return finish({ base, checks, flags, doc, failAt: firstFail() });

  // (b1) the declared roles and profiles.
  const refused1 = declaredShape(doc.members);
  if (refused1) return { kind: "refused", code: refused1, checks };

  // (a2) M2 to M9.
  const members = doc.members;
  const byRole = (role) => members.filter((m) => m.role === role);
  const opMembers = byRole("operator-key").map((m) => ({ member: m.id, profile: m.profile, ...tryParse(decoded.get(m.id)) }));
  const opKeys = operatorKeysByThumbprint(opMembers.filter((o) => !o.error));
  const logs = byRole("gate-log").map((m) => {
    try {
      const { records, checkpoint } = parseChirindoLog(decoded.get(m.id));
      return { member: m.id, profile: m.profile, records, checkpoint, error: null };
    } catch (e) {
      return { member: m.id, profile: m.profile, records: [], checkpoint: null, error: e.message };
    }
  });
  for (const log of logs) {
    if (log.error) {
      log.m2 = { status: "FAIL", reason: null, detail: `the log does not read: ${log.error}`, flags: [], entryHashes: [] };
    } else log.m2 = m2ChirindoLog(log, opKeys);
    flags.push(...log.m2.flags);
    add("M2.log", log.member, log.m2.status, log.m2.reason, log.m2.detail);
  }
  const logKey = (l) => `${l.records[0]?.kid}\u0000${l.records[0]?.session_id}`;
  for (let i = 0; i < logs.length; i++)
    for (let j = i + 1; j < logs.length; j++) {
      const [a, b] = [logs[i], logs[j]];
      if (a.error || b.error || a.records.length === 0 || b.records.length === 0 || logKey(a) !== logKey(b)) continue;
      const [short, long] = a.records.length <= b.records.length ? [a, b] : [b, a];
      const same = short.records.every((r, k) => jcs(r) === jcs(long.records[k]));
      add("M2.prefix", short.member, same ? "PASS" : "FAIL", null, same ? `its records are the first records of ${long.member}` : `its records differ from the first records of ${long.member}: the bundle shows a fork`);
    }

  // Checkpoints: in-file ones, and each sidecar line's.
  const checkpoints = [];
  const receipts = [];
  for (const log of logs) if (log.checkpoint) checkpoints.push({ member: log.member, cp: log.checkpoint, where: `${log.member} (in-file checkpoint)` });
  const sidecarErrors = [];
  for (const m of byRole("witness-sidecar")) {
    let lines;
    try {
      lines = parseSidecar(decoded.get(m.id));
    } catch (e) {
      sidecarErrors.push({ member: m.id, error: e.message });
      continue;
    }
    for (const ln of lines) {
      checkpoints.push({ member: m.id, cp: ln.checkpoint, where: `${m.id} line ${ln.line}` });
      if (ln.receipt) receipts.push({ member: m.id, r: ln.receipt, where: `${m.id} line ${ln.line}` });
      else if (ln.error !== null) flag("unwitnessed-attempt", `${m.id} line ${ln.line}: no witness receipt; witness_error is set`);
    }
  }
  for (const e of sidecarErrors) add("M3.checkpoint", e.member, "FAIL", null, `the sidecar does not read: ${e.error}`);
  const logFor = (kid, sid) => logs.find((l) => !l.error && l.records[0]?.kid === kid && l.records[0]?.session_id === sid);
  for (const c of checkpoints) {
    const shape = m3Shape(c.cp);
    c.shapeOk = !shape;
    add("M3.checkpoint", c.member, shape ? "FAIL" : "PASS", null, shape ? `${c.where}: ${shape}` : `${c.where}: the eight members and their field rules`);
    if (shape) {
      add("M3.signature", c.member, "NOT-EVALUATED", "prerequisite-failed:M3.checkpoint", c.where);
      add("M3.history", c.member, "NOT-EVALUATED", "prerequisite-failed:M3.checkpoint", c.where);
      c.ok = false;
      continue;
    }
    const pub = opKeys.get(c.cp.kid);
    if (!pub) {
      flag("unattached-member", `${c.where}: no operator key for its kid is carried`);
      add("M3.signature", c.member, "NOT-EVALUATED", "no-operator-key", c.where);
      c.sig = "NE";
    } else {
      c.sig = checkpointSigOk(c.cp, pub) ? "PASS" : "FAIL";
      add("M3.signature", c.member, c.sig, null, `${c.where}: sig ${c.sig === "PASS" ? "verifies" : "does not verify"} under the operator key for its kid`);
    }
    const log = logs.find((l) => l.records[0]?.kid === c.cp.kid && l.records[0]?.session_id === c.cp.session_id);
    if (!log) {
      add("M3.history", c.member, "NOT-EVALUATED", "log-not-carried", `${c.where}: no carried log has its kid and session_id`);
      c.hist = "NE";
    } else if (log.m2.status !== "PASS" && log.m2.status !== "NOT-EVALUATED") {
      add("M3.history", c.member, "NOT-EVALUATED", "prerequisite-failed:M2.log", c.where);
      c.hist = "NE";
    } else if (c.cp.count <= log.records.length) {
      c.hist = log.m2.entryHashes[c.cp.count - 1] === c.cp.last_entry_hash ? "PASS" : "FAIL";
      add("M3.history", c.member, c.hist, null, `${c.where}: last_entry_hash ${c.hist === "PASS" ? "is" : "is not"} the entry hash of record ${c.cp.count - 1} of ${log.member}`);
    } else {
      c.hist = "PASS";
      c.truncates = true;
      add("M3.history", c.member, "PASS", null, `${c.where}: count ${c.cp.count} is above the ${log.records.length} records of ${log.member}`);
    }
    c.ok = c.sig === "PASS" && c.hist === "PASS";
  }

  // M4, each sidecar line's receipt.
  const pinnedKey = (id) => pins.witness_keys.keys.find((k) => k.key_id === id) ?? null;
  const carriedWitnessKeys = [];
  for (const m of byRole("witness-key")) {
    const v = tryParse(decoded.get(m.id));
    let entries = null;
    try {
      entries = v.error ? null : witnessKeyEntries(v.value);
    } catch {
      entries = null;
    }
    carriedWitnessKeys.push({ member: m.id, error: v.error ?? (entries ? null : "the member has no readable keys list"), entries });
  }
  for (const x of receipts) {
    const shape = m4Shape(x.r);
    if (shape) {
      x.status = "FAIL";
      add("M4.witness-receipt", x.member, "FAIL", null, `${x.where}: ${shape}`);
      continue;
    }
    let k = pinnedKey(x.r.public_key_id);
    if (!k) {
      for (const w of carriedWitnessKeys) {
        const e = w.entries?.get(x.r.public_key_id);
        if (e && !witnessEntryShape(e)) {
          k = e;
          flag("witness-key-not-pinned", `${x.where}: key id ${x.r.public_key_id} is not in the verifier's key history; the carried ${w.member} gives its key`);
          break;
        }
      }
    }
    if (!k) {
      x.status = "NOT-EVALUATED";
      add("M4.witness-receipt", x.member, "NOT-EVALUATED", "witness-key-unknown", `${x.where}: no key for ${x.r.public_key_id} is pinned or carried`);
      continue;
    }
    const ok = receiptSigOk(x.r, k.public_key) && inWindow(x.r.received_at, k);
    x.status = ok ? "PASS" : "FAIL";
    add("M4.witness-receipt", x.member, x.status, null, ok ? `${x.where}: the signature verifies under ${x.r.public_key_id}, received_at inside its window` : `${x.where}: the signature does not verify under ${x.r.public_key_id}, or received_at is outside its window`);
  }

  // M5, an evm-payment subject's payment.
  const subject = doc.subject;
  let pay = null;
  if (!card) {
    const one = (role) => byRole(role)[0];
    const p = { txId: one("payment-transaction")?.id, rcId: one("payment-receipt")?.id, blkId: one("payment-block")?.id, parseErrors: {} };
    for (const [k, id] of [["tx", p.txId], ["rc", p.rcId], ["blk", p.blkId]]) {
      if (!id) continue;
      try {
        p[k] = readRpcJson(decoded.get(id));
      } catch (e) {
        p[k] = {};
        p.parseErrors[k] = `the member does not read as strict JSON: ${e.message}`;
      }
    }
    pay = await m5(p, subject, pins);
    pay.tx = p.tx;
    pay.to = p.tx?.to ?? null;
    checks.push(...pay.rows);
  }

  // M8.arguments.
  const argsHashes = new Set(logs.flatMap((l) => l.records.map((r) => (isPlainObject(r.event) ? r.event.args_hash : undefined))).filter(isStr));
  const argMembers = [];
  for (const m of byRole("action-arguments")) {
    let d;
    try {
      d = jcsJsonDigest(decoded.get(m.id));
    } catch (e) {
      add("M8.arguments", m.id, "FAIL", null, `the member does not read as jcs-json: ${e.message}`);
      continue;
    }
    argMembers.push({ member: m.id, ...d });
    const v = d.value;
    if (isPlainObject(v) && Object.keys(v).includes("instruction_sha256") && !(isStr(v.instruction_sha256) && /^sha256:[0-9a-f]{64}$/.test(v.instruction_sha256))) {
      add("M8.arguments", m.id, "FAIL", null, "instruction_sha256 is not sha256: and 64 lowercase hex digits");
    } else if (argsHashes.has(d.digest)) add("M8.arguments", m.id, "PASS", null, `its JCS SHA-256 ${d.digest} is the args_hash of a carried record`);
    else add("M8.arguments", m.id, "FAIL", null, `its JCS SHA-256 ${d.digest} is the args_hash of no carried record`);
  }

  // M9.
  const logKids = new Set(logs.map((l) => l.records[0]?.kid).filter((k) => isStr(k) && THUMBPRINT_RE.test(k)));
  for (const o of opMembers) {
    const problem = o.error ? `the member does not read as strict JSON: ${o.error}` : m9OperatorKey(o.profile, o.value, logKids);
    add("M9.operator-key", o.member, problem ? "FAIL" : "PASS", null, problem ?? `${o.profile}: a well-formed Ed25519 key, kid equal to its thumbprint where present`);
  }
  const receiptIds = [...new Set(receipts.map((x) => x.r.public_key_id).filter(isStr))];
  for (const w of carriedWitnessKeys) {
    if (w.error) {
      add("M9.witness-key", w.member, "FAIL", null, w.error);
      continue;
    }
    let status = "PASS";
    let reason = null;
    let detail = "";
    for (const id of receiptIds) {
      const e = w.entries.get(id);
      if (!e) {
        // A receipt's key id that the carried member lacks: not evaluated, never PASS or FAIL.
        status = status === "FAIL" ? "FAIL" : "NOT-EVALUATED";
        reason = status === "FAIL" ? null : "witness-key-unknown";
        detail = `the member has no entry for key id ${id}`;
        continue;
      }
      const shape = witnessEntryShape(e);
      const pin = pinnedKey(id);
      if (shape) [status, reason, detail] = ["FAIL", null, `${id}: ${shape}`];
      else if (pin && jcs(e) !== jcs(pin)) [status, reason, detail] = ["FAIL", null, `${id}: the entry differs from the verifier's pinned key history`];
      else if (status === "PASS") detail = `${id}: ${pin ? "every member equals the pinned entry" : "a well-formed Ed25519 entry"}`;
    }
    for (const k of pins.witness_keys.keys) if (!w.entries.has(k.key_id)) flag("carried-key-lacks-id", `${w.member} has no entry for ${k.key_id}, which the verifier's history holds`);
    add("M9.witness-key", w.member, status, reason, detail);
  }

  const cited = logs.find((l) => l.member === subject.cites.log);
  const citedRec = cited?.records[subject.cites.seq] ?? null;
  const H = citedRec && cited.m2.entryHashes[subject.cites.seq] ? cited.m2.entryHashes[subject.cites.seq].slice("sha256:".length) : null;
  const search = !card && pay?.supported && pay.tx && pay.rows.find((r) => r.id === "M5.transaction")?.status === "PASS" ? analyseSearch(pay.tx, pay.type, pay.call, H) : null;

  const ctx = { base, checks, flags, doc, logs, cited, citedRec, H, pay, search, receipts, checkpoints, card, stated, pins, argMembers };
  if (firstFail()) return finish({ ...ctx, failAt: firstFail() });

  // (b2) the decoded shape.
  const refused2 = decodedShape({ doc, logs, checkpoints, receipts, pay: pay ?? {}, search });
  if (refused2) return { kind: "refused", code: refused2, checks };

  return finish(ctx);
}

// Bindings, decision, verdict and output. When a check FAILed (failAt), the
// bindings that need the checks are not computed: each reads NOT EVALUATED
// with the reason naming the first FAIL, and V1 gives FAILS.
function finish(ctx) {
  const { base, checks, flags, doc, failAt } = ctx;
  const flag = (code, detail) => flags.push({ code, detail });
  const subject = doc?.subject ?? null;
  const card = subject?.kind === "card-payment";
  const B = new Map();
  const bind = (id, state, reason = null, extra = {}) => B.set(id, { id, state, reason, carrier: extra.carrier ?? null, signed_by: extra.signed_by ?? null, detail: extra.detail ?? "" });
  let decision = { value: "not-read", record: null, receipt: null, refusing_records: [] };
  let payment = { connected: false, reason: null, payer: null, movements: [], as_supplied: true };
  let hashSearch = null;
  const times = [];
  const orderings = [];
  let payerDerived = false;
  let bpay = null;

  const { logs, cited, citedRec, H, pay, search, receipts = [], checkpoints = [], stated, pins } = ctx;
  const seq = subject?.cites.seq;

  // B-LOG.
  if (cited?.m2) {
    if (cited.m2.status === "PASS" && seq < cited.records.length) bind("B-LOG", "BOUND", null, { detail: `record ${seq} of ${cited.member}, whose log passes M2` });
    else if (cited.m2.status === "NOT-EVALUATED") bind("B-LOG", "NOT-EVALUATED", "legacy-kid", { detail: `${cited.member} has a legacy kid` });
    else if (cited.m2.status === "PASS") bind("B-LOG", "FAIL", null, { detail: `${cited.member} has ${cited.records.length} records; the cited record ${seq} does not exist` });
    else bind("B-LOG", "FAIL", null, { detail: `${cited.member} fails M2` });
  } else bind("B-LOG", "NOT-EVALUATED", `prerequisite-failed:${failAt}`);

  const logBound = B.get("B-LOG").state === "BOUND";
  if (failAt || !logBound) {
    const why = failAt ? `prerequisite-failed:${failAt}` : "prerequisite-failed:B-LOG";
    for (const id of BINDING_IDS.slice(1)) bind(id, "NOT-EVALUATED", why);
    payment.reason = why;
  } else {
    const kid = citedRec.kid;
    const sid = citedRec.session_id;
    const n = cited.records.length;
    const hashes = cited.m2.entryHashes;

    // B-CKP.
    const mine = checkpoints.filter((c) => c.shapeOk && c.cp.kid === kid && c.cp.session_id === sid);
    let selectedCp = null;
    let selectedRc = null;
    if (mine.some((c) => c.sig === "FAIL" || c.hist === "FAIL")) bind("B-CKP", "FAIL");
    else if (mine.some((c) => c.ok && c.cp.count > n)) bind("B-CKP", "TRUNCATED", null, { detail: "a checkpoint shows the session continued beyond the carried log" });
    else if (mine.some((c) => c.ok && c.cp.count > seq)) bind("B-CKP", "BOUND", null, { detail: "a checkpoint signed by the log key covers the cited record" });
    else bind("B-CKP", "ABSENT");

    // B-WIT (offline: rules 1, 2, 4, 5 and 7).
    const forLog = receipts.filter((x) => x.r && x.r.kid === kid && x.r.session_id === sid);
    const verified = forLog.filter((x) => x.status === "PASS");
    const wouldCover = (x) => Number(x.r.count) > seq && Number(x.r.count) <= n && x.r.last_entry_hash === hashes[Number(x.r.count) - 1];
    const byCount = new Map();
    let witFail = receipts.some((x) => x.status === "FAIL");
    for (const x of verified) {
      const c = Number(x.r.count);
      if (c <= n && x.r.last_entry_hash !== hashes[c - 1]) witFail = true;
      if (byCount.has(c) && byCount.get(c) !== x.r.last_entry_hash) witFail = true;
      byCount.set(c, x.r.last_entry_hash);
    }
    const covering = verified.filter(wouldCover);
    if (witFail) bind("B-WIT", "FAIL");
    else if (verified.some((x) => Number(x.r.count) > n)) bind("B-WIT", "TRUNCATED", null, { detail: "a witness receipt shows a longer history than the carried log" });
    else if (covering.length) bind("B-WIT", "SUPPLIED", null, { detail: "a covering receipt is carried; offline, the witness's list is not read" });
    else if (forLog.some((x) => x.status === "NOT-EVALUATED" && wouldCover(x))) bind("B-WIT", "NOT-EVALUATED", "witness-key-unknown", { detail: "a carried receipt that would cover the cited record is under a key id the verifier cannot resolve" });
    else bind("B-WIT", "ABSENT");
    if (covering.length) {
      selectedRc = [...covering].sort((a, b) => Date.parse(a.r.received_at) - Date.parse(b.r.received_at) || Number(a.r.count) - Number(b.r.count) || (a.r.checkpoint_sha256 < b.r.checkpoint_sha256 ? -1 : 1))[0];
      if (!checkpoints.some((c) => c.shapeOk && jcsSha256(c.cp) === selectedRc.r.checkpoint_sha256)) flag("uncarried-checkpoint", `the selected receipt's checkpoint_sha256 matches no carried checkpoint`);
    }
    const coveringCps = mine.filter((c) => c.ok && c.cp.count > seq && c.cp.count <= n);
    if (coveringCps.length) {
      selectedCp = (selectedRc && coveringCps.find((c) => jcsSha256(c.cp) === selectedRc.r.checkpoint_sha256)) ?? [...coveringCps].sort((a, b) => a.cp.count - b.cp.count || (jcsSha256(a.cp) < jcsSha256(b.cp) ? -1 : 1))[0];
    }

    // B-KEY.
    const uri = Object.keys(citedRec).includes("jwks_uri") ? citedRec.jwks_uri : null;
    if (uri === null) bind("B-KEY", "KEY-ONLY", null, { detail: "the records name no jwks_uri; one key signed every record" });
    else {
      const jwks = ctx.doc.members.filter((m) => m.role === "operator-key" && m.profile === "jwks");
      if (!jwks.length) bind("B-KEY", "NOT-EVALUATED", "no-jwks-carried");
      else bind("B-KEY", "SUPPLIED", null, { detail: "the carried JWKS holds the key; offline, the jwks_uri is not read" });
    }

    // B-INS.
    const argsHash = isPlainObject(citedRec.event) ? citedRec.event.args_hash : undefined;
    const A = ctx.argMembers.find((a) => a.digest === argsHash) ?? null;
    if (!A) bind("B-INS", "NOT-EVALUATED", "args-not-carried", { detail: "the cited record's arguments are not carried, and no instruction is" });
    else {
      const D = isPlainObject(A.value) && Object.keys(A.value).includes("instruction_sha256") ? A.value.instruction_sha256 : null;
      if (D === null) bind("B-INS", "ABSENT", null, { detail: `${A.member} carries no instruction_sha256` });
      else bind("B-INS", "WITHHELD", null, { detail: `${A.member} cites ${D}, which no carried instruction has` });
    }

    // B-GRC: no gate receipt is carried in the shape this build judges.
    if (Object.keys(citedRec).includes("receipt_uid")) bind("B-GRC", "ABSENT", "receipt-missing", { detail: `the cited record names receipt ${citedRec.receipt_uid}, which the bundle does not carry` });
    else bind("B-GRC", "ABSENT", null, { detail: "no gate receipt is carried or named" });

    // B-CHAIN.
    if (card) bind("B-CHAIN", "NOT-EVALUATED", "card-subject");
    else bind("B-CHAIN", "SUPPLIED", null, { detail: "offline: the bundle's copies of the transaction, its receipt and its block" });

    // The cited decision's record source.
    const rd = decisionOf(citedRec);
    decision.record = { log: cited.member, seq, event_decision: rd.vals[0], event_outcome: rd.vals[1], gate_result: rd.vals[2], receipt_uid: Object.keys(citedRec).includes("receipt_uid") ? citedRec.receipt_uid : null };

    // B-PAY and the search.
    if (card) bind("B-PAY", "NOT-EVALUATED", "card-subject");
    else {
      bpay = bPay(ctx);
      bind("B-PAY", bpay.state, bpay.reason, bpay);
      payerDerived = bpay.payerDerived;
      if (search) hashSearch = { fields: search.fields, forms: search.forms, matches: search.matches };
      if (bpay.flagAuthorizer) flag("authorizer-not-stated", `the account that signed the bytes carrying the cited hash: ${bpay.signed_by}`);
      if (search && search.matches.some((m) => m.form === "hex-text")) flag("hash-as-ascii-hex", "the cited entry hash appears as text in the transaction's signed fields");
      if (pay.call?.trailerHex && pay.call.trailerHex !== "0x") {
        let note = "";
        try {
          const e = parseErc8021(pay.call.trailerHex);
          note = e ? `; it parses as an ERC-8021 suffix, schema ${e.schemaId}` : "";
        } catch {
          note = "";
        }
        flag("trailer", `${(pay.call.trailerHex.length - 2) / 2} bytes follow the call's ABI-encoded arguments${note}`);
      }
      // Other carried records whose entry hash the signed fields hold (rule 3),
      // and those among them that refuse in bytes the stated account signed.
      for (const l of logs) {
        if (l.m2.status === "FAIL") continue;
        l.records.forEach((r, k) => {
          if (l === cited && k === seq) return;
          const s = analyseSearch(pay.tx, pay.type, pay.call, l.m2.entryHashes[k].slice(7));
          if (!s || s.matches.length === 0) return;
          flag("other-entry-hash", `${l.member} record ${k}: its entry hash is in ${[...new Set(s.matches.map((m) => m.field))].join(", ")}`);
          const P = pay.signer;
          const signedByStated = stated.authorizer && s.binding.some((m) => signerOfMatch(m, pay.call, P, pay.sender) === stated.authorizer);
          if (signedByStated && decisionOf(r).value === "refuse") decision.refusing_records.push({ log: l.member, seq: k, source: "record" });
        });
      }
      if (payerDerived) {
        payment = { connected: true, reason: null, payer: stated.authorizer, movements: [bpay.movement], as_supplied: true };
      } else payment.reason = bpay.reason ?? "no-payer-derived";
    }
    if (card) payment.reason = "card-subject";
    const sources = [rd.value];
    decision.value = sources.includes("refuse") || decision.refusing_records.length ? "refuse" : sources.every((v) => v === "allow") ? "allow" : "not-read";

    // Times (spec 4.5), each with its clock.
    const supplied = (id) => B.get(id).state === "SUPPLIED";
    cited.records.forEach((r, k) => times.push({ what: `${cited.member} record ${k} ts`, value: r.ts, clock: "operator", as_supplied: false }));
    if (selectedCp) times.push({ what: `selected checkpoint ts (${selectedCp.where})`, value: selectedCp.cp.ts, clock: "operator", as_supplied: false });
    if (selectedRc) {
      times.push({ what: `selected witness receipt received_at (${selectedRc.where})`, value: selectedRc.r.received_at, clock: "headless-oracle", as_supplied: supplied("B-WIT") });
      times.push({ what: `selected witness receipt checkpoint_ts (${selectedRc.where})`, value: selectedRc.r.checkpoint_ts, clock: "headless-oracle", as_supplied: supplied("B-WIT") });
    }
    const blockTs = pay?.blockTs ?? null;
    if (blockTs !== null) times.push({ what: "block timestamp", value: isoUtc(blockTs), clock: "block-producer", as_supplied: supplied("B-CHAIN") });
    if (pay?.auth) {
      times.push({ what: "authorization validAfter", value: isoUtc(pay.auth.validAfter), clock: "payer", as_supplied: false });
      times.push({ what: "authorization validBefore", value: isoUtc(pay.auth.validBefore), clock: "payer", as_supplied: false });
    }

    // Orderings that need no clock (spec 4.5).
    orderings.push({ earlier: "each earlier record of the session", later: "each later record", rests_on: "the hash chain of the cited log", status: "SHOWN" });
    const shownH = bpay && bpay.carrier !== null && bpay.signed_by !== null && ["BOUND", "CARRIED-BY-OTHER", "NO-PAYMENT", "NOT-EVALUATED", "UNSUPPORTED-PATH"].includes(bpay.state);
    orderings.push({
      earlier: "the cited entry's content (all of it except sig)",
      later: bpay?.signed_by ? `the signature of ${bpay.signed_by} over the bytes that carry its hash` : "a signature over bytes that carry its hash",
      rests_on: "the cited entry hash as 32 raw bytes in the transaction's calldata (B-PAY)",
      status: shownH ? "SHOWN" : "NOT-EVALUATED",
    });
    if (selectedRc) {
      const cpMatch = checkpoints.some((c) => c.shapeOk && jcsSha256(c.cp) === selectedRc.r.checkpoint_sha256);
      orderings.push({ earlier: "the checkpoint, its sig included", later: "the witness receipt", rests_on: "the receipt's checkpoint_sha256 over the carried checkpoint", status: cpMatch ? "SHOWN" : "NOT-EVALUATED" });
      orderings.push({ earlier: "the log head", later: "the witness receipt", rests_on: "the receipt's last_entry_hash", status: "SHOWN" });
    }
    if (!card) {
      const blockOk = ["M5.block", "M5.block-hash"].every((id) => checks.find((c) => c.id === id)?.status === "PASS");
      orderings.push({ earlier: "the payment transaction", later: "its block", rests_on: "the block lists the transaction's hash and its hash recomputes from the header (as supplied: offline)", status: blockOk ? "SHOWN" : "NOT-EVALUATED" });
    }
    orderings.push({ earlier: "an instruction", later: "the cited entry", rests_on: "the entry's arguments carry the instruction's digest (B-INS BOUND or EXCEEDS)", status: "NOT-EVALUATED" });

    // Comparisons of two clocks, each reported as such (spec 4.5 and P7).
    if (shownH && blockTs !== null) {
      const t = tsMs(citedRec.ts);
      flag("two-clock-comparison", `the cited entry's ts (operator's clock) against the block timestamp (block producer's clock)`);
      if (t !== null && t > Number(blockTs) * 1000) flag("clock-contradiction", "the cited entry's ts is later than the block timestamp, while its hash sits in bytes signed for the payment");
    }
    if (selectedCp && selectedRc) {
      flag("two-clock-comparison", "the selected checkpoint's ts (operator's clock) against the witness receipt's received_at (Headless Oracle's clock)");
      if (tsMs(selectedCp.cp.ts) > tsMs(selectedRc.r.received_at)) flag("clock-contradiction", "the selected checkpoint's ts is later than its receipt's received_at");
    }
    if (selectedRc && blockTs !== null) flag("two-clock-comparison", "the witness receipt's received_at (Headless Oracle's clock) against the block timestamp (block producer's clock); this orders the checkpoint against the payment's inclusion in its block, never against its signing");
  }

  // The online checks that apply are listed as not evaluated (spec 4.2).
  if (doc) {
    const off = (id, detail) => checks.push({ id, member: null, status: "NOT-EVALUATED", reason: "offline", detail });
    if (cited && cited.records.length) off("O1.witness-list", "offline: the witness's list for the cited log's kid and session_id is not read");
    if (!card && pay) {
      off("O2.rpc", "offline: no endpoint is asked");
      off("O2.finality", "offline: no endpoint is asked");
    }
    if (cited && cited.records.some((r) => Object.keys(r).includes("jwks_uri"))) off("O3.jwks", "offline: the jwks_uri is not read");
    if (pay && pay.tokenPinned && pay.call && eip3009Readable(pay.call)) off("O5.token-domain-call", "offline: the token's own domain is not read");
    if (receipts.some((x) => x.r && isStr(x.r.public_key_id) && !pins.witness_keys.keys.some((k) => k.key_id === x.r.public_key_id))) off("O6.witness-keys", "offline: GET /v5/keys is not read");
    if (payerDerived) off("O7.account-code", "offline: the stated account's code at the end of blocks N-1 and N is not read; the payment transaction carries no authorization tuple and no account proof is carried");
  }

  // The verdict (spec 4.6, table 4-6a).
  const bindings = BINDING_IDS.map((id) => B.get(id));
  const st = (id) => B.get(id).state;
  const anyFail = checks.some((c) => c.status === "FAIL") || bindings.some((b) => b.state === "FAIL");
  const breach = decision.value === "refuse" || st("B-INS") === "EXCEEDS" || st("B-GRC") === "EXCEEDS";
  const gaps = bindings.filter((b) => b.state !== "BOUND" && !(b.id === "B-GRC" && b.state === "ABSENT" && b.reason === null)).map((b) => ({ binding: b.id, state: b.state, reason: b.reason }));
  let verdict;
  const v = (code, rule, reason, g = gaps) => ({ code, text: VERDICT_TEXT[code], rule, reason, gaps: g });
  const bp = B.get("B-PAY");
  if (anyFail) verdict = v("FAILS", "V1", null, []);
  else if (bp.state === "ABSENT" || bp.state === "NO-PAYMENT" || (bp.state === "CARRIED-BY-OTHER" && !payerDerived)) verdict = v("DOES-NOT-CONNECT", "V2", null);
  else if (bp.state === "UNSUPPORTED-PATH" || bp.state === "NOT-EVALUATED") verdict = v("PAYMENT-NOT-VERIFIED", "V3", bp.reason);
  else if (st("B-CHAIN") === "SUPPLIED" || st("B-CHAIN") === "NOT-EVALUATED") verdict = v("PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data");
  else if (!breach && decision.value === "not-read") verdict = v("PAYMENT-NOT-VERIFIED", "V3", "decision-not-read");
  else if (!breach && st("B-INS") === "NOT-EVALUATED" && B.get("B-INS").reason === "unread-outflow") verdict = v("PAYMENT-NOT-VERIFIED", "V3", "unread-outflow");
  else if (payerDerived && breach) verdict = v("VERIFIES-OUTSIDE-INSTRUCTION", "V4", decision.value === "refuse" ? "decision-not-allow" : st("B-GRC") === "EXCEEDS" ? "after-receipt-expiry" : null);
  else if (decision.value === "allow" && ["B-PAY", "B-INS", "B-LOG", "B-CKP", "B-WIT", "B-CHAIN", "B-KEY"].every((id) => st(id) === "BOUND") && (st("B-GRC") === "BOUND" || (st("B-GRC") === "ABSENT" && B.get("B-GRC").reason === null))) verdict = v("VERIFIES", "V5", null, []);
  else verdict = v("VERIFIES-WITH-GAPS", "V6", null);

  // The limits whose rule applies (spec section 8, table 8-1).
  const L = new Set(["L1", "L4", "L6", "L7", "L8", "L9"]);
  if (doc) {
    const ms = doc.members;
    if (ms.some((m) => m.role === "gate-log" && m.profile === "chirindo-evidence.action/1")) L.add("L2");
    if (receipts.length || ms.some((m) => m.role === "witness-receipt")) L.add("L3");
    if (ms.some((m) => m.role === "instruction" && (m.profile === "vi-0.1-draft" || m.profile === "ap2-0.2"))) L.add("L5");
    if (["BOUND", "CARRIED-BY-OTHER"].includes(bp.state)) {
      L.add("L10");
      if (cited?.profile === "chirindo-evidence.action/1") L.add("L11");
    }
    if (ms.some((m) => m.role === "instruction" && m.profile === "signed-instruction-ed25519/0.2")) L.add("L12");
    if (cited && cited.records.length && pins.operator_key_ids.includes(cited.records[0].kid)) L.add("L14");
    if (payerDerived) L.add("L15");
    if (ms.some((m) => m.role === "gate-receipt")) L.add("L16");
    if (card) L.add("L17");
    if (subject?.chain_id === "eip155:84532") L.add("L19");
    if (bp.state === "UNSUPPORTED-PATH" && ["other-sender", "unsupported-call"].includes(bp.reason)) L.add("L20");
    if (bp.state === "BOUND" && bpay?.path === "calldata") L.add("L21");
    if (cited?.profile === "jcs-sha256-chain/0.1") L.add("L22");
    if (payerDerived || (bp.state === "NOT-EVALUATED" && ["account-has-code", "contract-signer", "prerequisite-failed:O7.account-code"].includes(bp.reason))) L.add("L23");
  }
  const limits = Object.keys(LIMIT_TEXTS)
    .filter((id) => L.has(id))
    .map((id) => ({ id, text: LIMIT_TEXTS[id] }));

  const output = {
    type: OUTPUT_TYPE,
    verifier: { ...VERIFIER },
    bundle_sha256: base.bundle_sha256,
    mode: "offline",
    checked_at: new Date().toISOString(),
    stated: base.stated,
    endpoints: [],
    checks,
    bindings,
    decision,
    gate_receipts: [],
    instructions: [],
    payment,
    hash_search: hashSearch,
    times,
    orderings,
    flags,
    verdict,
    limits,
  };
  return { kind: "verdict", output };
}

// B-PAY (spec 4.3, rules 1 to 10), offline, for an evm-payment subject whose
// cited record exists.
function bPay(ctx) {
  const { checks, pay, search, stated, doc } = ctx;
  const out = { state: null, reason: null, carrier: null, signed_by: null, payerDerived: false, movement: null, path: null, flagAuthorizer: false, detail: "" };
  const done = (state, reason, detail) => Object.assign(out, { state, reason, detail: detail ?? out.detail });
  const m5fail = checks.find((c) => c.id.startsWith("M5.") && c.status === "FAIL");
  if (m5fail) return done("NOT-EVALUATED", `prerequisite-failed:${m5fail.id}`);
  const support = checks.find((c) => c.id === "M5.support");
  if (support?.status === "NOT-EVALUATED") return done("UNSUPPORTED-PATH", support.reason);
  const call = pay.call;
  if (["receive9", "receiveBytes", "userop", "creation"].includes(call.kind) || (call.kind === "twaBytes" && !eip3009Readable(call))) return done("UNSUPPORTED-PATH", "unsupported-call");
  const eip = eip3009Readable(call);
  out.path = eip ? "eip3009" : "calldata";
  out.carrier = search ? search.carrier : null;
  const tx = pay.tx;
  const sender = pay.sender;
  let P = null;
  let counted = false;
  if (eip) {
    if (!pay.tokenPinned) return done("NOT-EVALUATED", "token-not-pinned");
    if (pay.authStatus === "contract-signer") return done("NOT-EVALUATED", "contract-signer");
    P = pay.signer;
    const a = call.auth;
    if (out.carrier === "eip3009-nonce") out.signed_by = P;
    else if (out.carrier === "calldata") out.signed_by = sender === P ? P : sender;
    counted = a.value > 0n && a.to !== P && pay.tokenLogsOk;
    if (counted) out.movement = { asset: tx.to.toLowerCase(), amount: a.value.toString(), payee: a.to, source: "counted", log_index: pay.transferLogIndex ?? null };
  } else {
    out.signed_by = sender;
    const value = quantity(tx.value, "value");
    counted = value > 0n && tx.to.toLowerCase() !== sender;
    if (counted) out.movement = { asset: "native", amount: value.toString(), payee: tx.to.toLowerCase(), source: "counted", log_index: null };
  }
  // Rule 6.
  if (out.carrier === null && search && search.nonBinding.length) return done("NOT-EVALUATED", "unread-carrier", "the cited hash is found only where it does not bind");
  // Rule 7.
  const claimed = doc.subject.carried_as === "none" ? null : doc.subject.carried_as;
  if (claimed !== out.carrier) return done("FAIL", null, `subject.carried_as claims ${doc.subject.carried_as}; the transaction shows ${out.carrier ?? "none"}`);
  // Rule 8.
  if (eip && out.carrier === null) return done("ABSENT", null, "the cited hash is in none of the signed fields, in neither form");
  // Rule 9.
  const S = stated.authorizer;
  if (!S) {
    out.flagAuthorizer = out.signed_by !== null;
    return done("NOT-EVALUATED", "authorizer-not-stated");
  }
  if (!stated.tx) return done("NOT-EVALUATED", "tx-not-stated");
  // Rule 10.
  if (eip && out.signed_by !== P) {
    // 10a: the sender alone signed the bytes that carry H.
    out.payerDerived = P === S && counted;
    return done("CARRIED-BY-OTHER", null, out.payerDerived ? "a facilitator's bytes carry the hash of a payment the stated account authorized" : "the bytes that carry the hash were signed by the sender alone");
  }
  if (eip && P !== S) return done("CARRIED-BY-OTHER", null, `the authorization's signer is not the stated account; the transaction moves value from ${P}`);
  if (!eip && sender !== S) return done("UNSUPPORTED-PATH", "other-sender");
  if (!eip && out.carrier === null) return done("ABSENT", null, "the cited hash is not in the calldata the stated account sent");
  if (counted) {
    out.payerDerived = true;
    // Rule 10e offline: the payment transaction is of type 0x2 here (it carries
    // no authorization tuple) and no account proof is carried, so the state of
    // rule 10d stands, computed from the bundle's copies.
    return done("BOUND", null, "the stated account signed the bytes that carry the cited hash, and the payment moves value from it");
  }
  return eip ? done("NO-PAYMENT", null, "the authorization moves nothing out of the payer") : done("NOT-EVALUATED", "no-counted-movement");
}

