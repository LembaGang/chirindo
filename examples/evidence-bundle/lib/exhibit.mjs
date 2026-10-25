// The exhibit PDF (spec 4.9): a one-page view of one verdict JSON, for a
// chargeback platform to place among its own exhibits. It shows values of the
// verdict JSON, in 4.9's order, and nothing else: the limits stated first
// (L24, L14, L3 when attached); the items a dispute decider asks for, with the
// strength this run shows; the verdict; every binding; the times with their
// clocks; every other limit; a footer. Labels are this generator's words; every
// value is the verdict's. No limit, binding or verdict line is left out: the
// text gets smaller, down to 6 points, then the list of times is shortened,
// and when every limit still does not fit, no exhibit is written.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { built } from "./built.mjs";
import { LIMIT_IDS } from "./limits.mjs";
import { FONT_PATH, loadFont, widthOf, writePdf } from "./pdf.mjs";
import { validate } from "./schema-check.mjs";
import { OUTPUT_TYPE } from "./table.mjs";

export const GENERATOR = { name: "chirindo-evidence-bundle make-exhibit", version: "0.10.0" };
// US Letter and A4, in points.
export const PAGES = { letter: [612, 792], a4: [595.28, 841.89] };
const MARGIN = 36;
const SIZES = [8, 7.5, 7, 6.5, 6];
const STATED_FIRST = ["L24", "L14", "L3"];
const FREE_TEXT_MAX = 200;

const SCHEMA = JSON.parse(readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "schema", "evidence-bundle-verdict-0.10.schema.json"), "utf8"));

// exit 2: not a verdict this generator reads, or the font; exit 3: the
// limits do not fit one page at 6 points.
export class ExhibitError extends Error {
  constructor(exit, message) {
    super(message);
    this.exit = exit;
  }
}

// The verdict JSON: an evidence-bundle-verdict/0.10 object valid under the schema of spec D.3.
export function readVerdict(bytes) {
  let o;
  try {
    o = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new ExhibitError(2, "the file is not JSON, so not an evidence-bundle-verdict/0.10 verdict");
  }
  if (o === null || typeof o !== "object" || o.type !== OUTPUT_TYPE) throw new ExhibitError(2, `the file is not an ${OUTPUT_TYPE} verdict (its type is ${JSON.stringify(o?.type ?? null)})`);
  const errs = validate(SCHEMA, o);
  if (errs.length) throw new ExhibitError(2, `the file is not a valid ${OUTPUT_TYPE} verdict: ${errs[0]}`);
  return o;
}

// A label (this generator's words) and a value taken from the verdict at a path.
const L = (text) => ({ text, from: null });
const V = (o, p, { free = false } = {}) => {
  const raw = String(p.split(".").reduce((x, k) => x[/^\d+$/.test(k) ? Number(k) : k], o));
  // A free-text value from a bundle, an input or a server, cut at 200 characters (4.9).
  if (free && raw.length > FREE_TEXT_MAX) return { text: raw.slice(0, FREE_TEXT_MAX) + "...", from: p, cut: true };
  return { text: raw, from: p };
};

// The paragraphs of the page, each a list of segments, for a run that keeps
// `keepTimes` of the verdict's times.
function paragraphs(o, verdictSha256, keepTimes) {
  const P = [];
  const para = (segments, { indent = 0, gap = false } = {}) => P.push({ segments, indent, gap });
  const bi = (id) => o.bindings.findIndex((b) => b.id === id);
  const stateOf = (id) => (bi(id) < 0 ? [L(`${id} not listed`)] : [L(id), V(o, `bindings.${bi(id)}.state`), ...(o.bindings[bi(id)].reason !== null ? [V(o, `bindings.${bi(id)}.reason`)] : [])]);
  const li = (id) => o.limits.findIndex((l) => l.id === id);

  para([L("Agent evidence exhibit: a view of one verdict JSON (evidence-bundle-verdict/0.10). It shows the verdict's values and nothing else; the verdict JSON is the record.")]);

  // 1. The limits stated first.
  para([L("Stated first:")], { gap: true });
  for (const id of STATED_FIRST) if (li(id) >= 0) para([V(o, `limits.${li(id)}.id`), V(o, `limits.${li(id)}.text`)], { indent: 8 });

  // 2. The items a dispute decider asks for, with the strength this run shows.
  para([L("What a dispute decider asks for, and what this run shows:")], { gap: true });
  para([L("Agent identity (the gate's signed record of which agent key acted):"), ...stateOf("B-LOG"), L(";"), ...stateOf("B-KEY")], { indent: 8 });
  para([L("The customer's signed instruction with its limits:"), ...stateOf("B-INS"), L("; signed by an Annex A principal key (L12 attached):"), L(li("L12") >= 0 ? "yes" : "no")], { indent: 8 });
  const cart = [L("The cart at decision time against the charge, inside the instruction's limits:"), ...stateOf("B-CARD")];
  if (o.card) {
    if (o.card.order) {
      cart.push(L("; the order: merchant_id"), V(o, "card.order.merchant_id", { free: true }));
      for (const k of ["merchant_order_id", "checkout_ref"]) if (o.card.order[k] !== null) cart.push(L(k), V(o, `card.order.${k}`, { free: true }));
      for (const k of ["currency", "total_minor", "items_sum_minor", "item_count"]) cart.push(L(k), V(o, `card.order.${k}`));
    } else cart.push(L("; no committed order is reported"));
    cart.push(L("; against the stated charge:"));
    for (const k of ["amount", "currency", "merchant_order_id", "checkout_ref"]) cart.push(L(k), V(o, `card.matches.${k}`));
  } else cart.push(L("; no card member (no card subject with a stated charge)"));
  o.instructions.forEach((ins, i) => {
    if (!ins.cited || ins.card_limits.length === 0) return;
    cart.push(L(`; the cited instruction's limits:`));
    ins.card_limits.forEach((c, j) => {
      cart.push(V(o, `instructions.${i}.card_limits.${j}.limit`), V(o, `instructions.${i}.card_limits.${j}.result`));
      if (c.reason !== null) cart.push(V(o, `instructions.${i}.card_limits.${j}.reason`));
    });
  });
  para(cart, { indent: 8 });
  const timing = [L("Timing (Headless Oracle's received_at against the stated authorization time, B-CARD rule 3):")];
  if (o.card) timing.push(L("received_at"), V(o, "card.witness_received_at"), L("authorized at"), V(o, "card.authorized_at"), L("before the authorization:"), V(o, "card.before_authorization"), L(";"));
  timing.push(...stateOf("B-WIT"), L("; Headless Oracle is the only witness (L3)."));
  para(timing, { indent: 8 });
  para([L("Whether the agent interpreted the instruction correctly: not shown (L1).")], { indent: 8 });
  para([L("Customer recognition, 3-D Secure, AVS and fulfilment: not carried; they are the platform's and the processor's records.")], { indent: 8 });

  // 3. The verdict.
  para([L("Verdict:"), V(o, "verdict.code"), L("rule"), V(o, "verdict.rule"), L(":"), V(o, "verdict.text"), L("reason:"), o.verdict.reason === null ? L("none") : V(o, "verdict.reason")], { gap: true });

  // 4. Every binding.
  para([L("Bindings, each with its state and reason:")], { gap: true });
  o.bindings.forEach((b, i) => para([V(o, `bindings.${i}.id`), V(o, `bindings.${i}.state`), ...(b.reason !== null ? [V(o, `bindings.${i}.reason`)] : [])], { indent: 8 }));

  // 5. The times, each with its clock and whether it is as supplied.
  para([L("Times, each with its clock:")], { gap: true });
  o.times.slice(0, keepTimes).forEach((t, i) => para([V(o, `times.${i}.what`), V(o, `times.${i}.value`), L("clock"), V(o, `times.${i}.clock`), L("as supplied:"), V(o, `times.${i}.as_supplied`)], { indent: 8 }));
  if (keepTimes < o.times.length) para([L(`${o.times.length - keepTimes} more ${o.times.length - keepTimes === 1 ? "time is" : "times are"} left out here; every time is in the verdict JSON.`)], { indent: 8 });
  if (o.card) para([L("stated authorization time"), V(o, "card.authorized_at"), L("(clock processor, as stated)")], { indent: 8 });
  else if (o.stated.charge) para([L("stated authorization time"), V(o, "stated.charge.authorized_at"), L("(clock processor, as stated)")], { indent: 8 });

  // 6. Every other limit, in the order of table 8-1.
  para([L("Every other limit attached, in the order of table 8-1:")], { gap: true });
  for (const id of LIMIT_IDS) if (!STATED_FIRST.includes(id) && li(id) >= 0) para([V(o, `limits.${li(id)}.id`), V(o, `limits.${li(id)}.text`)], { indent: 8 });

  // The footer.
  const foot = [L("verdict JSON sha256:"), L(verdictSha256), L("; bundle_sha256:"), V(o, "bundle_sha256")];
  if (o.pointer) foot.push(L("; pointer:"), V(o, "pointer.uri", { free: true }), L("entry"), V(o, "pointer.stated_entry"), L("status"), V(o, "pointer.status"));
  foot.push(L("; verifier:"), V(o, "verifier.name"), V(o, "verifier.version"), L("commit"), V(o, "verifier.commit"), L("; mode"), V(o, "mode"), L("; checked_at"), V(o, "checked_at"), L(`; generator: ${GENERATOR.name} ${GENERATOR.version}`));
  para(foot, { gap: true });
  return P;
}

// Segments to lines no wider than `width` at `size`, joined by one space. A
// value that fits one line is kept whole on one line; a label, and a value
// wider than a line, wrap at spaces, and a word wider than a line is broken
// by characters.
function wrap(font, segments, size, width) {
  const fits = (s) => widthOf(font, s, size) <= width;
  const words = segments.flatMap((s) => (s.from !== null && fits(s.text) ? [s.text] : s.text.split(" "))).filter((w) => w !== "");
  const lines = [];
  let cur = "";
  for (let w of words) {
    const next = cur === "" ? w : `${cur} ${w}`;
    if (fits(next)) {
      cur = next;
      continue;
    }
    if (cur !== "") lines.push(cur);
    cur = "";
    while (!fits(w)) {
      let n = 1;
      while (n < w.length && fits([...w].slice(0, n + 1).join(""))) n++;
      const head = [...w].slice(0, n).join("");
      lines.push(head);
      w = [...w].slice(n).join("");
    }
    cur = w;
  }
  if (cur !== "") lines.push(cur);
  return lines;
}

// The page laid out at one size: its lines with positions, or null when it
// does not fit.
function layout(font, P, size, [width, height]) {
  const lead = size * 1.2;
  let y = height - MARGIN - size;
  const lines = [];
  for (const p of P) {
    if (p.gap) y -= size * 0.5;
    for (const text of wrap(font, p.segments, size, width - 2 * MARGIN - p.indent)) {
      if (y < MARGIN) return null;
      lines.push({ x: MARGIN + p.indent, y, size, text });
      y -= lead;
    }
  }
  return lines;
}

built("exhibit.pdf", "exhibit.determinism", "exhibit.text-only");
// The exhibit of one verdict JSON's bytes. Returns the PDF's bytes, the
// writer's list of the strings it drew (`drawn`, each with the verdict path it
// came from, or null for a label) and the page's lines as drawn (`lines`).
export function makeExhibit(bytes, { page = "letter", pageHeight = null, fontPath = FONT_PATH } = {}) {
  const o = readVerdict(bytes);
  if (!PAGES[page]) throw new ExhibitError(2, `the page is ${JSON.stringify(page)}, not letter or a4`);
  let font;
  try {
    font = loadFont(fontPath);
  } catch (e) {
    throw new ExhibitError(2, e.message);
  }
  const box = [PAGES[page][0], pageHeight ?? PAGES[page][1]];
  const digest = createHash("sha256").update(bytes).digest("hex");
  for (let keep = o.times.length; keep >= 0; keep--) {
    const P = paragraphs(o, `sha256:${digest}`, keep);
    for (const size of SIZES) {
      const lines = layout(font, P, size, box);
      if (!lines) continue;
      const t = o.checked_at;
      const pdf = writePdf(font, {
        width: box[0],
        height: box[1],
        lines,
        producer: `${GENERATOR.name} ${GENERATOR.version}`,
        creationDate: `D:${t.slice(0, 4)}${t.slice(5, 7)}${t.slice(8, 10)}${t.slice(11, 13)}${t.slice(14, 16)}${t.slice(17, 19)}Z`,
        idHex: digest.slice(0, 32),
      });
      return { bytes: pdf, drawn: P.flatMap((p) => p.segments), lines: lines.map((l) => l.text), size };
    }
  }
  throw new ExhibitError(3, `every limit does not fit one ${page} page at 6 points, with the list of times left out`);
}
