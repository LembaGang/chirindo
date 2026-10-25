// The views' cases (W3-07 to W3-09; spec 4.9, the exhibit PDF, and 4.10, the
// data-point export): the verdict JSON bytes each view is made from, and a
// reader of the exhibit's bytes that the tests use. The reader is the tests'
// own, not the writer's (lib/pdf.mjs): it splits the file into its objects and
// decodes the content stream's strings with its own WinAnsi table, so that a
// fault in the writer's encoding is not repeated by the check.

import { createHash } from "node:crypto";
import { verifyPointer } from "../lib/pointer.mjs";
import { runVector, VECTORS } from "./make-vectors.mjs";
import { POINTER_CASES } from "./pointer-cases.mjs";
import { cardArgs, cardDoc, cardPins, charge, WE4_ORDER } from "./rows-a3.mjs";

export const sha256 = (b) => createHash("sha256").update(b).digest("hex");

// The verdict JSON as check-bundle.mjs writes it (stdout's bytes), with its object.
export async function verdictOf(v, dir) {
  const r = await runVector(v, dir);
  if (r.status !== 0) throw new Error(`${v.id} gives no verdict: ${r.stderr}`);
  return { id: v.id, bytes: Buffer.from(r.stdout, "utf8"), output: r.output };
}
export const vectorById = (id) => VECTORS.find((v) => v.id === id);

// Every card vector of the vectors file that gives a verdict, in file order.
export async function cardVerdicts(dir) {
  const out = [];
  for (const v of VECTORS) {
    const built = await v.build();
    if (built.doc?.subject?.kind !== "card-payment") continue;
    const r = await runVector({ ...v, build: async () => built }, dir);
    if (r.status === 0) out.push({ id: v.id, bytes: Buffer.from(r.stdout, "utf8"), output: r.output });
  }
  return out;
}

// The pointer cases' verdicts (V-40 to V-45e), written as check-bundle.mjs
// writes a verdict (two-space JSON and a line feed).
export async function pointerVerdicts() {
  const out = [];
  for (const pc of POINTER_CASES) {
    const r = await pc.run(verifyPointer);
    if (r.kind === "verdict") out.push({ id: pc.id, bytes: Buffer.from(JSON.stringify(r.output, null, 2) + "\n", "utf8"), output: r.output });
  }
  return out;
}

// V-52: PDF string syntax, parentheses, a backslash, a tab, a control
// character, a character WinAnsi lacks and two the font's WinAnsi encoding
// cannot reach. In a card bundle these can stand in the subject's reference,
// an item's name and assembled_by, which no verdict member holds, and in the
// order's merchant_id, which the verdict reports (card.order.merchant_id).
export const HOSTILE = "TEST (a) \\ b)( tab\tend \u0007bell ★ 漢字";
// What the exhibit draws for HOSTILE: the parentheses and the backslash as
// themselves, every other character outside WinAnsi's printable range as
// [U+XXXX] (Appendix P's rule).
export const HOSTILE_SHOWN = "TEST (a) \\ b)( tab[U+0009]end [U+0007]bell [U+2605] [U+6F22][U+5B57]";
export const V52 = {
  id: "V-52",
  description: "a card bundle whose reference, an item's name, assembled_by and the order's merchant_id hold PDF string syntax, a control character and characters the font lacks",
  args: [...charge(), "--pins", "<pins>"],
  build: () => {
    const order = { ...WE4_ORDER, merchant_id: HOSTILE, items: [{ ...WE4_ORDER.items[0], name: HOSTILE }] };
    const doc = cardDoc({ args: cardArgs(order), reference: HOSTILE });
    doc.assembled_by = HOSTILE;
    return { doc, pins: cardPins() };
  },
};

// The exhibit's bytes split into its header, objects and trailer.
export function readPdf(bytes) {
  const s = bytes.toString("latin1");
  const objects = new Map();
  const re = /(\d+) 0 obj\n/g;
  let m;
  while ((m = re.exec(s))) {
    const n = Number(m[1]);
    const start = m.index + m[0].length;
    const dictEnd = s.indexOf("\n", start);
    const head = s.slice(start, dictEnd);
    const len = /^<< \/Length (\d+)/.exec(head);
    if (len && s.startsWith("stream\n", dictEnd + 1)) {
      const at = dictEnd + 1 + "stream\n".length;
      const stream = bytes.subarray(at, at + Number(len[1]));
      objects.set(n, { dict: head, stream });
      re.lastIndex = at + stream.length;
    } else objects.set(n, { dict: s.slice(start, s.indexOf("\nendobj\n", start)), stream: null });
  }
  const trailer = s.slice(s.lastIndexOf("trailer\n"));
  return { header: s.slice(0, s.indexOf("\n")), objects, trailer, text: s };
}

// WinAnsiEncoding back to characters: 32 to 126 and 160 to 255 as Latin-1,
// 128 to 159 by the encoding's table (PDF 32000-1, Annex D).
const WIN = { 128: 0x20ac, 130: 0x201a, 131: 0x192, 132: 0x201e, 133: 0x2026, 134: 0x2020, 135: 0x2021, 136: 0x2c6, 137: 0x2030, 138: 0x160, 139: 0x2039, 140: 0x152, 142: 0x17d, 145: 0x2018, 146: 0x2019, 147: 0x201c, 148: 0x201d, 149: 0x2022, 150: 0x2013, 151: 0x2014, 152: 0x2dc, 153: 0x2122, 154: 0x161, 155: 0x203a, 156: 0x153, 158: 0x17e, 159: 0x178 };
const charOf = (code) => {
  if ((code >= 32 && code <= 126) || (code >= 160 && code <= 255)) return String.fromCharCode(code);
  if (WIN[code]) return String.fromCodePoint(WIN[code]);
  throw new Error(`byte ${code} is not a WinAnsi character`);
};

// Every string the content stream draws, in order, decoded; and every
// operator that shows text with a string that is not a hex string.
export function drawnStrings(pdf) {
  const contents = [...pdf.objects.values()].find((o) => o.stream && !/\/Length1/.test(o.dict));
  const c = contents.stream.toString("latin1");
  const shown = [...c.matchAll(/<([0-9a-f]*)> Tj/g)].map((m) => [...Buffer.from(m[1], "hex")].map(charOf).join(""));
  const literal = [...c.matchAll(/\)\s*(Tj|TJ|'|")/g)].length + [...c.matchAll(/\]\s*TJ/g)].length;
  return { shown, literal, content: c };
}

// The form the exhibit draws a string in: each character outside WinAnsi's
// printable characters, and each control character, as [U+XXXX].
const WIN_CHARS = new Set([...Array.from({ length: 95 }, (_, i) => 32 + i), ...Array.from({ length: 96 }, (_, i) => 160 + i), ...Object.values(WIN)]);
export const shownForm = (s) => [...s].map((ch) => (WIN_CHARS.has(ch.codePointAt(0)) ? ch : `[U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}]`)).join("");
