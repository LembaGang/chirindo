// A one-page PDF 1.7 writer for the exhibit (spec 4.9): one TrueType font,
// pinned by its sha256, embedded whole (FontFile2, never subset) as a simple
// font with WinAnsiEncoding; every string drawn as a hex string with the
// font's text operators, so no string is ever read as PDF syntax; content
// uncompressed; objects numbered and written in one fixed order; no clock (the
// caller gives CreationDate and the ID). A character WinAnsi or the font
// lacks, and every control character, is drawn as [U+XXXX].

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// DejaVu Sans from dejavu-fonts-ttf 2.37.3 (fonts/DejaVu-LICENSE is its licence).
export const FONT_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "node_modules", "dejavu-fonts-ttf", "ttf", "DejaVuSans.ttf");
export const FONT_SHA256 = "7da195a74c55bef988d0d48f9508bd5d849425c1770dba5d7bfc6ce9ed848954";

export class FontError extends Error {}

// WinAnsiEncoding: 32 to 126 and 160 to 255 as Latin-1, 128 to 159 by the
// encoding's table (PDF 32000-1, Annex D).
const WIN = { 128: 0x20ac, 130: 0x201a, 131: 0x192, 132: 0x201e, 133: 0x2026, 134: 0x2020, 135: 0x2021, 136: 0x2c6, 137: 0x2030, 138: 0x160, 139: 0x2039, 140: 0x152, 142: 0x17d, 145: 0x2018, 146: 0x2019, 147: 0x201c, 148: 0x201d, 149: 0x2022, 150: 0x2013, 151: 0x2014, 152: 0x2dc, 153: 0x2122, 154: 0x161, 155: 0x203a, 156: 0x153, 158: 0x17e, 159: 0x178 };
const CODE_OF = new Map();
for (let c = 32; c <= 126; c++) CODE_OF.set(c, c);
for (let c = 160; c <= 255; c++) CODE_OF.set(c, c);
for (const [k, v] of Object.entries(WIN)) CODE_OF.set(v, Number(k));

// The pinned font, read and parsed for its dictionary and its widths.
export function loadFont(file = FONT_PATH) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (e) {
    throw new FontError(`the font ${file} cannot be read (${e.code ?? e.message})`);
  }
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== FONT_SHA256) throw new FontError(`the font file's sha256 is ${digest}, not the pinned ${FONT_SHA256}`);
  const u16 = (o) => bytes.readUInt16BE(o);
  const i16 = (o) => bytes.readInt16BE(o);
  const u32 = (o) => bytes.readUInt32BE(o);
  const tables = {};
  for (let i = 0, n = u16(4); i < n; i++) {
    const r = 12 + 16 * i;
    tables[bytes.toString("latin1", r, r + 4)] = u32(r + 8);
  }
  const head = tables["head"];
  const os2 = tables["OS/2"];
  const unitsPerEm = u16(head + 18);
  const numHMetrics = u16(tables["hhea"] + 34);
  // The (3,1) cmap subtable of format 4: Unicode BMP to glyph id.
  let cmap4 = null;
  const c = tables["cmap"];
  for (let i = 0, n = u16(c + 2); i < n; i++) {
    const p = u16(c + 4 + 8 * i);
    const e = u16(c + 6 + 8 * i);
    const off = u32(c + 8 + 8 * i);
    if (p === 3 && e === 1 && u16(c + off) === 4) cmap4 = c + off;
  }
  const glyphOf = (cp) => {
    if (cp > 0xffff) return 0;
    const segX2 = u16(cmap4 + 6);
    const ends = cmap4 + 14;
    const starts = ends + segX2 + 2;
    const deltas = starts + segX2;
    const ranges = deltas + segX2;
    for (let s = 0; s < segX2 / 2; s++) {
      if (cp > u16(ends + 2 * s)) continue;
      const start = u16(starts + 2 * s);
      if (cp < start) return 0;
      const delta = i16(deltas + 2 * s);
      const ro = u16(ranges + 2 * s);
      if (ro === 0) return (cp + delta) & 0xffff;
      const g = u16(ranges + 2 * s + ro + 2 * (cp - start));
      return g === 0 ? 0 : (g + delta) & 0xffff;
    }
    return 0;
  };
  const advance = (g) => u16(tables["hmtx"] + 4 * Math.min(g, numHMetrics - 1));
  const sc = (v) => Math.round((v * 1000) / unitsPerEm);
  // Widths of codes 32 to 255 in thousandths of the size; 0 for a code WinAnsi leaves undefined.
  const widths = [];
  for (let code = 32; code <= 255; code++) {
    const cp = code >= 128 && code <= 159 ? WIN[code] : code;
    widths.push(cp === undefined ? 0 : sc(advance(glyphOf(cp))));
  }
  const capHeight = u16(os2) >= 2 ? i16(os2 + 88) : i16(os2 + 68);
  return {
    bytes,
    glyphOf,
    widths,
    bbox: [i16(head + 36), i16(head + 38), i16(head + 40), i16(head + 42)].map(sc),
    ascent: sc(i16(os2 + 68)),
    descent: sc(i16(os2 + 70)),
    capHeight: sc(capHeight),
  };
}

// The WinAnsi codes a string is drawn with: each character WinAnsi or the
// font lacks, and each control character, as the codes of [U+XXXX].
export function codesOf(font, s) {
  const out = [];
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    const code = CODE_OF.get(cp);
    if (code === undefined || font.glyphOf(cp) === 0) for (const x of `[U+${cp.toString(16).toUpperCase().padStart(4, "0")}]`) out.push(x.charCodeAt(0));
    else out.push(code);
  }
  return out;
}

// A string's width in points at a size.
export const widthOf = (font, s, size) => (codesOf(font, s).reduce((w, c) => w + font.widths[c - 32], 0) * size) / 1000;

// Numbers in the file: at most two decimals, no trailing zeros, so that the
// same layout always prints the same bytes.
const num = (n) => {
  const s = (Math.round(n * 100) / 100).toFixed(2).replace(/\.?0+$/, "");
  return s === "-0" ? "0" : s;
};

// The file: catalog, pages, page, font, contents, font descriptor, font file,
// info, in that order. `lines` are { x, y, size, text } in points from the
// lower left; `creationDate` is D:YYYYMMDDHHmmSSZ; `idHex` 32 hex digits.
export function writePdf(font, { width, height, lines, producer, creationDate, idHex }) {
  let content = "";
  for (const l of lines) content += `BT /F1 ${num(l.size)} Tf ${num(l.x)} ${num(l.y)} Td <${Buffer.from(codesOf(font, l.text)).toString("hex")}> Tj ET\n`;
  const literal = (s) => {
    if (!/^[\x20-\x7e]*$/.test(s) || /[()\\]/.test(s)) throw new Error(`not a plain PDF literal: ${JSON.stringify(s)}`);
    return `(${s})`;
  };
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${num(width)} ${num(height)}] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>`,
    `<< /Type /Font /Subtype /TrueType /BaseFont /DejaVuSans /FirstChar 32 /LastChar 255 /Widths [${font.widths.join(" ")}] /Encoding /WinAnsiEncoding /FontDescriptor 6 0 R >>`,
    { stream: Buffer.from(content, "latin1"), dict: "" },
    `<< /Type /FontDescriptor /FontName /DejaVuSans /Flags 32 /FontBBox [${font.bbox.join(" ")}] /ItalicAngle 0 /Ascent ${font.ascent} /Descent ${font.descent} /CapHeight ${font.capHeight} /StemV 80 /FontFile2 7 0 R >>`,
    { stream: font.bytes, dict: ` /Length1 ${font.bytes.length}` },
    `<< /Producer ${literal(producer)} /CreationDate ${literal(creationDate)} >>`,
  ];
  const parts = [Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let pos = parts[0].length;
  const offsets = [];
  objs.forEach((o, i) => {
    offsets.push(pos);
    const b =
      typeof o === "string"
        ? Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`, "latin1")
        : Buffer.concat([Buffer.from(`${i + 1} 0 obj\n<< /Length ${o.stream.length}${o.dict} >>\nstream\n`, "latin1"), o.stream, Buffer.from("\nendstream\nendobj\n", "latin1")]);
    parts.push(b);
    pos += b.length;
  });
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("");
  xref += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info ${objs.length} 0 R /ID [<${idHex}> <${idHex}>] >>\nstartxref\n${pos}\n%%EOF\n`;
  parts.push(Buffer.from(xref, "latin1"));
  return Buffer.concat(parts);
}
