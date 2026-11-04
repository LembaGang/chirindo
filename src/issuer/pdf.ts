// A plain-text PDF for the issuer pack's summary (B-439 ruling 3: "a PDF
// summary ... under 6 MB"). A4, Courier 9 pt (fixed width, so wrapping is
// exact), WinAnsiEncoding, uncompressed content streams, no info dictionary,
// no dates and no file id: the bytes depend only on the lines given.
//
// Text never becomes PDF syntax: every string is written byte by byte with
// ( ) \ escaped and every byte outside printable ASCII as an octal escape. A
// character the font's encoding cannot show is written as "?" and counted;
// the caller says so on the page (pack.json carries the exact text).

export const PDF_MAX_BYTES = 6_000_000; // "Maximum file size : 6MB", read as 6,000,000 to be safe
const PAGE_W = 595;
const PAGE_H = 842;
const MARGIN = 42;
const FONT_SIZE = 9;
const LEADING = 11;
const CHAR_W = 0.6 * FONT_SIZE; // Courier: every glyph is 600/1000 em
export const PDF_COLUMNS = Math.floor((PAGE_W - 2 * MARGIN) / CHAR_W);
const LINES_PER_PAGE = Math.floor((PAGE_H - 2 * MARGIN - LEADING) / LEADING); // one line kept for the page number

// WinAnsiEncoding bytes 0x80 to 0x9F (the rest of 0xA0 to 0xFF is Latin-1).
const WIN_ANSI: Record<number, number> = {
  0x20ac: 0x80, 0x201a: 0x82, 0x0192: 0x83, 0x201e: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87,
  0x02c6: 0x88, 0x2030: 0x89, 0x0160: 0x8a, 0x2039: 0x8b, 0x0152: 0x8c, 0x017d: 0x8e,
  0x2018: 0x91, 0x2019: 0x92, 0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97,
  0x02dc: 0x98, 0x2122: 0x99, 0x0161: 0x9a, 0x203a: 0x9b, 0x0153: 0x9c, 0x017e: 0x9e, 0x0178: 0x9f,
};

export interface PdfLine {
  text: string;
  bold?: boolean;
  indent?: number; // in columns
}

export interface PdfResult {
  bytes: Buffer;
  pages: number;
  replaced: number; // characters shown as "?"
}

function encode(s: string): { bytes: number[]; replaced: number } {
  const out: number[] = [];
  let replaced = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0x20 && cp <= 0x7e) out.push(cp);
    else if (cp >= 0xa0 && cp <= 0xff) out.push(cp);
    else if (WIN_ANSI[cp] !== undefined) out.push(WIN_ANSI[cp]!);
    else if (cp === 0x09) out.push(0x20);
    else {
      out.push(0x3f);
      replaced++;
    }
  }
  return { bytes: out, replaced };
}

function literal(bytes: number[]): string {
  let s = "(";
  for (const b of bytes) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) s += "\\" + String.fromCharCode(b);
    else if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
    else s += "\\" + b.toString(8).padStart(3, "0");
  }
  return s + ")";
}

// Wrap at spaces into lines of at most `width` characters; a word longer than
// the width is cut. A wrapped line rejoined with single spaces gives the text
// back when it holds no run of spaces.
export function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (const para of text.split("\n")) {
    const words = para.split(" ");
    let line = "";
    for (let w of words) {
      while ([...w].length > width) {
        if (line !== "") {
          out.push(line);
          line = "";
        }
        const chars = [...w];
        out.push(chars.slice(0, width).join(""));
        w = chars.slice(width).join("");
      }
      if (line === "") line = w;
      else if ([...line].length + 1 + [...w].length <= width) line += " " + w;
      else {
        out.push(line);
        line = w;
      }
    }
    out.push(line);
  }
  return out;
}

export function renderPdf(lines: PdfLine[]): PdfResult {
  const laid: { text: string; bold: boolean; indent: number }[] = [];
  for (const l of lines) {
    const indent = Math.max(0, Math.min(l.indent ?? 0, 40));
    for (const t of wrap(l.text, PDF_COLUMNS - indent)) laid.push({ text: t, bold: l.bold === true, indent });
  }
  const pages: (typeof laid)[] = [];
  for (let i = 0; i < laid.length; i += LINES_PER_PAGE) pages.push(laid.slice(i, i + LINES_PER_PAGE));
  if (pages.length === 0) pages.push([]);

  let replaced = 0;
  // Objects: 1 catalog, 2 pages, 3 Courier, 4 Courier-Bold, then a page and
  // its content stream for each page.
  const objs: string[] = [];
  const kids = pages.map((_, i) => `${5 + 2 * i} 0 R`).join(" ");
  objs.push("<< /Type /Catalog /Pages 2 0 R >>");
  objs.push(`<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`);
  objs.push("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>");
  objs.push("<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>");
  pages.forEach((page, i) => {
    let body = "BT\n";
    let y = PAGE_H - MARGIN - FONT_SIZE;
    for (const l of page) {
      const e = encode(l.text);
      replaced += e.replaced;
      body += `/${l.bold ? "F2" : "F1"} ${FONT_SIZE} Tf 1 0 0 1 ${MARGIN + l.indent * CHAR_W} ${y} Tm ${literal(e.bytes)} Tj\n`;
      y -= LEADING;
    }
    body += `/F1 ${FONT_SIZE} Tf 1 0 0 1 ${MARGIN} ${MARGIN} Tm ${literal(encode(`page ${i + 1} of ${pages.length}`).bytes)} Tj\nET\n`;
    objs.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${6 + 2 * i} 0 R >>`,
    );
    objs.push(`<< /Length ${Buffer.byteLength(body, "latin1")} >>\nstream\n${body}endstream`);
  });

  let out = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(Buffer.byteLength(out, "latin1"));
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xrefAt = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`;
  return { bytes: Buffer.from(out, "latin1"), pages: pages.length, replaced };
}

// The text of a PDF this module wrote, one string per line, for tests and
// for checking a pack: each Tj string decoded back through WinAnsiEncoding.
export function pdfLines(pdf: Buffer): string[] {
  const rev = new Map<number, number>(Object.entries(WIN_ANSI).map(([cp, b]) => [b, Number(cp)]));
  const src = pdf.toString("latin1");
  const out: string[] = [];
  const re = /\((?:\\[0-7]{3}|\\[()\\]|[^\\()])*\) Tj/g;
  for (const m of src.matchAll(re)) {
    const body = m[0].slice(1, -4);
    let s = "";
    for (let i = 0; i < body.length; i++) {
      let b: number;
      if (body[i] === "\\") {
        if (/[0-7]/.test(body[i + 1]!)) {
          b = parseInt(body.slice(i + 1, i + 4), 8);
          i += 3;
        } else {
          b = body.charCodeAt(i + 1);
          i += 1;
        }
      } else b = body.charCodeAt(i);
      s += String.fromCodePoint(rev.get(b) ?? b);
    }
    out.push(s);
  }
  return out;
}
