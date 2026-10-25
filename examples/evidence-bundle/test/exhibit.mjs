// The exhibit PDF (W3-07; spec 4.9, Appendix P of the build): one page made
// from one verdict JSON by make-exhibit.mjs, deterministic, with the pinned
// font embedded whole and every string drawn as text. Each case runs the
// command line for its exit and its file, and the library entry for the
// writer's own list of what it drew; the PDF is read back by the tests' own
// reader (vectors/view-cases.mjs), not the writer's.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { FOLDER } from "../vectors/make-vectors.mjs";
import { cardVerdicts, drawnStrings, HOSTILE, HOSTILE_SHOWN, pointerVerdicts, readPdf, sha256, shownForm, V52, vectorById, verdictOf } from "../vectors/view-cases.mjs";

const FONT = path.join(FOLDER, "node_modules", "dejavu-fonts-ttf", "ttf", "DejaVuSans.ttf");
const FONT_SHA256 = "7da195a74c55bef988d0d48f9508bd5d849425c1770dba5d7bfc6ce9ed848954";
const MAX_BYTES = 5000000;

let dir;
let lib;
let v10;
let v52;
const card = [];
const pointer = [];
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-exhibit-"));
  v10 = await verdictOf(vectorById("V-10"), dir);
  v52 = await verdictOf(V52, dir);
  card.push(...(await cardVerdicts(dir)));
  pointer.push(...(await pointerVerdicts()));
  lib = await import("../lib/exhibit.mjs");
});
after(() => rmSync(dir, { recursive: true, force: true }));

// Runs make-exhibit.mjs on verdict bytes; returns its exit, streams and file.
function make(name, bytes, args) {
  const vp = path.join(dir, `${name}.verdict.json`);
  const out = path.join(dir, `${name}.pdf`);
  writeFileSync(vp, bytes);
  rmSync(out, { force: true });
  const r = spawnSync(process.execPath, [path.join(FOLDER, "make-exhibit.mjs"), vp, ...args.map((a) => (a === "<out>" ? out : a))], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, file: existsSync(out) ? readFileSync(out) : null };
}
const pages = (pdf) => [...pdf.text.matchAll(/\/Type \/Page\b(?!s)/g)].length;
// The PDF outside the embedded font program, where the forbidden keys are looked for.
const outsideFont = (pdf) => [...pdf.objects.values()].filter((o) => !/\/Length1/.test(o.dict)).map((o) => o.dict + (o.stream ? o.stream.toString("latin1") : "")).join("\n") + pdf.trailer;

for (const page of ["letter", "a4"]) {
  test(`V-50 (${page}): V-10's exhibit is written, one page, at most 5,000,000 bytes, and a second generation is byte-equal [spec, v0.10 4.9]`, () => {
    const a = make(`v50-${page}-1`, v10.bytes, ["--page", page, "--out", "<out>"]);
    assert.equal(a.status, 0, a.stderr);
    assert.equal(a.stdout, "");
    assert.ok(a.file, "the file is written");
    const pdf = readPdf(a.file);
    assert.equal(pdf.header, "%PDF-1.7");
    assert.equal(pages(pdf), 1);
    assert.ok(a.file.length <= MAX_BYTES, `${a.file.length} bytes`);
    const b = make(`v50-${page}-2`, v10.bytes, ["--page", page, "--out", "<out>"]);
    assert.equal(b.status, 0, b.stderr);
    assert.ok(a.file.equals(b.file), "a second generation from the same verdict JSON gives the same bytes");
  });

  test(`V-50 (${page}): the font is embedded whole, not subset: one FontFile2 stream, the pinned font's bytes [spec, v0.10 4.9]`, () => {
    const pdf = readPdf(make(`v50-${page}-font`, v10.bytes, ["--page", page, "--out", "<out>"]).file);
    const fonts = [...pdf.objects.values()].filter((o) => /\/Length1/.test(o.dict));
    assert.equal(fonts.length, 1);
    assert.equal(sha256(fonts[0].stream), FONT_SHA256);
    assert.match(fonts[0].dict, new RegExp(`/Length1 ${readFileSync(FONT).length}\\b`));
    assert.match(pdf.text, /\/FontFile2 \d+ 0 R/);
    assert.doesNotMatch(pdf.text, /\/BaseFont \/[A-Z]{6}\+/, "no subset tag");
    assert.equal([...pdf.text.matchAll(/\/Type \/Font\b/g)].length, 1, "the only font is the pinned one");
  });

  test(`V-50 (${page}): no licence notice, and no annotation, link, action, JavaScript, form field, embedded file, image or XMP metadata [spec, v0.10 4.9]`, () => {
    const pdf = readPdf(make(`v50-${page}-none`, v10.bytes, ["--page", page, "--out", "<out>"]).file);
    for (const k of ["/Annots", "/Link", "/URI", "/Action", "/A ", "/AA", "/OpenAction", "/JavaScript", "/JS", "/AcroForm", "/Widget", "/EmbeddedFile", "/XObject", "/Image", "/Metadata", "/XML"]) assert.ok(!outsideFont(pdf).includes(k), `no ${k}`);
    const all = drawnStrings(pdf).shown.join("\n");
    for (const w of [/licen[cs]e/i, /copyright/i, /bitstream/i, /dejavu/i]) assert.doesNotMatch(all, w);
  });

  test(`V-50 (${page}): PDF 1.7; the Info dictionary holds only Producer and CreationDate, from checked_at; both ID entries are the first 16 bytes of the verdict JSON's SHA-256 [spec, v0.10 4.9]`, () => {
    const pdf = readPdf(make(`v50-${page}-info`, v10.bytes, ["--page", page, "--out", "<out>"]).file);
    const info = Number(/\/Info (\d+) 0 R/.exec(pdf.trailer)[1]);
    const d = pdf.objects.get(info).dict;
    assert.deepEqual([...d.matchAll(/\/(\w+) /g)].map((m) => m[1]), ["Producer", "CreationDate"]);
    const t = v10.output.checked_at;
    assert.ok(d.includes(`/CreationDate (D:${t.slice(0, 4)}${t.slice(5, 7)}${t.slice(8, 10)}${t.slice(11, 13)}${t.slice(14, 16)}${t.slice(17, 19)}Z)`), d);
    assert.match(d, /\/Producer \(chirindo-evidence-bundle make-exhibit 0\.10\.0\)/);
    const id = sha256(v10.bytes).slice(0, 32);
    assert.ok(pdf.trailer.includes(`/ID [<${id}> <${id}>]`), pdf.trailer);
  });

  test(`V-50 (${page}): what the content stream draws is the writer's list, each a hex string, and the verdict values it shows are the verdict's [spec, v0.10 4.9]`, () => {
    const r = make(`v50-${page}-text`, v10.bytes, ["--page", page, "--out", "<out>"]);
    const { shown, literal } = drawnStrings(readPdf(r.file));
    assert.equal(literal, 0, "no string is drawn as a literal string");
    const w = lib.makeExhibit(v10.bytes, { page });
    assert.ok(w.bytes.equals(r.file), "the library entry gives the command's bytes");
    assert.deepEqual(shown, w.lines.map(shownForm), "each drawn line, as the writer lists it");
    // The lines are the writer's strings wrapped at spaces: no character is lost.
    const flat = (xs) => xs.join("").replace(/ /g, "");
    assert.equal(flat(w.lines), flat(w.drawn.map((d) => d.text)));
    // Each string the writer took from the verdict equals the verdict's value there.
    const at = (o, p) => p.split(".").reduce((x, k) => (x == null ? x : x[/^\d+$/.test(k) ? Number(k) : k]), o);
    const fromVerdict = w.drawn.filter((d) => d.from);
    assert.ok(fromVerdict.length > 40);
    for (const d of fromVerdict) assert.equal(d.text, String(at(v10.output, d.from)), d.from);
  });

  test(`V-50 (${page}): the blocks in 4.9's order: L24, L14 and L3 first, the items a dispute decider asks for, the verdict, every binding, the times, every other limit, then the footer [spec, v0.10 4.9]`, () => {
    const w = lib.makeExhibit(v10.bytes, { page });
    const o = v10.output;
    const first = (p) => w.drawn.findIndex((d) => d.from === p);
    const limitAt = (id) => first(`limits.${o.limits.findIndex((l) => l.id === id)}.text`);
    const items = w.drawn.findIndex((d) => !d.from && /^Agent identity/.test(d.text));
    // L24, L14 and L3 (all attached in V-10), the items, the verdict, the
    // bindings, the times, the first other limit (L1), the footer.
    const order = [limitAt("L24"), limitAt("L14"), limitAt("L3"), items, first("verdict.code"), first("bindings.0.id"), first("times.0.value"), limitAt("L1"), first("checked_at")];
    assert.ok(order.every((i) => i >= 0), JSON.stringify(order));
    for (let i = 1; i < order.length; i++) assert.ok(order[i] > order[i - 1], `block ${i} after block ${i - 1}: ${order}`);
    // Every limit in full, each once; every binding with its state and reason.
    for (const [i, l] of o.limits.entries()) assert.equal(w.drawn.filter((d) => d.from === `limits.${i}.text`).length, 1, `${l.id} once, in full`);
    for (const [i, b] of o.bindings.entries()) {
      assert.ok(first(`bindings.${i}.state`) > 0, `${b.id}'s state`);
      if (b.reason !== null) assert.ok(first(`bindings.${i}.reason`) > 0, `${b.id}'s reason`);
    }
    // The stated authorization time with the clock processor.
    const a = w.drawn.map((d) => d.from).lastIndexOf("card.authorized_at");
    assert.ok(a > first("times.0.value") && /clock processor/.test(w.drawn[a + 1].text), "the stated authorization time, clock processor");
  });

  test(`V-50 (${page}): the page's MediaBox [derived]`, () => {
    const pdf = readPdf(make(`v50-${page}-box`, v10.bytes, ["--page", page, "--out", "<out>"]).file);
    assert.match(pdf.text, page === "letter" ? /\/MediaBox \[0 0 612 792\]/ : /\/MediaBox \[0 0 595\.28 841\.89\]/);
  });
}

test("V-51: the exhibits of V-11 to V-31's verdicts and of the pointer cases' verdicts: one page, at most 5,000,000 bytes, a second generation byte-equal; a pointer-unfetchable verdict's outcome in the footer [spec, v0.10 4.9]", () => {
  // The card vectors of A1 and A2 have other ids; V-11 to V-31 are A3's.
  const num = (id) => Number(/^V-(\d+)/.exec(id)?.[1] ?? NaN);
  const set = [...card.filter((c) => num(c.id) >= 11 && num(c.id) <= 31), ...pointer];
  assert.ok(set.length >= 30, `${set.length} verdicts`);
  for (const c of set) {
    const a = make(`v51-${c.id}-1`, c.bytes, ["--page", "letter", "--out", "<out>"]);
    assert.equal(a.status, 0, `${c.id}: ${a.stderr}`);
    const pdf = readPdf(a.file);
    assert.equal(pages(pdf), 1, c.id);
    assert.ok(a.file.length <= MAX_BYTES, c.id);
    assert.ok(a.file.equals(make(`v51-${c.id}-2`, c.bytes, ["--page", "letter", "--out", "<out>"]).file), `${c.id}: byte-equal`);
    if (c.output.pointer) {
      const shown = drawnStrings(pdf).shown.join("\n");
      for (const v of [c.output.pointer.uri, c.output.pointer.stated_entry, c.output.pointer.status]) assert.ok(shown.includes(v), `${c.id}: the footer names ${v}`);
    }
  }
  assert.ok(pointer.some((c) => c.output.pointer.status === "unfetchable"), "a pointer-unfetchable verdict is among them");
});

test("V-52: PDF string syntax, a backslash, a tab, a control character and characters the font's encoding lacks are drawn as text: the parentheses and the backslash as themselves, the others as [U+XXXX] [spec for as text, derived for the form]", () => {
  assert.equal(v52.output.card.order.merchant_id, HOSTILE, "the verdict reports the order's merchant_id");
  const r = make("v52", v52.bytes, ["--page", "letter", "--out", "<out>"]);
  assert.equal(r.status, 0, r.stderr);
  const pdf = readPdf(r.file);
  const { shown, literal } = drawnStrings(pdf);
  assert.equal(literal, 0);
  assert.ok(shown.some((s) => s.includes(HOSTILE_SHOWN)), "merchant_id drawn in the [U+XXXX] form");
  // The content stream holds only text operators and hex strings: nothing in it is the string's own syntax.
  const { content } = drawnStrings(pdf);
  assert.doesNotMatch(content.replace(/<[0-9a-f]*> Tj/g, ""), /[()\\]/, "no parenthesis or backslash outside the hex strings");
  // The fixed set of objects: catalog, pages, page, font, contents, descriptor, font file, info.
  assert.equal(pdf.objects.size, 8);
});

test("V-52: the bundle's reference, the item's name and assembled_by are not in the verdict, so the exhibit, a view of the verdict, does not draw them [derived; spec 4.9 P9]", () => {
  const w = lib.makeExhibit(v52.bytes, { page: "letter" });
  const fromVerdict = new Set(w.drawn.filter((d) => d.from).map((d) => d.from));
  assert.deepEqual(w.drawn.filter((d) => d.text.includes(HOSTILE)).map((d) => d.from), ["card.order.merchant_id"]);
  assert.ok(fromVerdict.has("card.order.merchant_id"));
  assert.ok(!JSON.stringify(v52.output).includes('"reference"'), "the verdict has no reference member");
});

test("V-53: limits that cannot fit at 6 points give exit 3, exhibit not written, and no file [derived]", () => {
  const r = make("v53", v10.bytes, ["--page", "letter", "--out", "<out>", "--test-page-height", "200"]);
  assert.equal(r.status, 3);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /^exhibit not written: .+\n$/);
  assert.equal(r.file, null);
});

test("make-exhibit.mjs: usage errors, a font of another digest and a file that is not a 0.10 verdict exit 2 with nothing written [derived]", () => {
  const cases = [
    [[], /^usage error: /],
    [["--page", "legal", "--out", "<out>"], /^usage error: /],
    [["--page", "letter"], /^usage error: /],
    [["--page", "letter", "--out", "<out>", "--page", "a4"], /^usage error: /],
  ];
  for (const [args, re] of cases) {
    const r = make("usage", v10.bytes, args);
    assert.equal(r.status, 2, JSON.stringify(args));
    assert.match(r.stderr, re);
    assert.equal(r.file, null);
  }
  const other = path.join(dir, "other.ttf");
  copyFileSync(FONT, other);
  writeFileSync(other, Buffer.concat([readFileSync(other), Buffer.from([0])]));
  const f = make("font", v10.bytes, ["--page", "letter", "--out", "<out>", "--test-font", other]);
  assert.equal(f.status, 2);
  assert.match(f.stderr, /font/);
  assert.equal(f.file, null);
  const v09 = Buffer.from(JSON.stringify({ ...v10.output, type: "evidence-bundle-verdict/0.9" }, null, 2) + "\n");
  for (const bytes of [v09, Buffer.from("not json"), Buffer.from("{}")]) {
    const r = make("notverdict", bytes, ["--page", "letter", "--out", "<out>"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /^usage error: .*verdict/);
    assert.equal(r.file, null);
  }
});
