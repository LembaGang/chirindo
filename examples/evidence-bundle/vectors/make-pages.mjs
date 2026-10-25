// Writes the page-ready files of a card worked example under pages/: the
// bundle (<id>.bundle.json), the pins it is run with (<id>-pins/pins.json),
// the exhibit of its offline verdict (<id>.letter.pdf) and the page
// (<id>.json, lib/pages.mjs). The offline verdict is check-bundle.mjs's
// output for the committed bundle file with the page's stated inputs.
//
//   node vectors/make-pages.mjs --write we-4-1
//
// writes WE-4 variant 1's page from V-10's TEST bundle (TEST witness key and
// TEST pins). The live witness step replaces it, and writes the other three
// pages, from page bundles that carry Headless Oracle's receipts (writePage,
// with an online verdict).

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { makeExhibit } from "../lib/exhibit.mjs";
import { pageOf } from "../lib/pages.mjs";
import { bundleBytes } from "../lib/we1.mjs";
import { FOLDER, VECTORS } from "./make-vectors.mjs";

const PAGES = path.join(FOLDER, "pages");
const json = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8");

// Writes one page. `args` are check-bundle.mjs's stated inputs, with "<pins>"
// where the page's pins directory goes; `online` as lib/pages.mjs takes it.
export function writePage(id, { doc, args, pins, online }) {
  mkdirSync(path.join(PAGES, `${id}-pins`), { recursive: true });
  const rel = (f) => `pages/${f}`;
  const bundle = { path: rel(`${id}.bundle.json`), bytes: bundleBytes(doc) };
  writeFileSync(path.join(FOLDER, bundle.path), bundle.bytes);
  writeFileSync(path.join(PAGES, `${id}-pins`, "pins.json"), json(pins));
  const stated = { args: args.map((a) => (a === "<pins>" ? rel(`${id}-pins`) : a)), pins: rel(`${id}-pins/pins.json`) };
  const r = spawnSync(process.execPath, [path.join(FOLDER, "check-bundle.mjs"), bundle.path, ...stated.args], { cwd: FOLDER, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${id}: check-bundle.mjs exited ${r.status}: ${r.stderr.trim()}`);
  const verdictBytes = Buffer.from(r.stdout, "utf8");
  const exhibit = { path: rel(`${id}.letter.pdf`), bytes: makeExhibit(verdictBytes, { page: "letter" }).bytes };
  writeFileSync(path.join(FOLDER, exhibit.path), exhibit.bytes);
  const page = pageOf({ id, bundle, stated, verdictBytes, exhibit, online });
  writeFileSync(path.join(PAGES, `${id}.json`), json(page));
  return page;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  if (args[0] !== "--write" || args[1] !== "we-4-1" || args.length !== 2) {
    process.stderr.write("usage: node vectors/make-pages.mjs --write we-4-1\n");
    process.exitCode = 2;
  } else {
    const v = VECTORS.find((x) => x.id === "V-10");
    const built = await v.build();
    const p = writePage("we-4-1", { doc: built.doc, args: v.args, pins: built.pins });
    process.stdout.write(`${p.id} ${p.offline_verdict.verdict.code} ${p.bundle.sha256} ${p.exhibit.sha256}\n`);
  }
}
