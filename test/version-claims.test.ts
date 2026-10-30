// B-428: the version claims a reader sees agree with package.json. A release
// that bumps the version but leaves a doc saying "not yet released", or a
// README telling users to install a version that does not exist yet, fails
// here instead of on npm.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT } from "./trial-helpers.js";

const read = (f: string) => readFileSync(join(ROOT, f), "utf8").replace(/\r\n/g, "\n");
const pkg = JSON.parse(read("package.json")) as { version: string; exports: Record<string, unknown> };
const changelog = read("CHANGELOG.md");
const readme = read("README.md");

const parse = (v: string) => v.split(".").map(Number) as [number, number, number];
const cmp = (a: string, b: string) => {
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! < y[i]! ? -1 : 1;
  return 0;
};

describe("version claims agree with package.json", () => {
  it("package.json's version is x.y.z", () => {
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("the CHANGELOG's newest version heading is package.json's version", () => {
    const newest = /^## (\d+\.\d+\.\d+)\b/m.exec(changelog);
    expect(newest?.[1]).toBe(pkg.version);
  });

  it("no ## Unreleased heading describes package.json's version", () => {
    // An Unreleased heading may stand only above the entry for the version
    // package.json already names (work after it); the version under it must
    // not be one package.json has already reached.
    const unreleased = changelog.indexOf("\n## Unreleased");
    if (unreleased === -1) return;
    const firstVersion = /^## (\d+\.\d+\.\d+)\b/m.exec(changelog.slice(unreleased));
    expect(firstVersion?.[1]).toBe(pkg.version);
  });

  it("every @headlessoracle/chirindo@x.y.z in README.md is no newer than package.json's", () => {
    const named = [...readme.matchAll(/@headlessoracle\/chirindo@(\d+\.\d+\.\d+)/g)].map((m) => m[1]!);
    for (const v of named) expect([v, cmp(v, pkg.version) <= 0]).toEqual([v, true]);
  });

  it('README.md has no "not yet in a published npm release" once both exports ship', () => {
    expect(Object.keys(pkg.exports)).toEqual(expect.arrayContaining(["./purchase-check", "./trial-recorder"]));
    expect(readme).not.toContain("not yet in a published npm release");
  });
});
