// The gate's own version, read once from the package.json that ships with it.
//
// Receipts carry it as `agent.version` (src/receipt.ts GATE_AGENT); before
// 0.5.3 every receipt said "0.0.1" whatever the package version was. This file
// and its build output (dist/version.js) both sit one directory below the
// package root, so "../package.json" is the same file under tsx in the tests
// and in the published package; npm always packs package.json, whatever
// `files` lists. The name check refuses any other package's package.json.

import { readFileSync } from "node:fs";

const PACKAGE_NAME = "@headlessoracle/chirindo";

function readGateVersion(): string {
  const url = new URL("../package.json", import.meta.url);
  const pkg = JSON.parse(readFileSync(url, "utf8")) as {
    name?: unknown;
    version?: unknown;
  };
  if (
    pkg.name !== PACKAGE_NAME ||
    typeof pkg.version !== "string" ||
    pkg.version.length === 0
  ) {
    throw new Error(
      `chirindo: ${url.href} is not the ${PACKAGE_NAME} package.json; ` +
        `cannot tell the gate version`,
    );
  }
  return pkg.version;
}

export const GATE_VERSION: string = readGateVersion();
