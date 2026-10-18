// Writes the TEST FIXTURES that fixtures/make-fixtures.mjs builds:
//
//   node fixtures/write-fixtures.mjs
//
// It runs unconditionally, so it behaves the same however it is reached.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCase, testPins, writeFiles } from "./make-fixtures.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
writeFiles(path.join(HERE, "test-pins"), testPins());
writeFiles(path.join(HERE, "calldata"), await buildCase("calldata"));
writeFiles(path.join(HERE, "eip3009"), await buildCase("eip3009"));
console.log("wrote fixtures/test-pins, fixtures/calldata, fixtures/eip3009");
