// RFC 8785 JSON Canonicalization Scheme (JCS).
//
// We deliberately use a vetted third-party implementation rather than
// hand-rolling JCS. The golden vector locks correctness end-to-end:
// if `canonicalize` ever diverges from RFC 8785, the vector test fails
// and we notice before anything depends on the wrong bytes.

// `canonicalize` is a CJS module that uses `module.exports = function`.
// Under NodeNext + esModuleInterop this round-trips at runtime but TS sees
// the default import as a namespace, not as a callable. Resolve via
// createRequire so the call site is unambiguous to both type-checker and Node.
import { createRequire } from "node:module";
const cjsRequire = createRequire(import.meta.url);
const canonicalizeImpl = cjsRequire("canonicalize") as (
  input: unknown,
) => string | undefined;

export function jcs(value: unknown): string {
  const out = canonicalizeImpl(value);
  if (out === undefined) {
    throw new Error(
      "JCS canonicalization returned undefined (input contains a value " +
        "that has no JSON representation — e.g. function or undefined)",
    );
  }
  return out;
}

export function jcsBytes(value: unknown): Buffer {
  return Buffer.from(jcs(value), "utf8");
}
