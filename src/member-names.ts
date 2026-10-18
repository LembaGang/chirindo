// Member names that a downstream may read without regard to case.
//
// The gate reads each client line with JSON.parse, which matches member names
// exactly. A downstream server may not. Go's encoding/json, decoding into a
// struct, first looks for a field with the exact name and then for one whose
// name is equal under its fold (src/encoding/json/decode.go and fold.go in
// Go 1.24: ASCII letters to upper case, any other code point to the smallest
// one of its unicode.SimpleFold orbit), and a later member overwrites an
// earlier one. So "Method" or "METHOD" is read as method there, "paramſ"
// (U+017F) as params, and params {"name": "a", "Name": "b"} as the name "b",
// while the gate reads "a". The proxy refuses client lines where such a
// reading could differ from its own (src/proxy.ts).

// The members of a JSON-RPC message the gate reads.
export const ENVELOPE_MEMBERS: readonly string[] = ["jsonrpc", "id", "method", "params"];

// The members of a tools/call's params the gate reads or forwards with meaning.
export const TOOLS_CALL_PARAMS_MEMBERS: readonly string[] = ["name", "arguments", "_meta"];

// U+0130 (capital I with dot above) is not folded by Unicode simple case
// folding, nor by Go, but Java's String.equalsIgnoreCase matches it to i, so
// it folds to i here: the gate refuses more, never less. U+0131 (dotless i)
// folds to i by the rule below, since its upper case is I; Java matches it to
// i as well, Go does not.
const EXTRA_FOLDS = new Map<number, string>([[0x130, "i"]]);

// One code point: the lower case of its upper case, each taken only when it
// is a single code point. Checked against Go's fold for every code point in
// test/member-names.test.ts: whenever Go folds two code points together, so
// does this. It folds a few more together than Go 1.24 (U+0130 and U+0131
// with i, and case pairs that Unicode added after the version Go's tables
// carry), which only makes the gate refuse more.
function foldCodePoint(c: string): string {
  const extra = EXTRA_FOLDS.get(c.codePointAt(0)!);
  if (extra !== undefined) return extra;
  const upper = c.toUpperCase();
  const base = isOneCodePoint(upper) ? upper : c;
  const lower = base.toLowerCase();
  return isOneCodePoint(lower) ? lower : base;
}

function isOneCodePoint(s: string): boolean {
  const cp = s.codePointAt(0);
  return cp !== undefined && s.length === (cp > 0xffff ? 2 : 1);
}

// foldName(a) === foldName(b) when a decoder that ignores case may take a and
// b for the same member name.
export function foldName(name: string): string {
  let out = "";
  for (const c of name) {
    const code = c.charCodeAt(0);
    if (code < 0x80) {
      out += code >= 0x41 && code <= 0x5a ? String.fromCharCode(code + 0x20) : c;
    } else {
      out += foldCodePoint(c);
    }
  }
  return out;
}

// The first of `keys` that is not one of `names` but folds to one of them.
export function caseVariant(
  keys: readonly string[],
  names: readonly string[],
): { key: string; of: string } | null {
  const folded = new Map(names.map((n) => [foldName(n), n] as const));
  for (const key of keys) {
    if (names.includes(key)) continue;
    const of = folded.get(foldName(key));
    if (of !== undefined) return { key, of };
  }
  return null;
}

// The first two of `keys` (all different, as JSON.parse returns them) that
// fold to the same name.
export function foldCollision(keys: readonly string[]): [string, string] | null {
  const seen = new Map<string, string>();
  for (const key of keys) {
    const f = foldName(key);
    const earlier = seen.get(f);
    if (earlier !== undefined) return [earlier, key];
    seen.set(f, key);
  }
  return null;
}

// ---- reading member names from the text ---------------------------------
//
// JSON.parse keeps only the last of two members with the same name, so it
// cannot say whether an earlier "method" member held "tools/call". These
// helpers read the members of the top-level object (or of each object in a
// top-level array) from the text itself. They rely on the text being valid
// JSON (the proxy calls them only after JSON.parse accepted the line) and
// decode each member name and string value with JSON.parse.

const METHOD_FOLD = foldName("method");

// Whether a line holds a tools/call as a case-insensitive reader could take
// it: a top-level member whose name folds to "method" with the string value
// "tools/call" (an exact "method" member counts, and so does one that a later
// duplicate overwrote). For a top-level array, one answer per element; for
// any other top-level value, an empty list.
export function toolsCallClaims(text: string): boolean[] {
  let i = skipWs(text, 0);
  if (text[i] === "{") return [claimsToolsCall(text, i)];
  if (text[i] !== "[") return [];
  const claims: boolean[] = [];
  i = skipWs(text, i + 1);
  if (text[i] === "]") return claims;
  for (;;) {
    claims.push(text[i] === "{" && claimsToolsCall(text, i));
    i = skipWs(text, valueEnd(text, i));
    if (text[i] !== ",") return claims;
    i = skipWs(text, i + 1);
  }
}

function claimsToolsCall(text: string, open: number): boolean {
  let i = skipWs(text, open + 1);
  if (text[i] === "}") return false;
  let claims = false;
  for (;;) {
    const nameEnd = stringEnd(text, i);
    const name = JSON.parse(text.slice(i, nameEnd)) as string;
    i = skipWs(text, skipWs(text, nameEnd) + 1); // past the colon
    const end = valueEnd(text, i);
    if (
      text[i] === '"' &&
      foldName(name) === METHOD_FOLD &&
      JSON.parse(text.slice(i, end)) === "tools/call"
    ) {
      claims = true;
    }
    i = skipWs(text, end);
    if (text[i] !== ",") return claims;
    i = skipWs(text, i + 1);
  }
}

function skipWs(text: string, i: number): number {
  while (i < text.length) {
    const c = text[i];
    if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") break;
    i++;
  }
  return i;
}

// text[i] is the opening quote; returns the index just past the closing one.
function stringEnd(text: string, i: number): number {
  for (let j = i + 1; j < text.length; j++) {
    const c = text[j];
    if (c === "\\") j++;
    else if (c === '"') return j + 1;
  }
  throw new Error("member-names: unterminated string in text that JSON.parse accepted");
}

// text[i] starts a value; returns the index just past it.
function valueEnd(text: string, i: number): number {
  const c = text[i];
  if (c === '"') return stringEnd(text, i);
  if (c === "{" || c === "[") {
    let depth = 0;
    for (let j = i; j < text.length; j++) {
      const d = text[j];
      if (d === '"') {
        j = stringEnd(text, j) - 1;
      } else if (d === "{" || d === "[") {
        depth++;
      } else if (d === "}" || d === "]") {
        depth--;
        if (depth === 0) return j + 1;
      }
    }
    throw new Error("member-names: unclosed value in text that JSON.parse accepted");
  }
  let j = i;
  while (j < text.length) {
    const d = text[j];
    if (d === "," || d === "}" || d === "]" || d === " " || d === "\t" || d === "\n" || d === "\r") break;
    j++;
  }
  return j;
}
