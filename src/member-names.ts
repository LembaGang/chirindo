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
//
// Values a downstream may compare the same way are here too: a tool name for a
// deny rule (src/policy.ts) and a method value (src/proxy.ts) are compared
// without regard to case by caseKeys and sameUnderCase below, and a method
// that is not a string is read as String() would read it.

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

// Two keys for a name; sameUnderCase holds when either key is equal. The first
// is foldName: it puts together what Go's strings.EqualFold and Java's
// equalsIgnoreCase match. The second applies toUpperCase and toLowerCase until
// nothing changes, so that names equal after a full case mapping meet too:
// "ß" and "ss", or the ligature "ﬁ" (U+FB01) and "fi", which a downstream
// comparing upper-cased names, or Python's str.casefold(), takes for the same.
export function caseKeys(name: string): [string, string] {
  let full = name;
  for (let k = 0; k < 8; k++) {
    const next = full.toUpperCase().toLowerCase();
    if (next === full) break;
    full = next;
  }
  return [foldName(name), full];
}

export function sameUnderCase(a: string, b: string): boolean {
  const ka = caseKeys(a);
  const kb = caseKeys(b);
  return ka[0] === kb[0] || ka[1] === kb[1];
}

// White space at either end (JavaScript's \s and Unicode White_Space), and a
// control or format character (Unicode categories Cc and Cf).
export const EDGE_WHITE_SPACE = /^[\s\p{White_Space}]|[\s\p{White_Space}]$/u;
export const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
const EDGE_WHITE_SPACE_ALL = /^[\s\p{White_Space}]+|[\s\p{White_Space}]+$/gu;
const CONTROL_OR_FORMAT_ALL = /[\p{Cc}\p{Cf}]/gu;

// Whether a method value names tools/call for a downstream that drops control
// and format characters, trims white space at either end and compares without
// regard to case ("TOOLS/CALL", "tools/call ", "tools/call\u200b"). The exact
// "tools/call" counts too.
export function methodNamesToolsCall(value: string): boolean {
  const bare = value.replace(CONTROL_OR_FORMAT_ALL, "").replace(EDGE_WHITE_SPACE_ALL, "");
  return sameUnderCase(bare, "tools/call");
}

// Arrays nested deeper than this are not followed (see below).
const MAX_METHOD_DEPTH = 64;

// Whether a method value of any JSON type could be read as tools/call: a
// string through methodNamesToolsCall; an array through each of its elements,
// at any depth (a downstream may take method[0]). That covers what String()
// makes of an array too, which a downstream reading the method as text or as
// a key (HANDLERS[msg.method]) sees: String() joins the elements' texts with
// commas, and dropping control and format characters, trimming white space
// and folding case leave every comma in place, so an array's text reads as
// tools/call only when the array has a single element whose text does. A
// number, true, false, null or an object never reads as tools/call (an
// object's text is "[object Object]"; String() throws for one with its own
// toString member). Arrays nested deeper than MAX_METHOD_DEPTH count as
// tools/call: such a line is refused whatever this says, and this only
// decides whether the refusal gets a DENY receipt.
export function methodValueNamesToolsCall(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return methodNamesToolsCall(value);
  if (!Array.isArray(value)) return false;
  if (depth >= MAX_METHOD_DEPTH) return true;
  return value.some((element) => methodValueNamesToolsCall(element, depth + 1));
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

// The member names of the top-level object, in order and with any repeats
// (JSON.parse keeps one of each); an empty list for any other value.
export function topLevelMemberNames(text: string): string[] {
  let i = skipWs(text, 0);
  if (text[i] !== "{") return [];
  const names: string[] = [];
  i = skipWs(text, i + 1);
  if (text[i] === "}") return names;
  for (;;) {
    const nameEnd = stringEnd(text, i);
    names.push(JSON.parse(text.slice(i, nameEnd)) as string);
    i = skipWs(text, skipWs(text, nameEnd) + 1); // past the colon
    i = skipWs(text, valueEnd(text, i));
    if (text[i] !== ",") return names;
    i = skipWs(text, i + 1);
  }
}

// Whether one of `names` folds to "method": a reader matching member names
// without regard to case takes the message for a request or a notification.
export function namesMethod(names: readonly string[]): boolean {
  return names.some((n) => foldName(n) === METHOD_FOLD);
}

// Whether a line holds a tools/call as a case-insensitive reader could take
// it: a top-level member whose name folds to "method" with a value that
// methodValueNamesToolsCall accepts (an exact "method" member with
// "tools/call" counts, and so does one that a later duplicate overwrote, or a
// method that is not a string but reads as tools/call). For a top-level array,
// one answer per element; for any other top-level value, an empty list.
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
    if (foldName(name) === METHOD_FOLD && methodValueNamesToolsCall(JSON.parse(text.slice(i, end)))) {
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
