// Strict JSON ingest gate (F3 / F4).
//
// Closes the recomputability hole at the JSON-string ingest boundary. Bare
// JSON.parse silently:
//   (a) truncates integers outside the IEEE-754 safe range
//       (9007199254740993 -> 9007199254740992), and
//   (b) collapses duplicate object members to a single last-wins value.
// Either makes an evidence chain non-recomputable: the bytes a gate evaluated
// and the bytes an independent verifier reconstructs from the same source text
// can diverge, at the exact point where the signed commitment is supposed to be
// reproducible. See conformance vectors V8/V9 and VERIFICATION-REPORT F3/F4.
//
// Design: this is a GATE, not a second parser. `validate()` scans the raw text
// for the two violations and throws; the VALUE is then produced by the trusted
// built-in JSON.parse. The scanner never constructs the returned value, so a
// scanner defect can only over-reject valid input — it can never corrupt the
// parsed result. Fail-closed: a violation throws StrictJsonParseError and the
// caller MUST NOT fall back to hashing the raw bytes.
//
// Scope boundary (deliberate): "unsafe_number" means an INTEGER-form token
// (no fraction, no exponent) whose magnitude exceeds Number.MAX_SAFE_INTEGER.
// Fractional / exponential tokens are genuine IEEE-754 doubles whose shortest
// round-trip is shared by producer and verifier via the same JCS number
// formatting, so they are deterministic and are NOT rejected. This matches the
// corpus's V8 definition exactly. (A token like `1e400` that overflows to
// Infinity is an adjacent pathology not covered here — see the standing gap.)

export type StrictJsonReason = "unsafe_number" | "duplicate_member";

export class StrictJsonParseError extends Error {
  constructor(
    readonly reason: StrictJsonReason,
    readonly detail: string,
  ) {
    super(`${reason}: ${detail}`);
    this.name = "StrictJsonParseError";
  }
}

// True iff `token` is a full-form integer (optional sign, digits only) whose
// value is outside [-(2^53-1), 2^53-1]. Number(token) has already truncated a
// too-large integer to a non-safe value, so !Number.isSafeInteger catches it.
function isUnsafeIntegerToken(token: string): boolean {
  if (!/^-?\d+$/.test(token)) return false; // has '.', 'e', or 'E' -> genuine float
  return !Number.isSafeInteger(Number(token));
}

// Matches a JSON number token starting at the current position. Sticky so we
// never slice the input (O(1) per token, O(n) overall). Intentionally loose —
// validate() is not the real parser; JSON.parse rejects a malformed number.
const NUMBER_TOKEN = /-?\d[\d.eE+-]*/y;

interface ObjectFrame {
  kind: "object";
  keys: Set<string>;
}
interface ArrayFrame {
  kind: "array";
}
type Frame = ObjectFrame | ArrayFrame;

function isWs(c: string): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r";
}

// Read a JSON string beginning at text[start] === '"'. Returns the DECODED
// content (so a key written as "a" compares equal to "a") and the index
// just past the closing quote. Lenient on escapes — JSON.parse is the arbiter
// of true validity; this only needs correct string BOUNDARIES so structural
// scanning (key vs value, member counting) stays aligned.
function readString(text: string, start: number): { value: string; next: number } {
  let out = "";
  let i = start + 1; // skip opening quote
  const n = text.length;
  while (i < n) {
    const c = text[i++]!;
    if (c === '"') return { value: out, next: i };
    if (c === "\\") {
      const e = text[i++]!;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
          i += 4;
          break;
        }
        default: out += e; // unknown escape — JSON.parse will reject if invalid
      }
      continue;
    }
    out += c;
  }
  return { value: out, next: i }; // unterminated — JSON.parse produces the error
}

// Scan raw JSON text for unsafe integers and duplicate member names at ANY
// depth. Throws StrictJsonParseError on the first violation; otherwise returns.
function validate(text: string): void {
  const n = text.length;
  const stack: Frame[] = [];
  // In an object, the next string literal is a KEY when positioned right after
  // '{' or ','. Cleared after ':' (value) and inside arrays / at top level.
  let expectKey = false;
  let i = 0;

  while (i < n) {
    const c = text[i]!;
    if (isWs(c)) {
      i++;
      continue;
    }
    switch (c) {
      case "{":
        stack.push({ kind: "object", keys: new Set() });
        expectKey = true;
        i++;
        break;
      case "[":
        stack.push({ kind: "array" });
        expectKey = false;
        i++;
        break;
      case "}":
      case "]":
        stack.pop();
        expectKey = false; // back in the parent's value position
        i++;
        break;
      case ":":
        expectKey = false;
        i++;
        break;
      case ",": {
        const top = stack[stack.length - 1];
        expectKey = top !== undefined && top.kind === "object";
        i++;
        break;
      }
      case '"': {
        const { value, next } = readString(text, i);
        const top = stack[stack.length - 1];
        if (expectKey && top !== undefined && top.kind === "object") {
          if (top.keys.has(value)) {
            throw new StrictJsonParseError(
              "duplicate_member",
              `member "${value}" appears more than once in the same object`,
            );
          }
          top.keys.add(value);
        }
        i = next;
        break;
      }
      default: {
        NUMBER_TOKEN.lastIndex = i;
        const m = NUMBER_TOKEN.exec(text);
        if (m !== null && m.index === i) {
          if (isUnsafeIntegerToken(m[0])) {
            throw new StrictJsonParseError(
              "unsafe_number",
              `integer ${m[0]} is outside the IEEE-754 safe range [-(2^53-1), 2^53-1]`,
            );
          }
          i += m[0].length;
        } else {
          i++; // a char of true/false/null — harmless to step over
        }
        break;
      }
    }
  }
}

// Parse `text` as JSON, failing closed on unsafe integers or duplicate member
// names before any value is produced. On the two strict violations, throws
// StrictJsonParseError. On genuinely malformed JSON, throws whatever JSON.parse
// throws (a SyntaxError) — callers distinguish via `instanceof`.
export function strictJsonParse(text: string): unknown {
  validate(text);
  return JSON.parse(text);
}
