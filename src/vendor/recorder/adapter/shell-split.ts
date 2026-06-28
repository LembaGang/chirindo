// Deterministic shell tokenization.
//
// Cursor's beforeShellExecution hook passes `command` as a single string
// (see https://cursor.com/docs/hooks). The recorder's request_descriptor
// uses `argv` as the canonical identity (see src/request.ts and the A1.1
// amendment). To bridge the two, we split the command string with a
// well-defined, POSIX-shell-like algorithm. Determinism here is the property
// that lets a future gate and the recorder agree on a request's identity.
//
// Rules (kept minimal — full POSIX shell parsing is out of scope):
//   1. Whitespace (space, tab) separates tokens.
//   2. Single quotes preserve the enclosed text verbatim (no escapes inside).
//   3. Double quotes preserve the enclosed text, with backslash escapes for
//      `\\`, `\"`, `\$`, and `` \` ``. No variable expansion.
//   4. Outside quotes, a backslash escapes the next character literally.
//   5. Unterminated quotes throw — the caller decides whether to fall back.
//
// Anything beyond this (subshells, redirection, pipes, glob expansion) is
// NOT interpreted: it appears verbatim as a token. That is the correct
// behavior for a recorder — the gate authorizes the literal argv, and the
// shell itself does the runtime expansion.

export class ShellSplitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShellSplitError";
  }
}

export function shellSplit(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let hasContent = false; // distinguishes "" / '' from "no current token"

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;

    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
      }
      continue;
    }

    if (inDouble) {
      if (ch === '"') {
        inDouble = false;
      } else if (ch === "\\") {
        const next = command[i + 1];
        if (
          next === "\\" ||
          next === '"' ||
          next === "$" ||
          next === "`"
        ) {
          current += next;
          i++;
        } else {
          current += ch;
        }
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === " " || ch === "\t") {
      if (hasContent) {
        tokens.push(current);
        current = "";
        hasContent = false;
      }
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      hasContent = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      hasContent = true;
      continue;
    }
    if (ch === "\\") {
      const next = command[i + 1];
      if (next !== undefined) {
        current += next;
        i++;
        hasContent = true;
        continue;
      }
      // Trailing backslash — preserve literal.
      current += ch;
      hasContent = true;
      continue;
    }

    current += ch;
    hasContent = true;
  }

  if (inSingle || inDouble) {
    throw new ShellSplitError(
      `unterminated ${inSingle ? "single" : "double"} quote in command: ${command}`,
    );
  }
  if (hasContent) tokens.push(current);
  return tokens;
}
