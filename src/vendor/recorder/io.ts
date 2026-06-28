// Chain file IO — JSONL.
//
// One JSON object per line. Records appear first in seq order; an optional
// checkpoint is the LAST line. We distinguish by the discriminator:
//   record:     no top-level `type` field
//   checkpoint: `"type": "checkpoint"` at the top level
//
// JSONL is chosen so writers can append a single record without rewriting
// the file — relevant once the hook adapter (A1.3) is writing live.

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import type {
  SignedCheckpoint,
  SignedRecord,
} from "./record.js";

export interface ChainFile {
  records: SignedRecord[];
  checkpoint: SignedCheckpoint | null;
}

export class ChainParseError extends Error {
  constructor(
    message: string,
    public readonly lineNumber: number,
  ) {
    super(`line ${lineNumber}: ${message}`);
    this.name = "ChainParseError";
  }
}

// Parse JSONL text into records + optional trailing checkpoint.
// Tolerates blank lines and trailing newline. Does not validate signatures
// or linkage — that is the verifier's job; this is structural parsing only.
export function parseChainJsonl(text: string): ChainFile {
  const records: SignedRecord[] = [];
  let checkpoint: SignedCheckpoint | null = null;

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      throw new ChainParseError(
        `invalid JSON (${(e as Error).message})`,
        i + 1,
      );
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new ChainParseError("expected object", i + 1);
    }
    const obj = parsed as Record<string, unknown>;

    if (obj["type"] === "checkpoint") {
      if (checkpoint !== null) {
        throw new ChainParseError("multiple checkpoints", i + 1);
      }
      checkpoint = obj as unknown as SignedCheckpoint;
    } else {
      if (checkpoint !== null) {
        throw new ChainParseError(
          "record appears after checkpoint",
          i + 1,
        );
      }
      records.push(obj as unknown as SignedRecord);
    }
  }
  return { records, checkpoint };
}

// Serialize records + optional checkpoint to JSONL with LF line endings.
export function serializeChainJsonl(file: ChainFile): string {
  const lines = file.records.map((r) => JSON.stringify(r));
  if (file.checkpoint !== null) {
    lines.push(JSON.stringify(file.checkpoint));
  }
  return lines.join("\n") + (lines.length > 0 ? "\n" : "");
}

export function readChainFile(path: string): ChainFile {
  const text = readFileSync(path, "utf8");
  return parseChainJsonl(text);
}

export function writeChainFile(path: string, file: ChainFile): void {
  writeFileSync(path, serializeChainJsonl(file), "utf8");
}

// O(1) append: write a single record as one new line. Use this when an
// adapter handler is appending live; rewriting the whole file would defeat
// the JSONL-append design.
export function appendRecordLine(path: string, record: SignedRecord): void {
  appendFileSync(path, JSON.stringify(record) + "\n", "utf8");
}

// Read a chain file if it exists; return an empty chain otherwise. Lets a
// hook handler treat "first event of a session" identically to subsequent
// ones — no special "create the file" branch.
export function readChainFileOrEmpty(path: string): ChainFile {
  if (!existsSync(path)) {
    return { records: [], checkpoint: null };
  }
  return readChainFile(path);
}
