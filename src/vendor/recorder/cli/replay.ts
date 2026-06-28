// `recorder replay` — human-readable timeline of a chain file.
//
// Format: `[<seq>] <type>: <details>[ (outcome: <x>)]`
// Where `details` is per-type:
//   shell      — argv joined by space
//   file_edit  — path
//   file_read  — path
//   tool_call  — tool
//   mcp_call   — server.tool
//
// The outcome suffix is omitted for "executed" (the default success case) so
// the common path stays terse; it's shown for blocked/denied/errored/timed_out
// because those are what an operator scanning a timeline cares about.

import { readChainFile } from "../io.js";
import type { RecordEvent, SignedRecord } from "../record.js";

export interface ReplayOptions {
  chainPath: string;
}

export function runReplay(opts: ReplayOptions): string[] {
  const file = readChainFile(opts.chainPath);
  return file.records.map(formatRecord);
}

export function formatRecord(r: SignedRecord): string {
  const details = formatEvent(r.event);
  const outcomeSuffix =
    r.event.outcome === "executed" ? "" : ` (outcome: ${r.event.outcome})`;
  return `[${r.seq}] ${r.event.type}: ${details}${outcomeSuffix}`;
}

function formatEvent(event: RecordEvent): string {
  switch (event.type) {
    case "shell":
      return event.argv.join(" ");
    case "file_edit":
      return event.path;
    case "file_read":
      return event.path;
    case "tool_call":
      return event.tool_name;
    case "mcp_call":
      return `${event.server}.${event.tool_name}`;
  }
}
