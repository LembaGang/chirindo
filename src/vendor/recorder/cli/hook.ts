// `recorder hook` — the Cursor-side entry point.
//
// Reads a single hook payload from stdin, appends a signed record to the
// per-session chain file, and writes the permissive output to stdout. The
// process exits 0 in EVERY case the recorder is responsible for handling.
//
// OBSERVE-ONLY INVARIANT (hard, not a flag):
//   - We never emit deny / ask / block.
//   - We never exit non-zero on recording failures.
//   - We never use exit code 2 (which Cursor interprets as block).
//   - If signing, file I/O, identity load, or mapping throws, we log to
//     stderr, emit the permissive output, and exit 0. The agent loop runs
//     unimpeded; the worst-case effect of a recorder bug is a missing
//     record, never a stalled agent.
//
// See src/adapter/cursor.ts for the per-event payload mapping and the
// live-doc citations for Cursor's hook contract.

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { PRODUCT_NAME } from "../brand.js";
import { Chain } from "../chain.js";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  loadFullIdentity,
} from "../identity.js";
import { appendRecordLine, readChainFileOrEmpty } from "../io.js";
import { mapToRecord, type AdapterOptions } from "../adapter/cursor.js";
import type { CursorHookInput } from "../adapter/payloads.js";
import { permissiveOutputFor } from "../adapter/payloads.js";
import type { AgentInfo } from "../record.js";

export interface HookOptions {
  // Where the recorder stores its identity. Default: `./.<PRODUCT_NAME>/`.
  dataDir: string;
  // Where chain files are written. Default: `<dataDir>/sessions/`.
  sessionsDir?: string;
  hashSensitive?: boolean;
  // For tests: clock + agent metadata. In production these have defaults.
  agent?: AgentInfo;
  now?: () => string;
}

export interface HookResult {
  // What the CLI dispatcher writes to stdout.
  stdoutPayload: object;
  // Exit code — ALWAYS 0 in observe-only mode.
  exitCode: 0;
  // For tests / diagnostics. Errors here are logged to stderr by the
  // dispatcher; they NEVER affect stdoutPayload or exitCode.
  recordingError?: string;
  recordedPath?: string;
}

const DEFAULT_AGENT: AgentInfo = {
  vendor: "cursor",
  version: "unknown",
};

// The core handler. Pure-ish: side effects are file I/O on the chain file
// and identity reads. Returns the permissive response no matter what.
export function runHook(
  inputJson: string,
  opts: HookOptions,
): HookResult {
  let input: CursorHookInput;
  try {
    input = JSON.parse(inputJson) as CursorHookInput;
  } catch (e) {
    return permissiveResult("invalid hook input JSON: " + describe(e), {
      hookEventName: undefined,
    });
  }
  const hookEventName = input.hook_event_name;
  const out = permissiveOutputFor(hookEventName);

  try {
    const event = mapToRecord(input, adapterOptions(opts));
    if (event === null) {
      // No record to write (e.g. unsupported hook event). Still permissive.
      return { stdoutPayload: out, exitCode: 0 };
    }
    const sessionId = sessionIdOf(input);
    const chainPath = chainPathFor(opts, sessionId);
    const identityPath = join(opts.dataDir, IDENTITY_FILENAME);
    const privateKeyPath = join(opts.dataDir, PRIVATE_KEY_FILENAME);
    const identity = loadFullIdentity(identityPath, privateKeyPath);
    const file = readChainFileOrEmpty(chainPath);
    const chain = Chain.fromRecords(file.records, {
      sessionId,
      agent: opts.agent ?? DEFAULT_AGENT,
      kid: identity.kid,
      privateKey: identity.privateKey,
      ...(opts.now ? { now: opts.now } : {}),
    });
    const record = chain.append(event);
    ensureDir(dirname(chainPath));
    appendRecordLine(chainPath, record);
    return { stdoutPayload: out, exitCode: 0, recordedPath: chainPath };
  } catch (e) {
    return permissiveResult(describe(e), { hookEventName });
  }
}

function permissiveResult(
  recordingError: string,
  ctx: { hookEventName?: string | undefined },
): HookResult {
  return {
    stdoutPayload: permissiveOutputFor(ctx.hookEventName ?? ""),
    exitCode: 0,
    recordingError,
  };
}

function adapterOptions(opts: HookOptions): AdapterOptions {
  return opts.hashSensitive ? { hashSensitive: true } : {};
}

function sessionIdOf(input: CursorHookInput): string {
  // Cursor's beforeShellExecution / afterShellExecution / etc. carry
  // conversation_id in the common fields (sessionStart's own session_id
  // field is not present on these events). conversation_id is sufficient
  // for a per-Cursor-conversation chain file.
  if (typeof input.conversation_id === "string" && input.conversation_id) {
    return input.conversation_id;
  }
  // Fallback: use a fixed string. The chain file will still verify but
  // multiple unknown-conversation sessions would collide.
  return "unknown-conversation";
}

function chainPathFor(opts: HookOptions, sessionId: string): string {
  const sessions = opts.sessionsDir ?? join(opts.dataDir, "sessions");
  return join(sessions, `${sessionId}.jsonl`);
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function describe(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

// Convenience for the CLI dispatcher when it has been given stdin already.
export function readStdinSync(): string {
  return readFileSync(0, "utf8");
}

export function defaultDataDir(): string {
  return `./.${PRODUCT_NAME}`;
}
