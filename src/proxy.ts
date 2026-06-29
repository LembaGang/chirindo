// Stdio MCP proxy — fail-closed enforcement at the tools/call boundary.
//
// Architecture (per https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio):
//
//   MCP client (e.g. Claude Desktop) ──[stdio]──> THIS PROXY ──[stdio]──> downstream MCP server
//
// The client launches this proxy as its MCP server. The proxy spawns the
// real downstream server as a child process and mediates every JSON-RPC
// frame in both directions. On a `tools/call` from the client:
//
//   - Evaluate policy.
//   - ALLOW: forward to downstream; when the response arrives, append an
//     ALLOW receipt; pass the response back to the client.
//   - DENY:  do NOT forward. Synthesize a response with isError:true,
//     send it back to the client, append a DENY receipt.
//   - FAIL-CLOSED: if policy is unevaluable OR the receipt cannot be
//     written, DENY the call. The agent does NOT get an ungated action.
//
// Every other frame (initialize, tools/list, responses, notifications,
// cancellation) passes through unchanged.
//
// IMPORTANT: stderr is for logging only — MUST NOT carry MCP frames. We
// log gate decisions to stderr; the client's stdout sees only valid MCP.

import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { LoadedFullIdentity } from "./vendor/recorder/index.js";
import { type Policy, type PolicyDecision, evaluate } from "./policy.js";
import { appendReceipt, type GateDecision } from "./receipt.js";
import {
  denyToolResult,
  encodeMessage,
  isRequest,
  splitLines,
  type JsonRpcRequest,
} from "./rpc.js";

export interface ProxyDeps {
  // Process-like handles. Tests inject in-memory streams; the CLI uses
  // process.stdin/stdout and a spawn() for the downstream.
  clientIn: Readable;
  clientOut: Writable;
  spawnDownstream: () => DownstreamProcess;
  // Policy supplier — re-read on each tools/call so an operator can edit
  // the file mid-session. Returns null on load failure → fail-closed.
  loadPolicy: () => Policy | null;
  identity: LoadedFullIdentity;
  sessionId: string;
  serverLabel: string;
  chainPath: string;
  log: (msg: string) => void; // writes to stderr in production
  now?: () => string;
}

export interface DownstreamProcess {
  stdin: Writable;
  stdout: Readable;
  stderr?: Readable | null;
  kill?: () => void;
  // Resolves when the child exits (any exit code).
  exited: Promise<number | null>;
}

export interface ProxyHandle {
  // Resolves when client-side stream closes or downstream exits.
  done: Promise<void>;
  // Number of receipts written, for tests / diagnostics.
  receiptCount: () => number;
}

export function runProxy(deps: ProxyDeps): ProxyHandle {
  const downstream = deps.spawnDownstream();
  let downStdoutBuf = "";
  let clientStdinBuf = "";
  let receiptCount = 0;

  // Track pending tools/call requests by JSON-RPC id so when the
  // downstream's response arrives we know it's the ALLOW result we should
  // write a receipt for. Deny responses are written immediately and DO NOT
  // forward, so they never appear here.
  interface PendingAllow {
    request: JsonRpcRequest;
    toolArgs: unknown;
    server: string;
    toolName: string;
  }
  const pendingAllows = new Map<string | number, PendingAllow>();

  // ---- client -> downstream --------------------------------------------
  const onClientChunk = (chunk: Buffer | string) => {
    const { lines, rest } = splitLines(clientStdinBuf, chunk.toString("utf8"));
    clientStdinBuf = rest;
    for (const line of lines) {
      if (line.trim().length === 0) continue;

      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        // Forward unparseable lines verbatim — the downstream may parse
        // them or fail; either way, the proxy isn't authoritative over
        // arbitrary JSON-RPC validity.
        downstream.stdin.write(line + "\n");
        deps.log(`[proxy] forwarding unparseable client line as-is`);
        continue;
      }

      if (isRequest(parsed) && parsed.method === "tools/call") {
        handleToolsCall(parsed);
      } else {
        downstream.stdin.write(line + "\n");
      }
    }
  };

  function handleToolsCall(req: JsonRpcRequest): void {
    // Extract tool name + arguments per MCP spec §"Calling Tools".
    // Pass arguments through as the structured value — receipt's args_hash
    // is RFC 8785 JCS over this object, so we deliberately avoid an
    // intermediate JSON.stringify whose key order isn't canonical.
    const params = (req.params ?? {}) as { name?: string; arguments?: unknown };
    const toolName = typeof params.name === "string" ? params.name : "";
    const toolArgs = params.arguments ?? {};
    const decision = decide(toolName);

    if (decision.kind === "deny") {
      // Synthesize the deny result, send to client, do NOT forward.
      const denyResp = denyToolResult(req.id, decision.reason);
      deps.clientOut.write(encodeMessage(denyResp));
      writeReceiptSafely({
        decisionForReceipt: { kind: "deny", reason: decision.reason },
        server: deps.serverLabel,
        toolName,
        toolArgs,
        toolResult: undefined,
      });
      deps.log(
        `[proxy] DENY tool='${toolName}' reason='${decision.reason}' id=${String(req.id)}`,
      );
      return;
    }

    // ALLOW path: forward unchanged. Receipt is written when the response
    // arrives from downstream (so we capture result_hash).
    if (req.id !== null && req.id !== undefined) {
      pendingAllows.set(req.id, {
        request: req,
        toolArgs,
        server: deps.serverLabel,
        toolName,
      });
    }
    downstream.stdin.write(encodeMessage(req));
    deps.log(
      `[proxy] ALLOW tool='${toolName}' forwarded id=${String(req.id)}`,
    );
  }

  // Evaluates policy with fail-closed semantics. Any load failure -> deny.
  function decide(toolName: string): PolicyDecision {
    try {
      const policy = deps.loadPolicy();
      if (policy === null) {
        return {
          kind: "deny",
          reason: "policy could not be loaded — fail-closed",
        };
      }
      return evaluate(policy, { server: deps.serverLabel, tool: toolName });
    } catch (e) {
      return {
        kind: "deny",
        reason: `policy evaluation threw — fail-closed (${(e as Error).message})`,
      };
    }
  }

  // Receipt writing is wrapped so that an IO/signing failure does NOT
  // leak as a thrown error into the proxy loop. Fail-closed semantics
  // for receipt failures: if we cannot record the decision, we DENY (we
  // never let an un-receipted ALLOW through). That's handled by the
  // caller — this helper just logs and returns whether writing succeeded.
  function writeReceiptSafely(args: {
    decisionForReceipt: GateDecision;
    server: string;
    toolName: string;
    toolArgs: unknown;
    toolResult: unknown;
  }): boolean {
    try {
      appendReceipt({
        chainPath: deps.chainPath,
        sessionId: deps.sessionId,
        identity: deps.identity,
        server: args.server,
        toolName: args.toolName,
        toolArgs: args.toolArgs,
        toolResult: args.toolResult,
        decision: args.decisionForReceipt,
        ...(deps.now ? { ts: deps.now() } : {}),
      });
      receiptCount += 1;
      return true;
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      // Surface everything diagnostic: the resolved chain path we tried to
      // write to, the syscall, errno code, and the message. The Cursor-vs-
      // PowerShell discrepancy that motivated this logging was an ENOENT on
      // the sessions dir; the path + errno is what makes that obvious.
      deps.log(
        `[proxy] receipt write FAILED: ${err.message} ` +
          `(code=${err.code ?? "?"} syscall=${err.syscall ?? "?"} ` +
          `path=${err.path ?? deps.chainPath} chainPath=${deps.chainPath})`,
      );
      return false;
    }
  }

  // ---- downstream -> client --------------------------------------------
  const onDownstreamChunk = (chunk: Buffer | string) => {
    const { lines, rest } = splitLines(downStdoutBuf, chunk.toString("utf8"));
    downStdoutBuf = rest;
    for (const line of lines) {
      if (line.trim().length === 0) continue;

      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        deps.clientOut.write(line + "\n");
        deps.log(`[proxy] forwarding unparseable downstream line as-is`);
        continue;
      }

      // Is this a response to a tools/call we were tracking? If so, write
      // the ALLOW receipt before forwarding to the client.
      const id =
        typeof parsed === "object" && parsed !== null
          ? ((parsed as Record<string, unknown>)["id"] as
              | string
              | number
              | null
              | undefined)
          : undefined;

      if (id !== undefined && id !== null && pendingAllows.has(id)) {
        const pending = pendingAllows.get(id)!;
        pendingAllows.delete(id);
        // Pass the parsed `result` field — the MCP tool result object — to
        // the receipt builder. The recorder's resultHash applies JCS to it,
        // so an independent verifier given the same result derives byte-
        // identical bytes. Hashing the raw JSON-RPC envelope line would
        // re-introduce the same canonicalization bug class as args_hash
        // had (key order / whitespace dependence breaking recomputability).
        const toolResult = (parsed as Record<string, unknown>)["result"];
        const ok = writeReceiptSafely({
          decisionForReceipt: { kind: "allow" },
          server: pending.server,
          toolName: pending.toolName,
          toolArgs: pending.toolArgs,
          toolResult,
        });
        if (!ok) {
          // Fail-closed: receipt couldn't be written for an action that
          // already ran downstream. We cannot "un-run" the action; surface
          // the integrity failure to the client as a deny-style isError so
          // the agent sees the call as failed at the gate, AND log loudly.
          const errResp = denyToolResult(
            id,
            "gate receipt could not be written; result withheld (fail-closed)",
          );
          deps.clientOut.write(encodeMessage(errResp));
          continue;
        }
      }
      deps.clientOut.write(line + "\n");
    }
  };

  deps.clientIn.on("data", onClientChunk);
  downstream.stdout.on("data", onDownstreamChunk);

  // Forward downstream stderr to our stderr verbatim — the spec allows it
  // and the client may capture or ignore.
  if (downstream.stderr) {
    downstream.stderr.on("data", (chunk: Buffer | string) => {
      process.stderr.write(chunk);
    });
  }

  const done = new Promise<void>((resolve) => {
    let resolved = false;
    const finish = () => {
      if (resolved) return;
      resolved = true;
      try {
        downstream.stdin.end();
      } catch {
        /* ignore */
      }
      try {
        downstream.kill?.();
      } catch {
        /* ignore */
      }
      resolve();
    };
    deps.clientIn.on("end", finish);
    deps.clientIn.on("close", finish);
    downstream.exited.then(finish);
  });

  return {
    done,
    receiptCount: () => receiptCount,
  };
}

// Adapter for a real spawn()-based downstream.
//
// On Windows, `npx`, `yarn`, `pnpm`, `tsx` and similar are `.cmd`/`.bat`
// shims. Since the CVE-2024-27980 hardening Node refuses to spawn a
// shim without `shell: true` — the bare name resolves to `npx.cmd` only
// via the shell. MCP configs in the wild routinely pass the bare name,
// so default `shell: true` on win32 unless the caller explicitly
// overrides. Linux/macOS spawn behaviour is unchanged.
//
// Under shell:true the command line is parsed by cmd.exe, so a single
// unquoted `&` or `|` in any arg becomes a code-execution surface. Args
// come from the user's own MCP config (a trust boundary the user
// crossed deliberately), but we quote defensively anyway — agents that
// generate MCP configs will paste arg values without thinking about
// cmd.exe parsing.
export function spawnRealDownstream(
  command: string,
  args: string[],
  options?: { cwd?: string; env?: NodeJS.ProcessEnv; shell?: boolean },
): DownstreamProcess {
  const isWin = process.platform === "win32";
  const shell = options?.shell !== undefined ? options.shell : isWin;
  const spawnArgs = shell === true && isWin ? args.map(quoteForCmdShell) : args;

  const child = spawn(command, spawnArgs, {
    stdio: ["pipe", "pipe", "pipe"],
    ...(options?.cwd !== undefined ? { cwd: options.cwd } : {}),
    ...(options?.env !== undefined ? { env: options.env } : {}),
    shell,
  }) as ChildProcessByStdio<Writable, Readable, Readable>;

  return {
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    kill: () => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    },
    exited: new Promise((resolve) => {
      let resolved = false;
      const finish = (code: number | null) => {
        if (!resolved) {
          resolved = true;
          resolve(code);
        }
      };
      child.on("exit", (code) => finish(code));
      // A spawn-time failure (ENOENT for a missing/unresolvable command)
      // emits 'error' but may not emit 'exit'. Treat it as exit-with-null
      // so the proxy can shut down cleanly AND the error event has a
      // listener (otherwise Node escalates it to an uncaught exception).
      child.on("error", () => finish(null));
    }),
  };
}

// Quote a single arg for inclusion in a command line passed via
// `cmd.exe /d /s /c "<command + args>"`. cmd.exe under /s /c strips the
// outermost pair of quotes from the whole command line, so individual
// args wrapped in their own quotes survive intact. Args that are pure
// allowlist characters (paths, package specifiers, flags) pass bare;
// anything containing whitespace or shell metacharacters is wrapped.
// `%` and `!` can still expand inside quotes — out of scope for the
// spike; a future hardening pass would disable that via setlocal.
function quoteForCmdShell(arg: string): string {
  if (arg === "") return '""';
  if (/^[A-Za-z0-9._+\-=@:/\\,]+$/.test(arg)) return arg;
  return `"${arg.replace(/"/g, '\\"')}"`;
}
