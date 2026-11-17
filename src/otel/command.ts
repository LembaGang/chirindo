// B-481 T2: `chirindo otel-receiver`, the command around src/otel/receiver.ts.
// src/cli.ts dispatches to runOtelReceiverCli; the tests call
// startOtelReceiverCommand in the same process (no child process).
//
//   chirindo otel-receiver [--dir <path>] [--port <n>] [--token-file <file>]
//                          [--forward <http(s)-url>] [--no-retain]
//
// It listens on 127.0.0.1, and on ::1 too when the machine has it (ruling L2 b).
//
// Usage errors return 2 and a start failure 1, both before listening. On
// success one JSON line goes to stdout: {"listening", "addresses", "ipv6",
// "session_id", "chain", "pid"}.
// It ends on SIGINT or SIGTERM by closing the server (process.exitCode, never
// process.exit()). No checkpoint is made at shutdown: T3.

import { readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { OTEL_RECEIVER_DEFAULT_PORT, createOtelReceiver, type OtelListening, type OtelReceiver } from "./receiver.js";

export const OTEL_RECEIVER_COMMAND = "otel-receiver";
export const OTEL_RECEIVER_FLAGS = ["dir", "port", "token-file", "forward", "no-retain"] as const;
export const OTEL_RECEIVER_USAGE =
  "usage: chirindo otel-receiver [--dir <path>] [--port <n>] [--token-file <file>] [--forward <http(s)-url>] [--no-retain]";

export interface OtelCommandArgs {
  flags: Map<string, string | true>;
  positional: string[];
  passthrough: string[];
}

export interface OtelCommandIo {
  stdout(line: string): void;
  stderr(line: string): void;
  cwd?: string;
}

export interface OtelCommandStarted {
  code: number;
  receiver?: OtelReceiver;
  stop?: () => Promise<void>;
}

export async function startOtelReceiverCommand(args: OtelCommandArgs, io: OtelCommandIo): Promise<OtelCommandStarted> {
  const cmd = OTEL_RECEIVER_COMMAND;
  const usage = (why: string): OtelCommandStarted => {
    io.stderr(`chirindo ${cmd}: ${why}`);
    io.stderr(OTEL_RECEIVER_USAGE);
    return { code: 2 };
  };
  if (args.positional.length > 0 || args.passthrough.length > 0) return usage(`unexpected argument '${[...args.positional, ...args.passthrough][0]}'`);
  for (const k of args.flags.keys()) if (!(OTEL_RECEIVER_FLAGS as readonly string[]).includes(k)) return usage(`unknown flag --${k}`);
  const str = (k: string): string | undefined | null => {
    const v = args.flags.get(k);
    if (v === undefined) return undefined;
    return typeof v === "string" && v !== "" ? v : null;
  };
  const cwd = io.cwd ?? process.cwd();
  const abs = (p: string) => (isAbsolute(p) ? p : resolve(cwd, p));

  const dirFlag = str("dir");
  if (dirFlag === null) return usage("--dir takes a path");
  const dir = abs(dirFlag ?? ".gate");
  const portFlag = str("port") ?? String(OTEL_RECEIVER_DEFAULT_PORT);
  if (portFlag === null || !/^(0|[1-9][0-9]{0,4})$/.test(portFlag) || Number(portFlag) > 65_535) return usage("--port must be an integer from 0 to 65535");
  const retainFlag = args.flags.get("no-retain");
  if (retainFlag !== undefined && retainFlag !== true) return usage("--no-retain takes no value");
  const forward = str("forward");
  if (forward === null) return usage("--forward takes an http:// or https:// URL");
  if (forward !== undefined) {
    let u: URL | undefined;
    try {
      u = new URL(forward);
    } catch {
      u = undefined;
    }
    if (u === undefined || (u.protocol !== "http:" && u.protocol !== "https:")) return usage("--forward must be an http:// or https:// URL");
  }
  const tokenFile = str("token-file");
  if (tokenFile === null) return usage("--token-file takes a path");
  let token: string | undefined;
  if (tokenFile !== undefined) {
    try {
      token = readFileSync(abs(tokenFile), "utf8").trim();
    } catch (e) {
      return usage(`cannot read --token-file ${tokenFile} (${(e as NodeJS.ErrnoException).code ?? "unreadable"})`);
    }
    if (token === "") return usage(`--token-file ${tokenFile} is empty`);
    // L4 of the T2 read: a token others can read protects nothing (POSIX modes;
    // on Windows the folder's ACL decides and nothing is checked).
    if (process.platform !== "win32") {
      try {
        if ((statSync(abs(tokenFile)).mode & 0o077) !== 0) io.stderr(`[chirindo] ${cmd}: warning: --token-file ${tokenFile} can be read by other users (mode ${(statSync(abs(tokenFile)).mode & 0o777).toString(8)}); chmod 600 it`);
      } catch {
        /* read above; a stat failure here changes nothing */
      }
    }
  }

  let receiver: OtelReceiver;
  try {
    receiver = createOtelReceiver({
      dir,
      port: Number(portFlag),
      ...(token !== undefined ? { token } : {}),
      ...(forward !== undefined ? { forward } : {}),
      retain: retainFlag !== true,
      log: (line) => io.stderr(line),
    });
  } catch (e) {
    io.stderr(`[chirindo] ${cmd}: cannot start: ${(e as Error).message}`);
    return { code: 1 };
  }
  let bound: OtelListening;
  try {
    bound = await receiver.listen();
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "error";
    const at = (e as { address?: string }).address ?? `127.0.0.1:${portFlag}`;
    io.stderr(`[chirindo] ${cmd}: cannot listen on ${at} (${code})` + (code === "EADDRINUSE" ? ": another program holds this port; stop it or pass --port" : "") + "; nothing is listening");
    return { code: 1 };
  }
  if (receiver.keyCreated) io.stderr(`[chirindo] ${cmd}: no signing key in ${dir}; created one (identity.json, private-key.pem)`);
  io.stdout(JSON.stringify({ listening: bound.url, addresses: bound.addresses, ipv6: bound.ipv6, session_id: receiver.sessionId, chain: receiver.chainPath, pid: process.pid }));
  io.stderr(
    `[chirindo] ${cmd} up: ${bound.addresses.join(" ")} session=${receiver.sessionId} dir=${dir}` +
      ` retain=${retainFlag === true ? "off (hashes only)" : "on"}` +
      ` forward=${forward !== undefined ? new URL(forward).origin : "none"}` +
      (token !== undefined ? " token=required" : " token=none (any local process can add records; web pages are refused)"),
  );
  const stop = async () => {
    await receiver.close();
    await receiver.settled();
  };
  return { code: 0, receiver, stop };
}

// The CLI entry: start, then wait for SIGINT or SIGTERM.
export async function runOtelReceiverCli(args: OtelCommandArgs): Promise<number> {
  const started = await startOtelReceiverCommand(args, {
    stdout: (l) => process.stdout.write(l + "\n"),
    stderr: (l) => process.stderr.write(l + "\n"),
  });
  if (started.code !== 0 || started.stop === undefined) return started.code;
  const stop = started.stop;
  const onSignal = () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    void stop().then(() => {
      process.stderr.write(`[chirindo] ${OTEL_RECEIVER_COMMAND} exiting\n`);
      process.exitCode = 0;
    });
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return 0;
}
