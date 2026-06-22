#!/usr/bin/env node
// mcp-gate — fail-closed cryptographic gate at the MCP tools/call boundary.
//
// Two subcommands:
//   mcp-gate init [--dir <path>]
//       Generate the gate's signing identity (reuses recorder's runInit).
//
//   mcp-gate proxy --policy <file> --server-label <name> \
//                  -- <downstream-command> [<args>...]
//       Launch the proxy: spawn the downstream MCP server, mediate every
//       JSON-RPC frame, enforce policy at tools/call. Run by the MCP client
//       (e.g. Claude Desktop) as its configured MCP server.
//
// Identity defaults to ./.gate/identity.json + ./.gate/private-key.pem.
// Chain receipts default to ./.gate/sessions/<session-id>.jsonl.

import { randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  loadFullIdentity,
  runInit,
} from "recorder";
import { loadPolicy } from "./policy.js";
import { runProxy, spawnRealDownstream } from "./proxy.js";

const DATA_DIR = ".gate";

function helpText(): string {
  return `mcp-gate — fail-closed cryptographic gate at the MCP tools/call boundary

Usage:
  mcp-gate init [--dir <path>]
  mcp-gate proxy --policy <file> --server-label <name>
                 [--dir <path>] [--chain <file>] [--session-id <id>]
                 -- <downstream-command> [<args>...]

Defaults:
  data dir = ./${DATA_DIR}/
  identity = <data-dir>/${IDENTITY_FILENAME}
  chain    = <data-dir>/sessions/<session-id>.jsonl
  session-id = random UUID v4

Exit codes:
  0  proxy ran to clean shutdown / init succeeded
  1  proxy startup error (missing identity, unevaluable policy at boot, ...)
  2  usage error
`;
}

interface ParsedArgs {
  command: string | undefined;
  flags: Map<string, string | true>;
  positional: string[];
  passthrough: string[]; // everything after `--`
}

function parseArgs(argv: string[]): ParsedArgs {
  const command = argv[0];
  const flags = new Map<string, string | true>();
  const positional: string[] = [];
  const passthrough: string[] = [];
  let sawSep = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (sawSep) {
      passthrough.push(a);
      continue;
    }
    if (a === "--") {
      sawSep = true;
      continue;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        flags.set(a.slice(2, eq), a.slice(eq + 1));
      } else {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith("--") || next === "--") {
          flags.set(a.slice(2), true);
        } else {
          flags.set(a.slice(2), next);
          i++;
        }
      }
    } else {
      positional.push(a);
    }
  }
  return { command, flags, positional, passthrough };
}

function resolvePath(p: string): string {
  return resolve(process.cwd(), p);
}

function cmdInit(args: ParsedArgs): number {
  const dir = resolvePath((args.flags.get("dir") as string) ?? DATA_DIR);
  const result = runInit({ dir });
  if (result.kind === "exists") {
    process.stderr.write(
      `refusing to overwrite existing identity at ${result.identityPath}\n`,
    );
    return 1;
  }
  process.stdout.write(
    `initialized mcp-gate at ${result.dir}\n` +
      `  kid:          ${result.identity.kid}\n` +
      `  identity:     ${result.identityPath}\n` +
      `  private key:  ${result.privateKeyPath}\n`,
  );
  return 0;
}

function cmdProxy(args: ParsedArgs): number {
  const dir = resolvePath((args.flags.get("dir") as string) ?? DATA_DIR);
  const policyPath = args.flags.get("policy");
  const serverLabel = args.flags.get("server-label");
  if (typeof policyPath !== "string" || typeof serverLabel !== "string") {
    process.stderr.write(
      "usage: mcp-gate proxy --policy <file> --server-label <name> -- <cmd> [args...]\n",
    );
    return 2;
  }
  if (args.passthrough.length === 0) {
    process.stderr.write(
      "missing downstream command after `--` separator\n",
    );
    return 2;
  }
  const sessionId =
    (args.flags.get("session-id") as string | undefined) ?? randomUUID();
  const chainPath =
    (args.flags.get("chain") as string | undefined) !== undefined
      ? resolvePath(args.flags.get("chain") as string)
      : join(dir, "sessions", `${sessionId}.jsonl`);

  let identity;
  try {
    identity = loadFullIdentity(
      join(dir, IDENTITY_FILENAME),
      join(dir, PRIVATE_KEY_FILENAME),
    );
  } catch (e) {
    process.stderr.write(
      `[mcp-gate] cannot load identity from ${dir}: ${(e as Error).message}\n` +
        `[mcp-gate] run 'mcp-gate init' first.\n`,
    );
    return 1;
  }

  // Fail-closed at boot: if the policy file cannot be loaded, refuse to
  // start. The alternative (start and deny everything) would still be
  // safe, but a hard exit is clearer to the operator.
  const resolvedPolicyPath = resolvePath(policyPath);
  try {
    loadPolicy(resolvedPolicyPath);
  } catch (e) {
    process.stderr.write(
      `[mcp-gate] policy load failed at boot: ${(e as Error).message}\n`,
    );
    return 1;
  }

  const [downstreamCmd, ...downstreamArgs] = args.passthrough;
  const handle = runProxy({
    clientIn: process.stdin,
    clientOut: process.stdout,
    spawnDownstream: () => spawnRealDownstream(downstreamCmd!, downstreamArgs),
    loadPolicy: () => {
      try {
        return loadPolicy(resolvedPolicyPath);
      } catch (e) {
        process.stderr.write(
          `[mcp-gate] policy reload failed: ${(e as Error).message}\n`,
        );
        return null;
      }
    },
    identity,
    sessionId,
    serverLabel,
    chainPath,
    log: (m) => process.stderr.write(m + "\n"),
  });

  process.stderr.write(
    `[mcp-gate] proxy up: server-label='${serverLabel}' session=${sessionId} chain=${chainPath}\n`,
  );

  handle.done.then(() => {
    process.stderr.write(
      `[mcp-gate] proxy exiting (${handle.receiptCount()} receipts written)\n`,
    );
    process.exit(0);
  });

  // Keep the event loop alive — Node would otherwise exit once stdin/stdout
  // are piped but no top-level await is keeping us here.
  return 0;
}

function main(argv: string[]): number {
  const args = parseArgs(argv);
  if (
    args.command === undefined ||
    args.command === "-h" ||
    args.command === "--help" ||
    args.command === "help"
  ) {
    process.stdout.write(helpText());
    return args.command === undefined ? 2 : 0;
  }
  switch (args.command) {
    case "init":
      return cmdInit(args);
    case "proxy":
      return cmdProxy(args);
    default:
      process.stderr.write(`unknown command: ${args.command}\n`);
      process.stderr.write(helpText());
      return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
