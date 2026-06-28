#!/usr/bin/env node
// chirindo — fail-closed cryptographic gate at the MCP tools/call boundary.
//
// Subcommands:
//   chirindo init [--dir <path>]
//       Generate the gate's signing identity (reuses recorder's runInit).
//
//   chirindo proxy --policy <file> --server-label <name> \
//                  -- <downstream-command> [<args>...]
//       Launch the proxy: spawn the downstream MCP server, mediate every
//       JSON-RPC frame, enforce policy at tools/call. Run by the MCP client
//       (e.g. Claude Desktop) as its configured MCP server.
//
//   chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]
//                                [--max-skew-ms <ms>]
//       Independently verify a chain file. Re-exports the recorder's
//       verifier — same engine, same VALID/TAMPERED/UNRESOLVED output,
//       same exit codes. Lets a stranger close the loop with ONLY chirindo
//       installed.
//
// Identity defaults to ./.gate/identity.json + ./.gate/private-key.pem.
// Chain receipts default to ./.gate/sessions/<session-id>.jsonl.

import { randomUUID } from "node:crypto";
import {
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import {
  DEFAULT_JWKS_URL,
  IDENTITY_FILENAME,
  JWKS_URL_ENV_VAR,
  PRIVATE_KEY_FILENAME,
  formatVerifyResult,
  loadFullIdentity,
  runInit,
  runVerify,
} from "./vendor/recorder/index.js";
import { loadPolicy } from "./policy.js";
import { runProxy, spawnRealDownstream } from "./proxy.js";

const DATA_DIR = ".gate";

function helpText(): string {
  return `chirindo — fail-closed cryptographic gate at the MCP tools/call boundary

Usage:
  chirindo init   [--dir <path>]
  chirindo proxy  --policy <file> --server-label <name>
                  [--dir <path>] [--chain <file>] [--session-id <id>]
                  -- <downstream-command> [<args>...]
  chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]
                  [--max-skew-ms <ms>]

Defaults:
  data dir = ./${DATA_DIR}/
  identity = <data-dir>/${IDENTITY_FILENAME}
  chain    = <data-dir>/sessions/<session-id>.jsonl
  session-id = random UUID v4
  --key    = <data-dir>/${IDENTITY_FILENAME}
  --jwks   = $${JWKS_URL_ENV_VAR} or ${DEFAULT_JWKS_URL}

Key sources for verify: --key (local, offline) and --jwks (remote, HTTPS)
are alternatives — pass at most one. Without either, --key is used.

Exit codes:
  0  proxy ran to clean shutdown / init succeeded / VALID
  1  proxy startup error / TAMPERED / UNRESOLVED
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

// Resolve a user-supplied path to an absolute path. Absolute inputs are
// returned unchanged (so `--dir C:/...` is independent of process.cwd()).
// Relative inputs are anchored to cwd — that anchor is the only sensible
// default for a relative input, but cwd under a host (Cursor, Claude
// Desktop) is generally NOT the user's project. We log the resolved path
// at boot so the divergence is visible instead of silent.
function resolvePath(p: string): string {
  return isAbsolute(p) ? p : resolve(process.cwd(), p);
}

// Boot-time self-check: confirm we can write to the chain directory before
// we accept any tools/call. Fail-closed surfaces here as a clear fatal at
// startup, not as an opaque per-call "receipt could not be written" deny.
function probeChainDirOrFatal(chainPath: string): void {
  const chainDir = dirname(chainPath);
  try {
    mkdirSync(chainDir, { recursive: true });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    process.stderr.write(
      `[chirindo] FATAL: cannot create chain directory ${chainDir} ` +
        `(code=${err.code ?? "?"} syscall=${err.syscall ?? "?"}): ${err.message}\n`,
    );
    process.exit(1);
  }
  const probePath = join(chainDir, `.probe-${process.pid}-${Date.now()}`);
  try {
    writeFileSync(probePath, "ok", "utf8");
    rmSync(probePath, { force: true });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    process.stderr.write(
      `[chirindo] FATAL: chain directory ${chainDir} is not writable ` +
        `(code=${err.code ?? "?"} syscall=${err.syscall ?? "?"} ` +
        `path=${err.path ?? probePath}): ${err.message}\n`,
    );
    process.exit(1);
  }
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
    `initialized chirindo at ${result.dir}\n` +
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
      "usage: chirindo proxy --policy <file> --server-label <name> -- <cmd> [args...]\n",
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

  // Log the resolved absolute paths and the cwd we were spawned with. This
  // is the single most useful diagnostic when a host (Cursor / Claude
  // Desktop) launches us from an unexpected directory.
  process.stderr.write(
    `[chirindo] boot: cwd=${process.cwd()} dir=${dir} chain=${chainPath}\n`,
  );

  // Self-check: prove we can actually write to the chain dir. If not, fail
  // loudly at boot rather than denying every tools/call with an opaque
  // "receipt could not be written".
  probeChainDirOrFatal(chainPath);

  let identity;
  try {
    identity = loadFullIdentity(
      join(dir, IDENTITY_FILENAME),
      join(dir, PRIVATE_KEY_FILENAME),
    );
  } catch (e) {
    process.stderr.write(
      `[chirindo] cannot load identity from ${dir}: ${(e as Error).message}\n` +
        `[chirindo] run 'chirindo init' first.\n`,
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
      `[chirindo] policy load failed at boot: ${(e as Error).message}\n`,
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
          `[chirindo] policy reload failed: ${(e as Error).message}\n`,
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
    `[chirindo] proxy up: server-label='${serverLabel}' session=${sessionId} chain=${chainPath}\n`,
  );

  handle.done.then(() => {
    process.stderr.write(
      `[chirindo] proxy exiting (${handle.receiptCount()} receipts written)\n`,
    );
    process.exit(0);
  });

  // Keep the event loop alive — Node would otherwise exit once stdin/stdout
  // are piped but no top-level await is keeping us here.
  return 0;
}

// `chirindo verify` — independently verify a chain file. Pure wiring around
// the recorder's exported runVerify + formatVerifyResult. The crypto, the
// JWKS fetcher, and the VALID / TAMPERED / UNRESOLVED vocabulary all come
// from the recorder library — chirindo just dispatches argv. Same
// alternatives, same exit codes, same default JWKS URL fallback. This is
// what lets a stranger run the full getting-started loop with ONLY
// chirindo installed.
async function cmdVerify(args: ParsedArgs): Promise<number> {
  const chainArg = args.positional[0];
  if (chainArg === undefined) {
    process.stderr.write(
      "usage: chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]\n",
    );
    return 2;
  }
  const chainPath = resolvePath(chainArg);
  const keyFlag = args.flags.get("key");
  const jwksFlag = args.flags.get("jwks");
  if (typeof keyFlag === "string" && typeof jwksFlag === "string") {
    process.stderr.write(
      "chirindo verify: --key and --jwks are alternative key sources; pass at most one\n",
    );
    return 2;
  }
  const maxSkewFlag = args.flags.get("max-skew-ms");
  const skewOpt =
    typeof maxSkewFlag === "string"
      ? { maxSkewMs: Number.parseInt(maxSkewFlag, 10) }
      : {};

  // JWKS resolution precedence: --jwks <url> > $RECORDER_JWKS_URL > default.
  // Bare `--jwks` (no value) opts into the env-or-default URL — the form the
  // README's getting-started step 5 uses to keep the payoff command short.
  const envJwksUrl = process.env[JWKS_URL_ENV_VAR];
  const wantsJwks =
    jwksFlag !== undefined ||
    (typeof keyFlag !== "string" && envJwksUrl !== undefined);
  let result;
  if (wantsJwks) {
    const jwksUrl =
      typeof jwksFlag === "string"
        ? jwksFlag
        : (envJwksUrl ?? DEFAULT_JWKS_URL);
    result = await runVerify({ chainPath, jwksUrl, ...skewOpt });
  } else {
    const identityPath =
      typeof keyFlag === "string"
        ? resolvePath(keyFlag)
        : join(resolvePath(DATA_DIR), IDENTITY_FILENAME);
    result = runVerify({ chainPath, identityPath, ...skewOpt });
  }

  const formatted = formatVerifyResult(result);
  process.stdout.write(formatted.line + "\n");
  return formatted.exitCode;
}

async function main(argv: string[]): Promise<number> {
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
    case "verify":
      return await cmdVerify(args);
    default:
      process.stderr.write(`unknown command: ${args.command}\n`);
      process.stderr.write(helpText());
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`fatal: ${(e as Error).message}\n`);
    process.exitCode = 1;
  },
);
