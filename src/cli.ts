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
//   chirindo checkpoint <chain-file> [--dir <path>] [--witness <base-url>]
//       Sign a checkpoint over the chain head into <chain>.witness.ndjson and
//       optionally have a witness countersign it (WITNESS_SPEC v0.4).
//
//   chirindo verify <chain-file> [--key <identity.json> | --jwks <url>]
//                                [--max-skew-ms <ms>]
//                                [--witness <base-url> | --witness-file <f>]
//       Independently verify a chain file. Re-exports the recorder's
//       verifier — same engine, same VALID/TAMPERED/UNRESOLVED output,
//       same exit codes. Lets a stranger close the loop with ONLY chirindo
//       installed.
//
// Identity defaults to ./.gate/identity.json + ./.gate/private-key.pem.
// Chain receipts default to ./.gate/sessions/<session-id>.jsonl.

import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import {
  DEFAULT_JWKS_URL,
  IDENTITY_FILENAME,
  JWKS_URL_ENV_VAR,
  PRIVATE_KEY_FILENAME,
  buildJwk,
  buildJwks,
  formatVerifyResult,
  loadFullIdentity,
  readChainFile,
  readIdentityFile,
  runInit,
  runVerify,
} from "./vendor/recorder/index.js";
import { loadPolicy } from "./policy.js";
import { runProxy, spawnRealDownstream } from "./proxy.js";
import { appendSidecarLine, buildCheckpoint } from "./checkpoint.js";
import {
  DEFAULT_WITNESS_KEY_ID,
  DEFAULT_WITNESS_NAME,
  checkWitnessBaseUrl,
  parseWitnessKeyArg,
  readSidecar,
  sidecarPathFor,
  verifyAgainstWitness,
  witnessCheckpoint,
  witnessPubFromRaw,
  type WitnessPub,
  type WitnessTarget,
} from "./witness.js";

// Clean shutdown waits at most this long for the final witness POST.
const SHUTDOWN_WITNESS_WAIT_MS = 5_000;
const DATA_DIR = ".gate";

function helpText(): string {
  return `chirindo — fail-closed cryptographic gate at the MCP tools/call boundary

Usage:
  chirindo init        [--dir <path>]
  chirindo export-jwks [--dir <path>] [--out <file>]
  chirindo proxy       --policy <file> --server-label <name>
                       [--dir <path>] [--chain <file>] [--session-id <id>]
                       [--jwks-uri <https-url>]
                       [--checkpoint-every <N>] [--witness <base-url>]
                       [--witness-key <hex|jwk-file>] [--witness-name <name>]
                       -- <downstream-command> [<args>...]
  chirindo checkpoint  <chain-file> [--dir <path>] [--witness <base-url>]
                       [--witness-key <hex|jwk-file>] [--witness-name <name>]
  chirindo verify      <chain-file> [--key <identity.json> | --jwks [<url>]]
                       [--expect-thumbprint <tp>]... [--trust-file <file>]
                       [--max-skew-ms <ms>] [--allow-unproven-delivery]
                       [--witness <base-url> | --witness-file <sidecar>]
                       [--witness-key <hex|jwk-file>] [--witness-key-id <id>]
                       [--witness-name <name>]

Defaults:
  data dir = ./${DATA_DIR}/
  identity = <data-dir>/${IDENTITY_FILENAME}
  chain    = <data-dir>/sessions/<session-id>.jsonl
  session-id = random UUID v4
  --key    = <data-dir>/${IDENTITY_FILENAME}
  --jwks   = $${JWKS_URL_ENV_VAR} or ${DEFAULT_JWKS_URL}
  --out    (export-jwks) = <data-dir>/jwks.json

Self-describing receipts:
  --jwks-uri <https-url> on \`proxy\` stamps the operator's published JWKS
  location into every receipt's signed bytes. Verifiers given the chain
  resolve the key from that URL — Headless Oracle is not in the trust
  path. Use \`chirindo export-jwks\` to produce the file you host there.

verify key resolution (spec F precedence, highest first):
  --key <file>                            local identity, no network
  --jwks <url>                            explicit URL, overrides embedded jwks_uri
  receipt jwks_uri                        the self-describing URL (signed bytes)
  $${JWKS_URL_ENV_VAR}                   operator env override
  published default                       ${DEFAULT_JWKS_URL}
  Fallback only when the higher source is ABSENT. A receipt whose jwks_uri is
  present but cannot be fetched is UNVERIFIABLE — it never silently drops to a
  default. Use --key for the offline path (there is no implicit local default).

Trust / pinning (what VALID means):
  --expect-thumbprint <tp>   Accept only these RFC 7638 key thumbprints
                             (repeatable). Resolved key not in the set -> INVALID
                             (untrusted_key).
  --trust-file <file>        JSON of accepted thumbprints: a bare array, or
                             { "thumbprints": [ ... ] }. Merged with the flags.

  verify output ALWAYS names the verifying key:
    "verified under key <thumbprint> resolved from <source> (<origin>)"
  WITHOUT a pin (--expect-thumbprint / --trust-file), VALID means the chain is
  INTERNALLY CONSISTENT under the presented key — NOT that it was signed by
  Headless Oracle or anyone in particular. Pin a thumbprint to assert WHO.

Delivery proof (x402):
  A receipt MAY carry x402_payment_ref — a signed commitment to a payment,
  read together with the event's result_hash to answer "was anything actually
  delivered for that payment?". verify reports one of three delivery states:

    (no suffix)                  no payment claim — ordinary receipt
    DELIVERY PROVEN              payment ref + output hash both committed
    DELIVERY UNPROVEN            payment referenced, no output commitment

  DELIVERY UNPROVEN exits NON-ZERO by default: settled-but-nothing-delivered
  is the one outcome this must never wave through. --allow-unproven-delivery
  relaxes the EXIT CODE only — the verdict is still printed, and no flag ever
  turns UNPROVEN into PROVEN.

  PROVEN is an attestation of COMMITMENT, not of correctness: it proves the
  operator committed, in bytes it cannot alter, to a payment reference and to
  the hash of an output. It does NOT prove the output was correct, useful, or
  what the consumer actually received — that needs receiver-side signing.

Witness (checkpoints):
  Checkpoints go to <chain-file>.witness.ndjson, never into the chain file.
  --witness <base-url> POSTs each checkpoint to a witness (https, or http for
  loopback only); --witness-name is the expected receipt "witness" member
  (default ${DEFAULT_WITNESS_NAME}). On the proxy a witness failure is logged
  and the call is permitted. verify --witness / --witness-file compares the
  chain with witnessed checkpoints: a cut-off tail, or a rewrite by the key
  holder, of history up to the last witnessed checkpoint reads TAMPERED.
  --witness-file trusts the sidecar the operator supplied; only querying the
  witness is independent of the operator.

Exit codes:
  0  proxy ran to clean shutdown / init / export-jwks / checkpoint succeeded /
     VALID (and, in witness mode, WITNESSED under a pinned witness key)
  1  proxy startup error / TAMPERED / INVALID / UNVERIFIABLE /
     VALID with DELIVERY UNPROVEN (unless --allow-unproven-delivery) /
     NO WITNESS / witness key fetched but not pinned /
     checkpoint refused or witness failure
  2  usage error
`;
}

interface ParsedArgs {
  command: string | undefined;
  flags: Map<string, string | true>;
  // All string values seen for each flag, in order — supports repeatable
  // flags (e.g. --expect-thumbprint a --expect-thumbprint b). `flags` still
  // holds the LAST value for single-valued flags; `multi` is additive and does
  // not change any existing single-value consumer.
  multi: Map<string, string[]>;
  positional: string[];
  passthrough: string[]; // everything after `--`
}

// Flags that NEVER take a value. Without this, `--allow-unproven-delivery
// <chain>` would swallow the chain path as the flag's value and the command
// would fail with a confusing usage error — the flag must work in any
// position, because a scripted caller will not be careful about ordering.
const BOOLEAN_FLAGS = new Set(["allow-unproven-delivery"]);

function parseArgs(argv: string[]): ParsedArgs {
  const command = argv[0];
  const flags = new Map<string, string | true>();
  const multi = new Map<string, string[]>();
  const positional: string[] = [];
  const passthrough: string[] = [];
  const setFlag = (name: string, value: string) => {
    flags.set(name, value);
    const seen = multi.get(name);
    if (seen) seen.push(value);
    else multi.set(name, [value]);
  };
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
        setFlag(a.slice(2, eq), a.slice(eq + 1));
      } else if (BOOLEAN_FLAGS.has(a.slice(2))) {
        flags.set(a.slice(2), true);
      } else {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith("--") || next === "--") {
          flags.set(a.slice(2), true);
        } else {
          setFlag(a.slice(2), next);
          i++;
        }
      }
    } else {
      positional.push(a);
    }
  }
  return { command, flags, multi, positional, passthrough };
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

// `chirindo export-jwks` — write a hostable jwks.json from the local
// gate identity. The output is exactly what an adopter uploads to their
// own HTTPS-served URL so that `chirindo verify --jwks <their-url>` (or
// the embedded-jwks_uri path) can resolve the signing key. The JWK
// shape mirrors the format Headless Oracle's own JWKS serves — same
// kty/crv/use/alg, same kid string — so adopter-hosted and HO-hosted
// JWKS documents are interchangeable from the verifier's perspective.
function cmdExportJwks(args: ParsedArgs): number {
  const dir = resolvePath((args.flags.get("dir") as string) ?? DATA_DIR);
  const identityPath = join(dir, IDENTITY_FILENAME);
  let identity;
  try {
    identity = readIdentityFile(identityPath);
  } catch (e) {
    process.stderr.write(
      `[chirindo] cannot read identity at ${identityPath}: ${(e as Error).message}\n` +
        `[chirindo] run 'chirindo init' first.\n`,
    );
    return 1;
  }
  const jwks = buildJwks([
    buildJwk({
      kid: identity.kid,
      publicKeyBase64Url: identity.public_key_b64url,
    }),
  ]);
  const outFlag = args.flags.get("out");
  const outPath =
    typeof outFlag === "string" ? resolvePath(outFlag) : join(dir, "jwks.json");
  try {
    mkdirSync(dirname(outPath), { recursive: true });
    // Pretty-print with newline: a hosted jwks.json is meant to be read by
    // humans and edge proxies; nothing here is byte-sensitive (the verifier
    // re-parses the JSON anyway). Trailing newline by convention.
    writeFileSync(outPath, JSON.stringify(jwks, null, 2) + "\n", "utf8");
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    process.stderr.write(
      `[chirindo] cannot write JWKS to ${outPath} ` +
        `(code=${err.code ?? "?"} syscall=${err.syscall ?? "?"}): ${err.message}\n`,
    );
    return 1;
  }
  process.stdout.write(
    `exported chirindo JWKS\n` +
      `  kid:  ${identity.kid}\n` +
      `  file: ${outPath}\n` +
      `\n` +
      `Host this file at an https:// URL you control, then pass that URL\n` +
      `to 'chirindo proxy --jwks-uri <url>' so every receipt names where\n` +
      `verifiers should fetch its signing key.\n`,
  );
  return 0;
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

  // --jwks-uri stamps the operator's published-JWKS URL into every emitted
  // receipt's signed bytes. Verifiers given the chain see where to fetch
  // this gate's public key — no Headless Oracle hosting required. We
  // refuse non-HTTPS to keep the trust-root property explicit at the
  // signing side (the verifier also enforces this, but failing early at
  // the gate avoids producing receipts that name an insecure publication
  // URL the verifier will then refuse).
  const jwksUriFlag = args.flags.get("jwks-uri");
  let jwksUri: string | undefined;
  if (typeof jwksUriFlag === "string") {
    try {
      const u = new URL(jwksUriFlag);
      if (u.protocol !== "https:") {
        process.stderr.write(
          `[chirindo] --jwks-uri must be an https:// URL (got ${u.protocol}//...)\n`,
        );
        return 2;
      }
      jwksUri = jwksUriFlag;
    } catch {
      process.stderr.write(
        `[chirindo] --jwks-uri is not a valid URL: ${jwksUriFlag}\n`,
      );
      return 2;
    }
  }

  const everyFlag = args.flags.get("checkpoint-every");
  let checkpointEvery: number | undefined;
  if (everyFlag !== undefined) {
    if (
      typeof everyFlag !== "string" ||
      !/^[1-9][0-9]*$/.test(everyFlag) ||
      !Number.isSafeInteger(Number(everyFlag))
    ) {
      process.stderr.write("[chirindo] --checkpoint-every must be a positive integer\n");
      return 2;
    }
    checkpointEvery = Number(everyFlag);
  }
  const witness = parseWitnessTarget(args, "proxy");
  if (witness === null) return 2;

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
    ...(jwksUri !== undefined ? { jwksUri } : {}),
    ...(checkpointEvery !== undefined ? { checkpointEvery } : {}),
    ...(witness !== undefined ? { witness } : {}),
    log: (m) => process.stderr.write(m + "\n"),
  });

  process.stderr.write(
    `[chirindo] proxy up: server-label='${serverLabel}' session=${sessionId} ` +
      `chain=${chainPath}` +
      (jwksUri !== undefined ? ` jwks_uri=${jwksUri}` : "") +
      `\n`,
  );

  // The shutdown checkpoint (and its witness POST, capped at 5 s) must finish
  // BEFORE process.exit, or the head of every session would go unwitnessed.
  handle.done.then(async () => {
    try {
      await handle.finalCheckpoint(SHUTDOWN_WITNESS_WAIT_MS);
    } catch (e) {
      process.stderr.write(`[chirindo] shutdown checkpoint failed: ${(e as Error).message}\n`);
    }
    process.stderr.write(
      `[chirindo] proxy exiting (${handle.receiptCount()} receipts written)\n`,
    );
    process.exit(0);
  });

  // Keep the event loop alive — Node would otherwise exit once stdin/stdout
  // are piped but no top-level await is keeping us here.
  return 0;
}

// The pinned witness key. Its id is --witness-key-id if given, else the JWK
// file's kid, else DEFAULT_WITNESS_KEY_ID (spec section 5 step 4). Returns null
// after writing a diagnostic: an unreadable pin is a usage error, never "no pin".
function loadPinnedWitnessKey(
  arg: string,
  idFlag: string | undefined,
  cmd: string,
): WitnessPub | null {
  try {
    const parsed = parseWitnessKeyArg(arg);
    return {
      pubObj: witnessPubFromRaw(parsed.raw),
      hex: parsed.raw.toString("hex"),
      id: idFlag ?? parsed.jwkKid ?? DEFAULT_WITNESS_KEY_ID,
    };
  } catch (e) {
    process.stderr.write(`chirindo ${cmd}: ${(e as Error).message}\n`);
    return null;
  }
}

// --witness / --witness-key / --witness-name for `proxy` and `checkpoint`.
// undefined = no --witness; null = usage error already written.
function parseWitnessTarget(
  args: ParsedArgs,
  cmd: string,
): WitnessTarget | undefined | null {
  const url = args.flags.get("witness");
  const pinArg = args.flags.get("witness-key");
  const name = args.flags.get("witness-name");
  if (url === undefined) {
    if (pinArg !== undefined || name !== undefined) {
      process.stderr.write(
        `chirindo ${cmd}: --witness-key and --witness-name need --witness <base-url>\n`,
      );
      return null;
    }
    return undefined;
  }
  if (typeof url !== "string" || pinArg === true || name === true) {
    process.stderr.write(`chirindo ${cmd}: --witness, --witness-key and --witness-name take a value\n`);
    return null;
  }
  let baseUrl: string;
  try {
    baseUrl = checkWitnessBaseUrl(url);
  } catch (e) {
    process.stderr.write(`chirindo ${cmd}: ${(e as Error).message}\n`);
    return null;
  }
  const target: WitnessTarget = { baseUrl, name: name ?? DEFAULT_WITNESS_NAME };
  if (typeof pinArg === "string") {
    const pinned = loadPinnedWitnessKey(pinArg, undefined, cmd);
    if (pinned === null) return null;
    target.pinned = pinned;
  }
  return target;
}

// `chirindo checkpoint` — sign a checkpoint over the chain head into the
// sidecar, optionally witnessed. Refuses (exit 1, nothing written) unless the
// chain verifies VALID under this identity's key and that key is the one that
// signed it, so a checkpoint can only ever vouch for a chain we can stand behind.
async function cmdCheckpoint(args: ParsedArgs): Promise<number> {
  const chainArg = args.positional[0];
  if (chainArg === undefined) {
    process.stderr.write(
      "usage: chirindo checkpoint <chain-file> [--dir <path>] [--witness <base-url>] " +
        "[--witness-key <hex|jwk-file>] [--witness-name <name>]\n",
    );
    return 2;
  }
  const witness = parseWitnessTarget(args, "checkpoint");
  if (witness === null) return 2;
  const chainPath = resolvePath(chainArg);
  const dir = resolvePath((args.flags.get("dir") as string) ?? DATA_DIR);
  const identityPath = join(dir, IDENTITY_FILENAME);
  let identity;
  try {
    identity = loadFullIdentity(identityPath, join(dir, PRIVATE_KEY_FILENAME));
  } catch (e) {
    process.stderr.write(
      `chirindo checkpoint: cannot load identity from ${dir}: ${(e as Error).message}\n`,
    );
    return 1;
  }
  const refuse = (why: string): number => {
    process.stderr.write(`chirindo checkpoint: refused, nothing written: ${why}\n`);
    return 1;
  };

  let verdict;
  try {
    verdict = runVerify({ chainPath, identityPath });
  } catch (e) {
    return refuse(`cannot read chain ${chainPath}: ${(e as Error).message}`);
  }
  if (verdict.kind !== "valid") {
    const line = formatVerifyResult(verdict).line.split("\n")[0];
    return refuse(`chain does not verify VALID under the identity's key (${line})`);
  }
  const { records } = readChainFile(chainPath);
  if (records[0]!.kid !== identity.kid) {
    return refuse(`identity kid ${identity.kid} differs from the chain's kid ${records[0]!.kid}`);
  }
  if (identity.kid.startsWith("ed25519/")) {
    return refuse(`legacy kid ${identity.kid} cannot be witnessed; the witness accepts RFC 7638 thumbprint kids only`);
  }

  const cp = buildCheckpoint(records, identity);
  const sidecar = sidecarPathFor(chainPath);
  let existing: ReturnType<typeof readSidecar> = [];
  if (existsSync(sidecar)) {
    try {
      existing = readSidecar(sidecar);
    } catch (e) {
      return refuse((e as Error).message);
    }
  }
  const sameHead = existing.filter(
    (l) =>
      l.checkpoint.count === cp.count &&
      l.checkpoint.last_entry_hash === cp.last_entry_hash,
  );
  if (
    sameHead.some((l) => l.witness_receipt !== null) ||
    (witness === undefined && sameHead.length > 0)
  ) {
    process.stdout.write(`head already checkpointed at count ${cp.count}\n`);
    return 0;
  }

  if (witness === undefined) {
    appendSidecarLine(sidecar, { checkpoint: cp, witness_receipt: null, witness_error: null });
    process.stdout.write(`checkpoint at count ${cp.count} written to ${sidecar} (not witnessed)\n`);
    return 0;
  }
  const outcome = await witnessCheckpoint(cp, identity.publicKey, witness);
  appendSidecarLine(sidecar, {
    checkpoint: cp,
    witness_receipt: outcome.receipt,
    witness_error: outcome.error,
  });
  if (outcome.error !== null) {
    process.stderr.write(
      `chirindo checkpoint: witness failed for count ${cp.count}: ${outcome.error} (recorded in ${sidecar})\n`,
    );
    return 1;
  }
  process.stdout.write(
    `checkpoint at count ${cp.count} witnessed, received_at ${outcome.receipt.received_at}, written to ${sidecar}\n`,
  );
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
  // Witness mode (spec section 5). Usage errors exit 2 before any work.
  const witnessUrlFlag = args.flags.get("witness");
  const witnessFileFlag = args.flags.get("witness-file");
  const witnessPinFlag = args.flags.get("witness-key");
  const witnessIdFlag = args.flags.get("witness-key-id");
  const witnessNameFlag = args.flags.get("witness-name");
  const witnessMode = witnessUrlFlag !== undefined || witnessFileFlag !== undefined;
  if (witnessUrlFlag !== undefined && witnessFileFlag !== undefined) {
    process.stderr.write(
      "chirindo verify: --witness and --witness-file are alternatives; pass at most one\n",
    );
    return 2;
  }
  if (
    !witnessMode &&
    (witnessPinFlag !== undefined || witnessIdFlag !== undefined || witnessNameFlag !== undefined)
  ) {
    process.stderr.write(
      "chirindo verify: --witness-key, --witness-key-id and --witness-name need --witness or --witness-file\n",
    );
    return 2;
  }
  if (witnessFileFlag !== undefined && witnessPinFlag === undefined) {
    process.stderr.write(
      "chirindo verify: --witness-file requires --witness-key (a sidecar carries no key to trust)\n",
    );
    return 2;
  }
  if ([witnessUrlFlag, witnessFileFlag, witnessPinFlag, witnessIdFlag, witnessNameFlag].includes(true)) {
    process.stderr.write("chirindo verify: witness options take a value\n");
    return 2;
  }
  let witnessBase: string | undefined;
  if (typeof witnessUrlFlag === "string") {
    try {
      witnessBase = checkWitnessBaseUrl(witnessUrlFlag);
    } catch (e) {
      process.stderr.write(`chirindo verify: ${(e as Error).message}\n`);
      return 2;
    }
  }
  let witnessPinned: WitnessPub | undefined;
  if (typeof witnessPinFlag === "string") {
    const pinned = loadPinnedWitnessKey(
      witnessPinFlag,
      typeof witnessIdFlag === "string" ? witnessIdFlag : undefined,
      "verify",
    );
    if (pinned === null) return 2;
    witnessPinned = pinned;
  }

  const maxSkewFlag = args.flags.get("max-skew-ms");
  const skewOpt =
    typeof maxSkewFlag === "string"
      ? { maxSkewMs: Number.parseInt(maxSkewFlag, 10) }
      : {};

  // Pinning surface (spec C). --expect-thumbprint is repeatable; --trust-file
  // is a JSON file of accepted thumbprints. The two merge. Fail-closed: a
  // trust file that is named but unreadable/malformed is an error, NOT an
  // empty (= "trust everything") set — silently dropping a pin is exactly the
  // failure a trust anchor must never have.
  const expectThumbprints = args.multi.get("expect-thumbprint") ?? [];
  const trustFileFlag = args.flags.get("trust-file");
  if (typeof trustFileFlag === "string") {
    const loaded = loadTrustFile(resolvePath(trustFileFlag));
    if (loaded === null) return 2; // message already written
    expectThumbprints.push(...loaded);
  }

  // Key-source resolution precedence (spec F), highest first:
  //
  //   --key <file>            explicit local identity, no network (flag)
  //   --jwks <url>            explicit URL, overrides embedded jwks_uri (flag)
  //   receipt jwks_uri        the self-describing URL in the signed bytes
  //   $RECORDER_JWKS_URL      operator env override
  //   published default       DEFAULT_JWKS_URL
  //
  // Fallback happens ONLY when the higher source is ABSENT — never when it is
  // present-but-down. In particular, if a receipt carries a jwks_uri and that
  // fetch fails, the verdict is UNVERIFIABLE (from runVerify); we do NOT drop
  // to env or the published default, because silently verifying a
  // self-describing receipt under a DIFFERENT key would defeat the whole
  // point. The published default is reachable only for a legacy receipt with
  // no embedded jwks_uri (and no flag/env). There is no implicit local-
  // identity default — use --key for the offline path.
  //
  // The embedded URL is read from the FIRST record's `jwks_uri` field, which is
  // inside the signed bytes: a post-sign mutation breaks the signature, so a
  // verifier following it trusts the signer's committed location, not a
  // rewritable hint.
  let embeddedJwksUri: string | undefined;
  try {
    const chainFile = readChainFile(chainPath);
    embeddedJwksUri = chainFile.records[0]?.jwks_uri;
  } catch {
    // Reading errors are surfaced by runVerify with a richer reason; we just
    // skip the peek and let the normal path report.
  }
  const envJwksUrl = process.env[JWKS_URL_ENV_VAR];
  const useLocalKey = typeof keyFlag === "string";
  let result;
  if (useLocalKey) {
    const identityPath = resolvePath(keyFlag as string);
    result = runVerify({
      chainPath,
      identityPath,
      expectThumbprints,
      keySource: "flag",
      keyOrigin: identityPath,
      ...skewOpt,
    });
  } else {
    // No --key ⇒ a JWKS source is always chosen; the published default is the
    // terminal fallback. Classify precisely so the output names the source.
    let jwksUrl: string;
    let keySource: "flag" | "receipt-jwks" | "env" | "default";
    if (typeof jwksFlag === "string") {
      jwksUrl = jwksFlag;
      keySource = "flag";
    } else if (embeddedJwksUri !== undefined) {
      jwksUrl = embeddedJwksUri;
      keySource = "receipt-jwks";
    } else if (envJwksUrl !== undefined) {
      jwksUrl = envJwksUrl;
      keySource = "env";
    } else {
      jwksUrl = DEFAULT_JWKS_URL;
      keySource = "default";
    }
    result = await runVerify({
      chainPath,
      jwksUrl,
      expectThumbprints,
      keySource,
      keyOrigin: jwksUrl,
      ...skewOpt,
    });
  }

  // Delivery gate (delivery-proof spec §5.2). `delivery: "unproven"` — a
  // referenced payment with no committed output — exits non-zero by DEFAULT:
  // it is precisely the "settled, delivered nothing" case this feature exists
  // to expose, and a caller gating on `$?` must not read it as success.
  // --allow-unproven-delivery relaxes the exit gate ONLY; the verdict stays on
  // the output line either way.
  const formatted = formatVerifyResult(result, {
    allowUnprovenDelivery: args.flags.get("allow-unproven-delivery") === true,
  });
  if (!witnessMode) {
    process.stdout.write(formatted.line + "\n");
    return formatted.exitCode;
  }

  // Step 1: the witness layer only runs on a VALID chain (DELIVERY UNPROVEN
  // still counts as VALID here); anything else is reported unchanged.
  if (result.kind !== "valid") {
    process.stdout.write(formatted.line + "\n");
    return formatted.exitCode;
  }
  const witnessed = await verifyAgainstWitness({
    chainPath,
    validText: formatted.line,
    validExit: formatted.exitCode,
    witnessName: typeof witnessNameFlag === "string" ? witnessNameFlag : DEFAULT_WITNESS_NAME,
    ...(witnessBase !== undefined ? { baseUrl: witnessBase } : {}),
    ...(typeof witnessFileFlag === "string" ? { sidecarPath: resolvePath(witnessFileFlag) } : {}),
    ...(witnessPinned !== undefined ? { pinned: witnessPinned } : {}),
  });
  process.stdout.write(witnessed.text + "\n");
  return witnessed.code;
}

// Load a JSON trust file of accepted RFC 7638 thumbprints. Accepts either a
// bare array of strings or an object with a `thumbprints` string array.
// Returns null (after writing a diagnostic) on any read/parse/shape error —
// the caller treats null as a fail-closed usage error, never as "no pins."
function loadTrustFile(path: string): string[] | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    process.stderr.write(
      `chirindo verify: cannot read --trust-file ${path}: ${(e as Error).message}\n`,
    );
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    process.stderr.write(
      `chirindo verify: --trust-file ${path} is not valid JSON: ${(e as Error).message}\n`,
    );
    return null;
  }
  const list = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" &&
        parsed !== null &&
        Array.isArray((parsed as { thumbprints?: unknown }).thumbprints)
      ? (parsed as { thumbprints: unknown[] }).thumbprints
      : null;
  if (list === null || !list.every((t) => typeof t === "string" && t.length > 0)) {
    process.stderr.write(
      `chirindo verify: --trust-file ${path} must be a JSON array of thumbprint strings ` +
        `or an object { "thumbprints": [ ... ] }\n`,
    );
    return null;
  }
  return list as string[];
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
    case "export-jwks":
      return cmdExportJwks(args);
    case "proxy":
      return cmdProxy(args);
    case "checkpoint":
      return await cmdCheckpoint(args);
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
