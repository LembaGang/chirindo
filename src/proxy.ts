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
// cancellation) passes through unchanged, with these exceptions. These
// client lines are refused, never forwarded, because a downstream could read
// something in them that the gate did not check (each refusal writes one
// stderr line):
//
//   - a tools/call with no id: DENY receipt, no reply (it is a notification);
//   - a tools/call whose id is null or not a string or an integer: DENY
//     receipt and a -32600 error with id null;
//   - a JSON array (a JSON-RPC batch): a DENY receipt for each tools/call in
//     it and one -32600 error with id null. MCP removed batching in 2025-06-18;
//   - a line that is not JSON: -32700; a line with a carriage return inside
//     it: -32600 (both with id null);
//   - a message with a member name twice in one object, with a top-level
//     member that is jsonrpc, id, method or params in another case ("Method",
//     "paramſ"), or with two top-level members or two params members that
//     differ only in case, and a tools/call whose params has name, arguments
//     or _meta in another case: -32600 (src/member-names.ts says why);
//   - a message with a member named "__proto__" at the top level or in params:
//     -32600 (JSON.parse keeps it inert, but a downstream that merges the
//     message with Object.assign or for...in makes it the prototype, so a
//     method and params carried in it read as the message's own);
//   - a message whose method is not a string (["tools/call"], an object, a
//     number, true, false or null), is tools/call only after trimming white
//     space or folding case ("TOOLS/CALL", "tools/call "), or holds a control
//     or format character: -32600;
//   - a tools/call with an integer outside the JavaScript safe range, or a
//     number too large for a double (1e400), anywhere in it: -32600 (an
//     allowed call is forwarded re-encoded from JSON.parse's value, which
//     would change that number; 1e400 would become null);
//   - a tools/call nested more than MAX_VALUE_DEPTH levels deep, or whose
//     arguments otherwise cannot be canonicalized for a receipt: -32600, its
//     receipt's args_hash over the empty object. The receipt's args_hash and
//     request_commitment are computed before an allowed call is forwarded, so
//     a call the gate could not record never reaches the downstream;
//   - a tools/call whose id is already in flight: -32600;
//   - a tools/call whose params is not an object, or whose params.name is not
//     a non-empty string, begins or ends with white space, or holds a control
//     or format character: -32602 (src/policy.ts toolNameProblem);
//   - unless allowNonstandardToolNames is set (the CLI's
//     --allow-nonstandard-tool-names), a tools/call whose params.name is
//     outside MCP's tool-name rule, 1 to 128 characters each an ASCII letter,
//     a digit, _, - or .: -32602 (src/policy.ts standardToolNameProblem).
//
// From the duplicate-member rule down, the error carries the refused
// message's id when the message is a request (it has a member named method,
// in any case), has one member named exactly "id", and that id is a string or
// a safe integer; otherwise id null (replyIdOf below).
//
// Every refused line that is a tools/call, or that a reader could take for
// one (matching member names without regard to case, trimming, folding the
// case of or dropping control and format characters from the method, reading a
// method that is not a string as text, as String() does, or reading a
// "__proto__" member as the message's own members), also gets a DENY receipt
// (a batch, one per such element); a line that is not JSON or has a carriage
// return inside it gets none, nor does a tools/call whose arguments hold a
// number too large for a double, which no receipt can hash. A tools/call
// refused for nesting too deep gets a DENY receipt over the empty object.
// A refusal's DENY receipt reads like a policy deny (decision_source
// "config"): the reason is in the stderr line only.
//
// A tools/call is recognised by its method alone (src/rpc.ts isToolsCall);
// any other method that a reader could take for tools/call is refused above.
// Deny rules match tool names without regard to case (src/policy.ts).
//
// Client stdin and downstream stdout are each read through one streaming
// UTF-8 decoder, so a character split between two chunks is read whole.
//
// IMPORTANT: stderr is for logging only — MUST NOT carry MCP frames. We
// log gate decisions to stderr; the client's stdout sees only valid MCP.

import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import type { LoadedFullIdentity } from "./vendor/recorder/index.js";
import {
  type Policy,
  type PolicyDecision,
  evaluate,
  standardToolNameProblem,
  toolNameProblem,
} from "./policy.js";
import { ProxyCheckpointer } from "./checkpoint.js";
import { appendReceipt, type GateDecision } from "./receipt.js";
import { argsHash, findDuplicateMember, findUnsafeInteger } from "./vendor/recorder/index.js";
import {
  CONTROL_OR_FORMAT,
  ENVELOPE_MEMBERS,
  TOOLS_CALL_PARAMS_MEMBERS,
  caseVariant,
  foldCollision,
  methodNamesToolsCall,
  methodValueNamesToolsCall,
  namesMethod,
  toolsCallClaims,
  topLevelMemberNames,
} from "./member-names.js";
import {
  INVALID_PARAMS,
  INVALID_REQUEST,
  MAX_VALUE_DEPTH,
  PARSE_ERROR,
  denyToolResult,
  encodeMessage,
  errorResponse,
  exceedsDepth,
  hasNonFiniteNumber,
  isPlainObject,
  isToolsCall,
  isValidRequestId,
  splitLines,
  type JsonRpcRequest,
} from "./rpc.js";
import type { WitnessTarget } from "./witness.js";

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
  // OPTIONAL — HTTPS URL where this gate's JWKS is published. When set,
  // every emitted receipt carries this URL in `jwks_uri` inside the signed
  // bytes, telling verifiers where to fetch the public key for `kid`. The
  // signer commits to a specific location; HO is not in the trust path.
  jwksUri?: string;
  log: (msg: string) => void; // writes to stderr in production
  now?: () => string;
  // OPTIONAL checkpointing into `<chain>.witness.ndjson`. Setting either one
  // enables it (and the shutdown checkpoint). A checkpoint or witness step
  // never delays, alters or denies a tool call.
  checkpointEvery?: number;
  witness?: WitnessTarget;
  // OPTIONAL — forward a tools/call whose name is outside MCP's tool-name rule
  // (1 to 128 of A-Z, a-z, 0-9, _, - and .) instead of refusing it. Deny
  // rules then compare such names without regard to case only; a warning is
  // logged at start. The CLI sets it with --allow-nonstandard-tool-names.
  allowNonstandardToolNames?: boolean;
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
  // Clean-shutdown checkpoint of the head, awaiting queued witness POSTs for
  // at most `timeoutMs`. No-op when checkpointing is off or no receipt was
  // written. A killed process never gets here: it writes no final checkpoint.
  finalCheckpoint: (timeoutMs: number) => Promise<void>;
}

export function runProxy(deps: ProxyDeps): ProxyHandle {
  const downstream = deps.spawnDownstream();
  let downStdoutBuf = "";
  let clientStdinBuf = "";
  // One decoder per stream: the bytes of a character that a chunk boundary
  // cuts are held until the rest arrives, instead of each becoming U+FFFD.
  const clientDecoder = new StringDecoder("utf8");
  const downstreamDecoder = new StringDecoder("utf8");
  let receiptCount = 0;
  const allowNonstandardToolNames = deps.allowNonstandardToolNames === true;
  if (allowNonstandardToolNames) {
    deps.log(
      "[proxy] WARNING: --allow-nonstandard-tool-names: tool names outside MCP's rule " +
        "(1 to 128 of A-Z, a-z, 0-9, _, - and .) are forwarded, and deny rules compare them " +
        "only without regard to case; a downstream that normalizes names further (NFKC, " +
        "dropping invisible or combining characters) could run a tool a deny rule names",
    );
  }
  const checkpointer =
    deps.checkpointEvery !== undefined || deps.witness !== undefined
      ? new ProxyCheckpointer({
          chainPath: deps.chainPath,
          identity: deps.identity,
          ...(deps.checkpointEvery !== undefined ? { every: deps.checkpointEvery } : {}),
          ...(deps.witness !== undefined ? { witness: deps.witness } : {}),
          log: deps.log,
          ...(deps.now ? { now: deps.now } : {}),
        })
      : null;

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
    const text = typeof chunk === "string" ? chunk : clientDecoder.write(chunk);
    const { lines, rest } = splitLines(clientStdinBuf, text);
    clientStdinBuf = rest;
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      // One line can never stop the proxy: an unexpected throw while reading
      // this line (e.g. encoding or hashing a pathological payload) is logged
      // and the line dropped, and the proxy goes on serving the next line.
      try {
        handleClientLine(line);
      } catch (e) {
        deps.log(`[proxy] client line dropped, not forwarded: ${(e as Error).message}`);
      }
    }
  };

  function handleClientLine(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Not JSON to the gate. Never forwarded: a downstream whose parser
      // accepts more (NaN, comments, a byte order mark) could read a
      // tools/call here that the gate never checked.
      refuseLine(PARSE_ERROR, "Parse error: the line is not valid JSON", "that is not JSON");
      return;
    }

    // A carriage return left inside the line (splitLines removed a final
    // one). JSON.parse reads it as whitespace, but a reader that ends lines
    // at a bare CR (Node readline, Python text I/O) splits the line in two
    // and can find a whole tools/call inside a message the gate read as
    // something else.
    if (line.includes("\r")) {
      refuseLine(
        INVALID_REQUEST,
        "Invalid Request: carriage return inside a message",
        "with a carriage return inside it",
      );
      return;
    }

    if (Array.isArray(parsed)) {
      refuseBatch(line, parsed);
      return;
    }
    if (!isPlainObject(parsed)) {
      downstream.stdin.write(line + "\n");
      return;
    }

    // A member name twice in one object: JSON.parse keeps the last value,
    // another parser may keep the first (a "method" of tools/call, say).
    const duplicate = findDuplicateMember(line);
    if (duplicate !== null) {
      refuseMessage(
        line,
        parsed,
        "Invalid Request: a member name appears twice in one object",
        `with a duplicate member ${logText(duplicate.detail)}`,
      );
      return;
    }

    // Member names that a reader matching names without regard to case
    // could take for others: "Method" for method, say.
    const caseClash = caseProblem(parsed);
    if (caseClash !== null) {
      refuseMessage(
        line,
        parsed,
        "Invalid Request: member names that differ only in case",
        caseClash,
      );
      return;
    }

    // A member named "__proto__" at the top level or in params. JSON.parse
    // keeps it as an own member, so the gate reads no method or name from it
    // and would forward the line; but a downstream that copies the message
    // (Object.assign({}, msg), a for...in loop) makes that member the copy's
    // prototype, so its method and params read as the message's own.
    const protoClash = protoProblem(parsed);
    if (protoClash !== null) {
      refuseMessage(
        line,
        parsed,
        'Invalid Request: a member named "__proto__", which a downstream could read as the message\'s own members',
        protoClash,
      );
      return;
    }

    // A method that is not a string, which a reader turning it into text
    // (String(method), HANDLERS[msg.method]) may take for tools/call; a
    // method value a reader that trims it, folds its case or drops
    // invisible characters could take for tools/call, other than
    // tools/call itself; and any method value with such a character.
    const methodClash = methodProblem(parsed);
    if (methodClash !== null) {
      refuseMessage(line, parsed, methodClash.message, methodClash.what);
      return;
    }

    if (isToolsCall(parsed)) {
      gateToolsCall(line, parsed);
    } else {
      downstream.stdin.write(line + "\n");
    }
  }

  // The member names of a message, at the top level and in params, that a
  // reader matching names without regard to case could read differently from
  // JSON.parse (src/member-names.ts). Returns the stderr wording, or null.
  // Members below params (inside arguments or _meta) are not checked.
  function caseProblem(msg: Record<string, unknown>): string | null {
    const keys = Object.keys(msg);
    const variant = caseVariant(keys, ENVELOPE_MEMBERS);
    if (variant !== null) {
      return `with the member ${quote(variant.key)}, which is ${quote(variant.of)} in another case`;
    }
    const pair = foldCollision(keys);
    if (pair !== null) {
      return `with the members ${quote(pair[0])} and ${quote(pair[1])}, which differ only in case`;
    }
    const params = msg["params"];
    if (!isPlainObject(params)) return null;
    const paramKeys = Object.keys(params);
    if (isToolsCall(msg)) {
      const paramVariant = caseVariant(paramKeys, TOOLS_CALL_PARAMS_MEMBERS);
      if (paramVariant !== null) {
        return `with the params member ${quote(paramVariant.key)}, which is ${quote(paramVariant.of)} in another case`;
      }
    }
    const paramPair = foldCollision(paramKeys);
    if (paramPair !== null) {
      return `with the params members ${quote(paramPair[0])} and ${quote(paramPair[1])}, which differ only in case`;
    }
    return null;
  }

  // The method value of a message as JSON.parse read it (a member named method
  // in another case is refused before this): a value that is not a string, a
  // control or format character, or tools/call in another case or with white
  // space at either end. A message with no method member (a response) has
  // none of these.
  function methodProblem(msg: Record<string, unknown>): { message: string; what: string } | null {
    if (!Object.prototype.hasOwnProperty.call(msg, "method")) return null;
    const method = msg["method"];
    if (typeof method !== "string") {
      const kind = Array.isArray(method)
        ? "an array"
        : method === null
          ? "null"
          : typeof method === "object"
            ? "an object"
            : `a ${typeof method}`;
      return {
        message: "Invalid Request: method must be a string",
        what: `with a method that is ${kind}, not a string`,
      };
    }
    const found = CONTROL_OR_FORMAT.exec(method);
    if (found !== null) {
      const code = found[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
      return {
        message: "Invalid Request: a method holds a control or format character",
        what: `with the method ${quote(method)}, which holds the control or format character U+${code}`,
      };
    }
    if (method !== "tools/call" && methodNamesToolsCall(method)) {
      return {
        message: "Invalid Request: a method that is tools/call only in another case or with white space around it",
        what: `with the method ${quote(method)}, which is tools/call only after trimming white space or folding case`,
      };
    }
    return null;
  }

  // A member named "__proto__" at the top level of the message or of params.
  // JSON.parse makes it an inert own member (its own-property descriptor holds
  // the value; the object's prototype is untouched), so the gate reads no
  // method or name from it. A downstream that merges the message into a fresh
  // object (Object.assign({}, msg), { ...msg }, a for...in copy) instead
  // ASSIGNS "__proto__", setting that object's prototype, so a method and
  // params carried inside it read as the message's own. Returns the stderr
  // wording for the first such member, or null. Members below params (inside
  // arguments or _meta) are the tool's business and are not checked.
  function protoProblem(msg: Record<string, unknown>): string | null {
    if (Object.prototype.hasOwnProperty.call(msg, "__proto__")) {
      return 'with a member named "__proto__" at the top level';
    }
    const params = msg["params"];
    if (isPlainObject(params) && Object.prototype.hasOwnProperty.call(params, "__proto__")) {
      return 'with a member named "__proto__" in params';
    }
    return null;
  }

  // The own "__proto__" value of an object, read without triggering the
  // prototype accessor (obj["__proto__"] would return the prototype, not the
  // member). Undefined when there is no such own member.
  function ownProtoValue(obj: Record<string, unknown>): unknown {
    return Object.getOwnPropertyDescriptor(obj, "__proto__")?.value;
  }

  // The tool a refused, never-forwarded line would run if a downstream read it
  // as a tools/call, for the DENY receipt: the top-level method member reading
  // as tools/call (toolsCallClaims), or a "__proto__" member (top level or in
  // params) whose value is an object whose own method reads as tools/call (the
  // P18 case, where a downstream merges the message and reads method and params
  // from that member). Null when none does.
  function refusalCallTool(
    line: string,
    msg: Record<string, unknown>,
  ): { toolName: string; toolArgs: unknown } | null {
    if (toolsCallClaims(line)[0] === true) return toolOf(msg);
    const params = msg["params"];
    const containers: Array<Record<string, unknown>> = [msg];
    if (isPlainObject(params)) containers.push(params);
    for (const obj of containers) {
      const value = ownProtoValue(obj);
      if (isPlainObject(value) && methodValueNamesToolsCall(value["method"])) {
        return toolOf(value);
      }
    }
    return null;
  }

  // Text from the client in a stderr line: JSON-quoted, with every control,
  // format, line separator and paragraph separator character written as a \u
  // escape (JSON.stringify leaves U+0085, U+200B, U+202E, U+2028 and the like
  // as they are), so the entry stays on one line and shows what was sent.
  function logText(text: string): string {
    return JSON.stringify(text).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => {
      let out = "";
      for (let k = 0; k < c.length; k++) out += `\\u${c.charCodeAt(k).toString(16).padStart(4, "0")}`;
      return out;
    });
  }

  // logText, cut at 64 characters.
  function quote(text: string): string {
    return logText(text.length > 64 ? `${text.slice(0, 64)}...` : text);
  }

  // An id in a stderr line.
  function logId(id: string | number | null): string {
    return typeof id === "string" ? quote(id) : JSON.stringify(id);
  }

  // The id a refused message's error carries. JSON-RPC 2.0 and MCP answer a
  // request with its own id, so the error names the request when the message
  // is one (a member named method, in any case), has exactly one member named
  // "id", and that id is a string or a safe integer. Otherwise id null: MCP
  // ids are strings or integers, an integer beyond the safe range is no
  // longer the number the client wrote, a repeated id could be either value,
  // and a client's response carries the id of a request from the server,
  // which an error from the gate must not appear to answer.
  function replyIdOf(line: string, msg: Record<string, unknown>): string | number | null {
    const id = msg["id"];
    if (typeof id !== "string" && !Number.isSafeInteger(id)) return null;
    const names = topLevelMemberNames(line);
    if (names.filter((n) => n === "id").length !== 1 || !namesMethod(names)) return null;
    return id as string | number;
  }

  // A scanner message that quotes a number token from the client, cut at 120
  // characters.
  function short(text: string): string {
    return text.length > 120 ? `${text.slice(0, 120)}...` : text;
  }

  // Tool name and arguments per MCP spec §"Calling Tools". Arguments stay the
  // structured value: the receipt's args_hash is RFC 8785 JCS over it, so we
  // deliberately avoid an intermediate JSON.stringify whose key order isn't
  // canonical.
  function toolOf(msg: { params?: unknown }): { toolName: string; toolArgs: unknown } {
    const params = (msg.params ?? {}) as { name?: string; arguments?: unknown };
    const toolName = typeof params.name === "string" ? params.name : "";
    const toolArgs = params.arguments ?? {};
    return { toolName, toolArgs };
  }

  // Every tools/call passes here, whatever its id. Only a string or integer
  // id reaches handleToolsCall (policy, then forward or deny), and only when
  // the call holds no integer outside the safe range and no number too large
  // for a double, its id is not already in flight, and params.name is a
  // non-empty string with no white space at either end and no control or
  // format character, inside MCP's tool-name rule unless the operator allows
  // others. Anything else is refused before policy is consulted: DENY
  // receipt, never forwarded.
  function gateToolsCall(line: string, msg: Record<string, unknown>): void {
    const hasId = Object.prototype.hasOwnProperty.call(msg, "id");
    const id = msg["id"];
    if (hasId && isValidRequestId(id)) {
      const replyId = replyIdOf(line, msg);
      // JSON.parse has already rounded an integer outside the safe range, and
      // an allowed call is forwarded re-encoded from its value, so the
      // downstream would get another number than the client sent.
      const unsafe = findUnsafeInteger(line);
      if (unsafe !== null) {
        refuseToolsCall(
          msg,
          INVALID_REQUEST,
          "Invalid Request: an integer outside the JavaScript safe range",
          replyId,
          `has an integer outside the JavaScript safe range (${short(unsafe.detail)})`,
        );
        return;
      }
      // A number too large for a double (1e400) parses as Infinity: an
      // allowed call would reach the downstream with null in its place, and
      // its ALLOW receipt could not be written (JCS has no form for it).
      if (hasNonFiniteNumber(msg)) {
        refuseToolsCall(
          msg,
          INVALID_REQUEST,
          "Invalid Request: a number too large for a double",
          replyId,
          "has a number too large for a double (JSON.parse reads it as Infinity)",
        );
        return;
      }
      // A second call with the id of one still in flight: the downstream's
      // two answers could not be told apart, nor matched to their receipts.
      if (pendingAllows.has(id)) {
        refuseToolsCall(
          msg,
          INVALID_REQUEST,
          "Invalid Request: a tools/call with this id is already in flight",
          replyId,
          `has the id ${logId(id)} of a tools/call still in flight`,
        );
        return;
      }
      const params = msg["params"];
      if (!isPlainObject(params) || typeof params["name"] !== "string" || params["name"] === "") {
        refuseToolsCall(
          msg,
          INVALID_PARAMS,
          "Invalid params: tools/call needs params with a non-empty string name",
          replyId,
          "has no params object with a non-empty string name",
          "",
        );
        return;
      }
      // A name that a downstream trimming it, or dropping invisible
      // characters, could read as the name of a tool a deny rule names.
      const nameProblem = toolNameProblem(params["name"]);
      if (nameProblem !== null) {
        refuseToolsCall(
          msg,
          INVALID_PARAMS,
          "Invalid params: a tool name must not begin or end with white space or hold a control or format character",
          replyId,
          `has a tool name that ${nameProblem}`,
        );
        return;
      }
      // A name outside MCP's rule, which a downstream could normalize
      // (NFKC, dropping combining or ignorable characters) into the name of
      // a tool a deny rule names. Refused unless the operator chose otherwise.
      const standardProblem = allowNonstandardToolNames ? null : standardToolNameProblem(params["name"]);
      if (standardProblem !== null) {
        refuseToolsCall(
          msg,
          INVALID_PARAMS,
          "Invalid params: MCP tool names are 1 to 128 characters from A-Z, a-z, 0-9, _, - and . " +
            "(the gate's operator can allow others with --allow-nonstandard-tool-names)",
          replyId,
          `has a tool name that ${standardProblem}`,
        );
        return;
      }
      // The receipt's hashes (args_hash, and request_commitment over it) must
      // be computable before the call may run, so a call we could not record
      // never reaches the downstream. A message nested past MAX_VALUE_DEPTH,
      // whose canonicalization would overflow the stack, is refused here; so
      // is one whose arguments cannot be canonicalized for any other reason.
      // The DENY receipt hashes the empty object (the reason is on stderr),
      // and the line is not forwarded.
      const { toolArgs } = toolOf(msg);
      if (exceedsDepth(msg)) {
        refuseUnrecordable(
          msg,
          replyId,
          `is nested more than ${MAX_VALUE_DEPTH} levels deep, too deep to canonicalize for its receipt`,
        );
        return;
      }
      try {
        argsHash(toolArgs);
      } catch (e) {
        refuseUnrecordable(
          msg,
          replyId,
          `has arguments that cannot be canonicalized for its receipt (${(e as Error).message})`,
        );
        return;
      }
      handleToolsCall(msg as unknown as JsonRpcRequest);
      return;
    }
    const kind = Array.isArray(id)
      ? "an array"
      : typeof id === "number"
        ? "a number that is not an integer"
        : typeof id === "object"
          ? "an object"
          : `a ${typeof id}`;
    const problem = !hasId
      ? "has no id"
      : id === null
        ? "has a null id"
        : `has an id that is neither a string nor an integer (${kind})`;
    const { toolName, toolArgs } = toolOf(msg);
    const receipt = writeRefusalReceipt(toolName, toolArgs, `tools/call ${problem}`);
    // A message without an id is a notification: JSON-RPC 2.0 sends no reply.
    if (hasId) {
      deps.clientOut.write(
        encodeMessage(
          errorResponse(INVALID_REQUEST, "Invalid Request: tools/call needs a string or integer id"),
        ),
      );
    }
    deps.log(
      `[proxy] REFUSE tool=${quote(toolName)}: tools/call ${problem}; not forwarded; ` +
        `${hasId ? "-32600 sent" : "no reply (notification)"}; ` +
        `DENY receipt ${receipt}`,
    );
  }

  // The DENY receipt of a refused tools/call. Returns how it went, for the
  // refusal's stderr line: "written", "NOT written" (the write failed and
  // was logged), or not written because the arguments hold a number that no
  // receipt can hash (JCS has no form for Infinity). Arguments nested past
  // MAX_VALUE_DEPTH are hashed as the empty object, since canonicalizing them
  // would overflow the stack; the return note says so.
  function writeRefusalReceipt(toolName: string, toolArgs: unknown, why: string): string {
    if (hasNonFiniteNumber(toolArgs)) {
      return "not written: its arguments hold a number too large for a double, which no receipt can hash";
    }
    let argsForReceipt = toolArgs;
    let note = "";
    if (exceedsDepth(toolArgs)) {
      argsForReceipt = {};
      note = " (args_hash over the empty object: the arguments are nested too deep to canonicalize)";
    }
    const written = writeReceiptSafely({
      decisionForReceipt: { kind: "deny", reason: `${why}; refused (fail-closed)` },
      server: deps.serverLabel,
      toolName,
      toolArgs: argsForReceipt,
      toolResult: undefined,
    });
    return (written ? "written" : "NOT written") + note;
  }

  // A tools/call refused because the gate could not compute its receipt's
  // hashes (nested too deep, or otherwise not canonicalizable): -32600 with
  // `replyId`, a DENY receipt whose args_hash is over the empty object (the
  // real arguments are never canonicalized), not forwarded, one stderr line.
  function refuseUnrecordable(
    msg: Record<string, unknown>,
    replyId: string | number | null,
    problem: string,
  ): void {
    const { toolName } = toolOf(msg);
    const receipt = writeRefusalReceipt(toolName, {}, `tools/call ${problem}`);
    deps.clientOut.write(
      encodeMessage(errorResponse(INVALID_REQUEST, `Invalid Request: a tools/call that ${problem}`, replyId)),
    );
    deps.log(
      `[proxy] REFUSE tool=${quote(toolName)}: tools/call ${problem}; not forwarded; ` +
        `${INVALID_REQUEST} sent with id ${logId(replyId)}; DENY receipt ${receipt}`,
    );
  }

  // A tools/call refused after its id was found usable: a DENY receipt, the
  // error with `replyId`, one stderr line. `toolName` replaces the name read
  // from params when given.
  function refuseToolsCall(
    msg: Record<string, unknown>,
    code: number,
    message: string,
    replyId: string | number | null,
    problem: string,
    toolName?: string,
  ): void {
    const tool = toolOf(msg);
    const name = toolName ?? tool.toolName;
    const receipt = writeRefusalReceipt(name, tool.toolArgs, `tools/call ${problem}`);
    deps.clientOut.write(encodeMessage(errorResponse(code, message, replyId)));
    deps.log(
      `[proxy] REFUSE tool=${quote(name)}: tools/call ${problem}; not forwarded; ` +
        `${code} sent with id ${logId(replyId)}; ` +
        `DENY receipt ${receipt}`,
    );
  }

  // A client message refused before the tools/call rules: -32600 (with the id
  // replyIdOf gives) and one stderr line, plus a DENY receipt when the line
  // holds a tools/call as a reader matching member names without regard to
  // case, trimming, folding or dropping control and format characters from the
  // method, reading a method that is not a string as text, or reading a
  // "__proto__" member as the message's own members (refusalCallTool), could
  // take it.
  function refuseMessage(
    line: string,
    msg: Record<string, unknown>,
    message: string,
    what: string,
  ): void {
    let receipt = "no receipt (not a tools/call)";
    const tool = refusalCallTool(line, msg);
    if (tool !== null) {
      receipt = `DENY receipt ${writeRefusalReceipt(tool.toolName, tool.toolArgs, `client line ${what}`)} (tool ${quote(tool.toolName)})`;
    }
    const replyId = replyIdOf(line, msg);
    deps.clientOut.write(encodeMessage(errorResponse(INVALID_REQUEST, message, replyId)));
    deps.log(
      `[proxy] REFUSE client line ${what}: not forwarded; ${INVALID_REQUEST} sent with id ${logId(replyId)}; ${receipt}`,
    );
  }

  // A JSON-RPC batch is never forwarded, whatever it holds: each tools/call in
  // it (as toolsCallClaims reads it) gets a DENY receipt, and the client gets
  // one -32600 error.
  function refuseBatch(line: string, batch: unknown[]): void {
    const claims = toolsCallClaims(line);
    let calls = 0;
    let written = 0;
    for (const [k, element] of batch.entries()) {
      if (claims[k] !== true) continue;
      calls += 1;
      const { toolName, toolArgs } = toolOf(element as { params?: unknown });
      if (writeRefusalReceipt(toolName, toolArgs, "tools/call inside a JSON-RPC batch") === "written") {
        written += 1;
      }
    }
    deps.clientOut.write(
      encodeMessage(
        errorResponse(
          INVALID_REQUEST,
          "Invalid Request: JSON-RPC batches are not accepted; send one message per line",
        ),
      ),
    );
    deps.log(
      `[proxy] REFUSE JSON-RPC batch (${batch.length} elements, ${calls} tools/call): ` +
        `not forwarded; -32600 sent; ${written} of ${calls} DENY receipt(s) written`,
    );
  }

  // A client line the gate will not forward and cannot attribute to a tool:
  // one JSON-RPC error with id null, one stderr line, no receipt. Text taken
  // from the line is JSON-quoted so the log entry stays on one line.
  function refuseLine(code: number, message: string, what: string): void {
    deps.clientOut.write(encodeMessage(errorResponse(code, message)));
    deps.log(`[proxy] REFUSE client line ${what}: not forwarded; ${code} sent`);
  }

  function handleToolsCall(req: JsonRpcRequest): void {
    const { toolName, toolArgs } = toolOf(req);
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
        ...(deps.jwksUri !== undefined ? { jwksUri: deps.jwksUri } : {}),
        ...(deps.now ? { ts: deps.now() } : {}),
      });
      receiptCount += 1;
      // Its own try: a checkpoint failure must never turn into the receipt-
      // write failure path below, which withholds the result (fail-closed).
      try {
        checkpointer?.afterReceipt(receiptCount);
      } catch (e) {
        deps.log(`[chirindo] checkpoint failed: ${(e as Error).message}`);
      }
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
    const text = typeof chunk === "string" ? chunk : downstreamDecoder.write(chunk);
    const { lines, rest } = splitLines(downStdoutBuf, text);
    downStdoutBuf = rest;
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      // As on the client side: one downstream line can never stop the proxy.
      // A throw while reading it (e.g. hashing a pathological result) is
      // logged and the line dropped, and the proxy goes on.
      try {
        handleDownstreamLine(line);
      } catch (e) {
        deps.log(`[proxy] downstream line dropped: ${(e as Error).message}`);
      }
    }
  };

  function handleDownstreamLine(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      deps.clientOut.write(line + "\n");
      deps.log(`[proxy] forwarding unparseable downstream line as-is`);
      return;
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
        return;
      }
    }
    deps.clientOut.write(line + "\n");
  }

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
    finalCheckpoint: async (timeoutMs) => {
      await checkpointer?.shutdown(receiptCount, timeoutMs);
    },
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
