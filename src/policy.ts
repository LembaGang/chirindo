// Policy evaluation. Fail-closed: any read/parse failure denies.
//
// The spike supports the minimum policy shape needed to demonstrate
// allow/deny: a list of {tool, server?} deny rules. Match semantics:
//   - `tool` is matched against the MCP tools/call `name` without regard to
//     case (src/member-names.ts caseKeys), so a rule for mock_swap also stops
//     "MOCK_SWAP" and "mock_ſwap" (U+017F), which a downstream that looks
//     tools up without regard to case could run as mock_swap. Up to 0.5.2 the
//     match was literal.
//   - `server` (optional) is matched literally against the configured
//     downstream server label. If omitted, the rule matches any server.
// Anything not matched by a deny rule is allowed.
//
// Productization replaces this with a richer policy language (arguments
// matchers, capability scopes, principals). For the spike, deny-by-tool
// is enough to prove the fail-closed enforcement path end-to-end.

import { readFileSync } from "node:fs";
import { CONTROL_OR_FORMAT, EDGE_WHITE_SPACE, caseKeys } from "./member-names.js";

export interface DenyRule {
  tool: string;
  server?: string;
  reason?: string;
}

export interface Policy {
  deny: DenyRule[];
}

export type PolicyDecision =
  | { kind: "allow" }
  | { kind: "deny"; reason: string };

export class PolicyLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyLoadError";
  }
}

export function loadPolicy(path: string): Policy {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    throw new PolicyLoadError(
      `cannot read policy file ${path}: ${(e as Error).message}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new PolicyLoadError(
      `policy file ${path} is not valid JSON: ${(e as Error).message}`,
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as Record<string, unknown>)["deny"])
  ) {
    throw new PolicyLoadError(
      `policy file ${path} must be {deny: DenyRule[]}`,
    );
  }
  // We don't validate every rule deeply — extra fields are tolerated, but
  // a missing `tool` field on a deny rule is treated as a fatal config bug
  // (fail-closed implies we'd rather throw than silently let calls through).
  const deny = (parsed as { deny: unknown[] }).deny.map((r, i) => {
    if (
      typeof r !== "object" ||
      r === null ||
      typeof (r as Record<string, unknown>)["tool"] !== "string"
    ) {
      throw new PolicyLoadError(
        `policy file ${path}: deny[${i}] missing required string field "tool"`,
      );
    }
    return r as DenyRule;
  });
  return { deny };
}

export function evaluate(
  policy: Policy,
  call: { server: string; tool: string },
): PolicyDecision {
  const tool = caseKeys(call.tool);
  for (const rule of policy.deny) {
    const ruleTool = caseKeys(rule.tool);
    if (ruleTool[0] !== tool[0] && ruleTool[1] !== tool[1]) continue;
    if (rule.server !== undefined && rule.server !== call.server) continue;
    return {
      kind: "deny",
      reason: rule.reason ?? `tool '${call.tool}' denied by policy`,
    };
  }
  return { kind: "allow" };
}

// A tool name that a downstream could read as another one: white space at
// either end (a downstream that trims names reads " mock_swap" as
// mock_swap), or a control or format character anywhere (Unicode categories
// Cc and Cf, such as NUL, a zero-width space or a bidi override, which a
// downstream may drop). The proxy refuses a tools/call whose params.name is
// such a name (src/proxy.ts). Returns what is wrong with the name, for the
// refusal's stderr line, or null.
export function toolNameProblem(name: string): string | null {
  if (EDGE_WHITE_SPACE.test(name)) return "begins or ends with white space";
  const found = CONTROL_OR_FORMAT.exec(name);
  if (found === null) return null;
  const code = found[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
  return `holds the control or format character U+${code}`;
}

// MCP's rule for tool names (https://modelcontextprotocol.io/specification/
// 2026-07-28/server/tools, "Tool Names"): they SHOULD be 1 to 128 characters
// long, and "The following SHOULD be the only allowed characters": ASCII
// letters, digits, underscore, hyphen and dot. By default the proxy refuses a
// tools/call whose name is outside it (src/proxy.ts); the proxy flag
// --allow-nonstandard-tool-names turns that off. Inside the rule a name has no
// white space, control, format, compatibility or combining character that a
// downstream could drop or normalize. Returns what is wrong with the name, for
// the refusal's stderr line, or null.
const MCP_TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

export function standardToolNameProblem(name: string): string | null {
  if (MCP_TOOL_NAME.test(name)) return null;
  if (/^[A-Za-z0-9_.-]+$/.test(name)) return "is longer than 128 characters";
  return "holds a character outside A-Z, a-z, 0-9, _, - and .";
}
