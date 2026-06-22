// Policy evaluation. Fail-closed: any read/parse failure denies.
//
// The spike supports the minimum policy shape needed to demonstrate
// allow/deny: a list of {tool, server?} deny rules. Match semantics:
//   - `tool` is matched literally against the MCP tools/call `name`.
//   - `server` (optional) is matched literally against the configured
//     downstream server label. If omitted, the rule matches any server.
// Anything not matched by a deny rule is allowed.
//
// Productization replaces this with a richer policy language (arguments
// matchers, capability scopes, principals). For the spike, deny-by-tool
// is enough to prove the fail-closed enforcement path end-to-end.

import { readFileSync } from "node:fs";

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
  for (const rule of policy.deny) {
    if (rule.tool !== call.tool) continue;
    if (rule.server !== undefined && rule.server !== call.server) continue;
    return {
      kind: "deny",
      reason: rule.reason ?? `tool '${call.tool}' denied by policy`,
    };
  }
  return { kind: "allow" };
}
