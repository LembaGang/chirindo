// Regression: on Windows, `spawnRealDownstream("npx", ...)` must launch
// the real `npx.cmd` shim. The original code did not pass `shell:true`
// from the CLI path, so the bare-name MCP config used by every README
// example — `"command": "node", "args": [..., "--", "npx", "-y",
// "@modelcontextprotocol/server-everything"]` — crashed at boot with
//
//   Error: spawn npx ENOENT
//
// after `[mcp-gate] proxy up`. The old `proxy-spawn.test.ts` dodged this
// failure mode entirely: it hard-coded the `.cmd` extension AND passed
// `shell: IS_WIN` explicitly, so it never exercised the actual default
// spawn behaviour. This test does — bare command name, no shell
// override — so the regression is caught next time someone touches the
// spawn path.
//
// On Linux/macOS `npx` is a real shell script with a shebang, so the
// bare name works without shell:true. The test passes on every
// supported platform and is platform-agnostic by design.

import { describe, expect, it } from "vitest";
import { spawnRealDownstream } from "../src/proxy.js";

describe("spawnRealDownstream — bare shim name", () => {
  it("launches a bare `npx --version` without a shell override (regression)", async () => {
    const ds = spawnRealDownstream("npx", ["--version"]);

    let stdout = "";
    let stderr = "";
    ds.stdout.on("data", (c: Buffer | string) => {
      stdout += c.toString("utf8");
    });
    ds.stderr?.on("data", (c: Buffer | string) => {
      stderr += c.toString("utf8");
    });

    const code = await ds.exited;

    // Successful spawn: npx prints its semver to stdout and exits 0.
    // Spawn-time ENOENT: the 'error' event resolves `exited` with null,
    // these assertions fail, and the error message exposes the
    // regression (instead of hanging the test or aborting the process).
    expect(code, `exit code=${code} stderr=${stderr.trim()}`).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 30_000);
});
