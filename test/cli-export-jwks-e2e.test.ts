// End-to-end smoke for `chirindo export-jwks`: spawn the CLI, run init to
// produce an identity, run export-jwks, then prove the output file parses
// as a JWKS containing the same kid + x bytes as the identity.json. That's
// the contract an adopter relies on: chirindo init → chirindo export-jwks →
// upload that file to your HTTPS host → verifiers can resolve.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTmpDir, makeTmpDir } from "./helpers.js";

const CLI_ENTRY = resolve(import.meta.dirname, "..", "src", "cli.ts");
const IS_WIN = process.platform === "win32";

function runCli(args: string[]): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  const r = spawnSync(
    IS_WIN ? "npx.cmd" : "npx",
    ["tsx", CLI_ENTRY, ...args],
    { encoding: "utf8", shell: IS_WIN },
  );
  return {
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    status: r.status,
  };
}

describe("chirindo export-jwks (CLI end-to-end)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("writes a JWKS file whose key matches the gate's identity", () => {
    const dir = join(tmp, "gate");
    const initR = runCli(["init", "--dir", dir]);
    expect(initR.status).toBe(0);

    const out = join(tmp, "jwks.json");
    const expR = runCli(["export-jwks", "--dir", dir, "--out", out]);
    expect(expR.stdout).toMatch(/exported chirindo JWKS/);
    expect(expR.status).toBe(0);

    const jwks = JSON.parse(readFileSync(out, "utf8")) as {
      keys: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBe(1);
    const jwk = jwks.keys[0]!;
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.use).toBe("sig");
    expect(jwk.alg).toBe("EdDSA");

    // The kid + x in the JWKS must match the identity on disk byte-for-byte
    // (Buffer / b64url encoding round-trips have a history of subtle bugs;
    // the strict equality is the regression pin).
    const identity = JSON.parse(
      readFileSync(join(dir, "identity.json"), "utf8"),
    ) as { kid: string; public_key_b64url: string };
    expect(jwk.kid).toBe(identity.kid);
    expect(jwk.x).toBe(identity.public_key_b64url);
  }, 20_000);

  it("defaults --out to <dir>/jwks.json when omitted", () => {
    const dir = join(tmp, "gate");
    expect(runCli(["init", "--dir", dir]).status).toBe(0);
    const expR = runCli(["export-jwks", "--dir", dir]);
    expect(expR.status).toBe(0);
    // Existence + parse — content fidelity is covered above.
    const jwks = JSON.parse(readFileSync(join(dir, "jwks.json"), "utf8")) as {
      keys: unknown[];
    };
    expect(Array.isArray(jwks.keys)).toBe(true);
  }, 20_000);

  it("fails (exit 1) when no identity has been initialized", () => {
    const dir = join(tmp, "gate-empty");
    const expR = runCli(["export-jwks", "--dir", dir]);
    expect(expR.status).toBe(1);
    expect(expR.stderr).toMatch(/cannot read identity/);
  }, 20_000);
});
