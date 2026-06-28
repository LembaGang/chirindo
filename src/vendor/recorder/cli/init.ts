// `recorder init` — generate an Ed25519 keypair under the data directory.
// No network. Idempotent in failure (if dir exists with files, we refuse
// rather than overwrite).

import { existsSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair } from "../key.js";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  writeIdentity,
  type WriteIdentityResult,
} from "../identity.js";

export interface InitOptions {
  dir: string;
  // Refuse to overwrite if true (default). Set false ONLY in tests.
  failIfExists?: boolean;
}

export type InitResult =
  | (WriteIdentityResult & { kind: "created" })
  | {
      kind: "exists";
      dir: string;
      identityPath: string;
      privateKeyPath: string;
    };

export function runInit(opts: InitOptions): InitResult {
  const failIfExists = opts.failIfExists ?? true;
  const identityPath = join(opts.dir, IDENTITY_FILENAME);
  const privateKeyPath = join(opts.dir, PRIVATE_KEY_FILENAME);

  if (
    failIfExists &&
    (existsSync(identityPath) || existsSync(privateKeyPath))
  ) {
    return { kind: "exists", dir: opts.dir, identityPath, privateKeyPath };
  }

  const { privateKey, publicKey } = generateKeyPair();
  const written = writeIdentity(opts.dir, privateKey, publicKey);
  return { kind: "created", ...written };
}
