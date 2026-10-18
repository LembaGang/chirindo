#!/usr/bin/env node
// check-h4.mjs: checks one ordering-evidence case for a third-party pre-trade
// workflow on Base: two EIP-712 receipts from a pre-trade check issuer, read
// through an issuer profile the verifier pins by sha256, the hash-chained log
// entries that carry their uids, an Ed25519 checkpoint of that log witnessed
// by Headless Oracle, and a transaction in which the account the verifier
// names with --authorizer signed bytes that carry the later (destination)
// entry's hash.
//
//   node check-h4.mjs <case-dir> [--authorizer <address>] [--online] [--show-parties] [--pins <dir>] [--profile-sha256 <hex>]... [--rpc <url>]...
//
// Exit codes: 0 ordering mode, a pass: no FAIL and no FLAG line, the chain
// data read from two endpoints that gave byte-equal answers (--online), and
// the authorizer stated with --authorizer; 1 at least one FAIL; 2 usage
// error; 3 trailer-report mode finished with no FAIL (no ordering is
// claimed); 4 ordering mode, no FAIL, but the chain data is as the case
// supplies it (NOT VERIFIED OFFLINE lines): not a pass; 5 ordering mode, no
// FAIL, chain data verified, but at least one FLAG line (among them: no
// --authorizer): not a pass. NOT CHECKED and NOT SUPPORTED lines are listed,
// never counted as passes. README.md in this folder states the case layout,
// the log rules and what each exit code does and does not show.
//
// The checks are in lib/check.mjs. This file only runs them, with no test of
// whether it is the main module, so it runs the same however it is reached
// (through a symlink or a junction, or by another spelling of its path).

import { main } from "./lib/check.mjs";

await main();
