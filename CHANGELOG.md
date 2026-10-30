# Changelog

Published versions and their dates are listed on npm
(https://www.npmjs.com/package/@headlessoracle/chirindo?activeTab=versions).
Releases before 0.5.1 have no entry here; their notes are their commit
messages.

## 0.6.0 - 2026-10-30

This is B-432, the purchase check.

- **The purchase check:** `@headlessoracle/chirindo/purchase-check`, a new
  package export.
  - Before a provider charges, it checks a purchase against an Annex A.3
    card-only instruction the provider signed for its customer.
  - It answers allow or deny with the reasons, and writes each decision on a
    well-formed request as a signed, hash-chained receipt before it answers.
  - Exports: `createPurchaseCheck`, `evaluatePurchase` (a dry run),
    `signInstruction`, the mappers (`mapCrossmintOrderIntent`,
    `mapBasisTheoryAllowance`, `mapPravaMandate`), `merchantIdOf`,
    `toMinorUnits`, `toZ`, `CURRENCY_EXPONENTS`, `PURCHASE_REASON_PATTERNS`
    and `createPurchaseServer`.
  - The README section "Purchase check (before you charge)" states its claim
    and its limits.
- **`chirindo purchase-check`:** the check as a loopback HTTP endpoint,
  `POST /v1/check`. A token is required.
- **A new receipt member:** a purchase-check receipt carries a top-level
  `check` member. A receipt without it is byte-identical to one written
  before this change.
- **`docs/purchase-check-reasons.md`:** the frozen reason vocabulary,
  `purchase-check/0.1`.
- **`ProxyCheckpointer`** can sign checkpoints from a head the caller holds.
  The proxy does not use this, and is unchanged.
- **Development only (not in the package):** `npm test` runs
  `scripts/test-guard.mjs`. It reads free memory, then runs vitest normally
  at 3,000,000 KB and above, with `--no-file-parallelism` from 1,000,000 to
  2,999,999 KB, and not at all below 1,000,000 KB.

## 0.5.3 - 2026-10-18

Security fix. In the package, `README.md`, the version in `package.json`
and, in `dist/`, the CLI, the proxy, the policy evaluator, the JSON-RPC
helpers, the receipt writer, the checkpoint writer, the witness client
and the vendored strict-JSON scanner and its index differ from 0.5.2,
and `dist/version.js` and `dist/member-names.js` (each with its `.d.ts`
and `.map`) are new: 97 files.

**Security.** In every version on npm, 0.1.0 to 0.5.2, a client could
send a `tools/call` that a downstream server ran without the gate's
policy check or past a deny rule for its tool, or without a receipt
that matched what ran. Each item below was reproduced with both 0.1.0,
the first version on npm, and 0.5.2:

- The gate checked a line only when it parsed as a request with
  `"jsonrpc": "2.0"`, a string `method` and an `id` member, and forwarded
  anything else unchecked. Under a policy that denies `mock_swap`, a
  `tools/call` for it with no `id`, without the `jsonrpc` member, or in a
  line with a carriage return inside it, ran with no receipt; one whose
  `id` was `null` or an object ran with no receipt when the policy
  allowed it (the example downstream in `examples/observe-only-agent/`).
- The gate reads member names exactly. A downstream may not: Go's
  `encoding/json`, decoding into a struct, matches member names without
  regard to case and lets a later member overwrite an earlier one. With
  such a downstream and a policy that denies `mock_swap`, a line with
  `"Method": "tools/call"`, or with `"method": "ping"` beside
  `"METHOD": "tools/call"`, was no `tools/call` to the gate and ran
  `mock_swap` with no receipt; a `tools/call` whose `params` held
  `"name": "get_quote"` and `"Name": "mock_swap"`, or that spelled
  `params` as `"paramſ"` (U+017F), got an ALLOW receipt for another
  tool while `mock_swap` ran.
- A deny rule matched the tool name exactly, and only a method of
  exactly `tools/call` made a line a `tools/call` to the gate. With a
  downstream that looks tools up without regard to case, or trims or
  NFKC-normalizes the name first, and a policy that denies `mock_swap`,
  a `tools/call` for `MOCK_SWAP`, `Mock_Swap`, `" mock_swap"` or the
  fullwidth `ｍｏｃｋ＿ｓｗａｐ` ran `mock_swap` under an ALLOW receipt for
  the name sent. With one that compares upper-cased names and a policy
  that denies `delete_file`, `delete_ﬁle` (with the ligature U+FB01) ran
  `delete_file`. With one that trims and lowercases the method, a line
  whose method was `"TOOLS/CALL"` or `"tools/call "` was no `tools/call`
  to the gate and ran `mock_swap` with no receipt. So did a line whose
  method was not a string at all, such as `["tools/call"]`, with a
  downstream that turns the method into text (`String(method)`) or looks
  it up in a table of handlers keyed by method.
- Two `tools/call` lines with the same `id`, sent together under a
  policy that allows them, both ran, and the chain held one receipt.
- The gate forwards an allowed call re-encoded from its parsed value. An
  integer beyond JavaScript's safe range in it reached the downstream
  changed (12345678901234567891 arrived as 12345678901234567000). A
  number too large for a double, such as `1e400`, arrived as `null`, and
  that call ran with no receipt, because none could be written for it.

The forwarding behind each is in the `dist/proxy.js` and `dist/rpc.js`
of all seven versions on npm, and the exact match of tool names in
their `dist/policy.js`; git history traces both to the repository's
first commit. From 0.5.3 a `tools/call` is recognised by its method
alone, and these client lines are refused and never forwarded, each
with one line on stderr:

- a `tools/call` with no `id`: no reply (a message without an id is a
  notification);
- a `tools/call` whose `id` is `null`, or is not a string or an integer:
  `-32600` with `id: null`;
- a JSON-RPC batch: one `-32600` with `id: null` (MCP removed batching
  in its 2025-06-18 revision);
- a line that is not JSON (`-32700`), or that has a carriage return
  inside it (`-32600`), with `id: null`;
- a message that names a member twice in one object, has `jsonrpc`,
  `id`, `method` or `params` in another case, or has two members that
  differ only in case at the top level or in `params`, and a
  `tools/call` whose `params` has `name`, `arguments` or `_meta` in
  another case: `-32600`;
- a message with a member named `__proto__` at the top level or in
  `params`: `-32600`. `JSON.parse` keeps it as an inert member, but a
  downstream that copies the message into a fresh object
  (`Object.assign({}, msg)`, a `for...in` loop) sets that object's
  prototype from it, so a method and `params` carried inside read as the
  message's own;
- a message whose `method` is not a string (an array, an object, a
  number, `true`, `false` or `null`), is `tools/call` only after trimming
  white space or folding case (`"TOOLS/CALL"`, `"tools/call "`), or holds
  a control or format character: `-32600`;
- a `tools/call` with an integer outside JavaScript's safe range, or a
  number too large for a double, anywhere in it: `-32600`;
- a `tools/call` nested more than 128 levels deep, too deep to
  canonicalize for its receipt: `-32600`, its receipt's `args_hash` over
  the empty object. The gate computes a call's `args_hash` and
  `request_commitment` before forwarding it, so a call it could not
  record never reaches the downstream; a call within the limit runs;
- a `tools/call` with the `id` of a `tools/call` still in flight:
  `-32600`;
- a `tools/call` whose `params` is not an object, or whose `params.name`
  is not a non-empty string, begins or ends with white space, or holds
  a control or format character (Unicode categories Cc and Cf) anywhere,
  and, unless the proxy runs with `--allow-nonstandard-tool-names`, one
  whose `params.name` is outside MCP's rule for tool names: `-32602`.

The errors for the last seven carry the request's id: the message's `id`
when the message is a request (it has a `method` member, in any case),
has one member named exactly `id`, and that id is a string or an
integer within JavaScript's safe range. Otherwise the error has
`id: null`, and so does the error for a client's response to a request
from the server, since that id is the server's.

Deny rules now match tool names regardless of case: a rule for
`delete_file` also stops `DELETE_FILE`, `Delete_File` and `delete_ﬁle`,
names equal to it under Unicode case folding or after the full upper-
and lower-case mappings (which also make `ß` and `ss` equal). So a rule
now also stops a tool whose name differs from it only in case. The
server label still has to match exactly.

MCP's tools page
(https://modelcontextprotocol.io/specification/2026-07-28/server/tools,
"Tool Names") says tool names SHOULD be 1 to 128 characters long, and
"The following SHOULD be the only allowed characters": ASCII letters,
digits, underscore (`_`), hyphen (`-`) and dot (`.`). From 0.5.3 the
proxy refuses a `tools/call` whose name is outside that rule, so that a
downstream cannot normalize such a name (NFKC, dropping invisible or
combining characters) into the name of a tool a deny rule names. The
proxy flag `--allow-nonstandard-tool-names` forwards such names instead,
and the proxy then prints a warning to stderr at start.

Every refused line that is a `tools/call`, or that a downstream could
take for one (matching member names without regard to case, trimming,
folding the case of or dropping control and format characters from the
method, reading a method that is not a string as text, or reading a
`__proto__` member as the message's own members), gets a DENY receipt
(a batch, one for each such element). A line that is not JSON or has a
carriage return inside it gets none, nor does a `tools/call` whose
arguments hold a number too large for a double, which no receipt can
hash; one refused for nesting too deep gets a receipt over the empty
object. Lines that none of these rules refuse are gated and forwarded
as before, except that deny rules now match tool names without regard
to case (above).

Limits of this release:

- A refusal's DENY receipt reads like a policy denial: `decision`
  `"deny"`, `decision_source` `"config"`. The reason for a refusal goes
  to stderr only; a later release will record it in the receipt.
- An allowed call is forwarded re-encoded from its parsed value, so a
  number with a fraction or an exponent reaches the downstream as the
  JavaScript number it parses to (`1.50` as `1.5`, `1e2` as `100`,
  `12345678901234567891.5` as `12345678901234567000`). The receipt's
  `args_hash` covers the arguments as forwarded.
- An allowed call whose answer never arrives (the downstream exits or
  never replies) leaves no receipt: the ALLOW receipt is written when
  the answer comes back. Its id stays in flight, so a later `tools/call`
  with that id is refused for the rest of the session.
- The 128-level nesting limit is well above any real tool's arguments
  (a handful of levels). A call within it runs; one past it is refused
  (above), so the gate never tries to canonicalize a payload deep enough
  to overflow the stack.
- Member names inside `params.arguments` and `params._meta` are not
  checked, for case or for a `__proto__` member: they are the tool's
  arguments, not the gate's envelope. A downstream that merges a tool's
  arguments into a prototype-bearing object is choosing how to read its
  own arguments. The receipt's `args_hash` covers the arguments as the
  gate parsed them, which is what it forwards.
- Deny rules compare tool names without regard to case and in no other
  way. A downstream that reads one name inside MCP's rule as another
  (`mock-swap` as `mock_swap`, say) could run a tool a deny rule names,
  under an ALLOW receipt for the name sent.
- With `--allow-nonstandard-tool-names`, deny rules compare a name
  outside MCP's rule without regard to case only. Compatibility forms
  (the fullwidth `ｍｏｃｋ＿ｓｗａｐ`, which NFKC turns into `mock_swap`),
  default-ignorable characters such as U+034F and combining marks are
  compared as they are, so a downstream that normalizes names that way
  could run a tool a deny rule names.
- A method is refused when it is `tools/call` after trimming white space
  at either end, folding case or dropping control and format characters.
  A downstream that rewrites methods any further (removing white space
  inside, NFKC) could still read a `tools/call` the gate did not.
- The ALLOW and DENY lines on stderr print the tool name and a string id
  as sent, so an id that holds a line feed splits its line; refusal lines
  write such characters as `\u` escapes.
- A refused line is not forwarded, so a refused response to a request
  from the server leaves that request unanswered.
- The gate ends a message only at a line feed, as the MCP stdio
  transport defines (revision 2026-07-28,
  https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio,
  fetched 2026-10-17 07:00:02 UTC: "Messages are delimited by newlines,
  and MUST NOT contain embedded newlines."); a well-formed message may
  carry U+2028, U+2029 or U+0085 inside a string, and the gate forwards
  it unchanged (an allowed `tools/call`, re-encoded as above, carries
  them raw even where the client escaped them); a downstream that also
  ends messages at those characters can see a different boundary than
  the gate, so a downstream should end messages at line feed only.

Also in this release:

- **Whole characters across chunks.** Up to 0.5.2 the gate decoded each
  chunk of its input on its own, so a character that a chunk boundary
  cut became U+FFFD: in a `tools/call`'s arguments, in what the
  downstream got and in `args_hash`; in an answer, in what the client
  got. Reproduced with 0.1.0 and 0.5.2. Client stdin and downstream
  stdout are now each read through one streaming UTF-8 decoder.
- **Receipts name the gate's version.** A new receipt's `agent.version`
  is the package version; up to 0.5.2 it was always `"0.0.1"`.
- **CLI tests on Windows.** The `verify` and `export-jwks` CLI tests,
  and the proxy test that spawns a real downstream server, share one
  launcher (node and tsx, no shell) and have 30 s each.
- **A CI gate before publish.** `scripts/release-gate.mjs --require-ci
  <sha>` exits 0 only when the tag is at `<sha>` and its CI has passed.
  It polls every 30 s for up to 20 minutes, at most 40 requests; a 401,
  403 or 429 from GitHub fails it at once; it sends `GITHUB_TOKEN`, when
  set, as a bearer token and never prints it. It ends by setting its
  exit code (0 after `GATE PASS`, 1 after `GATE FAIL`), not with
  `process.exit()`, and each of its requests leaves nothing open.
- **The proxy ends on its own.** At shutdown, after its last checkpoint,
  `chirindo proxy` sets exit code 0 and lets the process end instead of
  calling `process.exit()`, which on Windows with Node 24 can fail after
  network requests with exit code 0xC0000409 (a libuv assertion). It
  closes its stdin and lets the downstream go; each witness request asks
  for `connection: close`, reads the whole answer and clears its own
  timer, and one still open when the 5 s shutdown wait runs out is ended
  and recorded as `witness_timeout`, as before.

## 0.5.2 — 2026-10-15

Docs only. `test/` is unchanged from 0.5.1 and `src/` changes only in
comments. In the package, `README.md`, `dist/receipt.js`,
`dist/receipt.js.map` and the version in `package.json` differ from 0.5.1.
This package is packed from an LF checkout, so `README.md`, `LICENSE`,
`NOTICE`, `package.json` and `dist/cli.js` no longer carry the CR line
endings 0.5.1 had.

- Corrects the 0.5.1 README and the 0.5.1 entry below, which say
  `gate_receipt` is the receipt's entry hash. It is not: `gate_receipt` (in
  the receipt's `gate` object) is the hash of the receipt computed while
  `gate_receipt` still held the placeholder `"self"`. The entry hash is
  `"sha256:" + hex(SHA-256(JCS(record without "sig")))`, the value the next
  record's `prev_hash` carries, and that computed value is what ordering
  evidence should carry. The README's field notes and "Showing a gate ran
  before an action" now say so; the 0.5.1 entry is left as published.
- `src/receipt.ts` comments on `gate_receipt` now match the README.
- Corrects the 0.5.1 publication record below, which says `chirindo --help`
  prints CRLF. It does not: JavaScript reads a CRLF inside a template
  literal as LF, so the 0.5.1 help text was already printed with LF.
- New `examples/ordering-evidence/`: an ALLOW receipt and a DENY receipt,
  each with a checkpoint witnessed on production, a Base Sepolia payment
  whose EIP-3009 nonce is the ALLOW receipt's entry hash, and an offline
  checker (`check.mjs`, Node built-ins only) with one-byte failure tests.
  Not part of the npm package.

### Publication record (added after publish)

Published to npm 2026-10-15T17:11:37.682Z (registry `time`), dist-tag
`latest`, by passing the tarball `headlessoracle-chirindo-0.5.2.tgz` to
`npm publish` by path. That tarball is the `npm pack` of a fresh detached
`git worktree` of the signed tag `v0.5.2` (commit `52136e8`), checked out
with `core.autocrlf=false`. As for 0.5.1, the registry metadata for 0.5.2
carries **no `gitHead`**. The tag, not npm, is what binds this version to a
commit.

Before publish:

- In the repository at `52136e8`: `npm ci`, `npm run build`,
  `npm run typecheck` all exit 0; conformance harness 4 of 4 exit 0;
  `npm audit --omit=dev --audit-level=high` 0 vulnerabilities; gitleaks
  8.30.1 over the full history (71 commits), no leaks found.
- In the worktree: `npm ci`, `npm run build`, `npm run typecheck` all exit
  0; `node scripts/release-gate.mjs --expect-version 0.5.2` GATE PASS
  (10/10). `npm pack` of the same tree is the reference tarball, and it is
  the file that was published.
- Tests: on the Windows machine that packed it, `npm test` was 179/181 and
  `npx vitest run --no-file-parallelism` 180/181. Every failure was
  `Test timed out in 5000ms` in `test/cli-verify-e2e.test.ts`, and the same
  test fails the same way on the unchanged source of the previous commit.
  With `--testTimeout=30000` that file passes 5/5. The full suite was
  181/181 on the identical tree in a separate cloud run, and GitHub's
  `build-test-conformance`, `audit` and `scan` checks on `52136e8` all
  completed with success (16:58:38Z) before publish.

Registry tarball (`npm pack @headlessoracle/chirindo@0.5.2`) against the
reference pack:

| | reference `npm pack` of `v0.5.2` | registry 0.5.2 |
|---|---|---|
| files | 91 | 91 |
| shasum (sha1) | `3f92da867b8ea63e6f1a7dd11a033af1fbfb62c9` | `3f92da867b8ea63e6f1a7dd11a033af1fbfb62c9` |
| integrity | `sha512-zrB8j2ph2IfjdMwWuQ3aaqDB0ejB6oyfs6CVhldu6yfLhTS51t1cDZujFCm1xVk1iuO236kQya80ByJHWHygSQ==` | same |
| unpacked size | 434898 | 434898 |
| `.tgz` SHA-256 | `24e6d7032d28a1a8666d049e7be8aa62ab5f2af550d36fde838384d23d722ca8` | same |

Each tarball was extracted to its own directory and every file hashed with
SHA-256. 91 of 91 files are identical, none is missing on either side, and
the two `.tgz` files are byte-equal. Control: appending one byte to
`dist/cli.js` in a copy of the registry extract makes the comparison fail on
exactly that file. The list below is the per-file SHA-256 manifest. Its own
SHA-256, over the manifest lines as printed below with LF endings and a
trailing newline, is
`f1d55ede82275f567c20f303bd4a82935302c8b70423532e837b3f8a7699b3cb`.

**Line endings.** Unlike 0.5.0 and 0.5.1, this package was packed from an
LF checkout (`core.autocrlf=false`) and published from that tarball by
path, so the packed files carry the LF bytes git stores: the registry 0.5.2
extract contains 0 CR bytes, where registry 0.5.1 contains 1072 (in
`LICENSE`, `NOTICE`, `README.md`, `package.json` and `dist/cli.js`). B-312's
test, whether an LF checkout of the tag packs to the registry's per-file
SHA-256 values, holds for 0.5.2: 91 of 91, and the manifest below is
identical to the one from a separate cloud LF pack of the same commit. This
does not change 0.5.0 or 0.5.1, which keep their CRs on the registry.

`dist/receipt.js` differs from registry 0.5.1, once its CRs are removed, in
exactly the seven comment lines changed in `src/receipt.ts`. The wording
that called `gate_receipt` the receipt's own `entry_hash` occurs 0 times in
the registry 0.5.2 package (2 in the 0.5.1 README, 2 in the 0.5.1
`dist/receipt.js`).

<details>
<summary>Per-file SHA-256 manifest of the 0.5.2 tarball (91 files)</summary>

```
d1061a7427c1ec344c4621fce77de056dd0660a1f7a1c70ead85078d4692f1df  package/LICENSE
26aa626c90f7a3ee67ff28b157c3c53bb2daaabfebef763576d7f62605b2dc09  package/NOTICE
a3b65bbd50ec568a24807cea7d11b9611d1e518041efcdf41f34890b4ee3dc57  package/README.md
d6e92ee1d8516739132461f86397c574bb0c089229a458013a4c1ec946fbc187  package/dist/checkpoint.d.ts
a349fefbef6c41c3839d55ba24f3790a87f79effdebd4d5212fc7d65beef1378  package/dist/checkpoint.js
60caf6e7f1394533dde0e76279bb6d7e55a0a3f1168c33e88865b4211adafd8c  package/dist/checkpoint.js.map
43e818adf60173644896298637f47b01d5819b17eda46eaa32d0c7d64724d012  package/dist/cli.d.ts
c6af726c25d6b70acc620b609d5dd7ca840e1599367727acced05110f442ad93  package/dist/cli.js
d5e3e2797255c76242712627fee959330429ea8e1abf4c87a68a8d80755b7e84  package/dist/cli.js.map
a79290e071db4a801bd686f6b4e74284b50fbf1396661e6611c0147e7ef3f0ad  package/dist/policy.d.ts
9e8d18838369a727d27b3359d4538ba6d2e793beb4b61a1ceb2bcade48398879  package/dist/policy.js
e4ff21eba348e65987083179a905d6c40a6f37ed2092d4468d1e4b5e55f78ed1  package/dist/policy.js.map
135c868a6dcce6255408759bae778cf7839bc84489e02e31e053ec89a1afdcfd  package/dist/proxy.d.ts
f593d25628741c9f84b2780c094d3491f0f5f74a834f941e668cb83deed67e74  package/dist/proxy.js
177477c6d24473d33ea0e6dd8fcccd5f7b7555e672d2187a2c49ed34501ac879  package/dist/proxy.js.map
67a52467cf0d5bce2a41779d32110f7ed93af2b2349042b44a950527f331f09f  package/dist/receipt.d.ts
19b520579d48d48f6c82f8b8a8601bc4aa468a9aa2ee0f614a19c39d843890e8  package/dist/receipt.js
167dec6134f53baa416a51b4d06c09fd76ea7a890637f81b4d59424cd32507b9  package/dist/receipt.js.map
e125b39ba3e8e9bd9ade30ec301e2d20a1e391419217cc096fe2e40e5e42a5ef  package/dist/rpc.d.ts
a9030a56835a527ca89f03387ed72a1b95deb75eb06e835b90fe4f858655270c  package/dist/rpc.js
866d159bb215faf957117183f80ef519658045562eb475328e53dffed742a136  package/dist/rpc.js.map
014d35459e9aae92cca8144e1454fb9bf6d5476a7db677c933d03de533a52030  package/dist/vendor/recorder/adapter/cursor.d.ts
6f5353b6feab1e3615912ad03d417b057479bd83213da6c9e53ad25799c5155b  package/dist/vendor/recorder/adapter/cursor.js
e176946c9ec222682cdf73ce5fab69a180dc67098561fe6f87b73003eea04626  package/dist/vendor/recorder/adapter/cursor.js.map
5d1b9a550170289fc0b1d95ea4810ae10bfb75aa2bdc87eaf954ee19882cafc7  package/dist/vendor/recorder/adapter/payloads.d.ts
5b85f220194d7846d32d45c131a77cf7e7a5d07058c7ed4d23edd4fa374c00f2  package/dist/vendor/recorder/adapter/payloads.js
0077b7ac74fc99bc4cfa257ce3705e321375e1ac86adef54e0c4ab3af274fd7b  package/dist/vendor/recorder/adapter/payloads.js.map
cfb512d90630de8c382e93ed8dfa62f0868ea7c96a0a51ff25fc95876a6034b5  package/dist/vendor/recorder/adapter/shell-split.d.ts
1f80b33896b6195460ad4286f383b6fd67cc10685fcedaf36d5946602cf0a276  package/dist/vendor/recorder/adapter/shell-split.js
7b30b53a77f1505d1f8a369fb0703a9275dc6891b9071b61e220852ceac365f0  package/dist/vendor/recorder/adapter/shell-split.js.map
7f0c02e3a80c64ba554ebf0a55cdf32fff482aa87bcc378e133f2bc1c079e511  package/dist/vendor/recorder/brand.d.ts
a3b609a5821607a6f4bcdc37a7adcdc3ac5f23a9fd40a7695217972b7284cf25  package/dist/vendor/recorder/brand.js
eb7a200a69be86c7806b71b2de18ba43beabd45ff8747a4c48790f800fb0230a  package/dist/vendor/recorder/brand.js.map
36f2fdcaf641292f9dfaaa92f22654053583b8ea855f58f10726e16aca4a4cd7  package/dist/vendor/recorder/canonicalize.d.ts
1679b9a6cab8d94958dd418b4acbe5df07126d41272463eeffb31831f7da429f  package/dist/vendor/recorder/canonicalize.js
3158915e13b33883b973421c228bf9c8cd325ca2762fa90aa79fd04f5dfbb8f4  package/dist/vendor/recorder/canonicalize.js.map
8acdba0e14b22a94db13b1e9339afb4959a8b70248e82e4bf13f0d26da47521b  package/dist/vendor/recorder/chain.d.ts
d8460be3f5573c6df96973731b514072512afa8910e9b386fe44fff30aeae572  package/dist/vendor/recorder/chain.js
df5f196c2277f8ff505cc3dabfec96684785c4dbfec4f635b3bea41b501ea633  package/dist/vendor/recorder/chain.js.map
9e832539cb67621f979c66a4c574c74d1f059e63f0982c5a5513dbad89bd0fb8  package/dist/vendor/recorder/cli/hook.d.ts
8141e25d59cf10eb8f6e29bd78819d5ad7a7695b800d26a585b16b90f28aad4b  package/dist/vendor/recorder/cli/hook.js
c392fdfb9ee5a8c4764100c0b3607c85603b3896e84e9b032c86a506845922d5  package/dist/vendor/recorder/cli/hook.js.map
09e4eae47a55d72f7515b7d7659e801228bf0394d964afcca31232d41aa521e7  package/dist/vendor/recorder/cli/init.d.ts
90833b8c5dd1df84e2b3a2c8b7f15314430402fd4b57be011b58d697c27ebb64  package/dist/vendor/recorder/cli/init.js
4dcc33e2fd4bc94a4d178ddc684b71b1a88ea7238b572d32a218e51b79c27a7b  package/dist/vendor/recorder/cli/init.js.map
91f8f002e3c27f5f1d33c670c13c117e9acddbe00892718ccc18b84e5b86fec3  package/dist/vendor/recorder/cli/replay.d.ts
bbceaccf7d5f74f069b8d19ac015b317430387e8084ab34c813e181d18649f51  package/dist/vendor/recorder/cli/replay.js
51d666e6f92c9d62d474a1262075d3ef798bf283e82fb4a4bc0f3f97321aba86  package/dist/vendor/recorder/cli/replay.js.map
400ec35c754d377ad9851ab2bf7b0b45dc737d626bec30c69079ca1134eea3db  package/dist/vendor/recorder/cli/verify.d.ts
bca41195973190ca8c0e3a14abc41b200ff7cfaf6a52afb88ae66ddc8942251a  package/dist/vendor/recorder/cli/verify.js
2d398f2208312b2909424ec0ac0f147c270a6d9abd9d00ac29813b943dfda3fb  package/dist/vendor/recorder/cli/verify.js.map
052005765c6f62536877de75c16d5a493a28aa65eb5b2a625da81ef72280e956  package/dist/vendor/recorder/hash.d.ts
4a4111503c959b8911fa4425b8b18d4c37744f69713671d6c44eaf4b5751c28e  package/dist/vendor/recorder/hash.js
316a7d1b5c7ae312cc50b9b549702559664d53188d9fc3a041fad5fa5c95ec20  package/dist/vendor/recorder/hash.js.map
3a8428a3ceba652aade4c1f86837db120ad9cd2c525b2c6bef614de4e6321845  package/dist/vendor/recorder/identity.d.ts
907cc6c8ea64abdb5dd0a3de5deef6042f78db6850251dc8f8087108d642434b  package/dist/vendor/recorder/identity.js
5bd0481feffb0e79656a46262a2e62c47819d884155f2d4c23cecde27d537f21  package/dist/vendor/recorder/identity.js.map
b48f65b2370660d98072775c332f9186b5cac7267fa993c49fce91c7910af625  package/dist/vendor/recorder/index.d.ts
13f41b27d7c1835a119327f133fd37b104e0b89fb04c54f96515051437c0ae08  package/dist/vendor/recorder/index.js
d946d825d6bd3fe0bb8083f6d119046ff58dfa02d12c3109883bfbb47c45b132  package/dist/vendor/recorder/index.js.map
8a128864b7902afb5ea5f1d49503fcfd83082c271d29f7613e4d148bff87812c  package/dist/vendor/recorder/io.d.ts
7c1e8dfad228468a99737a3795bf61b8a6b3c3318c6afc223e5009593724048d  package/dist/vendor/recorder/io.js
29ff3b6055f0db14dab3fe666328ae4e125baf1edcc00ced2f7c8dea96cb002b  package/dist/vendor/recorder/io.js.map
3b51685960694d79411a67fd37d778b48a8395ae01b69a2b6e71f7759e8a12f7  package/dist/vendor/recorder/jwks.d.ts
49fdf310278e9a78a084c6233cffed84e83a879d002ed347dde87adedbdb28c8  package/dist/vendor/recorder/jwks.js
533d538749a4c13912eef5a74d26961cd6177c1f67f0e5252c116feb2b7c4fc0  package/dist/vendor/recorder/jwks.js.map
618ef44958c054da166e0c4449c7a3e72114f5934b5bcf29f97f6d9fd21f4950  package/dist/vendor/recorder/key.d.ts
e357f62ec2e73657c364106b8bcc36ea522816ea40b7d87404bfa7fa60400790  package/dist/vendor/recorder/key.js
09da38c31a23823013c5bb8dff792a1120afcb9d7781d81869b8e265cba402bf  package/dist/vendor/recorder/key.js.map
7597298889a71b152fe47e9a6e0c7f9705a056fbe89c2a2ca2318052ef533cb7  package/dist/vendor/recorder/payment-ref.d.ts
85fb7c4bd57342f37855b8750ef695b34ce074cec8981bc076f2341c6025deca  package/dist/vendor/recorder/payment-ref.js
e8403a078fbee9a79b6ebe150378c4684c32f17dc0e4fe812fe0f9e3b9468390  package/dist/vendor/recorder/payment-ref.js.map
b4196e1def4cc07a18136261f09cee752db6aded7e0e5c304a0e67ff24f9caf4  package/dist/vendor/recorder/record.d.ts
798dd0624c01dc8a977bb419abfbccd8226c9dce47e4a0e0a610395096d2f7c3  package/dist/vendor/recorder/record.js
98758594f9e461d5d9aa8bcb14bc1849c4bb857d827cd9fd1d55457c380f43bb  package/dist/vendor/recorder/record.js.map
ff207dd41d91d661cd0c29f5caa0cebd02e0d2bf02e18da363631c2f3b2eb824  package/dist/vendor/recorder/request.d.ts
6f9189632f8cb13df12f9de761d83926d22357001b060dca8a78c8bc92eb1bd4  package/dist/vendor/recorder/request.js
66411f073beb80b08e950efb45bd54f45c3d182fe19c61ddbf6d660bec1afdea  package/dist/vendor/recorder/request.js.map
af21d0edd0281462832b55f469be5408e1e9a6464ac8a4dae7a4aac90c855ff2  package/dist/vendor/recorder/sign.d.ts
d0fb1c7dc4ea9ac3cc821c5c0170f39dbe758ac4c5405ead00c74e35926c5f57  package/dist/vendor/recorder/sign.js
2981eac7677c69152798b2c33c6f1d63e9504d5e4cd45645a524c6909c31820a  package/dist/vendor/recorder/sign.js.map
01878144de69babe656f0b0fde40de22ab553af193778d204602c767950b723a  package/dist/vendor/recorder/strict-json.d.ts
05c86f6efc78e9bb805332ba04644a8d5e9a1c89ddd1d75a3fdd1a7408875788  package/dist/vendor/recorder/strict-json.js
f48f68dbf15572f1a1589f6baf4eb217dea6d6eab99436b491bb7626c7629fac  package/dist/vendor/recorder/strict-json.js.map
7ad2c45f2fc44b5a55b5ab29a25644fb03868d18e50aaf28c0404b498ba6f0d7  package/dist/vendor/recorder/x402-registry.d.ts
7427a2fb7a055c1f02812b5dce5861cd274529e0d6df0c8210cf6f0450946745  package/dist/vendor/recorder/x402-registry.js
67acbc2b27d608c8b1d705ee70a49dba4db63df7d0e7d017d0250033c5d736b1  package/dist/vendor/recorder/x402-registry.js.map
5eda538167427d73a991b006713eaf1f4f002c9a6cb5c9896f147ea03bcf5664  package/dist/witness.d.ts
92585eefea50ff852f0d49194dc9da4ed4f8578ce979ceae9055c4d1d0f7b6f4  package/dist/witness.js
54be3d0b396d8e3b205f681c8f5f8778268db6a70f097e577edabc3eb2fe497b  package/dist/witness.js.map
d73d7fa6b429dc6fc2f06f7e2d0e5bd63088a22aabc7720f1a8d318dfc69f0c7  package/package.json
```

</details>

## 0.5.1 — 2026-10-09

Docs and package metadata only. No behaviour change: `src/` and `test/` are
unchanged from 0.5.0, and the test suite is unchanged.

- README, Witness: replaces "What has been exercised, and what has not" with
  a dated statement of the 9 Oct 2026 anonymous run of the 0.5.0 client
  code against production (`https://api.headlessoracle.com` and
  `https://headlessoracle.com`), and what that run did not exercise. Drops
  the stale line that `https://headlessoracle.com` does not serve the
  witness paths.
- README, field notes: `gate_receipt` keeps its meaning (the receipt's own
  `entry_hash`); "self-anchored for the spike" is replaced by how it gets an
  outside time. New subsection "Showing a gate ran before an action".
- README, "Also verified": the published-version sentence now points to the
  npm versions list instead of naming a version that goes stale.
- docs/WITNESS_SPEC_v0.5.md: editorial correction of the public edition
  (both hosts serve the witness paths); nothing a verifier checks.
- package.json: `keywords`, `homepage`, `bugs`.

### Publication record (added after publish)

Published to npm 2026-10-09T11:34:02.313Z (registry `time`), dist-tag
`latest`, from a fresh detached `git worktree` of the signed tag `v0.5.1`
(commit `8330691`). Because the worktree was detached, the registry metadata
for 0.5.1 carries **no `gitHead`**. The tag, not npm, is what binds this
version to a commit.

Before publish, in that worktree: `npm ci`, `npm run build`,
`npm run typecheck` all exit 0; `npm test` 181/181 (26 files);
`node scripts/release-gate.mjs --expect-version 0.5.1` GATE PASS (10/10).
`npm pack` of the same tree is the reference tarball.

Registry tarball (`npm pack @headlessoracle/chirindo@0.5.1`) against the
reference pack:

| | reference `npm pack` of `v0.5.1` | registry 0.5.1 |
|---|---|---|
| files | 91 | 91 |
| shasum (sha1) | `4dc25e6ed88a2fbcddcdc6d6130c1fec22ad3669` | `4dc25e6ed88a2fbcddcdc6d6130c1fec22ad3669` |
| integrity | `sha512-8SnTngkJdnOYIaOvooxCahHjHpeE5D4D3z1il89wvsMSfWdaWcAIOI5mD8nWNuLQyWqT0G9lYYqd20FawwfJEA==` | same |
| unpacked size | 435187 | 435187 |

Each tarball was extracted to its own directory and every file hashed with
SHA-256. 91 of 91 files are identical, none is missing on either side, and
the two `.tgz` files are byte-equal. Control: appending one byte to
`dist/cli.js` in a copy of the registry extract makes the comparison fail.
The list below is the per-file SHA-256 manifest. Its own SHA-256, over the
manifest lines as printed below with LF endings and a trailing newline, is
`548b52887a795017f678bc4bb99a453124eb3287394863cb5a8aab8d51e335d6`.

**What this does not show: line endings.** The worktree was checked out on
Windows with Git's system `core.autocrlf=true`, and this repo has no
`.gitattributes`. So the packed files carry CRLF where the git blobs carry
LF:

- `README.md`, `LICENSE` and `NOTICE` match their blobs at `v0.5.1` only
  after CRs are removed.
- `dist/cli.js` has CRLF on lines 44–157, the `helpText()` template literal.
  tsc kept the checkout's line endings there, so `chirindo --help` prints
  CRLF.
- 0.5.0 on the registry has the same CRs (114 in `dist/cli.js`; also in
  README, LICENSE, NOTICE and package.json), so 0.5.1 did not introduce
  this.

The comparison above shows that the registry serves exactly what was packed.
It does not show that the pack is byte-identical to an LF checkout of the tag.

<details>
<summary>Per-file SHA-256 manifest of the 0.5.1 tarball (91 files)</summary>

```
bce486143e9a9fafcd65ecbff62831191ebafb7864d498bc1c66d74471ae589f  package/LICENSE
a34028ff93313860d2b58a0304cb17fa15c1597a2033b207c3de235c8d328aa2  package/NOTICE
a55707a1a2c41dce6fbb558c3dffc0f1835a5025cef83beb13d2426014d90528  package/README.md
d6e92ee1d8516739132461f86397c574bb0c089229a458013a4c1ec946fbc187  package/dist/checkpoint.d.ts
a349fefbef6c41c3839d55ba24f3790a87f79effdebd4d5212fc7d65beef1378  package/dist/checkpoint.js
60caf6e7f1394533dde0e76279bb6d7e55a0a3f1168c33e88865b4211adafd8c  package/dist/checkpoint.js.map
43e818adf60173644896298637f47b01d5819b17eda46eaa32d0c7d64724d012  package/dist/cli.d.ts
06a9de8252316264511749dd4b2a2ce68605709a4fc77cbe02ac6d1b4d7cb686  package/dist/cli.js
d5e3e2797255c76242712627fee959330429ea8e1abf4c87a68a8d80755b7e84  package/dist/cli.js.map
a79290e071db4a801bd686f6b4e74284b50fbf1396661e6611c0147e7ef3f0ad  package/dist/policy.d.ts
9e8d18838369a727d27b3359d4538ba6d2e793beb4b61a1ceb2bcade48398879  package/dist/policy.js
e4ff21eba348e65987083179a905d6c40a6f37ed2092d4468d1e4b5e55f78ed1  package/dist/policy.js.map
135c868a6dcce6255408759bae778cf7839bc84489e02e31e053ec89a1afdcfd  package/dist/proxy.d.ts
f593d25628741c9f84b2780c094d3491f0f5f74a834f941e668cb83deed67e74  package/dist/proxy.js
177477c6d24473d33ea0e6dd8fcccd5f7b7555e672d2187a2c49ed34501ac879  package/dist/proxy.js.map
67a52467cf0d5bce2a41779d32110f7ed93af2b2349042b44a950527f331f09f  package/dist/receipt.d.ts
31989d880680fdc75e0d15dc5010bb898db1d170f1dfd0e9ffc82a12af2b8527  package/dist/receipt.js
cc0d04606ba3cd8704cd971d0cc391009623dc1754ea6697fa6b52d2133e42ab  package/dist/receipt.js.map
e125b39ba3e8e9bd9ade30ec301e2d20a1e391419217cc096fe2e40e5e42a5ef  package/dist/rpc.d.ts
a9030a56835a527ca89f03387ed72a1b95deb75eb06e835b90fe4f858655270c  package/dist/rpc.js
866d159bb215faf957117183f80ef519658045562eb475328e53dffed742a136  package/dist/rpc.js.map
014d35459e9aae92cca8144e1454fb9bf6d5476a7db677c933d03de533a52030  package/dist/vendor/recorder/adapter/cursor.d.ts
6f5353b6feab1e3615912ad03d417b057479bd83213da6c9e53ad25799c5155b  package/dist/vendor/recorder/adapter/cursor.js
e176946c9ec222682cdf73ce5fab69a180dc67098561fe6f87b73003eea04626  package/dist/vendor/recorder/adapter/cursor.js.map
5d1b9a550170289fc0b1d95ea4810ae10bfb75aa2bdc87eaf954ee19882cafc7  package/dist/vendor/recorder/adapter/payloads.d.ts
5b85f220194d7846d32d45c131a77cf7e7a5d07058c7ed4d23edd4fa374c00f2  package/dist/vendor/recorder/adapter/payloads.js
0077b7ac74fc99bc4cfa257ce3705e321375e1ac86adef54e0c4ab3af274fd7b  package/dist/vendor/recorder/adapter/payloads.js.map
cfb512d90630de8c382e93ed8dfa62f0868ea7c96a0a51ff25fc95876a6034b5  package/dist/vendor/recorder/adapter/shell-split.d.ts
1f80b33896b6195460ad4286f383b6fd67cc10685fcedaf36d5946602cf0a276  package/dist/vendor/recorder/adapter/shell-split.js
7b30b53a77f1505d1f8a369fb0703a9275dc6891b9071b61e220852ceac365f0  package/dist/vendor/recorder/adapter/shell-split.js.map
7f0c02e3a80c64ba554ebf0a55cdf32fff482aa87bcc378e133f2bc1c079e511  package/dist/vendor/recorder/brand.d.ts
a3b609a5821607a6f4bcdc37a7adcdc3ac5f23a9fd40a7695217972b7284cf25  package/dist/vendor/recorder/brand.js
eb7a200a69be86c7806b71b2de18ba43beabd45ff8747a4c48790f800fb0230a  package/dist/vendor/recorder/brand.js.map
36f2fdcaf641292f9dfaaa92f22654053583b8ea855f58f10726e16aca4a4cd7  package/dist/vendor/recorder/canonicalize.d.ts
1679b9a6cab8d94958dd418b4acbe5df07126d41272463eeffb31831f7da429f  package/dist/vendor/recorder/canonicalize.js
3158915e13b33883b973421c228bf9c8cd325ca2762fa90aa79fd04f5dfbb8f4  package/dist/vendor/recorder/canonicalize.js.map
8acdba0e14b22a94db13b1e9339afb4959a8b70248e82e4bf13f0d26da47521b  package/dist/vendor/recorder/chain.d.ts
d8460be3f5573c6df96973731b514072512afa8910e9b386fe44fff30aeae572  package/dist/vendor/recorder/chain.js
df5f196c2277f8ff505cc3dabfec96684785c4dbfec4f635b3bea41b501ea633  package/dist/vendor/recorder/chain.js.map
9e832539cb67621f979c66a4c574c74d1f059e63f0982c5a5513dbad89bd0fb8  package/dist/vendor/recorder/cli/hook.d.ts
8141e25d59cf10eb8f6e29bd78819d5ad7a7695b800d26a585b16b90f28aad4b  package/dist/vendor/recorder/cli/hook.js
c392fdfb9ee5a8c4764100c0b3607c85603b3896e84e9b032c86a506845922d5  package/dist/vendor/recorder/cli/hook.js.map
09e4eae47a55d72f7515b7d7659e801228bf0394d964afcca31232d41aa521e7  package/dist/vendor/recorder/cli/init.d.ts
90833b8c5dd1df84e2b3a2c8b7f15314430402fd4b57be011b58d697c27ebb64  package/dist/vendor/recorder/cli/init.js
4dcc33e2fd4bc94a4d178ddc684b71b1a88ea7238b572d32a218e51b79c27a7b  package/dist/vendor/recorder/cli/init.js.map
91f8f002e3c27f5f1d33c670c13c117e9acddbe00892718ccc18b84e5b86fec3  package/dist/vendor/recorder/cli/replay.d.ts
bbceaccf7d5f74f069b8d19ac015b317430387e8084ab34c813e181d18649f51  package/dist/vendor/recorder/cli/replay.js
51d666e6f92c9d62d474a1262075d3ef798bf283e82fb4a4bc0f3f97321aba86  package/dist/vendor/recorder/cli/replay.js.map
400ec35c754d377ad9851ab2bf7b0b45dc737d626bec30c69079ca1134eea3db  package/dist/vendor/recorder/cli/verify.d.ts
bca41195973190ca8c0e3a14abc41b200ff7cfaf6a52afb88ae66ddc8942251a  package/dist/vendor/recorder/cli/verify.js
2d398f2208312b2909424ec0ac0f147c270a6d9abd9d00ac29813b943dfda3fb  package/dist/vendor/recorder/cli/verify.js.map
052005765c6f62536877de75c16d5a493a28aa65eb5b2a625da81ef72280e956  package/dist/vendor/recorder/hash.d.ts
4a4111503c959b8911fa4425b8b18d4c37744f69713671d6c44eaf4b5751c28e  package/dist/vendor/recorder/hash.js
316a7d1b5c7ae312cc50b9b549702559664d53188d9fc3a041fad5fa5c95ec20  package/dist/vendor/recorder/hash.js.map
3a8428a3ceba652aade4c1f86837db120ad9cd2c525b2c6bef614de4e6321845  package/dist/vendor/recorder/identity.d.ts
907cc6c8ea64abdb5dd0a3de5deef6042f78db6850251dc8f8087108d642434b  package/dist/vendor/recorder/identity.js
5bd0481feffb0e79656a46262a2e62c47819d884155f2d4c23cecde27d537f21  package/dist/vendor/recorder/identity.js.map
b48f65b2370660d98072775c332f9186b5cac7267fa993c49fce91c7910af625  package/dist/vendor/recorder/index.d.ts
13f41b27d7c1835a119327f133fd37b104e0b89fb04c54f96515051437c0ae08  package/dist/vendor/recorder/index.js
d946d825d6bd3fe0bb8083f6d119046ff58dfa02d12c3109883bfbb47c45b132  package/dist/vendor/recorder/index.js.map
8a128864b7902afb5ea5f1d49503fcfd83082c271d29f7613e4d148bff87812c  package/dist/vendor/recorder/io.d.ts
7c1e8dfad228468a99737a3795bf61b8a6b3c3318c6afc223e5009593724048d  package/dist/vendor/recorder/io.js
29ff3b6055f0db14dab3fe666328ae4e125baf1edcc00ced2f7c8dea96cb002b  package/dist/vendor/recorder/io.js.map
3b51685960694d79411a67fd37d778b48a8395ae01b69a2b6e71f7759e8a12f7  package/dist/vendor/recorder/jwks.d.ts
49fdf310278e9a78a084c6233cffed84e83a879d002ed347dde87adedbdb28c8  package/dist/vendor/recorder/jwks.js
533d538749a4c13912eef5a74d26961cd6177c1f67f0e5252c116feb2b7c4fc0  package/dist/vendor/recorder/jwks.js.map
618ef44958c054da166e0c4449c7a3e72114f5934b5bcf29f97f6d9fd21f4950  package/dist/vendor/recorder/key.d.ts
e357f62ec2e73657c364106b8bcc36ea522816ea40b7d87404bfa7fa60400790  package/dist/vendor/recorder/key.js
09da38c31a23823013c5bb8dff792a1120afcb9d7781d81869b8e265cba402bf  package/dist/vendor/recorder/key.js.map
7597298889a71b152fe47e9a6e0c7f9705a056fbe89c2a2ca2318052ef533cb7  package/dist/vendor/recorder/payment-ref.d.ts
85fb7c4bd57342f37855b8750ef695b34ce074cec8981bc076f2341c6025deca  package/dist/vendor/recorder/payment-ref.js
e8403a078fbee9a79b6ebe150378c4684c32f17dc0e4fe812fe0f9e3b9468390  package/dist/vendor/recorder/payment-ref.js.map
b4196e1def4cc07a18136261f09cee752db6aded7e0e5c304a0e67ff24f9caf4  package/dist/vendor/recorder/record.d.ts
798dd0624c01dc8a977bb419abfbccd8226c9dce47e4a0e0a610395096d2f7c3  package/dist/vendor/recorder/record.js
98758594f9e461d5d9aa8bcb14bc1849c4bb857d827cd9fd1d55457c380f43bb  package/dist/vendor/recorder/record.js.map
ff207dd41d91d661cd0c29f5caa0cebd02e0d2bf02e18da363631c2f3b2eb824  package/dist/vendor/recorder/request.d.ts
6f9189632f8cb13df12f9de761d83926d22357001b060dca8a78c8bc92eb1bd4  package/dist/vendor/recorder/request.js
66411f073beb80b08e950efb45bd54f45c3d182fe19c61ddbf6d660bec1afdea  package/dist/vendor/recorder/request.js.map
af21d0edd0281462832b55f469be5408e1e9a6464ac8a4dae7a4aac90c855ff2  package/dist/vendor/recorder/sign.d.ts
d0fb1c7dc4ea9ac3cc821c5c0170f39dbe758ac4c5405ead00c74e35926c5f57  package/dist/vendor/recorder/sign.js
2981eac7677c69152798b2c33c6f1d63e9504d5e4cd45645a524c6909c31820a  package/dist/vendor/recorder/sign.js.map
01878144de69babe656f0b0fde40de22ab553af193778d204602c767950b723a  package/dist/vendor/recorder/strict-json.d.ts
05c86f6efc78e9bb805332ba04644a8d5e9a1c89ddd1d75a3fdd1a7408875788  package/dist/vendor/recorder/strict-json.js
f48f68dbf15572f1a1589f6baf4eb217dea6d6eab99436b491bb7626c7629fac  package/dist/vendor/recorder/strict-json.js.map
7ad2c45f2fc44b5a55b5ab29a25644fb03868d18e50aaf28c0404b498ba6f0d7  package/dist/vendor/recorder/x402-registry.d.ts
7427a2fb7a055c1f02812b5dce5861cd274529e0d6df0c8210cf6f0450946745  package/dist/vendor/recorder/x402-registry.js
67acbc2b27d608c8b1d705ee70a49dba4db63df7d0e7d017d0250033c5d736b1  package/dist/vendor/recorder/x402-registry.js.map
5eda538167427d73a991b006713eaf1f4f002c9a6cb5c9896f147ea03bcf5664  package/dist/witness.d.ts
92585eefea50ff852f0d49194dc9da4ed4f8578ce979ceae9055c4d1d0f7b6f4  package/dist/witness.js
54be3d0b396d8e3b205f681c8f5f8778268db6a70f097e577edabc3eb2fe497b  package/dist/witness.js.map
82c301e835d1c8d5b2a5177a9a7aef50bcc6f81eb01b65df5262a486474bf742  package/package.json
```

</details>
