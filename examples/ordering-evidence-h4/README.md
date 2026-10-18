# Ordering evidence for a pre-trade workflow on Base (H4)

`check-h4.mjs` checks one case, and a pass shows this: the transaction the
case names carried the decision hash in bytes that the stated account
signed. The decision hash is the hash of the log entry that records the
pre-trade check's destination receipt; the stated account is the one the
verifier names with `--authorizer`. A pass does not show that the
transaction was a trade, or what it bought. "H4" names this check
(pre-execution precedence). The case is a third party's workflow, not
Chirindo's own gate:

1. two EIP-712 receipts for one trade (a source check and a destination
   check) from a pre-trade check issuer, read through the issuer's profile
   (below), which the verifier pins by sha256;
2. the operator's hash-chained log, whose entries carry the two receipts'
   uids, source first;
3. an Ed25519 checkpoint of that log, witnessed by Headless Oracle
   (`witness-spec/0.5`, https://api.headlessoracle.com/v1/witness/spec);
4. a Base transaction in which the account the verifier names with
   `--authorizer` signed bytes that carry the hash of the later
   (destination) log entry.

The checker names no issuer. An issuer's EIP-712 domain and the signer keys
its published key document lists are supplied with the case, in an issuer
profile (`issuer/profile.json`, below) whose sha256 the verifier pins. The
account the trade must come from is named by the verifier (`--authorizer`),
never by the case.

**The fixtures in `fixtures/` are test fixtures.** Their issuer is made up
(its profile says so), and its signing key, the log key and the wallets are
throwaway test keys made from public seed strings in
`fixtures/make-fixtures.mjs`; their witness key is a STUB that Headless Oracle
never uses; their chain id is 31337 (a local test chain id, which the test
profile names); no transaction in them was ever broadcast. They show the
checks working and failing. The checker is for real receipts from a real
issuer, under that issuer's profile, with a real log, a real witness receipt
and a real Base transaction.

This folder is not part of the npm package.

## What exit 0 shows, and what it does not

Exit 0 is the only pass. It needs ordering mode, `--online` and
`--authorizer`, and it shows, from signatures and hashes the checker
recomputes and from two public endpoints' byte-equal answers:

- each receipt's uid is the EIP-712 digest of its signed fields under the
  domain and types of the pinned issuer profile, and its signature recovers
  to a signer the profile lists, valid at the receipt's check time;
- the log's entries form one chain from its genesis value, carry the two
  uids in order, and the checkpoint signed by the log key covers the
  destination entry;
- Headless Oracle's witness key signed a receipt for that checkpoint's head;
- the transaction's hash and sender recompute from its signed fields; two
  JSON-RPC endpoints gave byte-equal answers for it, its receipt and its
  block; the block hash recomputes from its header; and the case's chain id
  is the one the pinned profile names (Base mainnet, 8453, when it names
  none);
- the destination entry hash sits in bytes whose signature recovers to the
  account `--authorizer` names (see "Bindings");
- no FLAG line stands: the block is at or below both endpoints' finalized
  block, and its timestamp is neither before a receipt's check time nor
  after its valid-until time.

So the destination entry's content, and through the chain every earlier
entry and both receipt uids, existed before that account signed the bytes
that carry it (the transaction, or on the EIP-3009 path the authorization).
No clock is needed for that ordering.

A pass does not show:

- that the profile describes the issuer correctly: the verifier decides which
  profile to trust (it pins the profile's sha256), and the checker reads
  every receipt as that profile says;
- that the account `--authorizer` names is the trader: the verifier says so
  (for example from the trader or the issuer, out of band), and the checker
  shows only that this account signed the bytes that carry the hash. It is
  an address, not a person or a company;
- that a verdict was wise, or that a receipt's contents (prices, counts,
  verdicts) are true: a receipt shows who signed what, not that it is right;
- when the issuer signed: a uid is the digest of the signed fields, so the
  binding shows the fields existed before the trade; the signature itself may
  have been made later;
- that the transaction is a trade, or what it bought: the case names the
  transaction, and any transaction that the `--authorizer` account signed
  and whose signed bytes carry the hash passes, a zero-value transaction to
  its own address among them. Nor that it is the trade the receipts
  assessed: its chain, assets, action and size are not compared with the
  receipts, or with the request their request hash covers;
- who controls the log key, or that entries were written at the times they
  carry: the case supplies the log key, and the witness receipt binds only its
  thumbprint;
- that the witness is independent of Headless Oracle: a witness receipt is
  Headless Oracle's signed statement that at `received_at` it was shown a
  checkpoint signed by the key with that thumbprint. It is independent of the
  operator, not of Headless Oracle;
- more about the chain than two public endpoints answered: the endpoints are
  the verifier's (built in, or named with `--rpc`), the checker cannot tell
  whether two endpoints are run by different operators, and no full block is
  read, so the transactions and receipts roots are not recomputed; the
  transaction's place in its block, the receipt's status and its logs rest
  on the two byte-equal answers;
- anything about entries after the checkpoint, or sessions the case does not
  present (the witness spec's `honest_limits` apply).

## Exit codes

What each exit code establishes:

- 0, a pass (ordering mode): everything the section above lists. No FAIL
  and no FLAG line; the chain data is two endpoints' byte-equal answers
  (`--online`); the bytes that carry the hash were signed by the account
  `--authorizer` names.
- 1: at least one FAIL. A run that stops on an input it does not handle
  prints a FAIL line and a RESULT line and exits 1.
- 2: a usage error, among them an `--authorizer` that is not an address,
  whose mixed case is not its EIP-55 checksum, or that is given twice, and
  `--rpc` URLs that name fewer than two distinct hosts.
- 3 (trailer-report mode): no FAIL. The transaction was read: its call, any
  EIP-3009 authorization and any bytes after the arguments are reported. No
  ordering is claimed, and nothing about receipts or a log is checked.
- 4 (ordering mode): no FAIL, but the chain data was not compared with two
  endpoints (offline, or online with no endpoint known for the chain). The
  receipts, the log, the checkpoint, the witness receipt, the transaction's
  hash and sender and the binding were checked as for a pass; the receipt,
  its logs, the block, its hash and the times read from it are as the case
  supplies them, and each line that rests on them is NOT VERIFIED OFFLINE.
  Not a pass: made-up chain data reaches exit 4 offline.
- 5 (ordering mode, chain data verified): no FAIL, but at least one FLAG
  line stands: no `--authorizer` (the line names the account that signed
  the bytes that carry the hash), a block above an endpoint's finalized
  block, or a block timestamp before a receipt's check time or after its
  valid-until time. Not a pass.

When more than one applies, the first of 1, 4 and 5 is the exit code
(trailer-report mode exits 1 or 3). The output's last lines list the FLAG,
NOT VERIFIED OFFLINE, NOT CHECKED and NOT SUPPORTED lines, and the RESULT
line counts them with the PASS and FAIL lines. NOT CHECKED and NOT
SUPPORTED lines are never
counted as passes. A pass can still list NOT CHECKED lines that do not
decide the ordering (a request hash without its request, a signer the
issuer's key document no longer lists): read them.

## Not supported in this version

Each of these FAILs the ordering check (or, for an unsupported transaction
type, the transaction check) and is never counted as a pass:

- A trade whose authorizing signature is over an intent that another account
  (for example a relayer) submits to the chain. The transaction is signed by
  the submitting account, and the hash sits in calldata only that account
  signed; the intent's own signature is not read. With `--authorizer`
  naming the trader, the checker reports the hash as carried by another
  account (CARRIED-BY-OTHER) and FAILs, whatever value the submitting
  account moves.
- A UserOperation: a call to an ERC-4337 EntryPoint (`handleOps`) is NOT
  SUPPORTED; a hash inside a UserOperation is not read.
- A deposit transaction (type 0x7e), a blob transaction (0x3) or any other
  type than 0x0, 0x1, 0x2 and 0x4: FAIL "unsupported type".
- `receiveWithAuthorization`, an EIP-3009 authorization signed by a contract
  wallet (a signature that is not 65 bytes), and a hash in an authorization
  word other than the nonce: NOT SUPPORTED.

## Commands

```
cd examples/ordering-evidence-h4
npm ci
node check-h4.mjs fixtures/calldata --pins fixtures/test-pins --authorizer 0x328011696F785E3904E0a25d6f21a080778b16C0
node check-h4.mjs fixtures/eip3009 --pins fixtures/test-pins --authorizer 0xcc283999c9189E1be5998F803BFc45C5A14531fd
node --test --test-reporter=tap test/h4-checks.mjs
node check-h4.mjs <case-dir> [--authorizer <address>] [--online] [--show-parties] [--pins <dir>] [--profile-sha256 <hex>]... [--rpc <url>]...
```

The two fixture runs exit 4: their chain data is as the case supplies it,
and it was never on any chain, so outside the tests (which serve the
`--online` reads from a stand-in) no run of a fixture reaches exit 0. The
two addresses are the fixtures' test trader and test payer.

- `--authorizer <address>`: the account the trade must come from, as the
  verifier knows it (for example from the trader or the issuer, out of
  band); never read from the case. `0x` and 40 hex digits, all in lower
  case, all in upper case, or in mixed case that is the address's EIP-55
  checksum; mixed case that is not the checksum is refused, naming the
  first digit whose case is wrong. Give it once: a second `--authorizer` is
  refused, not read in place of the first. The bytes that carry the
  destination entry hash must have been signed by this account. Without it
  the binding line is FLAG and no run passes.
- `--pins <dir>`: the trust anchors (below). Default `pins/` in this folder.
  The fixtures need `--pins fixtures/test-pins`; under the default pins
  they fail, as they should.
- `--profile-sha256 <hex>`: accept, for this run, the issuer profile with this
  sha256 (64 lowercase hex digits), beside those `pins.json` lists. Obtain
  the value from the issuer, out of band, never from the case or from this
  checker's output.
- `--online`: also reads the key document the issuer profile names, Headless
  Oracle's witness list for the log's `kid` and `session_id` (following
  `next_after` for up to 10,000 pages), and the transaction, receipt and
  block from two public JSON-RPC endpoints, whose answers must be
  byte-equal: the same members with the same canonical JSON (RFC 8785)
  values. Endpoints are built in for chain ids 8453 and 84532. An endpoint
  that does not answer is passed over for the next in the list. Only reads:
  JSON-RPC read methods and HTTPS GETs. Nothing is written.
- `--rpc <url>`: an endpoint to use in place of the built-in ones, an http
  or https URL; give it at least twice, and the endpoints are tried in the
  order given. A URL whose host an earlier `--rpc` URL already names is not
  used (with `--online`, an INFO line names it), and URLs that name fewer
  than two distinct hosts are a usage error. Two answers are two sources only when two
  operators run the endpoints, which the checker cannot tell from a URL:
  the person running the check should choose endpoints run by different
  operators.
- `--show-parties`: print party addresses (senders, payers, authorizers,
  recipients) in full. By default each is printed as its first 6 and last 4
  hex digits, `0x123456...cdef`. This only keeps addresses off the page: the
  transaction hash is printed in full, and anyone who has it can read every
  party of the transaction from the chain. An error from a library is cut
  to its one-line summary, because its details can repeat calldata. Values
  decoded from a trailer (ERC-8021 codes and CBOR fields) are printed as
  they are.

`check-h4.mjs` only runs the checks, which are in `lib/check.mjs`; the
byte formats are in `lib/formats.mjs`, the Ethereum and Base formats in
`lib/evm.mjs`, and the `--online` reads in `lib/online.mjs`.

Node 20 or later. viem is pinned at exactly 2.56.9 in `package.json` (the
version `examples/ordering-evidence` pins) and supplies keccak-256, RLP,
secp256k1 recovery, EIP-712 hashing and ABI coding; SHA-256 and Ed25519 come
from `node:crypto`.

## The case directory

A fixed layout; `case.json` names no paths.

```
case.json                   format, mode, chain_id, tx_hash, binding
issuer/profile.json         the issuer profile; the verifier pins its sha256
receipts/source.json        the source check's receipt envelope
receipts/destination.json   the destination check's receipt envelope
requests/source.json        optional: the request it answered (the profile's request layout)
requests/destination.json   optional
log/entries.jsonl           the log, from its first entry through the checkpoint's last entry
log/public-key-jwk.json     the log key {kty: "OKP", crv: "Ed25519", x}
log/checkpoint.json         the checkpoint covering the destination entry
witness/receipt.json        Headless Oracle's witness receipt for that checkpoint
chain/transaction.json      eth_getTransactionByHash result
chain/receipt.json          eth_getTransactionReceipt result
chain/block.json            eth_getBlockByNumber(<its block>, false) result
chain/target-abi.json       optional: JSON ABI of the called function, to place the hash
chain/token-domain.json     trailer-report mode, offline: {name, version, chainId, verifyingContract, source}
```

`case.json`:

```
{
  "format": "chirindo-h4-case/1",
  "mode": "ordering",
  "chain_id": 8453,
  "tx_hash": "0x<64 hex>",
  "binding": "calldata" or "eip3009-nonce"
}
```

`case.json` names no authorizer; one that has an `expected_authorizer`
member FAILs.

A receipt envelope is the object the issuer returns, with the members its
profile names. A whole API response is accepted too when the profile names
where the receipt sits in it (`envelope.unwrap`); the response's other
members are not checked. `witness/receipt.json` is the receipt object as the
witness returned it (the POST's response body, or one element of the GET's
`receipts` list).

Each `chain/` file is a JSON-RPC `result` object, or the whole response
`{jsonrpc, id, result}`, so the output of a plain `curl` call can be saved
as is. A typed transaction must carry both `v` and `yParity`, and a receipt
`from`, `to`, `type`, `contractAddress` and, for each log, `blockHash`,
`blockNumber`, `transactionHash`, `transactionIndex`, `logIndex` and
`removed`; a missing member fails. With `--online` the three result files
may be left out; they are then read from the endpoints, held in memory and
not saved. When they are present, the checks read the endpoints' answers,
not the files, and the files must agree with the first endpoint's answers
on the 24 facts listed under check f below; their other members are not
compared.

Mode `trailer-report` (`case.json` with `format`, `mode`, `chain_id` and
`tx_hash` only) reads a Base mainnet transaction (`chain_id` 8453) without
any receipt, log or witness evidence: it recognises the call, checks an
EIP-3009 authorization if there is one (under the domain in
`chain/token-domain.json`, or with `--online` the token's own), reports the
token's logs and any bytes after the arguments, claims no entry hash and
exits 3. `--authorizer` is not read in this mode.

## Issuer profiles

An issuer profile (`chirindo-h4-issuer-profile/1`) is one JSON object, read
strictly (no member it does not name, no duplicate member name):

- `format`, `label`, `issuer` (the issuer's name, for the report) and `test`
  (true for a test profile; the result line then says so);
- `chain_id` (optional): the chain the issuer's trades are checked on. A
  case's `chain_id` must equal it (`a.chain-id`); without it, the chain is
  Base mainnet, 8453;
- `tokens` (optional): the EIP-3009 tokens a case may pay with, each
  `{address, name, version}`: the token contract and its EIP-712 domain name
  and version. A `transferWithAuthorization` to any other contract FAILs
  `g.token-domain`, and only these tokens' logs are read;
- `sources` (optional): what the profile was built from, each
  `{url, fetched_at, bytes, sha256}`, reported, not checked;
- `receipt`: `eip712` (`{domain, types, primaryType}`: the layout the issuer
  signs), `schema_version` (the value the receipt's schema-version field must
  hold), and `fields`, which names the signed fields that hold the check time
  (`checked_at`, a uint), the valid-until time (`valid_until`, a uint), the
  request hash (`request_hash`, a bytes32), the verdict (`verdict`, a string)
  and the schema version (`schema_version`, a uint);
- `envelope`: the envelope's `required` and `optional` member names; which
  member holds the uid (`uid`, the EIP-712 digest), the 65-byte signature
  (`signature`), the signer's address (`signer`) and the signed fields
  (`message`); optionally the members that must agree with the signed fields
  (`schema_version`, `valid_until`, and `valid_for_seconds`, which must be
  valid-until minus check time), a member that, when present, must equal the
  layout (`layout`, with `request_layout` naming the request layout's members
  inside it), and `unwrap`, the dotted paths at which an API response holds
  the receipt;
- `request` (optional): `eip712`, the layout of the request whose EIP-712 hash
  is the receipt's request hash;
- `signers`: each `{address, key_id, valid_from, valid_until}` (`valid_until`
  null for no end). A receipt's signer must be one of them, valid at the
  receipt's check time;
- `key_document` (optional, read only with `--online`): the `url` where the
  issuer publishes its keys, and where to find them in that document: `keys`
  (the list), `address`, `key_id`, `valid_from`, `valid_until`, `require`
  (members that must hold exact values, such as `{"revoked": false}`), `role`
  with `accepted_roles` (an entry with no role is accepted), `revoked_list`
  (a list the signer must not appear in) and `layout` (where the document
  shows the receipt layout, which must equal the profile's).

The verifier pins each profile it accepts: `pins.json` lists its sha256 in
`issuer_profiles`, or `--profile-sha256` names it for one run. A case whose
profile is not pinned FAILs `a.profile`, and nothing else in the case can
stand in for it. That FAIL line does not print the case profile's sha256:
obtain the sha256 of the issuer's published profile from the issuer, out of
band, and pin that; never pin a value read from the case. A profile is built
from the issuer's published key and schema documents, and its `sources` say
which bytes. The profile in `fixtures/` is a test profile of a made-up
issuer.

## The log rules

A log this checker reads follows Chirindo's chain rules:

- `log/entries.jsonl` is UTF-8, one JSON object per line (LF or CRLF), no
  blank line. Each line is read strictly: no duplicate member name, no
  number with a fraction or exponent, no integer outside JavaScript's safe
  range.
- Every entry has `v` (a non-empty string naming the log format, the same in
  every entry), `seq` (equal to its 0-based line index), `session_id` (1 to
  128 characters, the same in every entry) and `prev_hash`. An entry that
  records a receipt carries its uid as `receipt_uid` (`0x` + 64 lowercase
  hex). Other members are allowed; all of them are hashed.
- Entry hash: `"sha256:" + hex(SHA-256(JCS(entry without "sig")))`, lowercase
  hex, JCS per RFC 8785.
- Entry 0's `prev_hash` is the genesis value
  `"sha256:" + hex(SHA-256(JCS({"v": <v>, "session_id": <session_id>, "marker": "genesis"})))`;
  entry n's `prev_hash` is the entry hash of entry n-1.
- An entry may carry `sig`: Ed25519 over the JCS bytes of the entry without
  `sig`, under the log key, base64url without padding (86 characters, the
  canonical encoding). When present it must verify.
- Each receipt's uid is the `receipt_uid` of exactly one entry, the source's
  entry before the destination's.
- The checkpoint has exactly the eight members of the witness spec's
  `submit.checkpoint`: `v` is `"evidence.action/1"` whatever the entries'
  `v`, `type` is `"checkpoint"`, `kid` is the RFC 7638 thumbprint of the log
  key, `session_id` is the log's, `count` is the number of entries in
  `log/entries.jsonl`, and `last_entry_hash` is the entry hash of entry
  `count - 1`; `sig` is Ed25519 over the JCS bytes without `sig`.
- Entries are read by anyone who checks a later entry, so they should carry
  hashes, not request details, and a session should hold one workflow.

The destination entry hash, as 32 raw bytes (the hex after `sha256:`), is
what the trade carries.

## The checks, in order

Each line is `PASS`, `FAIL`, `INFO`, `FLAG`, `NOT VERIFIED OFFLINE`, `NOT
CHECKED` or `NOT SUPPORTED` with an id and a reason. A check whose
prerequisite did not pass is NOT CHECKED, naming the prerequisite. A check
that rests on chain data (`f.chain-data`, `f.receipt`, `f.block`,
`f.block-hash`, `g.token-logs`, `g.validity-window`) is NOT VERIFIED OFFLINE,
never PASS, when that data is the case's own and not two endpoints'
byte-equal answers.

- `pins`: the pinned witness key response matches the sha256 and size in
  `pins.json`, and its key equals the pinned `public_key_hex`; non-test pins
  must pin `key_2026_v1` with public key
  `03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178`; the
  accepted issuer profiles are listed.
- `case`: `case.json` has exactly the members above (`expected_authorizer`
  FAILs: the authorizer comes from the verifier); in trailer-report mode
  `chain_id` is 8453.
- a. `a.profile`: the case's `issuer/profile.json` has a sha256 the verifier
  pinned and reads as a profile (above). `a.chain-id`: the case's chain id is
  the one the profile names (8453 when it names none). `a.online-keys`
  (`--online`): the key document the profile names, read now, shows the same
  layout (when the profile says where) and lists each receipt's signer as an
  accepted key valid at its check time (a signer it no longer lists is NOT
  CHECKED, not FAIL).
- b. For each receipt: `envelope` (the profile's members, the signed fields
  exactly the layout's with their types, the schema version, the envelope
  members that must agree with the signed fields, a layout member equal to
  the profile's); `uid` (the EIP-712 digest recomputed from the profile's
  domain and types); `signature` (65 bytes, v 27 or 28, low s, recovers to
  the envelope's signer); `signer-key` (one of the profile's signers, valid
  at the check time); `fields` (INFO: the uid, verdict, request hash, check
  time and valid-until time, each with the field name the profile gives);
  `request-hash` (when `requests/<role>.json` is present: its EIP-712 hash
  under the profile's request layout equals the receipt's request hash;
  otherwise NOT CHECKED); `request-fields` (INFO: whether the request hash is
  that hash of the receipt's own fields of the same names).
- c. `c.log-key`, `c.entries`, `c.chain`, `c.entry-signatures`,
  `c.receipt-uids`: the log rules above.
- d. `d.checkpoint-shape`, `d.checkpoint-key`, `d.checkpoint-signature`,
  `d.checkpoint-session`, `d.checkpoint-covers`.
- e. `e.witness-receipt`: exactly the twelve members of the spec's receipt,
  all strings, `public_key_id` equal to the pinned key id, `signature` 128
  lowercase hex characters, Ed25519 over the JCS bytes without `signature`
  under the pinned key. `e.witness-covers-checkpoint`: `type`, `witness`,
  `kid`, `session_id`, `count` and `last_entry_hash` equal the checkpoint's,
  `fork` is `"false"`, and `checkpoint_sha256` is recomputed over the full
  signed checkpoint; when the witness stored another checkpoint of the same
  head (its spec allows this when one head is checkpointed twice) that is
  reported as `e.checkpoint-sha256` (INFO). `e.online-witness` (`--online`):
  GET `/v1/witness/checkpoints` for the log's `kid` and `session_id`,
  following `next_after`; every listed receipt must verify under the pinned
  key, the supplied receipt must be listed, two receipts at one count with
  different hashes FAIL (a fork), and a listed count within the log whose
  `last_entry_hash` differs from the log's entry hash FAILs (a rewrite after
  witnessing). Later counts are reported.
- f. `f.chain-data` (and with `--online`, `f.online-rpc`: the first two
  endpoints that answer give byte-equal answers for the transaction, its
  receipt and its block, every member. When the case has its own chain
  files, they must agree with the first endpoint's answers on 24 facts: the
  transaction's `hash`, `type`, `chainId`, `nonce`, `from`, `to` (these two
  in any letter case), `value`, `input`, `r`, `s`, `blockHash`,
  `blockNumber` and `transactionIndex`; the receipt's `status`,
  `transactionHash`, `blockHash`, `blockNumber`, `transactionIndex` and
  `logs` (each log's `address`, `topics`, `data` and `logIndex`, in order);
  and the block's `number`, `hash`, `parentHash` and `timestamp`, and
  whether its `transactions` list holds the transaction (`block.hasTx` in a
  FAIL line). The files' other members are not compared: online, every
  check reads the endpoints' answers, not the files. `f.finality`: the
  block is at or below each endpoint's `finalized` block, else FLAG);
  `f.transaction`: the
  case's chain id equals the transaction's, and the transaction hash
  recomputes from its signed fields for type 0x0 (legacy with EIP-155), 0x1,
  0x2 and 0x4; any other type (0x3, the deposit type 0x7e, unknown types) is
  FAIL "unsupported type"; `f.sender`: the sender recovered from the
  signature (low s) equals `from`; `f.receipt`: status 0x1, the same hash,
  block, index, sender, target and type, and each log in the same block and
  transaction; `f.block`: the block lists the transaction at its index, and a
  `blockTimestamp` on the transaction or a log equals the block's;
  `f.block-hash`: the block hash recomputed from its header fields (Base
  mainnet's current header has 21). A member this checker does not know is
  not hashed: if it is a header field of a newer format, the hash does not
  recompute and the check FAILs, naming it.
- g. The binding, below. For an EIP-3009 call also `g.token-domain`,
  `g.authorization`, `g.token-logs` (INFO only in trailer-report mode) and
  `g.validity-window`.
- h. `h.trailer` (INFO): bytes after a recognised call's ABI-encoded
  arguments, with their length and, when they parse as an ERC-8021 suffix
  (draft ERC-8021, ethereum/ERCs pull request 1209), its schema and decoded
  fields. A trailer is never read as an entry hash; only g decides whether a
  hash found in it binds.
- i. Times: each receipt's check time and valid-until time (the issuer's
  clock), entry `ts` if present and checkpoint `ts` (the log operator's
  clock), `received_at` (Headless Oracle's clock), the block timestamp (set
  by Base's block producer), all reported. FLAG lines name a block timestamp
  after a receipt's valid-until time or before its check time; each FLAG line
  keeps the run from passing (exit 5).

## Bindings

The authorizer is the account recovered from the signature over the bytes
that carry the destination entry hash. It must be the account the verifier
names with `--authorizer`; the case never names it. No value moved and no
log decides who the authorizer is.

- `binding: "eip3009-nonce"`: the call is
  `transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)`,
  or its `bytes signature` overload with a 65-byte signature, as the
  transaction's top-level call to a token the pinned profile names in
  `tokens`. The authorization signature is recomputed under that token's
  EIP-712 domain (the profile's name and version, the case's chain id and
  the token's address; with `--online` the token's own `name()`,
  `version()` and `DOMAIN_SEPARATOR()`, read by `eth_call` from both
  endpoints, whose answers must be byte-equal, must agree) and must recover
  to the authorization's `from`. That account signed the nonce, so it is the
  authorizer, and it must be the account `--authorizer` names. The nonce
  must be the destination entry hash, and the block timestamp must lie
  between `validAfter` and `validBefore`.
- The token's logs (`g.token-logs`): the receipt must hold exactly one
  `AuthorizationUsed(from, nonce)` from that token, which ties the payment to
  this authorization by its nonce, and exactly one `Transfer(from, to,
  value)` from that token with the authorization's `from`, `to` and
  `value`. A Transfer-shaped log counts only when all four hold: it comes
  from the token the pinned profile names, its amount is above zero, its
  `from` is the authorizer, and it is tied to the authorization by nonce. No
  other log is read.
- `binding: "calldata"`: the destination entry hash is anywhere in the
  transaction's calldata, which only the transaction's signature covers, so
  the authorizer is the sender recovered from it, and it must be the account
  `--authorizer` names. In an EIP-3009 payment the sender must also be the
  authorization's `from`, from which the value moves. The offset is reported,
  and whether it lies after the ABI-encoded arguments when
  `chain/target-abi.json` gives the function (the arguments are decoded and
  encoded again; the canonical encoding must be a prefix of the calldata).
- CARRIED-BY-OTHER, FAIL: the bytes that carry the hash were signed only by
  an account other than the one `--authorizer` names: calldata a relayer
  sent for a trader, whatever value the relayer attaches or logs its call
  emits; or, in an EIP-3009 payment, a facilitator's suffix after the
  authorization, which the payer did not sign.
- Without `--authorizer` the binding line is FLAG "authorizer not stated by
  the verifier", naming the account recovered from the signature over the
  bytes that carry the hash (shortened unless `--show-parties`). No run
  passes without `--authorizer`.
- ABSENT, FAIL: the hash is not in the calldata.
- NOT SUPPORTED, and the ordering FAILs: the paths listed under "Not
  supported in this version".
- The case's claimed `binding` must be the path where the hash binds.

## What a one-byte change does

A one-byte change to any value a signature, a hash or a comparison covers
makes the checker FAIL. The tests make two one-byte changes to every value
of every JSON member of both fixtures and of the test pins (a digit or a
letter replaced, and a letter's case flipped: 512 and 488 changes), rename
every member by one byte (269 and 267 renames), and check exactly what
follows. The values no check covers, where a one-byte change leaves the
result as it was, are:

- each receipt envelope: the optional members to which the profile gives no
  role (in the test profile, `label`, `issued_at` and `info_url`);
- `chain/transaction.json`: `gasPrice` (for types 0x2 and 0x4 it is the
  price paid, not a signed field);
- `chain/receipt.json`: `blobGasUsed`, `cumulativeGasUsed`,
  `daFootprintGasScalar`, `effectiveGasPrice`, `gasUsed`, the `l1...` fee
  fields, `logsBloom`, each log's `logIndex`, and the logs no check reads
  (in the calldata fixture its one `Transfer` log, since the calldata path
  reads no log);
- `chain/block.json`: `size`, and every entry of `transactions` other than
  the transaction's own;
- `chain/target-abi.json`: all of it (it only places the hash in the
  report: a change to it can alter where the report places the hash, or
  make the file unreadable, which FAILs);
- `pins.json`: `label`, the witness key's `fetched_at` and `url`, and each
  pinned profile's `label`.

With `--online` the endpoints' answers are what the chain checks read, and
they must be byte-equal, so a change between them in any member FAILs. The
case's own chain files, when present, are then compared with those answers
on the 24 facts of check f only.

Renaming a member fails, because the member is then missing or unexpected,
except for members the checker does not require: the uncovered ones above,
`blockTimestamp` on the transaction and on each log, and `size`, `uncles`
and `withdrawals` in the block.

The JSON text's form is not covered in any JSON member the checker parses:
white space, the order of members, a `\u` escape (with lower- or
upper-case hex digits) in place of the character, an escaped slash and `-0`
for `0` all parse to the same values, and signatures and hashes cover the
parsed values (JCS or EIP-712), not the file's bytes. The exceptions are
the two documents pinned by sha256 (the issuer profile in the case and the
witness key response in the pins): any byte change in them FAILs.

The case's sha256 values are printed (`INFO files`), so two readers can
confirm they checked the same bytes.

## Pins

`pins/pins.json` names the verifier's trust anchors, never the case's:
Headless Oracle's witness key, and the issuer profiles the verifier accepts.

| file | source | fetched (UTC) | bytes | sha256 |
|---|---|---|---|---|
| `v5-keys.response.json` | https://api.headlessoracle.com/v5/keys | 2026-10-16T16:39:45.504Z | 1913 | `642bc434c81092bb9f0103efc2478c0cf89fac330a4e1c049d2299e9c7b167b9` |

`issuer_profiles` is empty in the pins committed here: a verifier lists the
sha256 of each issuer profile it accepts (`{"label": ..., "sha256": ...}`),
or names one for a run with `--profile-sha256`.

A profile lists each signer with its validity window, so a key the issuer
later rotates out still verifies receipts it signed while it was valid, under
the profile that lists it; with `--online` a signer the issuer's key document
no longer lists is NOT CHECKED, not FAIL. The witness spec's
`honest_limits.key_rotation` describes the same for Headless Oracle's key:
receipts signed under an earlier key verify only against a copy pinned
before the rotation.

The witness spec read for the checkpoint and receipt shapes was
https://api.headlessoracle.com/v1/witness/spec, `witness-spec/0.5`, 14058
bytes, sha256 `000e5ce7c4946001e7839c3669fc4c34026f6059fa6b66583c05a8b4ebc5e13c`
(fetched 2026-10-16T16:39:45.008Z).

## Fixtures and tests

`node fixtures/write-fixtures.mjs` rebuilds `fixtures/test-pins`,
`fixtures/calldata` (a swap call with the destination entry hash appended
after its arguments, sent and signed by the trader's test key; both
requests present; signed entries) and `fixtures/eip3009` (a facilitator's
test key sends a `transferWithAuthorization` to the test token the test
profile names, whose nonce is the destination entry hash, signed by the
payer's test key, with a facilitator's ERC-8021 suffix after the arguments;
no requests; unsigned entries). Both carry the test issuer's profile, which
names chain id 31337 and the test token. The signatures are deterministic,
so the files come out byte for byte the same; a test checks that.

`test/h4-checks.mjs` (run it with `node --test --test-reporter=tap`): both
fixtures exit 4 offline with their chain facts NOT VERIFIED OFFLINE, exit 0
online against stand-in endpoints, and fail under the default pins; the
command itself, run through a symlinked folder, with exit codes 1, 2, 3 and
4, an `--authorizer` in lower or in upper case (read), one that is not an
address, has a bad checksum or is given twice, `--rpc` URLs that name fewer
than two distinct hosts or are not http or https URLs (usage errors), and a
folder in place of a request file; exit codes 1, 4 and 5 and their order;
the authorizer as the verifier states it (a relayer's trade with value 0,
with 1 wei and with a zero-amount Transfer-shaped log from a contract of its
own, a facilitator's suffix, and each fixture with the other's authorizer:
CARRIED-BY-OTHER; without `--authorizer`: FLAG and no pass; a case naming
`expected_authorizer`; a wrong claimed `binding`); ABSENT for a calldata
trade and an EIP-3009 settlement without the hash; the token-log rules (a
Transfer from another contract or from another account, an
`AuthorizationUsed` log for another nonce, from another contract or
missing, a value of 0, a token the profile does not name); the chain id
rules; two inputs that once stopped the checker with a stack trace; issuer
profiles (pinned in `pins.json` or with `--profile-sha256`, refused when not
pinned without printing the case's own hash, refused when malformed, among
them a bad `chain_id` or `tokens`, and an envelope found inside an API
response at the profile's `unwrap` path); the one-byte value changes and
member renames above; byte flips in the pinned documents; the JSON text's
form; each log rule broken in an otherwise well-formed, checkpointed log
(seq, session_id, v, one uid in two entries, order of the two uids, an
entry after the checkpoint's count, a checkpoint for another session_id, a
witness receipt for another head); a receipt log marked removed; each check
that another check could hide, broken on its own (a checkpoint naming
another key's kid, a witnessed checkpoint over another last entry hash, a
witness receipt reporting a fork or of another type, an authorization
signed by a key other than its `from`, in high-s form or for another token
contract, two `AuthorizationUsed` logs, a block time outside the
authorization's window, a pinned profile that does not list the signer or
whose signer is valid only outside the check time, receipt data with
another schema version, a receipt signature with v 0 or 1 or in high-s
form, a transaction and receipt whose `from` names someone else, a receipt
for another transaction, another block); the `bytes signature` overload of
`transferWithAuthorization` (binds), `receiveWithAuthorization` and the hash
in another authorization word (NOT SUPPORTED); receipts signed by a key the
profile does not list, by a key other than the envelope's signer and by the
test issuer's sample-role key; a wrong pinned witness key; a witness
receipt for another signed checkpoint of the same head; a UserOperation;
unsupported transaction types; trailer-report mode; ERC-8021 suffixes in
each layout of the draft, with made-up codes (one with a CBOR map longer
than 255 bytes), five malformed ones and three byte strings that are not
suffixes; the block hashes of two real Base mainnet blocks;
transaction hashes and senders against viem's serializer for every
supported type; the strict readers; chain files given as whole JSON-RPC
responses; the `--online` comparisons, served by a stand-in fetch
(endpoints whose answers differ on a field the checks read, on one they do
not read, or by a member; case files that differ from both endpoints, on
each of the 24 facts compared and on members that are not compared;
`--rpc` URLs on one host, and on two hosts with one repeated; chain files
left out; a witness list of 25 pages; a receipt the witness
does not list, a rewrite, a fork, later counts, a forged listed receipt, a
listed receipt for another session; the issuer's key document read with the
profile's map, with a signer it no longer lists, a revoked or sample-role
entry, a key valid only before the check time, a changed layout and an
entry listed twice; a block above the finalized one; the token's domain
read by `eth_call` with a wrong `DOMAIN_SEPARATOR`, another version, or
answers that differ between the endpoints); and redaction, also for a call
that does not decode and with no `--authorizer`.
