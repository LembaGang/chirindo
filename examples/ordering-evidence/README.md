# Ordering evidence: a gate receipt, its witness, and a Base Sepolia payment that cites it

A worked example, run against production on 9 Oct 2026, of the evidence a
reviewer needs to judge a claim that a gate ran before an action:

1. the gate receipt, and its verified inclusion in the gate's hash chain (the log);
2. the checkpoint whose `count` covers that receipt;
3. a witness receipt for that checkpoint, verifiable against a pinned public key;
4. for an action on Base Sepolia, the transaction's block evidence;

then the witness time beside the block time, with the limits stated below.
There are two cases: an ALLOW that is followed by a payment (Case A), and a
refusal that leaves nothing on any blockchain (Case B).

Everything here can be checked offline in a fresh clone with Node alone:

```
node examples/ordering-evidence/check.mjs            # offline, every case; exit 0 only if every check passes
node examples/ordering-evidence/check.mjs --online   # also re-fetches the transaction and the witness records
node --test examples/ordering-evidence/test/         # each check shown failing on a one-byte change
```

Run from the repository root. `check.mjs` and the tests use Node built-ins
only; they need no `npm install` in this directory.

## The entry hash

A receipt's entry hash is `"sha256:" + hex(SHA-256(JCS(record without "sig")))`,
the value the next record's `prev_hash` carries; `check.mjs` computes it from
the record and never reads it from the receipt's `gate_receipt` member, which
is a different hash. In Case A the entry hash is
`sha256:78302a65c3a6dec3797474473365dfa4f6ee1968b996bdd16ec101b2b167a867`; that
receipt's `gate_receipt` is `sha256:998f342e…5e74`.

## Files

| Path | What it is |
|---|---|
| `client.mjs` | A minimal MCP client: starts `node dist/cli.js proxy` (this repository's gate, with an explicit `--dir` taken from `CHIRINDO_Y2_OPERATOR_DIR`) in front of `examples/observe-only-agent/downstream-mcp-server.mjs`, makes one `tools/call` of `mock_swap`, and exits. Edited after the runs only to read that directory from the environment instead of a fixed path; not re-run. |
| `keys/operator-identity.json`, `keys/operator-jwks.json` | The example operator's public key (identity file without its secret, and the JWK from `chirindo export-jwks`). The secret is not in this repository. |
| `keys/witness-key.jwk.json` | The witness public key, pinned from `https://api.headlessoracle.com/v5/keys` (`key_2026_v1`). |
| `keys/witness-key.pin.json`, `keys/v5-keys.response.json` | Where and when that key was fetched, the SHA-256 of its 32 raw bytes, and the response it was taken from. |
| `case-a/policy.json` | `{"deny":[]}`: the gate allows the call. |
| `case-a/ordering-evidence-case-a-1.jsonl` | The hash chain: one signed ALLOW receipt for `mock_swap`. |
| `case-a/ordering-evidence-case-a-1.jsonl.witness.ndjson` | The signed checkpoint (`count` 1) and the witness receipt for it, from `chirindo checkpoint --witness https://api.headlessoracle.com`. |
| `case-a/facilitator/` | The x402 payment request sent to the facilitator, its `/verify` and `/settle` responses, and their times. |
| `case-a/rpc/*.sealed.json` | The transaction, its receipt and its block as `https://sepolia.base.org` returned them once the block was sealed and at least 5 blocks deep. These are the copies `check.mjs` checks. |
| `case-a/rpc/transaction.json`, `receipt.json`, `block.json`, `fetched.json` | The first snapshots, kept unedited (see below). |
| `case-a/pay.mjs` | The script that built the payment and settled it (uses `viem`, a dev dependency of this directory only). pay.mjs is shown as edited after the run: the wait for a sealed block, reading the payer file from `CHIRINDO_Y2_PAYER_FILE`, and one comment's wording were changed afterwards, and it was not re-run. fetch-sealed.mjs is the script that fetched the sealed copies the checker reads. |
| `case-a/fetch-sealed.mjs` | The text that fetched `rpc/*.sealed.json`, committed as it ran: it was run inline with `node --input-type=module -e` from `case-a/`, so its output paths are relative to that directory. |
| `case-a/case.json`, `case-b/case.json` | Which file is which, for `check.mjs`. |
| `case-b/policy.json` | `{"deny":[{"tool":"mock_swap"}]}`: the gate refuses the call. |
| `case-b/ordering-evidence-case-b-1.jsonl`, `…witness.ndjson` | One signed DENY receipt, and the witnessed checkpoint covering it. |
| `check.mjs` | The checker. |
| `test/` | `one-byte.mjs` (loaded by `index.js`): the committed files pass, and a one-byte change to each file makes its check fail. |

## Case A: ALLOW, then a payment that cites the receipt

The gate forwarded `mock_swap`, and wrote the ALLOW receipt when the
downstream answered, so the receipt records a tool call that had already run.
The checkpoint covering it was witnessed at `received_at`
2026-10-09T13:12:54.082Z. A separate action followed: an EIP-3009
`transferWithAuthorization` of 0.01 test USDC on Base Sepolia whose `nonce` is
the receipt's entry hash (32 bytes, the `sha256:` prefix removed). It was
included in block 47894278 (timestamp 2026-10-09T14:40:44Z), in transaction
[`0x30ca1568…5ce3`](https://sepolia.basescan.org/tx/0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3),
whose `AuthorizationUsed` log carries the same nonce.

The payment was settled by the public x402 facilitator (`https://x402.org/facilitator`),
which paid the gas, and the ordering evidence does not depend on trusting it:
the nonce and the `AuthorizationUsed` log are read from the blockchain.

The first copies of the transaction and its receipt were fetched before the
block was sealed (their block hash was empty), so they were kept unedited and
fetched again once the block was sealed; the sealed copies are the ones
checked, and `check.mjs` confirms both copies agree on the transaction hash,
input, status and `AuthorizationUsed` log.

## Case B: DENY, nothing executes

The gate refused `mock_swap`; nothing was forwarded and there is no
transaction. The DENY receipt is in the hash chain, and the checkpoint
covering it was witnessed at `received_at` 2026-10-09T13:03:33.974Z.

## What this shows, and what it does not

- **(a)** The payment and the gated tool call are separate actions. The ALLOW
  receipt records a tool call that had already run. The payment's nonce is the
  receipt's entry hash, so (as long as SHA-256 holds) the payment
  authorization could not have been signed before the receipt's content
  existed, and the receipt's content (everything except `sig`) existed no
  later than block 47894278, on Base Sepolia's ordering, without trusting any
  clock. This does not show that the receipt's contents are true, or that the
  payment was authorized by them.
- **(b)** The witness receipt is Headless Oracle's signed statement that it
  received the checkpoint at `received_at`, on Headless Oracle's clock. It is
  only as reliable as Headless Oracle and its signing key; see `honest_limits`
  in the served spec, https://api.headlessoracle.com/v1/witness/spec.
- **(c)** For a refusal there is no transaction; the witnessed checkpoint is
  the outside record that the gate said no, with the same limits as (b).
- **(d)** `check.mjs` prints `received_at` beside the block timestamp. They
  come from two different clocks: block timestamps are set by the block
  producer within Base Sepolia's rules. Here the block is about 88 minutes
  after `received_at`; nothing in the ordering above rests on that gap.

`check.mjs` hard-codes two Ethereum constants, because Node has no
keccak-256: the selector `0xe3ee160e` of
`transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)`
and the topic `0x98de5035…10a5` of `AuthorizationUsed(address,bytes32)`. Both
were computed with `viem` 2.56.9 when this example was built. The token
contract's verified source emits `AuthorizationUsed(authorizer, nonce)` when it
marks a payer-chosen `bytes32` nonce as used.
