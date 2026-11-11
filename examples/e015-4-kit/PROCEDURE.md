# The five-alteration test for agent logs

## 1. What this is

This is a test anyone can run in about five minutes. It shows whether an AI agent's log is tamper-evident in fact, not only by configuration. You take one real log, make five copies, and alter each copy in a different way. Then you run the tool's own verification on each copy. You record what it catches and what it misses.

## 2. The five alterations

In each case, "detected" means the tool's own verification fails and says where the problem is. A silent pass is not detection. Neither is a failure that does not name a record or a checkpoint.

| Alteration | What you do | What can detect it |
|---|---|---|
| Edit | Change one field in one record. Do not re-sign it. | A signature and hash chain, even one held by the operator. |
| Remove | Delete one record from the middle. | A signature and hash chain, even one held by the operator. |
| Swap | Swap the places of two records. | A signature and hash chain, even one held by the operator. |
| Cut off | Delete the last records. | Only a checkpoint held by someone outside the operator. The records that remain are still a valid chain. |
| Rewrite and re-sign | Change a record, then re-sign and re-link the whole log with the operator's own key. | Only a checkpoint held by someone outside the operator. The operator's key makes every signature valid again. |

The first three alterations are made by someone who does not hold the signing key. The last two are made by the operator, or by anyone who has the operator's key.

## 3. Run it on a Chirindo log

You need Node 20 or later and a checkout of this repository. Run these commands from the repository root. `npm ci` installs exactly what the lockfile names and does not change it.

```
npm ci
npx tsx examples/e015-4-kit/run.mjs
```

The second command makes a short session of seven tool calls. A local stub witness checkpoints the log at counts 2, 4, 6 and 7. The command then writes six copies of the log, verifies each one twice, and prints:

```
all 12 outcomes match the expected table; wrote <repository>/examples/e015-4-kit/RESULTS.md
```

To run each check yourself, set two shell variables (POSIX shells such as Git Bash; in PowerShell, write the paths out in full):

```
K=examples/e015-4-kit/work
W="--witness-file $K/gate/sessions/e015-4-kit-0001.jsonl.witness.ndjson --witness-key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394 --witness-name stub.invalid"
```

Each copy is checked first with the chain alone, then with the witness checkpoints:

```
npx tsx src/cli.ts verify $K/copies/<copy>.jsonl --key $K/gate/identity.json
npx tsx src/cli.ts verify $K/copies/<copy>.jsonl --key $K/gate/identity.json $W
```

`<copy>` is each of `intact`, `edited`, `deleted`, `reordered`, `truncated` and `resigned`. The first line of output is the verdict. Below, each line after a `#` label is the verdict line exactly as the tool prints it:

```
# intact: chain alone, and with witness checkpoints (exit 0 both)
VALID — 7 entries, chain intact, all signatures verified, session e015-4-kit-0001
# edited: chain alone, and with witness checkpoints (exit 1 both)
TAMPERED — entry 3: request_commitment mismatch
# deleted: chain alone, and with witness checkpoints (exit 1 both)
TAMPERED — entry 3: sequence gap
# reordered: chain alone, and with witness checkpoints (exit 1 both)
TAMPERED — entry 3: sequence gap
# truncated: chain alone (exit 0)
VALID — 5 entries, chain intact, all signatures verified, session e015-4-kit-0001
# truncated: with witness checkpoints (exit 1)
TAMPERED — witnessed count 6 is beyond the chain (5 records)
# resigned: chain alone (exit 0)
VALID — 7 entries, chain intact, all signatures verified, session e015-4-kit-0001
# resigned: with witness checkpoints (exit 1)
TAMPERED — witnessed count 4: last_entry_hash mismatch
```

A VALID line is followed by a line naming the key it was verified under and the path you gave. The intact copy, checked with witness checkpoints, also prints the unwitnessed tail count:

```
WITNESSED through count 7, received_at 2026-10-03T00:00:03.000Z, witness key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
0 records after the last witnessed checkpoint are not witness-protected (sidecar supplied by the operator)
```

The full output for all twelve checks is in [RESULTS.md](RESULTS.md).

## 4. Run it on any other tool's log

1. Export one real session log with the tool's own export.
2. Make five copies. Alter each one as section 2 describes, using a text editor or a short script. For "rewrite and re-sign", use the operator's own signing key and the tool's own way of writing records.
3. Run the tool's own verification command on the untouched log. It must pass. If it does not, stop: the test has no baseline.
4. Run the same command on each altered copy. Copy the first lines it prints.
5. Note whether that command asked an outside party, such as a witness service, a transparency log or a timestamp authority. A file the operator handed you does not count.
6. Write down how many records come after the last outside checkpoint. If the tool gives you no way to read that count, write "not reported by the tool".

| Alteration | Detected (yes/no) | What the tool printed | Checked against an outside party (yes/no) | Records after the last outside checkpoint (count) |
|---|---|---|---|---|
| Edit | | | | |
| Remove | | | | |
| Swap | | | | |
| Cut off | | | | |
| Rewrite and re-sign | | | | |

## 5. What a pass means, and its limits

A pass means each altered copy failed verification and the tool said where. Read each of these limits as part of that claim:

- **Records after the last outside checkpoint can be cut off or rewritten without detection.** A pass must state that count. The kit shows 0 only because it checkpoints on a clean shutdown. An agent that runs for a long time and never stops cleanly can have any number.
- A pass does not show that every action was recorded. An action the agent never logged leaves nothing to alter.
- A pass does not show that a record is true. It shows only that the record was not changed after it was signed.
- A checkpoint file handed over by the operator is not independent. Only a query to the outside party is. The kit's `--witness-file` checks use such a file. A real check queries the witness with `--witness <url>` and a pinned witness key.
- The kit's own results use a local stub witness (`stub.invalid`), not a real witness service.
- Any outside witness qualifies, not only Headless Oracle's.
- Headless Oracle's witness is run by Headless Oracle alone today. It is one outside party, not several.

## 6. Where the wording comes from

The AIUC-1 standard's control E015.4 (https://standard.aiuc-1.com/accountability/log-model-activity.md, as read on 9 November 2026) asks for logs that are "tamper-evident and independently verifiable", and for missing or reordered records to be detectable. This procedure is our own reading of that published text. AIUC, its auditors and its insurers have not reviewed, endorsed or required it.
