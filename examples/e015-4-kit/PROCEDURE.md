# The five-alteration test for agent logs

## 1. What this is

This is a test for any tool that keeps a log of an AI agent's actions and has a command that verifies the log. It shows whether that verification catches five specific alterations of one log. It does not show that the tool is tamper-evident in general.

You take one log and make six copies: one left untouched and five altered, each in a different way. You run the tool's own verification on every copy and record what it catches and what it misses.

Headless Oracle wrote this test. Headless Oracle also makes Chirindo, the tool tested in section 3, and runs a witness service. Run the test yourself; do not take our results on trust.

## 2. The five alterations

"Detected" means the tool's own verification fails and says where the problem is. A silent pass is not detection. Neither is a failure that names no record and no checkpoint.

| Alteration | What you do | What can detect it |
|---|---|---|
| Edit | Change one field in one record. Do not re-sign it. | A signature and hash chain over the records, even one whose key the operator holds. |
| Remove | Delete one record from the middle. | The same. |
| Swap | Swap two neighbouring records. | The same. |
| Cut off | Delete the last two records. | Something outside the log that fixes where it ends: a checkpoint held by someone other than the operator, or a count or copy the tester already holds. The records that remain are still a valid chain. |
| Rewrite and re-sign | Change a record, then re-sign and re-link the whole log with the operator's own key. | A checkpoint or copy held by someone other than the operator, and only for history up to when it was taken. The operator's key makes every signature valid again. |

The first three can be made by anyone who can write to the file. In a tool with a signed hash chain they are caught without any outside party, because without the key the signatures cannot be repaired. Cutting off the tail needs no key either. Rewriting and re-signing needs the operator's key.

An outside party here means someone other than the operator and other than anyone who can change the log: for example a witness service, a public transparency log or a timestamp authority.

## 3. Run it on a Chirindo log

You need git, Node 20 or later and npm. Clone https://github.com/LembaGang/chirindo and run these two commands from the repository root. `npm ci` installs exactly what the lockfile names. It does not change the lockfile, and it replaces any `node_modules` folder already there.

```
npm ci
npx tsx examples/e015-4-kit/run.mjs
```

The second command makes a short session of seven tool calls. A local stub witness checkpoints the log at counts 2, 4, 6 and 7. The command then writes the six copies into `examples/e015-4-kit/work/copies`, verifies each one twice, and prints:

```
all 12 outcomes match the expected table; wrote <repository>/examples/e015-4-kit/RESULTS.md
```

On the author's Windows laptop that command took about 17 seconds, not counting `npm ci`.

To run a check yourself, use these two commands once the command above has created the `work` folder. Replace COPY with one of `intact`, `edited`, `deleted`, `reordered`, `truncated` or `resigned`. The first command checks the chain alone. The second also checks it against the witness checkpoints.

```
npx tsx src/cli.ts verify examples/e015-4-kit/work/copies/COPY.jsonl --key examples/e015-4-kit/work/gate/identity.json
```

```
npx tsx src/cli.ts verify examples/e015-4-kit/work/copies/COPY.jsonl --key examples/e015-4-kit/work/gate/identity.json --witness-file examples/e015-4-kit/work/gate/sessions/e015-4-kit-0001.jsonl.witness.ndjson --witness-key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394 --witness-name stub.invalid
```

The first line of output is the verdict. To see the exit code, run `echo $?` in bash or zsh, or `$LASTEXITCODE` in PowerShell, straight after the command. Below, each line after a `#` label is the verdict line exactly as the tool prints it:

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

A VALID line is followed by a line naming the key it was verified under and the path you gave. The intact copy, checked with witness checkpoints, also prints how many records come after the last witnessed checkpoint:

```
WITNESSED through count 7, received_at 2026-10-03T00:00:03.000Z, witness key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
0 records after the last witnessed checkpoint are not witness-protected (sidecar supplied by the operator)
```

The full output for all twelve checks is in [RESULTS.md](RESULTS.md).

**How this run scores on the table in section 4.** Edit, Remove and Swap are detected by the chain alone. Cut off and Rewrite and re-sign pass the chain alone as VALID. They are detected only with the witness checkpoints. In this kit those checkpoints come from a local stub witness and are read from a file the operator supplies, which section 4 does not count as an outside party. So for this run the outside-party column reads "no" on every row. The kit shows what the verifier does with checkpoints. It is not an independent check. By the definition in section 5, this run is therefore not a pass.

## 4. Run it on any other tool's log

This test alters copies of a log, so it tests the tool's verification. It does not test whether the tool's storage would have let the original be altered.

1. Export one session log of at least five records with the tool's own export.
2. Make the five altered copies as section 2 describes, using a text editor or a short script. For "rewrite and re-sign", use the operator's own signing key and the tool's own way of writing records.
3. Run the tool's own verification command on the untouched log. It must pass. If it does not, stop: the test has no baseline.
4. Run the same command on each altered copy. Copy the first lines it prints and the exit code.
5. Note whether that command asked an outside party, as section 2 defines one. A file the operator handed you does not count.
6. Write down how many records come after the last outside checkpoint. If the tool gives you no way to read that count, write "not reported by the tool".

If you cannot make an alteration, because the storage refuses it or because the vendor holds the signing key and the operator does not, write "not testable" in the Detected column. Say why, and say which account could make the change. Do not score it yes or no.

| Alteration | Detected (yes, no or not testable) | What the tool printed | Exit code | Checked against an outside party (yes/no) | Records after the last outside checkpoint (count) |
|---|---|---|---|---|---|
| Edit | | | | | |
| Remove | | | | | |
| Swap | | | | | |
| Cut off | | | | | |
| Rewrite and re-sign | | | | | |

## 5. What a pass means, and its limits

A pass means each of the five altered copies failed verification, the tool said where, and for the last two the check was made against an outside party. If any row is marked not testable, no pass can be claimed for the test as a whole. Read each of these limits as part of that claim:

- **Records after the last outside checkpoint can be cut off or rewritten without detection.** A pass must state that count. The kit shows 0 because it writes a final checkpoint before it verifies. An agent that stops without a final checkpoint leaves a tail of records after its last one.
- A pass does not show that every action was recorded. An action the agent never logged leaves nothing to alter.
- A pass does not show that a record is true. It shows only that the record was not changed after it was signed.
- A checkpoint file handed over by the operator is not independent. Only a query to the outside party is. The kit's `--witness-file` checks use such a file. A check against a live witness uses `--witness` with the witness's address and `--witness-key` with its public key. Without `--witness-key` the tool says the witness key is not pinned.
- The kit's own results use a local stub witness (`stub.invalid`), not a witness service.
- Any outside witness qualifies, not only Headless Oracle's.
- Headless Oracle's witness is run by Headless Oracle alone today. It is one outside party, not several. When the operator being tested is Headless Oracle itself, that witness is not an outside party.

## 6. Where the wording comes from

The AIUC-1 standard's control E015, "Log AI system activity" (https://standard.aiuc-1.com/accountability/log-model-activity.md, as read on 9 and 11 November 2026), lists among the things an implementation may include technical controls to ensure logs are "tamper-evident and independently verifiable", with sequence integrity so that gaps, omissions and reordering can be detected. E015 itself is mandatory. The standard lists E015.4, log integrity protection, among the things an implementation may include. This procedure tests the detection part only. It is our own reading of that published text. It is not an AIUC document. We are not aware that AIUC, its auditors or its insurers have endorsed or required it.
