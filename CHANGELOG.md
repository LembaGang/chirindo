# Changelog

Published versions and their dates are listed on npm
(https://www.npmjs.com/package/@headlessoracle/chirindo?activeTab=versions).
Releases before 0.5.1 have no entry here; their notes are their commit
messages.

## Unreleased

- Corrects the 0.5.1 README and the 0.5.1 entry below, which say
  `gate_receipt` is the receipt's entry hash. It is not: `gate_receipt` (in
  the receipt's `gate` object) is the hash of the receipt computed while
  `gate_receipt` still held the placeholder `"self"`. The entry hash is
  `"sha256:" + hex(SHA-256(JCS(record without "sig")))`, the value the next
  record's `prev_hash` carries, and that computed value is what ordering
  evidence should carry. The README's field notes and "Showing a gate ran
  before an action" now say so; the 0.5.1 entry is left as published.
- New `examples/ordering-evidence/`: an ALLOW receipt and a DENY receipt,
  each with a checkpoint witnessed on production, a Base Sepolia payment
  whose EIP-3009 nonce is the ALLOW receipt's entry hash, and an offline
  checker (`check.mjs`, Node built-ins only) with one-byte failure tests.
  Not part of the npm package.

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
