# Purchase check examples

Three runnable scripts, one for each provider format the purchase check maps:
a Crossmint order intent, a Basis Theory allowance and a Prava mandate. Each
script uses the published `@headlessoracle/chirindo` 0.6.0. This folder is not
part of the npm package.

The examples use each provider's public documentation as read on 2026-10-30; no provider has reviewed or endorsed them.

Each script copies its provider's documented example verbatim, and names the
page and the time it was read. It maps the example with the package's mapper
and signs it with a throwaway Ed25519 key that is never written to disk. It
then checks three orders in a fresh temporary folder: one inside the
instruction, one over the cap, one at a different merchant. It prints each
decision with its reasons and the result of `chirindo verify` on the chain,
then deletes the folder. The output holds no keys, hashes or times, so it is
the same on every run.

## Run

```
npm install
node crossmint-order-intent.mjs
node basis-theory-allowance.mjs
node prava-mandate.mjs
```

Node 20 or later.

## crossmint-order-intent.mjs

The Crossmint order intent from "Create the Order Intent": USD 150.00 at
`https://acme.example.com`, expiring seven days from now. It becomes a signed
instruction that allows a purchase of up to 150.00 at that merchant, for two
uses (the script's choice; the order intent sets no count).

```
Crossmint order intent: USD max_total_minor 15000, merchants ["https://acme.example.com"], max_uses 2
(a) inside the instruction: USD 12000 minor at https://acme.example.com -> allow []
(b) over the cap: USD 18000 minor at https://acme.example.com -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 5000 minor at https://other.example.net -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## basis-theory-allowance.mjs

The Basis Theory allowance from "Create an Allowance": USD 100.00 at
`https://acme.example.com`, expiring 2030-07-08T00:00:00.000Z. After that
instant, every order in this script is denied as expired.

```
Basis Theory allowance: USD max_total_minor 10000, merchants ["https://acme.example.com"], max_uses 2
(a) inside the instruction: USD 8000 minor at https://acme.example.com -> allow []
(b) over the cap: USD 12000 minor at https://acme.example.com -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 5000 minor at https://other.example.net -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## prava-mandate.mjs

The Prava mandate from "Get a Mandate", USD 40.00 per charge, with the session
from the "Mandate setup" example of "Create Session". That session locks the
mandate to `https://acme.example.com` for up to 12 charges. The session names
no `effective_until_minutes`, so the instruction is valid for the mapper's
default of 15 minutes from approval.

```
Prava mandate: USD max_total_minor 4000, merchants ["https://acme.example.com"], max_uses 12
(a) inside the instruction: USD 3500 minor at https://acme.example.com -> allow []
(b) over the cap: USD 4500 minor at https://acme.example.com -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 2000 minor at https://other.example.net -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## What a decision shows

See the package README, section "Purchase check (before you charge)",
subsection "What it claims, and its limits".
