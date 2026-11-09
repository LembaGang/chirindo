# Purchase check examples

Seven runnable scripts, one for each provider format the purchase check maps:
a Crossmint order intent, a Basis Theory allowance, a Prava mandate, a Reap
mandate, a Skyfire PAY token, a Stripe Shared Payment Issued Token and a
Nevermined card delegation. The first three use the published
`@headlessoracle/chirindo` 0.6.0. The other four use mappers not yet in a
published release, so they run against this repository's own build
(`../../dist`). This folder is not part of the npm package.

The examples use each provider's public documentation as read on 2026-10-30; no provider has reviewed or endorsed them.

The Reap and Skyfire examples use each provider's public documentation as read on 2026-11-04; no provider has reviewed or endorsed them.

The Stripe and Nevermined examples use each provider's public documentation as read on 2026-11-09; no provider has reviewed or endorsed them.

Each script copies its provider's documented example verbatim, and names the
page and the time it was read. It maps the example with the package's mapper
and signs it with a throwaway Ed25519 key that is never written to disk. It
then checks three orders in a fresh temporary folder: one inside the
instruction, one over the cap, one at a different merchant (the Nevermined
script, whose object names no merchant, adds one past the expiry). It prints each
decision with its reasons and the result of `chirindo verify` on the chain,
then deletes the folder. The output holds no keys, hashes or times, so it is
the same on every run.

## Run

```
npm install
node crossmint-order-intent.mjs
node basis-theory-allowance.mjs
node prava-mandate.mjs

npm --prefix ../.. install
npm --prefix ../.. run build
node reap-mandate.mjs
node skyfire-pay-token.mjs
node stripe-shared-payment-token.mjs
node nevermined-card-delegation.mjs
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

## reap-mandate.mjs

The Reap mandate from the "Response" example of "Recurring Purchases": USD
150 per charge at `https://example.com`, monthly, up to 12 charges. Reap's page
says mandates are not available yet and their endpoints are not live, so this
runs on the documented shape only. The mandate states no end; the script
names one, 30 days from approval.

```
Reap mandate: USD max_total_minor 15000, merchants ["https://example.com"], max_uses 12
(a) inside the instruction: USD 14000 minor at https://example.com -> allow []
(b) over the cap: USD 16000 minor at https://example.com -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 5000 minor at https://other.example.net -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## skyfire-pay-token.mjs

The payload of Skyfire's "Example PAY Token": USD 15 for the seller agent
account in `aud`, up to 1600 requests, expiring 2026-03-18T21:00:54Z. That
time has passed, so the script runs the check on an injected clock inside the
token's window; on the real clock every order would be denied as expired. The
mapper reads the decoded payload and does not verify the token's signature.

```
Skyfire PAY token: USD max_total_minor 1500, merchants ["37888095-2721-48d9-a2df-bfe4075f223a"], max_uses 3
(a) inside the instruction: USD 1000 minor at 37888095-2721-48d9-a2df-bfe4075f223a -> allow []
(b) over the cap: USD 2000 minor at 37888095-2721-48d9-a2df-bfe4075f223a -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 500 minor at 00000000-0000-4000-8000-000000000000 -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## stripe-shared-payment-token.mjs

The example object of Stripe's "The Shared Payment Issued Token object": up to
1000 in the minor unit of USD (USD 10.00) captured in total, for the seller
platform in `seller_details.network_business_profile`, expiring
2025-07-04T00:00:20Z. Less what `usage_details` says is already captured (0
here), that is the cap. The merchant checked is the seller platform's profile
id: `seller_details.external_id`, the seller within that platform, is not
checked, so two sellers on one platform are one merchant here. The token's
expiry has passed, so the script runs the check on an injected clock inside
its window; on the real clock (run 2026-11-09) the same order is denied as
`expired`.

```
Stripe Shared Payment Issued Token: USD max_total_minor 1000, merchants ["profile_test_61TU90nIeGjU7NNVXA6TU90m7ISQWsBxpcx9lASWWXTk"], max_uses 3
(a) inside the instruction: USD 900 minor at profile_test_61TU90nIeGjU7NNVXA6TU90m7ISQWsBxpcx9lASWWXTk -> allow []
(b) over the cap: USD 1500 minor at profile_test_61TU90nIeGjU7NNVXA6TU90m7ISQWsBxpcx9lASWWXTk -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 500 minor at profile_test_OTHER -> deny ["limit-exceeded:merchants"]
receipts written: 3
chirindo verify: VALID, 3 entries
```

## nevermined-card-delegation.mjs

The "Stripe Delegation" request of Nevermined's "Delegations" page: USD
100.00 (10000 cents) over the delegation's lifetime, valid 604800 seconds (7
days) from its creation, up to 100 charges. The request carries no creation
time, so the script fixes one, 2026-11-09T00:00:00Z, and the instruction is
valid until 2026-11-16T00:00:00Z.

**The delegation names no merchant, so the check cannot refuse an order at
another merchant.** Case (c) shows one allowed. Only the amount, the expiry and
the number of uses are checked.

```
Nevermined card delegation: USD max_total_minor 10000, merchants none named, valid_until 2026-11-16T00:00:00Z, max_uses 3
(a) inside the instruction: USD 9000 minor at https://shop.example -> allow []
(b) over the cap: USD 12000 minor at https://shop.example -> deny ["limit-exceeded:max_total_minor"]
(c) at a different merchant: USD 500 minor at https://other.example.net -> allow []
(d) past the expiry: USD 500 minor at https://shop.example -> deny ["expired"]
receipts written: 4
chirindo verify: VALID, 4 entries
```

## What a decision shows

See the package README, section "Purchase check (before you charge)",
subsection "What it claims, and its limits".
