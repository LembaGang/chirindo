# Purchase check reasons: `purchase-check/0.1`

Every reason the Chirindo purchase check gives, in `CheckResult.reasons` and in a receipt's `check.reasons`, matches exactly one pattern below. This list is frozen under the version in `check.v`, `purchase-check/0.1`. A change to a pattern, or to any word list here, is a new `check.v`.

The same list is exported as `PURCHASE_REASON_PATTERNS` (`src/purchase/reasons.ts`), and `test/purchase-vocabulary.test.ts` holds this file to it.

## How a reason is read

A reason is a prefix and, for most patterns, a suffix. The suffix is one of:

- **none**: the prefix is the whole reason.
- **word**: one word from the list given.
- **card-limit**: one of the nine Annex A.3 card limits, `currency`, `max_total_minor`, `max_unit_price_minor`, `merchants`, `items`, `categories`, `refundable_only`, `service_window`, `locations`.
- **json-pointer**: a JSON Pointer to the member at fault, e.g. `/order/items/0/name` or `/constraints/max_uses`.
  - Each segment is a member name of `[A-Za-z0-9_-]{1,64}` or an array index.
  - Any other member name is written `~invalid-key`, so a pointer never carries the caller's text.
  - A pointer is cut at 128 characters.

## Steps and receipts

- **Step 1** reasons refuse the input. No receipt is written, and `receipt` is null.
- **Steps 2, 2b and 3** reasons are decisions. Each is a signed deny receipt, written before the answer.
- **`record-failed`** means no receipt could be written, so the answer is deny. On a deny it follows the decision's own reasons. On what would have been an allow it stands alone.
- Step 1 reasons stand alone, and so do step 2 reasons (step 2 includes 2b). Step 3 lists every failure, in the order of the table.

| Prefix | Suffix | Step | Meaning |
|---|---|---|---|
| `instruction-invalid:` | word: `not-a-string`, `too-large`, `syntax`, `bom`, `lone-surrogate`, `duplicate-member`, `non-integer-number`, `nesting-too-deep`, `unsafe-integer`, `not-an-object`, `wrong-profile`, `kid-not-thumbprint`, `card-missing`, `card-limits-empty`, `window-reversed`, `time-not-z`, `time-not-calendar`, `bad-signature`, `not-canonical` | 1 or 2 | See "Instruction problems" below. |
| `instruction-invalid:not-an-object:` | json-pointer | 2 | A member that must be an object is not one. |
| `instruction-invalid:missing-member:` | json-pointer | 2 | A member the profile requires is absent. |
| `instruction-invalid:extra-member:` | json-pointer | 2 | A member the profile does not name. |
| `instruction-invalid:bad-value:` | json-pointer | 2 | A member's value has the wrong type or form. |
| `order-invalid:` | json-pointer | 1 | Any of: the order is not the committed order of spec 4.3; a value is not plain JSON; a string is not well formed; or an item's name, location or category holds card-number-like or e-mail-like text. |
| `unsupported-limit:` | word: `chain_id`, `asset`, `max_amount`, `payees`, `budget` | 2 | The instruction sets a limit outside v0.1, which checks card limits only. |
| `order-ref-reused` | none | 2b | An earlier allow on this instruction has the same merchant and order references, with a different order. |
| `not-yet-valid` | none | 3 | The check's time is before `valid_from`. |
| `expired` | none | 3 | The check's time is after `valid_until`. |
| `agent-not-named` | none | 3 | The gate's kid is not in `agent_kid`. |
| `uses-exhausted` | none | 3 | This purchase would exceed `max_uses` (1 when absent). |
| `limit-exceeded:` | card-limit | 3 | The order is outside that card limit. |
| `order-field-missing:` | card-limit | 3 | The instruction sets that limit, and an item lacks the field it is judged on. |
| `record-failed` | none | 5 | No receipt could be written, or the gate clock failed: the answer is deny. |

## Instruction problems

The words of `instruction-invalid:` fall into two groups.

**Step 1: the text does not read.** No receipt is written.

| Word | Meaning |
|---|---|
| `not-a-string` | The instruction is not passed as JSON text. |
| `too-large` | The text is over 64 KB. |
| `syntax` | The text is not JSON. |
| `bom` | The text starts with a byte order mark. |
| `lone-surrogate` | A string holds a lone surrogate. |
| `duplicate-member` | An object names a member twice. |
| `non-integer-number` | A number has a fraction or an exponent. |
| `nesting-too-deep` | Nesting is deeper than 64. |
| `unsafe-integer` | An integer is outside the safe range. |

**Step 2: the instruction is not a valid Annex A.3 card-only instruction.** A deny receipt is written.

| Word | Meaning |
|---|---|
| `not-an-object` | The instruction is not a JSON object. |
| `wrong-profile` | `v` is not `signed-instruction-ed25519/0.3`. |
| `kid-not-thumbprint` | `principal.kid` is not its key's thumbprint. |
| `card-missing` | There is no `constraints.card`. |
| `card-limits-empty` | The card limits nothing beyond `currency`. |
| `window-reversed` | `valid_from` is after `valid_until`. |
| `time-not-z` | A time is not an instant ending in `Z`. |
| `time-not-calendar` | A time ends in `Z` but names no calendar instant, e.g. 30 February, hour 24 or second 60. |
| `bad-signature` | `sig` does not verify. |
| `not-canonical` | The instruction has no RFC 8785 form. |
