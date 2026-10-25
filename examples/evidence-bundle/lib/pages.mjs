// The page-ready JSON of a card worked example (pages/<id>.json), which the
// site's example pages read: the example's stated limit, the bundle file with
// its sha256 and size, the stated inputs and the pins named, the offline
// verdict, its data-point export, its exhibit (US Letter) and, once the live
// witness step has run, the online verdict. Every value is the verifier's or
// a view's output for the bundle beside it; a page never states an online
// verdict it did not get from its own bundle.

import { createHash } from "node:crypto";
import { built } from "./built.mjs";
import { datapointsOf } from "./datapoints.mjs";

// The examples' stated limits, spec section 7: WE-4's (line 926), and WE-5's
// own sentence after "as WE-4's" (line 943).
export const PAGE_LIMITS = {
  "we-4": "in WE-4, Headless Oracle is the gate's operator (it runs the gate and holds the operator key) and the witness, and the customer, the merchant and the charge are test parties the example makes. The example demonstrates the format and the checks, not independence between those parties (L14, L3). The card data is test data only: no card number, expiry, security code, network token or last four digits appears in the bundle, in the stated inputs, on the page or on the exhibit, because B-CARD reads none of them; the charge id and every merchant and item value are labelled test values (`TEST`, and the domain `test-merchant.example`, under the `.example` name reserved for examples).",
  "we-5": "Headless Oracle is the gate's operator and the witness; the traveller, the hotel and the charge are test parties; test card data only.",
};

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

built("pages.json");
// A page's members in their order. `online`, when given, is { verdict,
// reason }: the online verdict JSON, or null with the reason the live step
// stopped.
export function pageOf({ id, bundle, stated, verdictBytes, exhibit, online }) {
  const page = {
    id,
    limit: PAGE_LIMITS[id.slice(0, 4)],
    bundle: { path: bundle.path, sha256: sha256(bundle.bytes), size: bundle.bytes.length },
    stated,
    offline_verdict: JSON.parse(verdictBytes.toString("utf8")),
    datapoints: datapointsOf(verdictBytes),
    exhibit: { page: "letter", path: exhibit.path, sha256: sha256(exhibit.bytes), size: exhibit.bytes.length },
  };
  if (online !== undefined) page.online = online;
  return page;
}
