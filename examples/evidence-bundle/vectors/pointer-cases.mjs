// The Agent Evidence Pointer's cases (W3-05; spec section 3, "The Agent
// Evidence Pointer", and 4.2, P1.pointer and P2.entry): V-10's TEST bundle
// served by a fake fetch, which the library entry (lib/pointer.mjs) takes as a
// parameter, so no case reads the network. The fake answers as WHATWG fetch
// does, Node's and the browser's: redirects are returned when the caller asks
// for redirect "manual", and a content coding the response names is already
// removed from the body. Each case's `run(verifyPointer)` gives the library's
// result; the CLI's own cases (usage errors) are in test/pointer.mjs.

import { createHash } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import { entryHash } from "../lib/records.mjs";
import { bundleBytes } from "../lib/we1.mjs";
import { cardArgs, cardDoc, cardPins, T_AUTHORIZED, WE4_ORDER, WE4_ORDER_2, we4Instruction } from "./rows-a3.mjs";

export const URI = "https://evidence.test-merchant.example/orders/TEST-1001/bundle.json";
const sha = (b) => "sha256:" + createHash("sha256").update(b).digest("hex");

// V-10's bundle (WE-4 variant 1) and, for a bundle that cites another entry,
// V-11's (WE-4 variant 2, another order, so another cited record).
export function we4Bundle(order = WE4_ORDER) {
  const ins = we4Instruction();
  const doc = cardDoc({ args: cardArgs(order, ins), ins });
  const bytes = bundleBytes(doc);
  const log = Buffer.from(doc.members.find((m) => m.id === "log-d").bytes_b64, "base64").toString("utf8");
  return { doc, bytes, entry: entryHash(JSON.parse(log.split("\n")[0])), sha256: sha(bytes) };
}
// WE-4 variant 1's stated charge, as the library takes it (lib/cli.mjs's form).
export const STATED = { authorizer: null, tx: null, charge: { id: "TEST-ch-we4-1", amount_minor: "4800", currency: "USD", authorized_at: T_AUTHORIZED, merchant_order_id: "TEST-1001", checkout_ref: null } };

// A fake fetch over a table of URLs: each answer is { status, headers, body }
// or a function of the init that returns a promise. It records every call.
export function fakeFetch(table) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, init });
    const a = table[url];
    if (!a) throw new TypeError("fetch failed", { cause: { code: "ENOTFOUND" } });
    if (typeof a === "function") return a(init);
    const headers = new Headers(a.headers ?? {});
    // Fetch removes the content coding the response names (Fetch standard, "HTTP-network fetch").
    const body = headers.get("content-encoding") === "gzip" ? gunzipSync(a.body) : a.body;
    return new Response(a.status === 200 ? body : null, { status: a.status, headers });
  };
  f.calls = calls;
  return f;
}

const served = (bytes, headers) => ({ [URI]: { status: 200, headers, body: bytes } });
const redirects = (n, last) => {
  const t = {};
  for (let i = 0; i < n; i++) t[i === 0 ? URI : `${URI}?hop=${i}`] = { status: 302, headers: { location: i === n - 1 ? last : `${URI}?hop=${i + 1}` } };
  return t;
};
// A body above 67,108,864 bytes, streamed in chunks of one MiB, one buffer reused.
const bigBody = () => {
  const chunk = new Uint8Array(1 << 20);
  let n = 0;
  return new ReadableStream({
    pull(c) {
      if (n++ > 64) c.close();
      else c.enqueue(chunk);
    },
  });
};

// [id, what, the pointer, the fake's table (or a function giving it), options]
export const POINTER_CASES = [
  ["V-40", "the bundle served, the entry stated and no digest", (b) => ({ uri: URI, entry: b.entry, sha256: null }), (b) => served(b.bytes)],
  ["V-41", "with its digest stated, in upper-case hex", (b) => ({ uri: URI, entry: b.entry, sha256: "sha256:" + b.sha256.slice(7).toUpperCase() }), (b) => served(b.bytes)],
  ["V-42", "another digest stated", (b) => ({ uri: URI, entry: b.entry, sha256: sha(Buffer.from("TEST another bundle file")) }), (b) => served(b.bytes)],
  ["V-43", "a bundle that cites another entry (WE-4 variant 2's)", (b) => ({ uri: URI, entry: b.entry, sha256: null }), () => served(we4Bundle(WE4_ORDER_2).bytes)],
  ["V-44", "served with Content-Encoding gzip, its digest stated", (b) => ({ uri: URI, entry: b.entry, sha256: b.sha256 }), (b) => served(gzipSync(b.bytes), { "content-encoding": "gzip" })],
  ["V-45a", "a 404", (b) => ({ uri: URI, entry: b.entry, sha256: null }), () => ({ [URI]: { status: 404 } })],
  ["V-45b", "a redirect to http", (b) => ({ uri: URI, entry: b.entry, sha256: null }), () => redirects(1, "http://evidence.test-merchant.example/bundle.json")],
  ["V-45c", "six redirects", (b) => ({ uri: URI, entry: b.entry, sha256: null }), (b) => ({ ...redirects(6, `${URI}?final`), [`${URI}?final`]: { status: 200, body: b.bytes } })],
  ["V-45d", "a body above 67,108,864 bytes", (b) => ({ uri: URI, entry: b.entry, sha256: null }), () => ({ [URI]: () => Promise.resolve(new Response(bigBody(), { status: 200 })) })],
  // No answer: the fake waits for the abort; the timer fires at once and the case checks its delay.
  ["V-45e", "no answer within 60 s", (b) => ({ uri: URI, entry: b.entry, sha256: null }), () => ({ [URI]: (init) => new Promise((_, reject) => (init.signal.aborted ? reject(init.signal.reason) : init.signal.addEventListener("abort", () => reject(init.signal.reason)))) }), { timer: true }],
].map(([id, what, pointer, table, o = {}]) => ({
  id,
  what,
  async run(verifyPointer) {
    const b = we4Bundle();
    const fetch = fakeFetch(table(b));
    const delays = [];
    const setTimer = o.timer ? (fn, ms) => (delays.push(ms), setImmediate(fn)) : undefined;
    const clearTimer = o.timer ? (h) => clearImmediate(h) : undefined;
    const r = await verifyPointer(pointer(b), STATED, cardPins(), { fetch, setTimer, clearTimer });
    return { ...r, bundle: b, fetch, delays };
  },
}));
