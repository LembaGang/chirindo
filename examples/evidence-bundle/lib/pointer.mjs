// The Agent Evidence Pointer (spec section 3 and 4.2, P1.pointer; D.1; D.4):
// the fetch of the bundle a merchant's order names, and the library entry that
// reads a bundle through it. The fetch function is a parameter, called as
// WHATWG fetch is: the CLI passes Node's fetch, the tests a fake. Redirects
// are followed here, not by fetch, so that each hop is checked.

import { createHash } from "node:crypto";
import { built } from "./built.mjs";
import { verifyBundle } from "./verify.mjs";

export const MAX_REDIRECTS = 5;
export const MAX_BYTES = 67108864;
export const TIMEOUT_MS = 60000;
const REDIRECTS = [301, 302, 303, 307, 308];

// One GET of the URI with no cookies, no credentials and no header the person
// did not choose; at most 5 redirects, each to https; a final status of 200,
// a body of at most 67,108,864 bytes, all within 60 s. The digest is over the
// body after fetch has removed any content coding the response names.
// Returns the output's `pointer` members, with the bytes (null unless fetched).
built("P1.pointer");
export async function fetchPointer({ uri, entry, sha256 }, fetchFn, { setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  const out = { uri, stated_entry: entry.toLowerCase(), stated_sha256: sha256 ? sha256.toLowerCase() : null, fetched_sha256: null, status: "unfetchable", detail: "", bytes: null };
  const unfetchable = (why) => Object.assign(out, { detail: `the bundle could not be fetched: ${why}` });
  const ac = new AbortController();
  const timer = setTimer(() => ac.abort(new Error("timeout")), TIMEOUT_MS);
  try {
    let url = uri;
    let res;
    for (let hop = 0; ; hop++) {
      res = await fetchFn(url, { method: "GET", redirect: "manual", credentials: "omit", signal: ac.signal });
      if (!REDIRECTS.includes(res.status)) break;
      const loc = res.headers.get("location");
      if (!loc) return unfetchable(`status ${res.status} with no Location header`);
      let next;
      try {
        next = new URL(loc, url);
      } catch {
        return unfetchable(`a redirect to ${JSON.stringify(loc)}, which is not a URL`);
      }
      if (next.protocol !== "https:") return unfetchable(`a redirect to ${next.href}, which is not https`);
      if (hop + 1 > MAX_REDIRECTS) return unfetchable(`a redirect beyond the ${MAX_REDIRECTS} the pointer follows`);
      url = next.href;
    }
    if (res.status !== 200) return unfetchable(`the final status is ${res.status}, not 200`);
    const chunks = [];
    let n = 0;
    if (res.body) {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.byteLength;
        if (n > MAX_BYTES) {
          await reader.cancel().catch(() => {});
          return unfetchable("the body exceeds 67,108,864 bytes");
        }
        // A view, not a copy: the bytes are concatenated once, at the end.
        chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      }
    }
    const bytes = Buffer.concat(chunks);
    const digest = "sha256:" + createHash("sha256").update(bytes).digest("hex");
    Object.assign(out, { bytes, fetched_sha256: digest });
    if (out.stated_sha256 === null) return Object.assign(out, { status: "fetched", detail: `${bytes.length} bytes fetched from ${url}; no digest was stated` });
    if (out.stated_sha256 === digest) return Object.assign(out, { status: "match", detail: `${bytes.length} bytes fetched from ${url}, of the stated digest` });
    return Object.assign(out, { status: "mismatch", detail: `the bytes fetched from ${url} have the digest ${digest}, not the stated ${out.stated_sha256}: they are not the bundle the order names` });
  } catch (e) {
    if (ac.signal.aborted) return unfetchable("no answer within 60 s");
    return unfetchable(e?.cause?.code ? `${e.message} (${e.cause.code})` : String(e?.message ?? e));
  } finally {
    clearTimer(timer);
  }
}

// The library entry with the pointer in place of a bundle's bytes: the fetch,
// then the verifier on what it fetched (spec 4.2: when P1.pointer does not
// pass, nothing else runs).
export async function verifyPointer(pointer, stated, pins, { fetch: fetchFn, setTimer, clearTimer } = {}) {
  const f = await fetchPointer(pointer, fetchFn, { setTimer, clearTimer });
  return verifyBundle(f.bytes, stated, pins, { pointer: f });
}
