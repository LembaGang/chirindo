// The online reads of a card subject (spec 4.2 and 4.3; `--online`): the
// witness's own list of receipts for the cited log (O1.witness-list), the
// witness key list when a receipt names a key id the pins lack
// (O6.witness-keys), and the jwks_uri the records name (O3.jwks). GET only;
// the fetch function is a parameter (the command line passes Node's, the
// tests a fake), so this file makes no request of its own. Each read
// returns what it got, or why it did not complete; B-WIT and B-KEY judge
// what was read (lib/verify.mjs).

import { isPlainObject } from "../../ordering-evidence-h4/lib/formats.mjs";

// As chirindo's own witness client does (src/witness.ts): 10 s for each
// request, no redirect followed, at most 10,000 pages, and a next_after of
// the served form.
export const WITNESS_TIMEOUT_MS = 10_000;
export const MAX_WITNESS_PAGES = 10_000;
const NEXT_AFTER = /^\d+:sha256:[0-9a-f]{64}$/;
// The JWKS read (B-KEY, 4.3): https, port 443, at most one same-origin redirect.
export const JWKS_TIMEOUT_MS = 10_000;
const MAX_BODY = 1_048_576;

// The registrable domain an endpoint counts under: the last two labels of its
// host (the hosts this build reads are headlessoracle.com's and a jwks_uri's).
export const registrableDomain = (url) => new URL(url).hostname.split(".").slice(-2).join(".");

// One GET: the status and the body as text, or the reason it failed.
async function get(fetchFn, url, { timeoutMs, redirect, timers }) {
  const controller = new AbortController();
  const set = timers?.setTimer ?? setTimeout;
  const clear = timers?.clearTimer ?? clearTimeout;
  const timer = set(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, { method: "GET", redirect, headers: { accept: "application/json" }, signal: controller.signal });
    if (redirect === "manual" && res.status >= 300 && res.status < 400) return { status: res.status, location: res.headers.get("location"), text: null };
    const text = await res.text();
    if (text.length > MAX_BODY) return { error: `the body exceeds ${MAX_BODY} bytes` };
    return { status: res.status, text };
  } catch (e) {
    return { error: controller.signal.aborted ? `no answer within ${timeoutMs / 1000} s` : `the request failed (${e?.cause?.message ?? e?.message ?? String(e)})` };
  } finally {
    clear(timer);
  }
}
const parse = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

// O1.witness-list: every receipt the witness lists for (kid, session_id),
// read to its end, or why the read is incomplete. The query uses the log's
// kid and session_id, never a receipt's.
export async function readWitnessList(fetchFn, base, kid, sessionId, timers) {
  const receipts = [];
  let after;
  let url;
  for (let page = 0; page < MAX_WITNESS_PAGES; page++) {
    const q = new URLSearchParams({ kid, session_id: sessionId });
    if (after !== undefined) q.set("after", after);
    url = `${base}/v1/witness/checkpoints?${q.toString()}`;
    const r = await get(fetchFn, url, { timeoutMs: WITNESS_TIMEOUT_MS, redirect: "error", timers });
    if (r.error) return { ok: false, receipts, reason: `GET ${url}: ${r.error}`, answered: page > 0 };
    if (r.status !== 200) return { ok: false, receipts, reason: `GET ${url}: the status is ${r.status}, not 200`, answered: true };
    const b = parse(r.text);
    if (!isPlainObject(b) || !Array.isArray(b.receipts)) return { ok: false, receipts, reason: `GET ${url}: the answer is not an object with a receipts list`, answered: true };
    receipts.push(...b.receipts);
    if (!Object.keys(b).includes("next_after")) return { ok: true, receipts, reason: null, answered: true, pages: page + 1 };
    if (typeof b.next_after !== "string" || !NEXT_AFTER.test(b.next_after) || b.next_after === after) return { ok: false, receipts, reason: `GET ${url}: a malformed next_after`, answered: true };
    after = b.next_after;
  }
  return { ok: false, receipts, reason: `more than ${MAX_WITNESS_PAGES} pages of receipts`, answered: true };
}

// O6.witness-keys: the witness's key list (GET /v5/keys), as the
// witness-key members carry it.
export async function readWitnessKeys(fetchFn, base, timers) {
  const url = `${base}/v5/keys`;
  const r = await get(fetchFn, url, { timeoutMs: WITNESS_TIMEOUT_MS, redirect: "error", timers });
  if (r.error) return { ok: false, value: null, reason: `GET ${url}: ${r.error}`, answered: false };
  if (r.status !== 200) return { ok: false, value: null, reason: `GET ${url}: the status is ${r.status}, not 200`, answered: true };
  const v = parse(r.text);
  if (!isPlainObject(v)) return { ok: false, value: null, reason: `GET ${url}: the answer is not a JSON object`, answered: true };
  return { ok: true, value: v, reason: null, answered: true };
}

// O3.jwks: the jwks_uri's JWKS, read with https on port 443 and at most one
// redirect to the same origin, as chirindo's fetcher does.
export async function readJwks(fetchFn, uri, timers) {
  const okUrl = (u) => u.protocol === "https:" && (u.port === "" || u.port === "443");
  let url = new URL(uri);
  if (!okUrl(url)) return { ok: false, value: null, reason: `${uri} is not https on port 443`, answered: false };
  for (let hop = 0; hop <= 1; hop++) {
    const r = await get(fetchFn, url.href, { timeoutMs: JWKS_TIMEOUT_MS, redirect: "manual", timers });
    if (r.error) return { ok: false, value: null, reason: `GET ${url.href}: ${r.error}`, answered: false };
    if (r.status >= 300 && r.status < 400) {
      let next;
      try {
        next = new URL(r.location ?? "", url);
      } catch {
        return { ok: false, value: null, reason: `GET ${url.href}: a redirect without a usable location`, answered: true };
      }
      if (hop === 1) return { ok: false, value: null, reason: `GET ${url.href}: a second redirect`, answered: true };
      if (next.origin !== url.origin || !okUrl(next)) return { ok: false, value: null, reason: `GET ${url.href}: a redirect to ${next.origin}, not the same origin`, answered: true };
      url = next;
      continue;
    }
    if (r.status !== 200) return { ok: false, value: null, reason: `GET ${url.href}: the status is ${r.status}, not 200`, answered: true };
    const v = parse(r.text);
    if (!isPlainObject(v) || !Array.isArray(v.keys)) return { ok: false, value: null, reason: `GET ${url.href}: the answer is not a JWKS`, answered: true };
    return { ok: true, value: v, reason: null, answered: true };
  }
  return { ok: false, value: null, reason: "unreachable", answered: false };
}
