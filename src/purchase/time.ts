// Times for the purchase check (B-432). Ports of examples/evidence-bundle:
// TIME_RE (lib/table.mjs), tsMs (lib/records.mjs), compareInstants and dateOk
// (lib/card.mjs). The package never imports examples/; the parity test
// (test/purchase-parity.test.ts) holds each port to its original.

// An instruction time as the verifier reads one: any number of fractional
// digits, Z only.
export const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// The gate clock's form, as the trial recorder's (src/trial/recorder.ts):
// at most nine fractional digits. Every ISO_UTC time is a TIME_RE time.
export const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

const isStr = (v: unknown): v is string => typeof v === "string";

// Milliseconds of a TIME_RE time, or null. Date.parse rolls a day or an hour
// that is out of range over (2026-02-30 reads as 2 March), and this keeps that
// reading, because M6 does.
export function tsMs(s: unknown): number | null {
  return isStr(s) && TIME_RE.test(s) && Number.isFinite(Date.parse(s)) ? Date.parse(s) : null;
}

// Spec D.1: two times compared as instants, by their text. The whole part is
// compared as a string, and the fractions at the precision both carry, the
// shorter read with trailing zeros. Never by Date milliseconds, which would
// lose the digits past the third. Returns -1, 0 or 1; throws on a non-time.
export function compareInstants(a: string, b: string): -1 | 0 | 1 {
  if (!TIME_RE.test(a) || !TIME_RE.test(b)) throw new Error("not a time");
  const split = (t: string): [string, string] => {
    const [whole, frac = ""] = t.slice(0, -1).split(".");
    return [whole!, frac];
  };
  const [wa, fa] = split(a);
  const [wb, fb] = split(b);
  if (wa !== wb) return wa < wb ? -1 : 1;
  const n = Math.max(fa.length, fb.length);
  const pa = fa.padEnd(n, "0");
  const pb = fb.padEnd(n, "0");
  return pa === pb ? 0 : pa < pb ? -1 : 1;
}

// D9: a TIME_RE time whose date and time fields, rebuilt as an instant, give
// back the same fields. 2026-02-30, hour 24 and second 60 are not calendar
// instants; TIME_RE and tsMs alone accept the first two.
export function isCalendarInstant(s: unknown): boolean {
  if (!isStr(s) || !TIME_RE.test(s)) return false;
  const d = new Date(s);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 19) === s.slice(0, 19);
}

// A date YYYY-MM-DD that names a calendar day.
export function dateOk(s: unknown): boolean {
  if (!isStr(s) || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
