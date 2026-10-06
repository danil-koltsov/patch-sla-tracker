const DAY_MS = 86_400_000;

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function isIsoDate(s: string): boolean {
  if (!ISO_DATE.test(s)) return false;
  const t = Date.parse(`${s}T00:00:00Z`);
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 10) === s; // rejects 2024-02-31
}

/** Whole days from `from` to `to` (both "YYYY-MM-DD", UTC). Positive when `to` is later. */
export function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
}

export function minDate(dates: readonly string[]): string | null {
  let m: string | null = null;
  for (const d of dates) if (m === null || d < m) m = d;
  return m;
}

export function maxDate(dates: readonly string[]): string | null {
  let m: string | null = null;
  for (const d of dates) if (m === null || d > m) m = d;
  return m;
}

const MONTHS: Record<string, number> = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
};

/** Parses "March 5, 2024", "5 Mar 2024", "05 Mar 2024". Returns null when it cannot. */
export function parseEnglishDate(text: string): string | null {
  const t = text.trim().replace(/ /g, " ");
  let m = /^([A-Za-z]+)\.?\s+(\d{1,2}),\s*(\d{4})$/.exec(t);
  let y: number, mo: number | undefined, d: number;
  if (m) {
    mo = MONTHS[m[1]!.slice(0, 3).toLowerCase()];
    d = Number(m[2]);
    y = Number(m[3]);
  } else {
    m = /^(\d{1,2})\s+([A-Za-z]+)\.?\s+(\d{4})$/.exec(t);
    if (!m) return null;
    d = Number(m[1]);
    mo = MONTHS[m[2]!.slice(0, 3).toLowerCase()];
    y = Number(m[3]);
  }
  if (!mo) return null;
  const iso = `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  return isIsoDate(iso) ? iso : null;
}

/** "2026-10-06 14:03 UTC" */
export function formatUtcTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}
