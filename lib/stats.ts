/** Median of a list; mean of the two middle values for even counts. Null for an empty list. */
export function median(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

export interface Worst<T> {
  value: number;
  item: T;
}

/** Item with the largest value; ties are broken by the first item in input order. */
export function worst<T>(items: readonly T[], value: (t: T) => number): Worst<T> | null {
  let best: Worst<T> | null = null;
  for (const item of items) {
    const v = value(item);
    if (best === null || v > best.value) best = { value: v, item };
  }
  return best;
}

export function formatDays(n: number | null): string {
  if (n === null) return "unknown";
  const rounded = Math.round(n * 10) / 10;
  const abs = Math.abs(rounded);
  return `${rounded} ${abs === 1 ? "day" : "days"}`;
}
