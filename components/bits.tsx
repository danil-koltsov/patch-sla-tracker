import type { ReactNode } from "react";
import { formatDays } from "../lib/stats.ts";

export function Def({ term, children }: { term: string; children: ReactNode }) {
  return (
    <p className="def">
      <dfn>{term}</dfn>: {children}
    </p>
  );
}

export function Days({ n }: { n: number | null }) {
  return <>{formatDays(n)}</>;
}

export function CveLink({ id }: { id: string }) {
  return <a href={`/cve/${id}`}>{id}</a>;
}

export function Unknown() {
  return <span className="muted">unknown</span>;
}

export function DateOrUnknown({ d }: { d: string | null }) {
  return d ? <time dateTime={d}>{d}</time> : <Unknown />;
}

/** Scrollable table container that keyboard users can scroll (WCAG 2.1.1). */
export function TableScroll({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="table-scroll" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}

export function Exports({ base, label }: { base: string; label: string }) {
  return (
    <p className="exports">
      Export {label}: <a href={`${base}/data.csv`}>CSV</a> · <a href={`${base}/data.json`}>JSON</a> · Permalink:{" "}
      <a href={base}>{base}</a>
    </p>
  );
}

export function DataError({ error }: { error: unknown }) {
  return (
    <p role="alert">
      Data is currently unavailable ({error instanceof Error ? error.message : "unknown error"}). No numbers are shown rather than stale or
      guessed ones.
    </p>
  );
}

/** "+3 days after" / "5 days before" / "same day" for signed day differences. */
export function relative(n: number, after: string, before: string): string {
  if (n === 0) return "same day";
  const a = Math.abs(n);
  return `${a} ${a === 1 ? "day" : "days"} ${n > 0 ? after : before}`;
}
