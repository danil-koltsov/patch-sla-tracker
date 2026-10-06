import { daysBetween } from "../lib/dates.ts";
import type { CveTimeline } from "../lib/metrics.ts";

/** Fix date per branch on a shared date axis, with KEV and NVD dates as reference lines. */
export function CveTimelineSvg({ t }: { t: CveTimeline }) {
  const rows = t.platforms.flatMap((p) =>
    p.outcomes
      .filter((o) => o.status.kind === "fixed" || o.status.kind === "later-major")
      .map((o) => ({ label: o.branch.name, date: (o.status as { fixDate: string }).fixDate, later: o.status.kind === "later-major" })),
  );
  if (rows.length === 0) return null;

  const refs = [
    t.cve.kevDateAdded ? { label: "KEV added", date: t.cve.kevDateAdded, dash: "4 3" } : null,
    t.cve.nvdPublished ? { label: "NVD published", date: t.cve.nvdPublished, dash: "1 3" } : null,
  ].filter((r): r is { label: string; date: string; dash: string } => r !== null);

  const all = [...rows.map((r) => r.date), ...refs.map((r) => r.date)].sort();
  const start = all[0]!;
  const end = all.at(-1)!;
  const span = Math.max(daysBetween(start, end), 1);
  const left = 140;
  const width = 640;
  const plot = width - left - 30;
  const rowH = 24;
  const top = 34;
  const height = top + rows.length * rowH + 28;
  const x = (d: string) => left + (daysBetween(start, d) / span) * plot;

  const desc = [
    ...rows.map((r) => `${r.label} fixed on ${r.date} (${daysBetween(t.firstFixDate, r.date)} days after first fix${r.later ? ", branch released later" : ""})`),
    ...refs.map((r) => `${r.label} on ${r.date}`),
  ].join("; ");

  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-labelledby="tl-t tl-d">
        <title id="tl-t">{`${t.id} timeline across branches`}</title>
        <desc id="tl-d">{desc}</desc>
        {refs.map((r, i) => (
          <g key={r.label}>
            <line x1={x(r.date)} x2={x(r.date)} y1={top - 6} y2={top + rows.length * rowH} stroke="#000" strokeWidth="1" strokeDasharray={r.dash} />
            <text x={x(r.date)} y={12 + i * 12} textAnchor={x(r.date) > width - 120 ? "end" : "start"}>
              {r.label} {r.date}
            </text>
          </g>
        ))}
        {rows.map((r, i) => {
          const cy = top + i * rowH + rowH / 2;
          return (
            <g key={`${r.label}-${i}`}>
              <text x={0} y={cy + 4}>
                {r.label}
              </text>
              <line x1={x(start)} x2={x(r.date)} y1={cy} y2={cy} stroke="#8a8a8a" strokeWidth="1" />
              <circle cx={x(r.date)} cy={cy} r={4.5} fill={r.later ? "#fff" : "#000"} stroke="#000" strokeWidth="1.5" />
            </g>
          );
        })}
        <text x={left} y={height - 4}>
          {start}
        </text>
        <text x={left + plot} y={height - 4} textAnchor="end">
          {end}
        </text>
      </svg>
      <figcaption>Filled circle: first fix on that branch. Hollow circle: branch released after the earliest fix (not a backport).</figcaption>
    </figure>
  );
}
