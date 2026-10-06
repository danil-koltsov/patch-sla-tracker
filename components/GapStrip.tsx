import type { BackportSummary, CveTimeline } from "../lib/metrics.ts";
import { formatDays } from "../lib/stats.ts";

/**
 * One row per branch; one tick per CVE at its backport gap. Static SVG, no JS.
 * The table next to it carries the same numbers for screen readers; this figure has its own summary.
 */
export function GapStrip({ summary, timelines }: { summary: BackportSummary; timelines: CveTimeline[] }) {
  const rows = summary.rows
    .map((r) => {
      const gaps: { days: number; cveId: string }[] = [];
      for (const t of timelines) {
        if (!t.inWindow || (summary.scope === "exploited" && !t.exploited)) continue;
        const p = t.platforms.find((x) => x.platform === summary.platform);
        const o = p?.outcomes.find((x) => x.branch.id === r.branch.id);
        if (o?.status.kind === "fixed") gaps.push({ days: o.status.gapDays, cveId: t.id });
      }
      return { name: r.branch.name, gaps };
    })
    .filter((r) => r.gaps.length > 0);
  if (rows.length === 0) return null;

  const max = Math.max(30, ...rows.flatMap((r) => r.gaps.map((g) => g.days)));
  const niceMax = Math.ceil(max / 30) * 30;
  const left = 120;
  const width = 640;
  const plot = width - left - 20;
  const rowH = 26;
  const top = 10;
  const height = top + rows.length * rowH + 30;
  const x = (d: number) => left + (d / niceMax) * plot;
  const ticks = Array.from({ length: 5 }, (_, i) => Math.round((niceMax / 4) * i));
  const id = `gap-${summary.platform}`;
  const desc = rows
    .map((r) => {
      const sorted = r.gaps.map((g) => g.days).sort((a, b) => a - b);
      return `${r.name}: ${r.gaps.length} fixes, from ${formatDays(sorted[0]!)} to ${formatDays(sorted.at(-1)!)}`;
    })
    .join("; ");

  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-labelledby={`${id}-t ${id}-d`}>
        <title id={`${id}-t`}>{`${summary.platform} backport gaps per branch, in days after the earliest fix`}</title>
        <desc id={`${id}-d`}>{desc}</desc>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={top} y2={top + rows.length * rowH} stroke="#c8c8c8" strokeWidth="1" />
            <text x={x(t)} y={top + rows.length * rowH + 16} textAnchor="middle">
              {t}
            </text>
          </g>
        ))}
        {rows.map((r, i) => {
          const cy = top + i * rowH + rowH / 2;
          return (
            <g key={r.name}>
              <text x={0} y={cy + 4}>
                {r.name}
              </text>
              <line x1={left} x2={left + plot} y1={cy} y2={cy} stroke="#8a8a8a" strokeWidth="1" />
              {r.gaps.map((g) => (
                <circle key={g.cveId} cx={x(g.days)} cy={cy} r={4} fill="none" stroke="#000" strokeWidth="1.5" />
              ))}
            </g>
          );
        })}
        <text x={left + plot} y={height - 2} textAnchor="end">
          days after earliest fix
        </text>
      </svg>
      <figcaption>Each circle is one CVE. Circles at 0 were fixed the same day as the earliest fix.</figcaption>
    </figure>
  );
}
