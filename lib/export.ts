import type { CveTimeline } from "./metrics.ts";
import { METHODOLOGY_VERSION, WINDOW_START } from "./methodology.ts";
import type { DatasetMeta } from "./types.ts";

export interface ExportRow {
  cve_id: string;
  exploited: boolean;
  exploited_before_patch: boolean;
  apple_exploited_note: boolean;
  first_fix_date: string;
  kev_date_added: string | null;
  kev_window_days: number | null;
  nvd_published: string | null;
  disclosure_lag_days: number | null;
  platform: string;
  branch: string;
  branch_status: string;
  branch_fix_date: string | null;
  branch_fix_release: string | null;
  gap_days: number | null;
  older_branch: boolean;
}

/** One row per CVE × platform × branch. Unknown values are null (empty in CSV). */
export function exportRows(timelines: CveTimeline[]): ExportRow[] {
  const rows: ExportRow[] = [];
  for (const t of timelines) {
    for (const p of t.platforms) {
      for (const o of p.outcomes) {
        const s = o.status;
        rows.push({
          cve_id: t.id,
          exploited: t.exploited,
          exploited_before_patch: t.exploitedBeforePatch,
          apple_exploited_note: t.appleExploitedNote,
          first_fix_date: t.firstFixDate,
          kev_date_added: t.cve.kevDateAdded,
          kev_window_days: t.kevWindowDays,
          nvd_published: t.cve.nvdPublished,
          disclosure_lag_days: t.disclosureLagDays,
          platform: p.platform,
          branch: o.branch.name,
          branch_status: s.kind,
          branch_fix_date: s.kind === "fixed" || s.kind === "later-major" ? s.fixDate : null,
          branch_fix_release: s.kind === "fixed" || s.kind === "later-major" ? s.releaseId : null,
          gap_days: s.kind === "fixed" ? s.gapDays : null,
          older_branch: o.older,
        });
      }
    }
  }
  return rows;
}

export function exportEnvelope(meta: DatasetMeta, permalink: string) {
  return {
    permalink,
    methodology_version: METHODOLOGY_VERSION,
    window_start: WINDOW_START,
    data_updated_at: meta.updatedAt || null,
    kev_catalog_version: meta.kevCatalogVersion,
    sources: {
      apple: "https://support.apple.com/en-us/100100",
      kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      nvd: "https://nvd.nist.gov/developers/vulnerabilities",
    },
  };
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rows: ExportRow[], header: Record<string, unknown>): string {
  const cols: (keyof ExportRow)[] = [
    "cve_id", "exploited", "exploited_before_patch", "apple_exploited_note", "first_fix_date", "kev_date_added", "kev_window_days",
    "nvd_published", "disclosure_lag_days", "platform", "branch", "branch_status", "branch_fix_date", "branch_fix_release", "gap_days", "older_branch",
  ];
  const comments = Object.entries(header).map(([k, v]) => `# ${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  return [...comments, cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n") + "\n";
}

export function csvResponse(body: string, filename: string): Response {
  return new Response(body, {
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `inline; filename="${filename}"` },
  });
}
