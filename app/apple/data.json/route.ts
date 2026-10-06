import { loadData, REVALIDATE_SECONDS } from "../../../lib/data.ts";
import { exportEnvelope, exportRows } from "../../../lib/export.ts";
import { backportSummary, disclosureSummary, exploitedSummary } from "../../../lib/metrics.ts";
import { PLATFORMS } from "../../../lib/types.ts";

export const revalidate = REVALIDATE_SECONDS;

export async function GET() {
  const { dataset, timelines } = await loadData();
  const inWindow = timelines.filter((t) => t.inWindow);
  const strip = (s: ReturnType<typeof backportSummary>) => ({
    platform: s.platform,
    scope: s.scope,
    cves: s.cves,
    older_branches: s.older,
    branches: s.rows.map((r) => ({
      branch: r.branch.name,
      branch_id: r.branch.id,
      fixed: r.fixed,
      same_day: r.sameDay,
      no_fix_listed: r.noFixListed,
      branch_ended: r.branchEnded,
    })),
  });
  return Response.json({
    ...exportEnvelope(dataset.meta, "/apple"),
    metrics: {
      exploited_before_patch_kev_proxy: exploitedSummary(timelines),
      backport_gap: PLATFORMS.flatMap((p) => [strip(backportSummary(timelines, p, "exploited")), strip(backportSummary(timelines, p, "all"))]),
      disclosure_lag: disclosureSummary(timelines),
    },
    rows: exportRows(inWindow),
  });
}
