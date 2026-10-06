import { loadData } from "../../../lib/data.ts";
import { exportEnvelope, exportRows } from "../../../lib/export.ts";
import { backportSummary, disclosureSummary, exploitedSummary } from "../../../lib/metrics.ts";
import { PLATFORMS } from "../../../lib/types.ts";

export const dynamic = "force-static"; // emitted as a file by the static export

export async function GET() {
  const { dataset, index, timelines } = await loadData();
  const inWindow = timelines.filter((t) => t.inWindow);
  const strip = (s: ReturnType<typeof backportSummary>) => ({
    platform: s.platform,
    scope: s.scope,
    cves: s.cves,
    oldest_maintained_branch: s.oldestMaintained?.branch.name ?? null,
    branches: s.rows.map((r) => ({
      branch: r.branch.name,
      branch_id: r.branch.id,
      maintained: r.maintained,
      fixed: r.fixed,
      same_day: r.sameDay,
      no_fix_listed: r.noFixListed,
      branch_ended: r.branchEnded,
      fixed_at_branch_release: r.atBranchRelease,
    })),
  });
  return Response.json({
    ...exportEnvelope(dataset.meta, "/apple"),
    metrics: {
      exploited_before_patch_kev_proxy: exploitedSummary(timelines),
      backport_gap: PLATFORMS.flatMap((p) => [strip(backportSummary(index, timelines, p, "exploited")), strip(backportSummary(index, timelines, p, "all"))]),
      disclosure_lag: disclosureSummary(timelines),
    },
    rows: exportRows(inWindow),
  });
}
