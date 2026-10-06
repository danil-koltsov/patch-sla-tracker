import { loadData } from "../../../../lib/data.ts";
import { exportEnvelope, exportRows } from "../../../../lib/export.ts";
import { cveTimeline } from "../../../../lib/metrics.ts";

export const revalidate = 86400; // must be a literal; equals REVALIDATE_SECONDS

/** Rendered on first request, then cached like the page (ISR). */
export async function generateStaticParams() {
  return [];
}

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const id = decodeURIComponent((await params).id).toUpperCase();
  const { dataset, index } = await loadData();
  const t = cveTimeline(index, id);
  if (!t) return Response.json({ error: "not found", id }, { status: 404 });
  return Response.json({
    ...exportEnvelope(dataset.meta, `/cve/${id}`),
    cve: t.cve,
    first_fix_date: t.firstFixDate,
    in_window: t.inWindow,
    exploited: t.exploited,
    exploited_before_patch: t.exploitedBeforePatch,
    kev_window_days: t.kevWindowDays,
    disclosure_lag_days: t.disclosureLagDays,
    listings: t.listings.map((l) => ({
      release: l.release.name,
      release_id: l.release.id,
      branch: l.branch.name,
      release_date: l.release.releaseDate,
      rerelease_dates: l.release.rereleaseDates,
      advisory_url: l.release.advisoryUrl,
      entry_added: l.entryAdded,
      entry_updated: l.entryUpdated,
      exploited_note: l.exploitedNote,
    })),
    rows: exportRows([t]),
  });
}
