import { loadData, REVALIDATE_SECONDS } from "../../../../lib/data.ts";
import { csvResponse, exportEnvelope, exportRows, toCsv } from "../../../../lib/export.ts";
import { cveTimeline } from "../../../../lib/metrics.ts";

export const revalidate = REVALIDATE_SECONDS;

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const id = decodeURIComponent((await params).id).toUpperCase();
  const { dataset, index } = await loadData();
  const t = cveTimeline(index, id);
  if (!t) return new Response("not found\n", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  return csvResponse(toCsv(exportRows([t]), exportEnvelope(dataset.meta, `/cve/${id}`)), `${id}.csv`);
}
