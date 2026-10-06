import { loadData } from "../../../lib/data.ts";
import { csvResponse, exportEnvelope, exportRows, toCsv } from "../../../lib/export.ts";

export const revalidate = 86400; // must be a literal; equals REVALIDATE_SECONDS

export async function GET() {
  const { dataset, timelines } = await loadData();
  return csvResponse(toCsv(exportRows(timelines.filter((t) => t.inWindow)), exportEnvelope(dataset.meta, "/apple")), "apple.csv");
}
