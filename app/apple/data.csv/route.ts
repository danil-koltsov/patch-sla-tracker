import { loadData } from "../../../lib/data.ts";
import { csvResponse, exportEnvelope, exportRows, toCsv } from "../../../lib/export.ts";

export const dynamic = "force-static"; // emitted as a file by the static export

export async function GET() {
  const { dataset, timelines } = await loadData();
  return csvResponse(toCsv(exportRows(timelines.filter((t) => t.inWindow)), exportEnvelope(dataset.meta, "/apple")), "apple.csv");
}
