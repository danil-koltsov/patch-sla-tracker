import { loadData } from "../../../lib/data.ts";

/** Every CVE inside the metric window gets a page and exports; others fall through to the 404 page. */
export async function generateStaticParams(): Promise<{ id: string }[]> {
  const { timelines } = await loadData();
  return timelines.filter((t) => t.inWindow).map((t) => ({ id: t.id }));
}
