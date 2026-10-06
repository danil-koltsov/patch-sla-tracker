import { parseEnglishDate } from "../../lib/dates.ts";
import { decodeEntities, stripTags } from "./html.ts";

export interface IndexRow {
  name: string;
  date: string; // YYYY-MM-DD
  url: string | null; // null when Apple lists "no published CVE entries"
  noCveEntries: boolean;
}

/** Parses the table on https://support.apple.com/en-us/100100 and its yearly archives. */
export function parseIndex(html: string): IndexRow[] {
  const rows: IndexRow[] = [];
  for (const tr of html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/g)) {
    const cells = [...tr[1]!.matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/g)].map((c) => c[1]!);
    if (cells.length < 3) continue;
    const date = parseEnglishDate(stripTags(cells[2]!));
    if (!date) continue; // header row
    const href = /href="([^"]+)"/.exec(cells[0]!)?.[1];
    const text = stripTags(cells[0]!);
    const noCveEntries = /no published CVE entries/i.test(text);
    rows.push({
      name: text.replace(/\s*This update has no published CVE entries\.?/i, "").trim(),
      date,
      url: href ? absolutize(decodeEntities(href)) : null,
      noCveEntries,
    });
  }
  return rows;
}

function absolutize(href: string): string {
  if (href.startsWith("http")) return href.replace(/^http:/, "https:");
  return new URL(href, "https://support.apple.com").toString();
}
