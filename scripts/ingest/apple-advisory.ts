import { parseEnglishDate } from "../../lib/dates.ts";
import { stripTags } from "./html.ts";

export interface AdvisoryEntry {
  cves: string[];
  entryAdded: string | null;
  entryUpdated: string | null;
  exploited: boolean;
}

export interface AdvisorySection {
  heading: string;
  released: string | null;
  entries: AdvisoryEntry[];
}

export interface Advisory {
  title: string;
  sections: AdvisorySection[];
}

const DATE = "([A-Z][a-z]+\\.? \\d{1,2}, \\d{4})";
const EXPLOITED = /may have been (?:actively )?exploited/i;

/**
 * Parses an Apple "About the security content of …" page.
 * Structure: <h2> per release, "Released <date>", then per component:
 * heading, "Available for:", "Impact:", "Description:", "CVE-…", optional "Entry added/updated …".
 */
export function parseAdvisory(html: string): Advisory {
  const clean = html.replace(/<(script|style|noscript)\b[\s\S]*?<\/\1>/gi, "");
  const title = stripTags(/<title>([\s\S]*?)<\/title>/i.exec(clean)?.[1] ?? "").replace(/\s*-\s*Apple Support$/, "");
  const start = clean.indexOf('id="sections"');
  const endMarker = clean.indexOf('id="disclaimer"', Math.max(start, 0));
  const body = clean.slice(start >= 0 ? start : 0, endMarker > start ? endMarker : undefined);

  const sections: AdvisorySection[] = [];
  let section: AdvisorySection | null = null;
  let entry: AdvisoryEntry | null = null;
  let stopped = false;

  for (const m of body.matchAll(/<(h2|h3|p)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    if (stopped) break;
    const tag = m[1]!.toLowerCase();
    const text = stripTags(m[2]!);
    if (!text) continue;

    if (tag === "h2") {
      if (/additional recognition/i.test(text)) {
        stopped = true;
        break;
      }
      section = { heading: text, released: null, entries: [] };
      sections.push(section);
      entry = null;
      continue;
    }
    if (!section) continue;

    const rel = new RegExp(`^Released ${DATE}`).exec(text);
    if (rel && !section.released) {
      section.released = parseEnglishDate(rel[1]!);
      continue;
    }
    if (/^Available for:/i.test(text)) {
      entry = { cves: [], entryAdded: null, entryUpdated: null, exploited: false };
      section.entries.push(entry);
      continue;
    }
    if (!entry) continue;
    if (EXPLOITED.test(text)) entry.exploited = true;
    if (/^CVE-\d{4}-\d{4,}/.test(text)) {
      for (const c of text.matchAll(/CVE-\d{4}-\d{4,}/g)) if (!entry.cves.includes(c[0])) entry.cves.push(c[0]);
      continue;
    }
    if (/^Entry (added|updated)/i.test(text)) {
      const added = new RegExp(`Entry added ${DATE}`, "i").exec(text);
      const updated = new RegExp(`updated ${DATE}`, "i").exec(text);
      if (added) entry.entryAdded = minNullable(entry.entryAdded, parseEnglishDate(added[1]!));
      if (updated) entry.entryUpdated = maxNullable(entry.entryUpdated, parseEnglishDate(updated[1]!));
    }
  }
  for (const s of sections) s.entries = s.entries.filter((e) => e.cves.length > 0);
  return { title, sections };
}

function minNullable(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return a < b ? a : b;
}
function maxNullable(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return a > b ? a : b;
}
