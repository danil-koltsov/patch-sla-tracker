import type { KevEntry } from "./build.ts";
import { cachedGet } from "./http.ts";

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevFeed {
  catalogVersion?: string;
  vulnerabilities: { cveID: string; dateAdded: string; dueDate?: string; vendorProject?: string }[];
}

export function parseKev(json: string): { catalogVersion: string | null; entries: Map<string, KevEntry> } {
  const feed = JSON.parse(json) as KevFeed;
  if (!Array.isArray(feed.vulnerabilities)) throw new Error("KEV feed: missing vulnerabilities[]");
  const entries = new Map<string, KevEntry>();
  for (const v of feed.vulnerabilities) {
    // Joined on cveID only: Apple-shipped CVEs can be filed under other vendors (Google, WebRTC).
    entries.set(v.cveID, {
      dateAdded: v.dateAdded.slice(0, 10),
      dueDate: v.dueDate ? v.dueDate.slice(0, 10) : null,
      vendorProject: v.vendorProject?.trim() || null,
    });
  }
  return { catalogVersion: feed.catalogVersion ?? null, entries };
}

export async function fetchKev() {
  const res = await cachedGet(KEV_URL, { maxAgeMs: 0 }); // full reload every run
  return parseKev(res.body);
}
