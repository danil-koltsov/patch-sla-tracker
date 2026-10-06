import { cachedGet, DAY, HOUR } from "./http.ts";

const API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const APPLE_CNA = "product-security@apple.com";
const PAGE = 2000;

interface NvdPage {
  totalResults: number;
  vulnerabilities: { cve: { id: string; published?: string } }[];
}

function options(maxAgeMs: number) {
  const key = process.env.NVD_API_KEY;
  // NVD limits: 5 requests / 30 s without a key, 50 with one.
  return { maxAgeMs, minIntervalMs: key ? 700 : 6500, headers: key ? { apiKey: key } : undefined, cacheNotFound: true };
}

/** NVD "published" is a UTC timestamp without zone; we keep the UTC date. */
export function parseNvdPage(json: string): { total: number; published: Map<string, string | null> } {
  const page = JSON.parse(json) as NvdPage;
  const published = new Map<string, string | null>();
  for (const v of page.vulnerabilities ?? []) published.set(v.cve.id, v.cve.published ? v.cve.published.slice(0, 10) : null);
  return { total: page.totalResults ?? 0, published };
}

/** All CVEs assigned by Apple's CNA (~9k) in a handful of paged requests. */
export async function fetchAppleCna(log: (s: string) => void): Promise<Map<string, string | null>> {
  const all = new Map<string, string | null>();
  for (let start = 0; ; start += PAGE) {
    const res = await cachedGet(`${API}?sourceIdentifier=${encodeURIComponent(APPLE_CNA)}&resultsPerPage=${PAGE}&startIndex=${start}`, options(20 * HOUR));
    const { total, published } = parseNvdPage(res.body);
    for (const [k, v] of published) all.set(k, v);
    log(`nvd: apple cna page ${start / PAGE + 1} (${all.size}/${total})${res.fromCache ? " [cache]" : ""}`);
    if (start + PAGE >= total) break;
  }
  return all;
}

/**
 * Single-CVE lookups for CVEs from other CNAs. Found records are cached 30 days, misses 7 days.
 * A lookup that keeps failing yields null ("unknown") and is reported, instead of aborting the run.
 */
export async function fetchMissing(ids: string[], log: (s: string) => void): Promise<{ published: Map<string, string | null>; failed: string[] }> {
  const published = new Map<string, string | null>();
  const failed: string[] = [];
  let i = 0;
  for (const id of ids) {
    i++;
    try {
      let res = await cachedGet(`${API}?cveId=${id}`, options(30 * DAY));
      let parsed = res.status === 404 ? { published: new Map<string, string | null>() } : parseNvdPage(res.body);
      if (!parsed.published.get(id) && Date.now() - Date.parse(res.fetchedAt) > 7 * DAY) {
        res = await cachedGet(`${API}?cveId=${id}`, options(0));
        parsed = res.status === 404 ? { published: new Map() } : parseNvdPage(res.body);
      }
      published.set(id, parsed.published.get(id) ?? null);
      if (!res.fromCache && i % 25 === 0) log(`nvd: single lookups ${i}/${ids.length}`);
    } catch (e) {
      failed.push(id);
      published.set(id, null);
      log(`nvd: ${id} lookup failed, recorded as unknown (${String(e).slice(0, 120)})`);
    }
  }
  return { published, failed };
}
