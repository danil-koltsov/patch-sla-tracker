import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { CACHE_DIR, cachedGet, DAY, HOUR } from "./http.ts";

const API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const APPLE_CNA = "product-security@apple.com";
const PAGE = 2000;

interface NvdPage {
  totalResults: number;
  vulnerabilities: { cve: { id: string; published?: string; sourceIdentifier?: string } }[];
}

function options(maxAgeMs: number) {
  const key = process.env.NVD_API_KEY;
  // NVD limits: 5 requests / 30 s without a key, 50 with one.
  return { maxAgeMs, minIntervalMs: key ? 700 : 6500, headers: key ? { apiKey: key } : undefined, cacheNotFound: true };
}

/** NVD "published" is a UTC timestamp without zone; we keep the UTC date. */
export function parseNvdPage(json: string): { total: number; published: Map<string, string | null>; appleCna: Set<string> } {
  const page = JSON.parse(json) as NvdPage;
  const published = new Map<string, string | null>();
  const appleCna = new Set<string>();
  for (const v of page.vulnerabilities ?? []) {
    published.set(v.cve.id, v.cve.published ? v.cve.published.slice(0, 10) : null);
    if (v.cve.sourceIdentifier === APPLE_CNA) appleCna.add(v.cve.id);
  }
  return { total: page.totalResults ?? 0, published, appleCna };
}

/**
 * NVD state kept between runs (restored from the Actions cache): published date per CVE we care about.
 * A full pull of Apple-CNA CVEs (~9k, 5 requests) runs weekly or when the state is missing/old;
 * every other run fetches only records NVD modified since the last sync (one or two requests).
 */
interface NvdState {
  syncedAt: string; // start of the last successful sync (ISO)
  fullSyncAt: string;
  published: Record<string, string | null>;
}

const STATE_PATH = join(CACHE_DIR, "..", "nvd-state.json");
const FULL_SYNC_EVERY = 7 * DAY;
const MAX_WINDOW = 100 * DAY; // NVD allows at most 120 days per lastMod range
const OVERLAP = HOUR; // re-read the last hour so records modified during the previous run are not missed

async function loadState(): Promise<NvdState | null> {
  try {
    return JSON.parse(await readFile(STATE_PATH, "utf8")) as NvdState;
  } catch {
    return null;
  }
}

async function saveState(state: NvdState): Promise<void> {
  await mkdir(dirname(STATE_PATH), { recursive: true });
  await writeFile(STATE_PATH, JSON.stringify(state));
}

async function pages(urlFor: (start: number) => string, log: (s: string) => void, label: string) {
  const published = new Map<string, string | null>();
  const appleCna = new Set<string>();
  for (let start = 0; ; start += PAGE) {
    const res = await cachedGet(urlFor(start), { ...options(0), noStore: true, cacheNotFound: false });
    const p = parseNvdPage(res.body);
    for (const [k, v] of p.published) published.set(k, v);
    for (const id of p.appleCna) appleCna.add(id);
    log(`nvd: ${label} ${Math.min(start + PAGE, p.total)}/${p.total}`);
    if (start + PAGE >= p.total) break;
  }
  return { published, appleCna };
}

/**
 * Brings the published-date map up to date. `tracked` = CVE IDs listed in Apple advisories;
 * modified records are kept if they are Apple-CNA, tracked, or already known.
 */
export async function syncNvd(tracked: Set<string>, log: (s: string) => void): Promise<{ published: Map<string, string | null>; mode: "full" | "incremental"; updated: number }> {
  const now = new Date();
  const state = await loadState();
  const full = !state || now.getTime() - Date.parse(state.fullSyncAt) > FULL_SYNC_EVERY || now.getTime() - Date.parse(state.syncedAt) > MAX_WINDOW;
  const published = new Map<string, string | null>(Object.entries(state?.published ?? {}));
  let updated = 0;

  if (full) {
    const r = await pages((start) => `${API}?sourceIdentifier=${encodeURIComponent(APPLE_CNA)}&resultsPerPage=${PAGE}&startIndex=${start}`, log, "full apple-cna sync");
    for (const [k, v] of r.published) {
      if (published.get(k) !== v) updated++;
      published.set(k, v);
    }
  } else {
    const from = new Date(Date.parse(state!.syncedAt) - OVERLAP).toISOString();
    const to = now.toISOString();
    const r = await pages(
      (start) => `${API}?lastModStartDate=${encodeURIComponent(from)}&lastModEndDate=${encodeURIComponent(to)}&resultsPerPage=${PAGE}&startIndex=${start}`,
      log,
      `modified since ${from.slice(0, 16)}Z`,
    );
    for (const [k, v] of r.published) {
      if (!(r.appleCna.has(k) || tracked.has(k) || published.has(k))) continue;
      if (published.get(k) !== v) updated++;
      published.set(k, v);
    }
  }
  await saveState({ syncedAt: now.toISOString(), fullSyncAt: full ? now.toISOString() : state!.fullSyncAt, published: Object.fromEntries(published) });
  return { published, mode: full ? "full" : "incremental", updated };
}

/** Records single-lookup results in the state so incremental syncs keep them current. */
export async function rememberPublished(found: Map<string, string | null>): Promise<void> {
  const state = await loadState();
  if (!state) return;
  for (const [k, v] of found) if (v !== null) state.published[k] = v;
  await saveState(state);
}

/**
 * Single-CVE lookups for tracked CVEs NVD has not given us yet. Misses are retried after a day.
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
      if (!parsed.published.get(id) && Date.now() - Date.parse(res.fetchedAt) > DAY) {
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
