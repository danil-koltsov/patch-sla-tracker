/**
 * Daily ingestion. Usage:
 *   node scripts/ingest/run.ts                 # write to Supabase (needs SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)
 *   node scripts/ingest/run.ts --no-db --out data/snapshot.json
 *   node scripts/ingest/run.ts --force         # skip the shrink guard
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import { METHODOLOGY_VERSION } from "../../lib/methodology.ts";
import { daysBetween } from "../../lib/dates.ts";
import { parseAdvisory, type Advisory } from "./apple-advisory.ts";
import { parseIndex, type IndexRow } from "./apple-index.ts";
import { parseReleaseName } from "./apple-names.ts";
import { buildDataset } from "./build.ts";
import { cachedGet, DAY, HOUR } from "./http.ts";
import { fetchKev } from "./kev.ts";
import { fetchAppleCna, fetchMissing } from "./nvd.ts";
import { SupabaseWriter } from "./supabase.ts";

const INDEX_PAGES = [
  "https://support.apple.com/en-us/100100", // current
  "https://support.apple.com/en-us/121012", // 2022–2023
  "https://support.apple.com/en-us/120989", // 2020–2021 (branch start dates only)
];
/** Releases before this date only provide branch start dates; their advisories are not fetched. */
const ADVISORIES_FROM = "2022-01-01";
/** Fail instead of deleting data when a table shrinks more than this. */
const MAX_SHRINK = 0.1;

const log = (s: string) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${s}`);

async function main() {
  const { values: args } = parseArgs({
    options: { "no-db": { type: "boolean", default: false }, out: { type: "string" }, force: { type: "boolean", default: false } },
  });
  const updatedAt = new Date().toISOString();
  const today = updatedAt.slice(0, 10);

  // 1. Apple index
  const rows: IndexRow[] = [];
  for (const url of INDEX_PAGES) {
    const res = await cachedGet(url, { maxAgeMs: url.endsWith("100100") ? 20 * HOUR : 7 * DAY });
    const parsed = parseIndex(res.body);
    if (parsed.length < 50) throw new Error(`Apple index ${url}: only ${parsed.length} rows parsed; page format changed?`);
    rows.push(...parsed);
    log(`apple index ${url}: ${parsed.length} rows`);
  }
  const osRows = rows.filter((r) => parseReleaseName(r.name).length > 0 || /^(Background Security|Rapid Security)/i.test(r.name));
  log(`apple index: ${osRows.length} iOS/iPadOS/macOS rows`);

  // 2. Advisories. Recent ones change ("Entry added"), so refetch daily; older ones monthly.
  const advisories = new Map<string, Advisory>();
  const wanted = [...new Set(osRows.filter((r) => r.url && !r.noCveEntries && r.date >= ADVISORIES_FROM).map((r) => [r.url!, r.date] as const))];
  let fetched = 0;
  for (const [url, date] of wanted) {
    if (advisories.has(url)) continue;
    const recent = daysBetween(date, today) < 400;
    const res = await cachedGet(url, { maxAgeMs: recent ? 20 * HOUR : 30 * DAY, minIntervalMs: 1500 });
    if (!res.fromCache) fetched++;
    advisories.set(url, parseAdvisory(res.body));
  }
  log(`apple advisories: ${advisories.size} (${fetched} fetched, rest cached)`);

  // 3. KEV
  const kev = await fetchKev();
  log(`kev: ${kev.entries.size} entries, catalog ${kev.catalogVersion}`);

  // 4. Build, then NVD for the CVEs we actually list
  const draft = buildDataset({ rows: osRows, advisories, kev: kev.entries, kevCatalogVersion: kev.catalogVersion, nvdPublished: new Map(), updatedAt });
  const nvd = await fetchAppleCna(log);
  const needed = draft.dataset.cves.map((c) => c.id).filter((id) => !nvd.has(id));
  log(`nvd: ${needed.length} CVEs from other CNAs need single lookups`);
  for (const [k, v] of await fetchMissing(needed, log)) nvd.set(k, v);

  const { dataset, warnings } = buildDataset({ rows: osRows, advisories, kev: kev.entries, kevCatalogVersion: kev.catalogVersion, nvdPublished: nvd, updatedAt });
  const counts = {
    branches: dataset.branches.length,
    releases: dataset.releases.length,
    cves: dataset.cves.length,
    release_cves: dataset.releaseCves.length,
  };
  log(`dataset: ${JSON.stringify(counts)}`);
  for (const w of warnings) log(`warning: ${w}`);

  if (args.out) {
    await mkdir(dirname(args.out), { recursive: true });
    await writeFile(args.out, JSON.stringify(dataset));
    log(`wrote ${args.out}`);
  }
  if (args["no-db"]) return;

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required (or pass --no-db)");
  const db = new SupabaseWriter(url, key);

  const previous = await db.lastCounts();
  if (previous && !args.force) {
    for (const [k, v] of Object.entries(counts)) {
      const before = previous[k];
      if (before && v < before * (1 - MAX_SHRINK)) throw new Error(`${k} would shrink from ${before} to ${v}; refusing to write (use --force after checking)`);
    }
  }

  const run = await db.startRun(METHODOLOGY_VERSION);
  try {
    await db.write(dataset, run);
    await db.finishRun(run, "ok", { counts, warnings, kev_catalog_version: kev.catalogVersion });
    log(`supabase: run ${run} ok`);
  } catch (e) {
    await db.finishRun(run, "failed", { warnings: [...warnings, String(e)] }).catch(() => {});
    throw e;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
