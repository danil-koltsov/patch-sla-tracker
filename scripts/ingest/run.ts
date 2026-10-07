/**
 * Daily ingestion. Usage:
 *   node scripts/ingest/run.ts                 # write to Supabase (needs SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)
 *   node scripts/ingest/run.ts --no-db --out data/snapshot.json
 *   node scripts/ingest/run.ts --force         # skip the shrink guard
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import { METHODOLOGY_VERSION } from "../../lib/methodology.ts";
import { daysBetween } from "../../lib/dates.ts";
import { parseAdvisory, type Advisory } from "./apple-advisory.ts";
import { parseIndex, type IndexRow } from "./apple-index.ts";
import { parseReleaseName } from "./apple-names.ts";
import { buildDataset } from "./build.ts";
import { allTimelines, buildIndex } from "../../lib/metrics.ts";
import { cachedGet, DAY, HOUR } from "./http.ts";
import { fetchKev } from "./kev.ts";
import { fetchMissing, rememberPublished, syncNvd } from "./nvd.ts";
import { SupabaseWriter } from "./supabase.ts";

const INDEX_PAGES = [
  "https://support.apple.com/en-us/100100", // current
  "https://support.apple.com/en-us/121012", // 2022–2023
  "https://support.apple.com/en-us/120989", // 2020–2021 (branch start dates only)
];
/** Releases before this date only provide branch start dates; their advisories are not fetched. */
const ADVISORIES_FROM = "2022-01-01";
/**
 * Advisory refresh tiers. Apple adds CVEs to existing advisories weeks or months after release
 * ("Entry added"), so recent advisories are re-read on every run (every 6 hours).
 */
const REFETCH_EVERY_RUN_DAYS = 90;
const REFETCH_DAILY_DAYS = 400;
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
    // The current index is re-read every run; the yearly archives no longer change much.
    const res = await cachedGet(url, { maxAgeMs: url.endsWith("100100") ? 0 : 7 * DAY });
    const parsed = parseIndex(res.body);
    if (parsed.length < 50) throw new Error(`Apple index ${url}: only ${parsed.length} rows parsed; page format changed?`);
    rows.push(...parsed);
    log(`apple index ${url}: ${parsed.length} rows`);
  }
  const osRows = rows.filter((r) => parseReleaseName(r.name).length > 0 || /^(Background Security|Rapid Security)/i.test(r.name));
  log(`apple index: ${osRows.length} iOS/iPadOS/macOS rows`);

  // 2. Advisories: last 90 days every run, up to 400 days daily, older monthly.
  const advisories = new Map<string, Advisory>();
  const wanted = [...new Set(osRows.filter((r) => r.url && !r.noCveEntries && r.date >= ADVISORIES_FROM).map((r) => [r.url!, r.date] as const))];
  let fetched = 0;
  for (const [url, date] of wanted) {
    if (advisories.has(url)) continue;
    const age = daysBetween(date, today);
    const maxAgeMs = age <= REFETCH_EVERY_RUN_DAYS ? 0 : age <= REFETCH_DAILY_DAYS ? 20 * HOUR : 30 * DAY;
    const res = await cachedGet(url, { maxAgeMs, minIntervalMs: 1500 });
    if (!res.fromCache) fetched++;
    advisories.set(url, parseAdvisory(res.body));
  }
  log(`apple advisories: ${advisories.size} (${fetched} fetched, rest cached)`);

  // 3. KEV: full reload every run (one 2 MB file)
  const kev = await fetchKev();
  log(`kev: ${kev.entries.size} entries, catalog ${kev.catalogVersion}`);

  // 4. Build, then NVD for the CVEs we actually list: weekly full sync, otherwise only recently modified records
  const draft = buildDataset({ rows: osRows, advisories, kev: kev.entries, kevCatalogVersion: kev.catalogVersion, nvdPublished: new Map(), updatedAt });
  const sync = await syncNvd(new Set(draft.dataset.cves.map((c) => c.id)), log);
  const nvd = sync.published;
  log(`nvd: ${sync.mode} sync, ${sync.updated} published dates added or changed`);
  // Only CVEs inside the metric window need a date; older ones are shown for reference only.
  const inWindow = new Set(allTimelines(buildIndex(draft.dataset)).filter((t) => t.inWindow).map((t) => t.id));
  const needed = draft.dataset.cves.map((c) => c.id).filter((id) => !nvd.get(id) && inWindow.has(id));
  log(`nvd: ${needed.length} in-window CVEs without a published date need single lookups`);
  const missing = await fetchMissing(needed, log);
  for (const [k, v] of missing.published) nvd.set(k, v);
  await rememberPublished(missing.published);

  const { dataset, warnings } = buildDataset({ rows: osRows, advisories, kev: kev.entries, kevCatalogVersion: kev.catalogVersion, nvdPublished: nvd, updatedAt });
  const counts = {
    branches: dataset.branches.length,
    releases: dataset.releases.length,
    cves: dataset.cves.length,
    release_cves: dataset.releaseCves.length,
  };
  // Content hash (without the timestamp) decides whether anything changed and the site needs a rebuild.
  const contentHash = createHash("sha256")
    .update(JSON.stringify({ b: dataset.branches, r: dataset.releases, l: dataset.releaseCves, c: dataset.cves }))
    .digest("hex");
  log(`dataset: ${JSON.stringify(counts)} hash ${contentHash.slice(0, 12)}`);
  if (missing.failed.length) warnings.push(`NVD lookup failed (published date unknown) for ${missing.failed.length} CVEs: ${missing.failed.join(", ")}`);
  for (const w of warnings) log(`warning: ${w}`);

  if (args.out) {
    const prev = await readFile(args.out, "utf8").then((s) => JSON.parse(s) as typeof dataset).catch(() => null);
    const prevHash = prev
      ? createHash("sha256").update(JSON.stringify({ b: prev.branches, r: prev.releases, l: prev.releaseCves, c: prev.cves })).digest("hex")
      : null;
    if (args["no-db"]) await setOutput("changed", String(prevHash !== contentHash));
    await mkdir(dirname(args.out), { recursive: true });
    await writeFile(args.out, JSON.stringify(dataset));
    log(`wrote ${args.out}`);
  }
  if (args["no-db"]) return;

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required (or pass --no-db)");
  const db = new SupabaseWriter(url, key);

  const last = await db.lastRun();
  const previous = last?.counts ?? null;
  if (last?.content_hash === contentHash) {
    const run = await db.startRun(METHODOLOGY_VERSION);
    await db.finishRun(run, "ok", { counts, warnings, kev_catalog_version: kev.catalogVersion, content_hash: contentHash, changed: false });
    await setOutput("changed", "false");
    log(`supabase: run ${run} ok, no changes since the last run; tables not rewritten`);
    return;
  }
  if (previous && !args.force) {
    for (const [k, v] of Object.entries(counts)) {
      const before = previous[k];
      if (before && v < before * (1 - MAX_SHRINK)) throw new Error(`${k} would shrink from ${before} to ${v}; refusing to write (use --force after checking)`);
    }
  }

  const run = await db.startRun(METHODOLOGY_VERSION);
  try {
    await db.write(dataset, run);
    await db.finishRun(run, "ok", { counts, warnings, kev_catalog_version: kev.catalogVersion, content_hash: contentHash, changed: true });
    await setOutput("changed", "true");
    log(`supabase: run ${run} ok, data changed`);
  } catch (e) {
    await db.finishRun(run, "failed", { warnings: [...warnings, String(e)] }).catch(() => {});
    throw e;
  }
}

/** Step output for GitHub Actions (e.g. `changed=true` triggers the site rebuild). */
async function setOutput(name: string, value: string): Promise<void> {
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
