import { readFile } from "node:fs/promises";
import type { Branch, Cve, Dataset, Platform, Release, ReleaseCve } from "./types.ts";
import { allTimelines, buildIndex, type CveTimeline, type Index } from "./metrics.ts";

const PAGE = 1000;

async function fetchAll<T>(base: string, key: string, table: string, order: string): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += PAGE) {
    const res = await fetch(`${base}/rest/v1/${table}?select=*&order=${order}`, {
      headers: { apikey: key, Authorization: `Bearer ${key}`, Range: `${from}-${from + PAGE - 1}`, "Range-Unit": "items" },
      cache: "force-cache", // read once per build; the site is rebuilt daily after ingestion
    });
    if (!res.ok) throw new Error(`Supabase ${table}: HTTP ${res.status}`);
    const rows = (await res.json()) as T[];
    out.push(...rows);
    if (rows.length < PAGE) return out;
  }
}

interface Row {
  [k: string]: unknown;
}

async function fromSupabase(url: string, key: string): Promise<Dataset> {
  const base = url.replace(/\/$/, "");
  const [branches, releases, releaseCves, cves, runs] = await Promise.all([
    fetchAll<Row>(base, key, "branches", "id"),
    fetchAll<Row>(base, key, "releases", "id"),
    fetchAll<Row>(base, key, "release_cves", "release_id,cve_id"),
    fetchAll<Row>(base, key, "cves", "id"),
    fetchAll<Row>(base, key, "v_last_ingest", "id"),
  ]);
  const run = runs[0];
  return {
    meta: { updatedAt: (run?.finished_at as string) ?? "", kevCatalogVersion: (run?.kev_catalog_version as string) ?? null },
    branches: branches.map((b): Branch => ({ id: b.id as string, platform: b.platform as Platform, major: b.major as number, name: b.name as string })),
    releases: releases.map(
      (r): Release => ({
        id: r.id as string,
        branchId: r.branch_id as string,
        version: r.version as string,
        suffix: (r.suffix as string) ?? null,
        kind: r.kind as Release["kind"],
        releaseDate: r.release_date as string,
        rereleaseDates: (r.rerelease_dates as string[]) ?? [],
        name: r.name as string,
        advisoryUrl: (r.advisory_url as string) ?? null,
        hasCveEntries: r.has_cve_entries as boolean,
      }),
    ),
    releaseCves: releaseCves.map(
      (l): ReleaseCve => ({
        releaseId: l.release_id as string,
        cveId: l.cve_id as string,
        entryAdded: (l.entry_added as string) ?? null,
        entryUpdated: (l.entry_updated as string) ?? null,
        exploitedNote: l.exploited_note as boolean,
      }),
    ),
    cves: cves.map(
      (c): Cve => ({
        id: c.id as string,
        nvdPublished: (c.nvd_published as string) ?? null,
        kevDateAdded: (c.kev_date_added as string) ?? null,
        kevDueDate: (c.kev_due_date as string) ?? null,
        kevVendorProject: (c.kev_vendor_project as string) ?? null,
      }),
    ),
  };
}

export interface Loaded {
  dataset: Dataset;
  index: Index;
  timelines: CveTimeline[];
}

let memo: { value: Promise<Loaded> } | null = null;

/** Loads and indexes the dataset once per build process. */
export function loadData(): Promise<Loaded> {
  if (memo) return memo.value;
  const value = (async () => {
    const snapshot = process.env.DATA_SNAPSHOT;
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_ANON_KEY;
    let dataset: Dataset;
    if (snapshot) dataset = JSON.parse(await readFile(snapshot, "utf8")) as Dataset;
    else if (url && key) dataset = await fromSupabase(url, key);
    else throw new Error("No data source: set SUPABASE_URL + SUPABASE_ANON_KEY, or DATA_SNAPSHOT for local development.");
    const index = buildIndex(dataset);
    return { dataset, index, timelines: allTimelines(index) };
  })();
  memo = { value };
  value.catch(() => {
    memo = null;
  });
  return value;
}
