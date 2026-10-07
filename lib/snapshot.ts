import type { Dataset } from "./types.ts";

/** The dataset lives in git at this path; the site builds from it and ingestion rewrites it. */
export const SNAPSHOT_PATH = "data/snapshot.json";

/**
 * Deterministic JSON with one record per line, so a git diff shows exactly which releases,
 * listings or CVEs changed. Record order and key order come from the ingestion build.
 */
export function serializeDataset(ds: Dataset): string {
  const list = (xs: readonly unknown[]) => (xs.length ? `[\n${xs.map((x) => JSON.stringify(x)).join(",\n")}\n]` : "[]");
  return [
    "{",
    `"meta": ${JSON.stringify(ds.meta)},`,
    `"branches": ${list(ds.branches)},`,
    `"releases": ${list(ds.releases)},`,
    `"releaseCves": ${list(ds.releaseCves)},`,
    `"cves": ${list(ds.cves)}`,
    "}",
    "",
  ].join("\n");
}
