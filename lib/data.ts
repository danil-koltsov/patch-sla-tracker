import { readFile } from "node:fs/promises";
import type { Dataset } from "./types.ts";
import { allTimelines, buildIndex, type CveTimeline, type Index } from "./metrics.ts";
import { SNAPSHOT_PATH } from "./snapshot.ts";

export interface Loaded {
  dataset: Dataset;
  index: Index;
  timelines: CveTimeline[];
}

let memo: Promise<Loaded> | null = null;

/**
 * Loads and indexes the dataset once per build process. The source is the snapshot committed to git
 * (data/snapshot.json); DATA_SNAPSHOT overrides the path (CI builds against a small fixture).
 */
export function loadData(): Promise<Loaded> {
  if (memo) return memo;
  const value = (async () => {
    const path = process.env.DATA_SNAPSHOT || SNAPSHOT_PATH;
    let text: string;
    try {
      text = await readFile(path, "utf8");
    } catch {
      throw new Error(`No data snapshot at ${path}. Run \`npm run ingest\` to create it.`);
    }
    const dataset = JSON.parse(text) as Dataset;
    const index = buildIndex(dataset);
    return { dataset, index, timelines: allTimelines(index) };
  })();
  memo = value;
  value.catch(() => {
    memo = null;
  });
  return value;
}
