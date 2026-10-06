import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const CACHE_DIR = process.env.INGEST_CACHE_DIR ?? ".cache/http";
const USER_AGENT = "patch-sla-tracker-ingest/1.0 (daily, cached; open-source research project)";

interface Meta {
  url: string;
  finalUrl: string;
  status: number;
  fetchedAt: string;
}

export interface Fetched {
  body: string;
  finalUrl: string;
  status: number;
  fetchedAt: string;
  fromCache: boolean;
}

const lastRequestAt = new Map<string, number>();

export interface FetchOptions {
  /** Reuse a cached response younger than this. */
  maxAgeMs: number;
  /** Minimum spacing between requests to the same host. */
  minIntervalMs?: number;
  headers?: Record<string, string>;
  /** Cache 404s too (for "not in NVD yet"), for at most maxAgeMs. */
  cacheNotFound?: boolean;
}

/** GET with an on-disk cache, per-host pacing and retries. Throws on persistent failure. */
export async function cachedGet(url: string, opts: FetchOptions): Promise<Fetched> {
  await mkdir(CACHE_DIR, { recursive: true });
  const key = createHash("sha256").update(url).digest("hex").slice(0, 32);
  const bodyPath = join(CACHE_DIR, `${key}.body`);
  const metaPath = join(CACHE_DIR, `${key}.json`);

  try {
    const meta = JSON.parse(await readFile(metaPath, "utf8")) as Meta;
    if (Date.now() - Date.parse(meta.fetchedAt) < opts.maxAgeMs) {
      return { body: await readFile(bodyPath, "utf8"), finalUrl: meta.finalUrl, status: meta.status, fetchedAt: meta.fetchedAt, fromCache: true };
    }
  } catch {
    // no cache entry
  }

  const host = new URL(url).host;
  for (let attempt = 1; ; attempt++) {
    const wait = (lastRequestAt.get(host) ?? 0) + (opts.minIntervalMs ?? 1000) - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequestAt.set(host, Date.now());

    let res: Response | null = null;
    let error: unknown = null;
    try {
      res = await fetch(url, { headers: { "User-Agent": USER_AGENT, ...opts.headers }, redirect: "follow", signal: AbortSignal.timeout(60_000) });
    } catch (e) {
      error = e;
    }
    const retryable = error !== null || (res !== null && (res.status === 429 || res.status === 403 || res.status >= 500));
    if (retryable && attempt < 4) {
      await sleep(2 ** attempt * 3000);
      continue;
    }
    if (error) throw new Error(`GET ${url} failed: ${String(error)}`);
    const r = res!;
    const ok = r.ok || (opts.cacheNotFound && r.status === 404);
    if (!ok) throw new Error(`GET ${url} -> HTTP ${r.status}`);
    const body = await r.text();
    const meta: Meta = { url, finalUrl: r.url || url, status: r.status, fetchedAt: new Date().toISOString() };
    await writeFile(bodyPath, body);
    await writeFile(metaPath, JSON.stringify(meta));
    return { body, finalUrl: meta.finalUrl, status: r.status, fetchedAt: meta.fetchedAt, fromCache: false };
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
