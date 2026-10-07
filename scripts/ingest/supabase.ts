import type { Dataset } from "../../lib/types.ts";

/** Minimal PostgREST client for the service role (ingestion only). */
export class SupabaseWriter {
  private url: string;
  private key: string;

  constructor(url: string, serviceKey: string) {
    this.url = url.replace(/\/$/, "") + "/rest/v1";
    this.key = serviceKey;
  }

  private async req(method: string, path: string, body?: unknown, prefer?: string): Promise<unknown> {
    const res = await fetch(`${this.url}/${path}`, {
      method,
      headers: {
        apikey: this.key,
        Authorization: `Bearer ${this.key}`,
        "Content-Type": "application/json",
        ...(prefer ? { Prefer: prefer } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
    if (!res.ok) throw new Error(`Supabase ${method} ${path}: HTTP ${res.status} ${await res.text()}`);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  async startRun(methodologyVersion: string): Promise<number> {
    const rows = (await this.req("POST", "ingest_runs", { methodology_version: methodologyVersion }, "return=representation")) as { id: number }[];
    return rows[0]!.id;
  }

  async finishRun(id: number, status: "ok" | "failed", fields: Record<string, unknown>): Promise<void> {
    await this.req("PATCH", `ingest_runs?id=eq.${id}`, { status, finished_at: new Date().toISOString(), ...fields }, "return=minimal");
  }

  async lastRun(): Promise<{ counts: Record<string, number>; content_hash: string | null } | null> {
    const rows = (await this.req("GET", "ingest_runs?status=eq.ok&order=finished_at.desc&limit=1&select=counts,content_hash")) as {
      counts: Record<string, number>;
      content_hash: string | null;
    }[];
    return rows[0] ?? null;
  }

  private async upsert(table: string, conflict: string, rows: object[]): Promise<void> {
    for (let i = 0; i < rows.length; i += 1000) {
      await this.req("POST", `${table}?on_conflict=${conflict}`, rows.slice(i, i + 1000), "resolution=merge-duplicates,return=minimal");
    }
  }

  /** Idempotent: upsert everything with this run id, then delete rows the sources no longer contain. */
  async write(ds: Dataset, run: number): Promise<void> {
    await this.upsert("branches", "id", ds.branches.map((b) => ({ id: b.id, vendor_id: "apple", platform: b.platform, major: b.major, name: b.name })));
    await this.upsert(
      "releases",
      "id",
      ds.releases.map((r) => ({
        id: r.id,
        branch_id: r.branchId,
        version: r.version,
        suffix: r.suffix,
        kind: r.kind,
        release_date: r.releaseDate,
        rerelease_dates: r.rereleaseDates,
        name: r.name,
        advisory_url: r.advisoryUrl,
        has_cve_entries: r.hasCveEntries,
        last_seen_run: run,
      })),
    );
    await this.upsert(
      "cves",
      "id",
      ds.cves.map((c) => ({
        id: c.id,
        nvd_published: c.nvdPublished,
        kev_date_added: c.kevDateAdded,
        kev_due_date: c.kevDueDate,
        kev_vendor_project: c.kevVendorProject,
        last_seen_run: run,
      })),
    );
    await this.upsert(
      "release_cves",
      "release_id,cve_id",
      ds.releaseCves.map((l) => ({
        release_id: l.releaseId,
        cve_id: l.cveId,
        entry_added: l.entryAdded,
        entry_updated: l.entryUpdated,
        exploited_note: l.exploitedNote,
        last_seen_run: run,
      })),
    );
    for (const t of ["release_cves", "cves", "releases"]) await this.req("DELETE", `${t}?last_seen_run=lt.${run}`, undefined, "return=minimal");
  }
}
