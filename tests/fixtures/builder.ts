import type { Branch, Cve, Dataset, Platform, Release, ReleaseCve } from "../../lib/types.ts";

/** Small builder so each edge-case fixture reads like a release history. */
export class Fixture {
  branches: Branch[] = [];
  releases: Release[] = [];
  releaseCves: ReleaseCve[] = [];
  cves: Cve[] = [];
  /** Data date ("as of"); decides whether a quiet branch counts as still maintained. */
  asOf = "2026-10-06";

  branch(platform: Platform, major: number): string {
    const id = `${platform.toLowerCase()}-${major}`;
    if (!this.branches.some((b) => b.id === id)) this.branches.push({ id, platform, major, name: `${platform} ${major}` });
    return id;
  }

  /** release("iOS", "16.5.1", "2023-06-21", ["CVE-1"]) — suffix via opts. */
  release(
    platform: Platform,
    version: string,
    date: string,
    cves: (string | { id: string; entryAdded?: string; exploited?: boolean })[] = [],
    opts: { suffix?: string; kind?: Release["kind"]; rereleaseDates?: string[] } = {},
  ): string {
    const major = Number(version.split(".")[0]);
    const branchId = this.branch(platform, major);
    const id = `${branchId}:${version}${opts.suffix ?? ""}`;
    this.releases.push({
      id,
      branchId,
      version,
      suffix: opts.suffix ?? null,
      kind: opts.kind ?? (opts.suffix ? "rsr" : "full"),
      releaseDate: date,
      rereleaseDates: opts.rereleaseDates ?? [],
      name: `${platform} ${version}${opts.suffix ? ` ${opts.suffix}` : ""}`,
      advisoryUrl: cves.length ? `https://support.apple.com/en-us/${id}` : null,
      hasCveEntries: cves.length > 0,
    });
    for (const c of cves) {
      const o = typeof c === "string" ? { id: c } : c;
      this.releaseCves.push({ releaseId: id, cveId: o.id, entryAdded: o.entryAdded ?? null, entryUpdated: null, exploitedNote: o.exploited ?? false });
    }
    return id;
  }

  cve(id: string, f: Partial<Omit<Cve, "id">> = {}): this {
    this.cves = this.cves.filter((c) => c.id !== id);
    this.cves.push({
      id,
      nvdPublished: f.nvdPublished ?? null,
      kevDateAdded: f.kevDateAdded ?? null,
      kevDueDate: f.kevDueDate ?? null,
      kevVendorProject: f.kevVendorProject ?? (f.kevDateAdded ? "Apple" : null),
    });
    return this;
  }

  dataset(): Dataset {
    return {
      meta: { updatedAt: `${this.asOf}T00:00:00Z`, kevCatalogVersion: "test" },
      branches: this.branches,
      releases: this.releases,
      releaseCves: this.releaseCves,
      cves: this.cves,
    };
  }
}
