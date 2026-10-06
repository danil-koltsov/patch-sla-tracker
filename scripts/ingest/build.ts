import type { Branch, Cve, Dataset, Release, ReleaseCve } from "../../lib/types.ts";
import type { Advisory, AdvisorySection } from "./apple-advisory.ts";
import type { IndexRow } from "./apple-index.ts";
import { branchId, parseReleaseName, releaseId, sameRelease, type ReleaseIdentity } from "./apple-names.ts";

export interface KevEntry {
  dateAdded: string;
  dueDate: string | null;
  vendorProject: string | null;
}

export interface BuildInput {
  rows: IndexRow[];
  advisories: Map<string, Advisory>; // keyed by IndexRow.url
  kev: Map<string, KevEntry>;
  kevCatalogVersion: string | null;
  nvdPublished: Map<string, string | null>;
  updatedAt: string;
}

export interface BuildResult {
  dataset: Dataset;
  warnings: string[];
}

/** Turns parsed source documents into the normalized dataset. Pure. */
export function buildDataset(input: BuildInput): BuildResult {
  const warnings: string[] = [];
  const branches = new Map<string, Branch>();
  const releases = new Map<string, Release & { dates: Set<string> }>();
  const listings = new Map<string, ReleaseCve>();
  const codenames = new Map<number, string>();

  const rows = [...input.rows].sort((a, b) => a.date.localeCompare(b.date));
  for (const row of rows) {
    const isBsi = /^Background Security/i.test(row.name);
    const advisory = row.url ? input.advisories.get(row.url) : undefined;
    let ids = parseReleaseName(row.name);
    if (ids.length === 0 && (isBsi || /^Rapid Security/i.test(row.name)) && advisory) {
      ids = advisory.sections.flatMap((s) => parseReleaseName(s.heading));
    }
    if (ids.length === 0) continue;

    for (const id of ids) {
      if (id.codename && !codenames.has(id.major)) codenames.set(id.major, id.codename);
      const bId = branchId(id.platform, id.major);
      if (!branches.has(bId)) branches.set(bId, { id: bId, platform: id.platform, major: id.major, name: `${id.platform} ${id.major}` });

      const rId = releaseId(id);
      const existing = releases.get(rId);
      if (existing) {
        existing.dates.add(row.date);
        if (!existing.advisoryUrl && row.url) existing.advisoryUrl = row.url;
        if (row.url && !row.noCveEntries) existing.hasCveEntries = true;
      } else {
        releases.set(rId, {
          id: rId,
          branchId: bId,
          version: id.version,
          suffix: id.suffix,
          kind: isBsi ? "bsi" : id.suffix ? "rsr" : "full",
          releaseDate: row.date,
          rereleaseDates: [],
          name: row.name,
          advisoryUrl: row.url,
          hasCveEntries: row.url !== null && !row.noCveEntries,
          dates: new Set([row.date]),
        });
      }

      if (!advisory) continue;
      const section = pickSection(advisory, id);
      if (section === "ambiguous") {
        warnings.push(`ambiguous advisory sections for ${rId} at ${row.url}`);
        continue;
      }
      if (!section) continue;
      for (const e of section.entries) {
        for (const cveId of e.cves) {
          const key = `${rId}|${cveId}`;
          const prev = listings.get(key);
          if (prev) {
            prev.exploitedNote ||= e.exploited;
            if (e.entryAdded && (!prev.entryAdded || e.entryAdded < prev.entryAdded)) prev.entryAdded = e.entryAdded;
            if (e.entryUpdated && (!prev.entryUpdated || e.entryUpdated > prev.entryUpdated)) prev.entryUpdated = e.entryUpdated;
          } else {
            listings.set(key, { releaseId: rId, cveId, entryAdded: e.entryAdded, entryUpdated: e.entryUpdated, exploitedNote: e.exploited });
          }
        }
      }
    }
    if (advisory && row.url && !row.noCveEntries && advisory.sections.every((s) => s.entries.length === 0)) {
      warnings.push(`advisory has no parseable CVE entries: ${row.name} ${row.url}`);
    }
  }

  for (const b of branches.values()) {
    const cn = b.platform === "macOS" ? codenames.get(b.major) : undefined;
    if (cn) b.name = `macOS ${b.major} ${cn}`;
  }

  const releaseList: Release[] = [...releases.values()].map(({ dates, ...r }) => {
    const sorted = [...dates].sort();
    return { ...r, releaseDate: sorted[0]!, rereleaseDates: sorted.slice(1) };
  });

  const cveIds = new Set([...listings.values()].map((l) => l.cveId));
  const cves: Cve[] = [...cveIds].sort().map((id) => {
    const k = input.kev.get(id);
    return {
      id,
      nvdPublished: input.nvdPublished.get(id) ?? null,
      kevDateAdded: k?.dateAdded ?? null,
      kevDueDate: k?.dueDate ?? null,
      kevVendorProject: k?.vendorProject ?? null,
    };
  });

  return {
    dataset: {
      meta: { updatedAt: input.updatedAt, kevCatalogVersion: input.kevCatalogVersion },
      branches: [...branches.values()].sort((a, b) => a.id.localeCompare(b.id)),
      releases: releaseList.sort((a, b) => a.releaseDate.localeCompare(b.releaseDate) || a.id.localeCompare(b.id)),
      releaseCves: [...listings.values()].sort((a, b) => a.releaseId.localeCompare(b.releaseId) || a.cveId.localeCompare(b.cveId)),
      cves,
    },
    warnings,
  };
}

/** Which advisory section describes this release. */
function pickSection(advisory: Advisory, id: ReleaseIdentity): AdvisorySection | null | "ambiguous" {
  const matching = advisory.sections.filter((s) => parseReleaseName(s.heading).some((h) => sameRelease(h, id)));
  if (matching.length >= 1) return mergeSections(matching);
  const withEntries = advisory.sections.filter((s) => s.entries.length > 0);
  if (withEntries.length <= 1) return withEntries[0] ?? null;
  return "ambiguous";
}

function mergeSections(sections: AdvisorySection[]): AdvisorySection {
  if (sections.length === 1) return sections[0]!;
  return { heading: sections[0]!.heading, released: sections[0]!.released, entries: sections.flatMap((s) => s.entries) };
}
