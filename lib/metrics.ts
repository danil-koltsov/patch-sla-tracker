/**
 * The three metrics. Pure functions over a Dataset; no I/O.
 * Definitions live in lib/methodology.ts and /methodology.
 */
import type { Branch, Cve, Dataset, Platform, Release, ReleaseCve } from "./types.ts";
import { PLATFORMS } from "./types.ts";
import { daysBetween, maxDate, minDate } from "./dates.ts";
import { median, worst } from "./stats.ts";
import { ACTIVE_BRANCH_DAYS, WINDOW_START } from "./methodology.ts";

// ---------------------------------------------------------------------------
// Index

export interface BranchSpan {
  firstReleaseDate: string;
  /** Last release of any kind, including ones with no published CVE entries. */
  lastReleaseDate: string;
  /** Sorted release dates of releases that list at least one CVE. */
  securityReleaseDates: string[];
}

export interface Index {
  branches: Map<string, Branch>;
  releases: Map<string, Release>;
  spans: Map<string, BranchSpan>;
  listingsByCve: Map<string, ReleaseCve[]>;
  cves: Map<string, Cve>;
  /** Date the data describes ("as of"); used to tell an ended branch from one whose next update is still due. */
  asOf: string;
}

export function buildIndex(ds: Pick<Dataset, "branches" | "releases" | "releaseCves" | "cves"> & { meta?: Dataset["meta"] }): Index {
  const branches = new Map(ds.branches.map((b) => [b.id, b]));
  const releases = new Map(ds.releases.map((r) => [r.id, r]));
  const spans = new Map<string, BranchSpan>();
  for (const r of ds.releases) {
    let s = spans.get(r.branchId);
    if (!s) {
      s = { firstReleaseDate: r.releaseDate, lastReleaseDate: r.releaseDate, securityReleaseDates: [] };
      spans.set(r.branchId, s);
    }
    if (r.releaseDate < s.firstReleaseDate) s.firstReleaseDate = r.releaseDate;
    const last = [r.releaseDate, ...r.rereleaseDates].sort().at(-1)!;
    if (last > s.lastReleaseDate) s.lastReleaseDate = last;
    if (r.hasCveEntries) s.securityReleaseDates.push(r.releaseDate);
  }
  for (const s of spans.values()) s.securityReleaseDates.sort();
  const listingsByCve = new Map<string, ReleaseCve[]>();
  for (const rc of ds.releaseCves) {
    if (!releases.has(rc.releaseId)) continue;
    const l = listingsByCve.get(rc.cveId);
    if (l) l.push(rc);
    else listingsByCve.set(rc.cveId, [rc]);
  }
  const cves = new Map(ds.cves.map((c) => [c.id, c]));
  const latestRelease = maxDate(ds.releases.map((r) => r.releaseDate)) ?? "1970-01-01";
  const asOf = ds.meta?.updatedAt ? ds.meta.updatedAt.slice(0, 10) : latestRelease;
  return { branches, releases, spans, listingsByCve, cves, asOf };
}

// ---------------------------------------------------------------------------
// Per-CVE timeline

export type BranchStatus =
  | { kind: "fixed"; fixDate: string; releaseId: string; gapDays: number }
  | { kind: "no-fix-listed" }
  | { kind: "branch-ended"; lastSecurityReleaseDate: string | null }
  | { kind: "later-major"; fixDate: string; releaseId: string };

export interface BranchOutcome {
  branch: Branch;
  status: BranchStatus;
  /** True when this branch's major is below the newest major that existed at the earliest fix. */
  older: boolean;
}

export interface PlatformTimeline {
  platform: Platform;
  earliestFixDate: string;
  newestMajorAtFirstFix: number;
  outcomes: BranchOutcome[]; // sorted by major, newest first
}

export interface Listing {
  release: Release;
  branch: Branch;
  entryAdded: string | null;
  entryUpdated: string | null;
  exploitedNote: boolean;
}

export interface CveTimeline {
  id: string;
  cve: Cve; // synthesized with nulls when no NVD/KEV record exists
  listings: Listing[]; // sorted by release date
  firstFixDate: string;
  firstFixReleaseIds: string[];
  inWindow: boolean;
  exploited: boolean;
  appleExploitedNote: boolean;
  /** Documented exploitation before a patch existed (Apple's note, or KEV listing earlier than the first fix). */
  exploitedBeforePatch: boolean;
  /** Metric 1: first fix − KEV dateAdded, in days. Positive = KEV listed it before a patch existed. */
  kevWindowDays: number | null;
  /** Metric 3: NVD published − first fix, in days. */
  disclosureLagDays: number | null;
  platforms: PlatformTimeline[];
}

export function cveTimeline(idx: Index, cveId: string): CveTimeline | null {
  const raw = idx.listingsByCve.get(cveId);
  if (!raw || raw.length === 0) return null;

  const listings: Listing[] = raw
    .map((rc) => {
      const release = idx.releases.get(rc.releaseId)!;
      const branch = idx.branches.get(release.branchId)!;
      return { release, branch, entryAdded: rc.entryAdded, entryUpdated: rc.entryUpdated, exploitedNote: rc.exploitedNote };
    })
    .sort((a, b) => a.release.releaseDate.localeCompare(b.release.releaseDate) || a.release.id.localeCompare(b.release.id));

  const firstFixDate = listings[0]!.release.releaseDate;
  const firstFixReleaseIds = listings.filter((l) => l.release.releaseDate === firstFixDate).map((l) => l.release.id);
  const cve: Cve = idx.cves.get(cveId) ?? { id: cveId, nvdPublished: null, kevDateAdded: null, kevDueDate: null };

  const appleExploitedNote = listings.some((l) => l.exploitedNote);
  const kevWindowDays = cve.kevDateAdded ? daysBetween(cve.kevDateAdded, firstFixDate) : null;
  const exploited = appleExploitedNote || cve.kevDateAdded !== null;
  const exploitedBeforePatch = appleExploitedNote || (kevWindowDays !== null && kevWindowDays > 0);
  const disclosureLagDays = cve.nvdPublished ? daysBetween(firstFixDate, cve.nvdPublished) : null;

  const platforms: PlatformTimeline[] = [];
  for (const platform of PLATFORMS) {
    const pl = listings.filter((l) => l.branch.platform === platform);
    if (pl.length === 0) continue;
    platforms.push(platformTimeline(idx, platform, pl));
  }

  return {
    id: cveId,
    cve,
    listings,
    firstFixDate,
    firstFixReleaseIds,
    inWindow: firstFixDate >= WINDOW_START,
    exploited,
    appleExploitedNote,
    exploitedBeforePatch,
    kevWindowDays,
    disclosureLagDays,
    platforms,
  };
}

function platformTimeline(idx: Index, platform: Platform, listings: Listing[]): PlatformTimeline {
  const earliestFixDate = minDate(listings.map((l) => l.release.releaseDate))!;

  // First fix per branch (several releases of one branch may list the same CVE).
  const firstByBranch = new Map<string, Listing>();
  for (const l of listings) {
    const cur = firstByBranch.get(l.branch.id);
    if (!cur || l.release.releaseDate < cur.release.releaseDate) firstByBranch.set(l.branch.id, l);
  }

  const platformBranches = [...idx.branches.values()].filter((b) => b.platform === platform);
  const existedAt = (b: Branch) => {
    const span = idx.spans.get(b.id);
    return span !== undefined && span.firstReleaseDate <= earliestFixDate;
  };
  const newestMajorAtFirstFix = Math.max(...platformBranches.filter(existedAt).map((b) => b.major));

  const outcomes: BranchOutcome[] = [];
  for (const branch of platformBranches) {
    const span = idx.spans.get(branch.id);
    if (!span) continue;
    const fix = firstByBranch.get(branch.id);
    const older = branch.major < newestMajorAtFirstFix;
    if (!existedAt(branch)) {
      if (fix) outcomes.push({ branch, older: false, status: { kind: "later-major", fixDate: fix.release.releaseDate, releaseId: fix.release.id } });
      continue; // branches that did not exist yet and never listed it are irrelevant
    }
    if (fix) {
      outcomes.push({
        branch,
        older,
        status: { kind: "fixed", fixDate: fix.release.releaseDate, releaseId: fix.release.id, gapDays: daysBetween(earliestFixDate, fix.release.releaseDate) },
      });
      continue;
    }
    const lastBefore = span.securityReleaseDates.filter((d) => d < earliestFixDate).at(-1) ?? null;
    // Still maintained: it shipped something on/after the earliest fix, or its next update may simply not be due yet.
    const stillActive =
      span.lastReleaseDate >= earliestFixDate || daysBetween(span.lastReleaseDate, idx.asOf) <= ACTIVE_BRANCH_DAYS;
    if (stillActive) outcomes.push({ branch, older, status: { kind: "no-fix-listed" } });
    else if (lastBefore !== null) outcomes.push({ branch, older, status: { kind: "branch-ended", lastSecurityReleaseDate: lastBefore } });
    // A branch with no security releases at all, ever, carries no information: omitted.
  }
  outcomes.sort((a, b) => b.branch.major - a.branch.major);
  return { platform, earliestFixDate, newestMajorAtFirstFix, outcomes };
}

export function allTimelines(idx: Index): CveTimeline[] {
  const out: CveTimeline[] = [];
  for (const id of idx.listingsByCve.keys()) {
    const t = cveTimeline(idx, id);
    if (t) out.push(t);
  }
  return out.sort((a, b) => b.firstFixDate.localeCompare(a.firstFixDate) || a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------------------
// Aggregates (median and worst case, never the mean)

export interface Stat {
  n: number;
  median: number | null;
  worst: { days: number; cveId: string } | null;
}

function stat(rows: { days: number; cveId: string }[]): Stat {
  const w = worst(rows, (r) => r.days);
  return { n: rows.length, median: median(rows.map((r) => r.days)), worst: w ? { days: w.value, cveId: w.item.cveId } : null };
}

/** Metric 1 — exploited CVEs: KEV dateAdded relative to the first fix. */
export interface ExploitedSummary {
  exploited: number; // exploited CVEs in window
  appleNote: number; // of which Apple said "may have been exploited"
  withKev: number;
  kevBeforePatch: number; // KEV dateAdded earlier than the first fix
  unknownKev: number; // exploited per Apple, not (yet) in KEV
  /** Over CVEs with a KEV date: first fix − KEV dateAdded. Worst = the largest value. */
  window: Stat;
  /** Same data, as "days from first fix until KEV listing" (positive = after), for plain-language headlines. */
  kevAfterPatch: Stat;
}

export function exploitedSummary(timelines: CveTimeline[]): ExploitedSummary {
  const ex = timelines.filter((t) => t.inWindow && t.exploited);
  const withKev = ex.filter((t) => t.kevWindowDays !== null);
  return {
    exploited: ex.length,
    appleNote: ex.filter((t) => t.appleExploitedNote).length,
    withKev: withKev.length,
    kevBeforePatch: withKev.filter((t) => t.kevWindowDays! > 0).length,
    unknownKev: ex.length - withKev.length,
    window: stat(withKev.map((t) => ({ days: t.kevWindowDays!, cveId: t.id }))),
    kevAfterPatch: stat(withKev.map((t) => ({ days: -t.kevWindowDays!, cveId: t.id }))),
  };
}

/** Metric 2 — backport gap per branch. */
export interface BranchGapRow {
  branch: Branch;
  fixed: Stat; // gap over CVEs this branch received
  sameDay: number; // fixed with gap 0
  noFixListed: number;
  branchEnded: number;
}

export interface BackportSummary {
  platform: Platform;
  scope: "exploited" | "all";
  cves: number;
  rows: BranchGapRow[]; // newest major first
  /** Gaps on branches older than the newest branch existing at the earliest fix. */
  older: Stat & { noFixListed: number };
}

export function backportSummary(timelines: CveTimeline[], platform: Platform, scope: "exploited" | "all"): BackportSummary {
  const relevant = timelines.filter((t) => t.inWindow && (scope === "all" || t.exploited));
  const perBranch = new Map<string, { branch: Branch; gaps: { days: number; cveId: string }[]; noFix: number; ended: number }>();
  const olderGaps: { days: number; cveId: string }[] = [];
  let olderNoFix = 0;
  let cves = 0;
  for (const t of relevant) {
    const p = t.platforms.find((x) => x.platform === platform);
    if (!p) continue;
    cves++;
    for (const o of p.outcomes) {
      if (o.status.kind === "later-major") continue;
      let row = perBranch.get(o.branch.id);
      if (!row) {
        row = { branch: o.branch, gaps: [], noFix: 0, ended: 0 };
        perBranch.set(o.branch.id, row);
      }
      if (o.status.kind === "fixed") {
        row.gaps.push({ days: o.status.gapDays, cveId: t.id });
        if (o.older) olderGaps.push({ days: o.status.gapDays, cveId: t.id });
      } else if (o.status.kind === "no-fix-listed") {
        row.noFix++;
        if (o.older) olderNoFix++;
      } else row.ended++;
    }
  }
  const rows = [...perBranch.values()]
    .sort((a, b) => b.branch.major - a.branch.major)
    .map((r) => ({ branch: r.branch, fixed: stat(r.gaps), sameDay: r.gaps.filter((g) => g.days === 0).length, noFixListed: r.noFix, branchEnded: r.ended }));
  return { platform, scope, cves, rows, older: { ...stat(olderGaps), noFixListed: olderNoFix } };
}

/** Metric 3 — disclosure lag (NVD published − first fix) over all CVEs in window. */
export interface DisclosureSummary {
  cves: number;
  lag: Stat;
  unknown: number;
  publishedBeforeFix: number;
  lateAdvisoryEntries: number; // CVEs whose first listing carries "Entry added" after the release date
}

export function disclosureSummary(timelines: CveTimeline[]): DisclosureSummary {
  const inWin = timelines.filter((t) => t.inWindow);
  const known = inWin.filter((t) => t.disclosureLagDays !== null);
  return {
    cves: inWin.length,
    lag: stat(known.map((t) => ({ days: t.disclosureLagDays!, cveId: t.id }))),
    unknown: inWin.length - known.length,
    publishedBeforeFix: known.filter((t) => t.disclosureLagDays! < 0).length,
    lateAdvisoryEntries: inWin.filter((t) =>
      t.listings.some((l) => l.release.releaseDate === t.firstFixDate && l.entryAdded !== null && l.entryAdded > t.firstFixDate),
    ).length,
  };
}
