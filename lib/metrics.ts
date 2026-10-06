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
  /** Sorted release dates of security releases (releases that list at least one CVE). */
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
      s = { firstReleaseDate: r.releaseDate, securityReleaseDates: [] };
      spans.set(r.branchId, s);
    }
    if (r.releaseDate < s.firstReleaseDate) s.firstReleaseDate = r.releaseDate;
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

/**
 * Branches still maintained on the data date: their last security release is at most
 * ACTIVE_BRANCH_DAYS old. Updates without published CVE entries do not count.
 */
export function maintainedBranchIds(idx: Index): Set<string> {
  const out = new Set<string>();
  for (const [id, span] of idx.spans) {
    const last = span.securityReleaseDates.at(-1);
    if (last && daysBetween(last, idx.asOf) <= ACTIVE_BRANCH_DAYS) out.add(id);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Per-CVE timeline

export type BranchStatus =
  | { kind: "fixed"; fixDate: string; releaseId: string; gapDays: number }
  | { kind: "no-fix-listed" }
  | { kind: "branch-ended"; lastSecurityReleaseDate: string | null }
  /**
   * The branch was first released after the earliest fix, so it is not a backport.
   * listed: an advisory of this branch lists the CVE (releaseId/fixDate from that listing);
   * otherwise the fix is assumed inherited and fixDate is the branch's first release.
   */
  | { kind: "fixed-at-branch-release"; fixDate: string; releaseId: string | null; listed: boolean };

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
  /** KEV files the CVE under a vendor other than Apple (e.g. Google for Chromium/ANGLE). Null when not third-party or unknown. */
  thirdPartyVendor: string | null;
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
  const cve: Cve = idx.cves.get(cveId) ?? { id: cveId, nvdPublished: null, kevDateAdded: null, kevDueDate: null, kevVendorProject: null };

  const appleExploitedNote = listings.some((l) => l.exploitedNote);
  const kevWindowDays = cve.kevDateAdded ? daysBetween(cve.kevDateAdded, firstFixDate) : null;
  const exploited = appleExploitedNote || cve.kevDateAdded !== null;
  const exploitedBeforePatch = appleExploitedNote || (kevWindowDays !== null && kevWindowDays > 0);
  const disclosureLagDays = cve.nvdPublished ? daysBetween(firstFixDate, cve.nvdPublished) : null;
  const vendor = cve.kevVendorProject?.trim() ?? null;
  const thirdPartyVendor = vendor && vendor.toLowerCase() !== "apple" ? vendor : null;

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
    thirdPartyVendor,
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
      // Not a backport target: the branch did not exist when the fix first shipped.
      // Only branches newer than the platform's newest at that date inherit the fix.
      if (fix) {
        outcomes.push({
          branch,
          older: false,
          status: { kind: "fixed-at-branch-release", fixDate: fix.release.releaseDate, releaseId: fix.release.id, listed: true },
        });
      } else if (branch.major > newestMajorAtFirstFix) {
        outcomes.push({ branch, older: false, status: { kind: "fixed-at-branch-release", fixDate: span.firstReleaseDate, releaseId: null, listed: false } });
      }
      continue;
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
    // Maintained = shipped a security release on/after the earliest fix, or its last security release
    // is recent enough that the next one may simply not be due yet. Updates without CVE entries don't count.
    const lastSecurity = span.securityReleaseDates.at(-1) ?? null;
    const maintained =
      lastSecurity !== null && (lastSecurity >= earliestFixDate || daysBetween(lastSecurity, idx.asOf) <= ACTIVE_BRANCH_DAYS);
    if (maintained) outcomes.push({ branch, older, status: { kind: "no-fix-listed" } });
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

/** Metric 1 — exploited CVEs: Apple's zero-day note, and KEV dateAdded relative to the first fix. */
export interface ExploitedSummary {
  exploited: number; // exploited CVEs in window
  appleNote: number; // of which Apple said "may have been exploited" (attacked before a patch existed)
  withKev: number;
  kevBeforePatch: number; // KEV dateAdded earlier than the first fix
  unknownKev: number; // exploited per Apple, not (yet) in KEV
  thirdParty: number; // KEV vendor is not Apple
  /** Over CVEs with a KEV date: first fix − KEV dateAdded. Worst = the largest value. */
  window: Stat;
  /** Same data, as "days from first fix until KEV listing" (positive = after), for plain-language text. */
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
    thirdParty: ex.filter((t) => t.thirdPartyVendor !== null).length,
    window: stat(withKev.map((t) => ({ days: t.kevWindowDays!, cveId: t.id }))),
    kevAfterPatch: stat(withKev.map((t) => ({ days: -t.kevWindowDays!, cveId: t.id }))),
  };
}

/** Metric 2 — backport gap per branch. */
export interface BranchGapRow {
  branch: Branch;
  maintained: boolean; // still receiving security releases on the data date
  fixed: Stat; // gap over CVEs this branch received
  sameDay: number; // fixed with gap 0
  noFixListed: number;
  branchEnded: number;
  atBranchRelease: number; // newer branch released after the earliest fix (not counted in gaps)
}

export interface BackportSummary {
  platform: Platform;
  scope: "exploited" | "all";
  cves: number;
  rows: BranchGapRow[]; // newest major first
  /** The oldest branch still maintained on the data date that is older than the newest branch — the headline. */
  oldestMaintained: BranchGapRow | null;
}

export function backportSummary(idx: Index, timelines: CveTimeline[], platform: Platform, scope: "exploited" | "all"): BackportSummary {
  const maintained = maintainedBranchIds(idx);
  const relevant = timelines.filter((t) => t.inWindow && (scope === "all" || t.exploited));
  const perBranch = new Map<string, { branch: Branch; gaps: { days: number; cveId: string }[]; noFix: number; ended: number; atRelease: number }>();
  let cves = 0;
  for (const t of relevant) {
    const p = t.platforms.find((x) => x.platform === platform);
    if (!p) continue;
    cves++;
    for (const o of p.outcomes) {
      let row = perBranch.get(o.branch.id);
      if (!row) {
        row = { branch: o.branch, gaps: [], noFix: 0, ended: 0, atRelease: 0 };
        perBranch.set(o.branch.id, row);
      }
      if (o.status.kind === "fixed") row.gaps.push({ days: o.status.gapDays, cveId: t.id });
      else if (o.status.kind === "no-fix-listed") row.noFix++;
      else if (o.status.kind === "branch-ended") row.ended++;
      else row.atRelease++;
    }
  }
  const rows: BranchGapRow[] = [...perBranch.values()]
    .sort((a, b) => b.branch.major - a.branch.major)
    .map((r) => ({
      branch: r.branch,
      maintained: maintained.has(r.branch.id),
      fixed: stat(r.gaps),
      sameDay: r.gaps.filter((g) => g.days === 0).length,
      noFixListed: r.noFix,
      branchEnded: r.ended,
      atBranchRelease: r.atRelease,
    }));
  const newest = rows[0]?.branch.major;
  const candidates = rows.filter((r) => r.maintained && r.branch.major !== newest && r.fixed.n > 0);
  return { platform, scope, cves, rows, oldestMaintained: candidates.at(-1) ?? null };
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
