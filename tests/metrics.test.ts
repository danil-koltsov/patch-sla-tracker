import { describe, expect, it } from "vitest";
import { Fixture } from "./fixtures/builder.ts";
import {
  allTimelines,
  backportSummary,
  buildIndex,
  cveTimeline,
  disclosureSummary,
  exploitedSummary,
  maintainedBranchIds,
  type BranchOutcome,
} from "../lib/metrics.ts";

function outcome(f: Fixture, cve: string, branchId: string): BranchOutcome | undefined {
  const t = cveTimeline(buildIndex(f.dataset()), cve)!;
  return t.platforms.flatMap((p) => p.outcomes).find((o) => o.branch.id === branchId);
}

/** Two live iOS branches (17 newest, 16 older) with regular security releases. */
function base(): Fixture {
  const f = new Fixture();
  f.release("iOS", "16.0", "2022-09-12", ["CVE-2022-0001"]);
  f.release("iOS", "17.0", "2023-09-18", ["CVE-2023-0001"]);
  return f;
}

describe("edge case: CVE fixed in several releases of the same branch", () => {
  it("uses the first release of that branch as its fix date", () => {
    const f = base();
    f.release("iOS", "17.1", "2023-10-25", ["CVE-2023-1000"]);
    f.release("iOS", "17.2", "2023-12-11", ["CVE-2023-1000"]); // re-listed (incomplete fix)
    f.release("iOS", "16.7.2", "2023-11-07", ["CVE-2023-1000"]);
    const o = outcome(f, "CVE-2023-1000", "ios-17")!;
    expect(o.status).toEqual({ kind: "fixed", fixDate: "2023-10-25", releaseId: "ios-17:17.1", gapDays: 0 });
    expect(outcome(f, "CVE-2023-1000", "ios-16")!.status).toMatchObject({ kind: "fixed", gapDays: 13 });
  });
});

describe("edge case: re-releases and letter-suffix emergency updates", () => {
  it("counts a Rapid Security Response (a) as the first fix, ahead of the full release", () => {
    const f = base();
    f.release("iOS", "16.5.1", "2023-07-10", [{ id: "CVE-2023-37450", exploited: true }], { suffix: "(a)" });
    f.release("iOS", "16.5.1", "2023-07-12", [], { suffix: "(c)" }); // replacement RSR, no new CVEs
    f.release("iOS", "16.6", "2023-07-24", [{ id: "CVE-2023-37450", exploited: true }]);
    f.cve("CVE-2023-37450", { kevDateAdded: "2023-07-13" });
    const t = cveTimeline(buildIndex(f.dataset()), "CVE-2023-37450")!;
    expect(t.firstFixDate).toBe("2023-07-10");
    expect(t.firstFixReleaseIds).toEqual(["ios-16:16.5.1(a)"]);
    expect(t.kevWindowDays).toBe(-3); // KEV listed 3 days after the RSR
    expect(t.exploitedBeforePatch).toBe(true); // Apple's own note
  });

  it("uses the original date of a re-released update, not the re-release date", () => {
    const f = base();
    f.release("iOS", "17.7.7", "2026-03-24", ["CVE-2026-0007"], { rereleaseDates: ["2026-04-01"] });
    const t = cveTimeline(buildIndex(f.dataset()), "CVE-2026-0007")!;
    expect(t.firstFixDate).toBe("2026-03-24");
  });
});

describe("edge case: CVE added to release notes after the release date", () => {
  it("keeps the release date as fix date and reports the late advisory entry separately", () => {
    const f = base();
    f.release("iOS", "17.2", "2023-12-11", [{ id: "CVE-2024-0100", entryAdded: "2024-05-13" }]);
    f.cve("CVE-2024-0100", { nvdPublished: "2024-05-14" });
    const timelines = allTimelines(buildIndex(f.dataset()));
    const t = timelines.find((x) => x.id === "CVE-2024-0100")!;
    expect(t.firstFixDate).toBe("2023-12-11");
    expect(t.disclosureLagDays).toBe(155);
    expect(disclosureSummary(timelines).lateAdvisoryEntries).toBe(1);
  });
});

describe("edge case: missing NVD or KEV dates", () => {
  it("reports unknown (null) and excludes them from medians", () => {
    const f = base();
    f.release("iOS", "17.3", "2024-01-22", [{ id: "CVE-2024-0001", exploited: true }, "CVE-2024-0002", "CVE-2024-0003"]);
    f.cve("CVE-2024-0002", { nvdPublished: "2024-01-23" });
    // CVE-2024-0001: exploited per Apple, no KEV, no NVD. CVE-2024-0003: no record at all.
    const timelines = allTimelines(buildIndex(f.dataset()));
    const t1 = timelines.find((x) => x.id === "CVE-2024-0001")!;
    expect(t1.kevWindowDays).toBeNull();
    expect(t1.disclosureLagDays).toBeNull();
    expect(t1.exploited).toBe(true);

    const ex = exploitedSummary(timelines);
    expect(ex.exploited).toBe(1);
    expect(ex.unknownKev).toBe(1);
    expect(ex.window.median).toBeNull();

    const d = disclosureSummary(timelines);
    expect(d.lag.n).toBe(1);
    expect(d.lag.median).toBe(1);
    expect(d.unknown).toBe(d.cves - 1);
  });
});

describe("edge case: branch that stopped receiving updates entirely", () => {
  it("is 'branch-ended', not 'no-fix-listed'", () => {
    const f = base();
    f.release("iOS", "15.7.9", "2023-09-11", ["CVE-2023-0915"]); // last ever iOS 15 security release
    f.release("iOS", "16.7.5", "2024-01-22", ["CVE-2024-0500"]);
    f.release("iOS", "17.3", "2024-01-22", ["CVE-2024-0500", "CVE-2024-0501"]);
    f.release("iOS", "16.7.6", "2024-03-05", ["CVE-2024-0600"]); // iOS 16 keeps getting updates
    expect(outcome(f, "CVE-2024-0501", "ios-15")!.status).toEqual({ kind: "branch-ended", lastSecurityReleaseDate: "2023-09-11" });
    expect(outcome(f, "CVE-2024-0501", "ios-16")!.status).toEqual({ kind: "no-fix-listed" });

    const idx = buildIndex(f.dataset());
    const s = backportSummary(idx, allTimelines(idx), "iOS", "all");
    const row15 = s.rows.find((r) => r.branch.id === "ios-15")!;
    expect(row15.noFixListed).toBe(0);
    expect(row15.branchEnded).toBeGreaterThan(0);
  });
});

describe("edge case: CVE fixed in an older branch before the newest one", () => {
  it("measures the newest branch's gap from the older branch's earlier fix", () => {
    const f = base();
    f.release("iOS", "16.7.8", "2024-05-13", ["CVE-2024-0800"]);
    f.release("iOS", "17.6", "2024-07-29", ["CVE-2024-0800"]);
    expect(outcome(f, "CVE-2024-0800", "ios-16")!.status).toMatchObject({ kind: "fixed", gapDays: 0 });
    expect(outcome(f, "CVE-2024-0800", "ios-17")!.status).toMatchObject({ kind: "fixed", gapDays: 77 });
    expect(outcome(f, "CVE-2024-0800", "ios-17")!.older).toBe(false);
  });

  it("does not count a new major release that re-lists a fix shipped before it existed", () => {
    const f = base();
    f.release("iOS", "17.6", "2024-07-29", ["CVE-2024-0900"]);
    f.release("iOS", "18.0", "2024-09-16", ["CVE-2024-0900"]);
    const o = outcome(f, "CVE-2024-0900", "ios-18")!;
    expect(o.status).toEqual({ kind: "fixed-at-branch-release", fixDate: "2024-09-16", releaseId: "ios-18:18.0", listed: true });
    const idx = buildIndex(f.dataset());
    const row = backportSummary(idx, allTimelines(idx), "iOS", "all").rows.find((r) => r.branch.id === "ios-18")!;
    expect(row.fixed.n).toBe(0);
    expect(row.atBranchRelease).toBe(2); // this CVE + base fixture CVE-2023-0001, both shipped before iOS 18 existed
  });
});

describe("window and aggregates", () => {
  it("excludes CVEs first fixed before the window start", () => {
    const f = base();
    f.release("iOS", "16.2", "2022-12-13", ["CVE-2022-1213"]);
    f.release("iOS", "15.7.3", "2023-01-23", ["CVE-2022-1213"]);
    const t = cveTimeline(buildIndex(f.dataset()), "CVE-2022-1213")!;
    expect(t.inWindow).toBe(false);
    expect(disclosureSummary([t]).cves).toBe(0);
  });

  it("reports the oldest maintained branch's median and worst case, exploited only", () => {
    const f = base();
    f.asOf = "2024-01-15";
    f.release("iOS", "17.1", "2023-10-25", ["CVE-A", "CVE-B", "CVE-C"]);
    f.release("iOS", "16.7.2", "2023-10-25", ["CVE-A"]);
    f.release("iOS", "16.7.3", "2023-11-04", ["CVE-B"]);
    f.release("iOS", "16.7.4", "2023-12-24", ["CVE-D"]); // keeps branch alive; CVE-C never listed
    f.cve("CVE-A", { kevDateAdded: "2023-10-26" }).cve("CVE-B", { kevDateAdded: "2023-10-20" }).cve("CVE-C", { kevDateAdded: "2023-10-27" });
    const idx = buildIndex(f.dataset());
    const timelines = allTimelines(idx);
    const s = backportSummary(idx, timelines, "iOS", "exploited");
    expect(s.cves).toBe(3);
    const o = s.oldestMaintained!;
    expect(o.branch.id).toBe("ios-16");
    expect(o.fixed.n).toBe(2);
    expect(o.fixed.median).toBe(5); // gaps 0 and 10
    expect(o.fixed.worst).toEqual({ days: 10, cveId: "CVE-B" });
    expect(o.noFixListed).toBe(1);

    const e = exploitedSummary(timelines);
    expect(e.withKev).toBe(3);
    expect(e.kevBeforePatch).toBe(1); // CVE-B listed 5 days before the fix
    expect(e.window.worst).toEqual({ days: 5, cveId: "CVE-B" });
    expect(e.kevAfterPatch.median).toBe(1);
  });

  it("keeps platforms separate (iPadOS-only branch)", () => {
    const f = base();
    f.release("iOS", "18.3", "2025-01-27", ["CVE-2025-24085"]);
    f.release("iPadOS", "18.3", "2025-01-27", ["CVE-2025-24085"]);
    f.release("iPadOS", "17.7.3", "2024-12-11", ["CVE-2024-1211"]);
    f.release("iPadOS", "17.7.6", "2025-03-31", ["CVE-2025-24085"]);
    const t = cveTimeline(buildIndex(f.dataset()), "CVE-2025-24085")!;
    expect(t.platforms.map((p) => p.platform)).toEqual(["iOS", "iPadOS"]);
    const ipad17 = t.platforms[1]!.outcomes.find((o) => o.branch.id === "ipados-17")!;
    expect(ipad17.status).toMatchObject({ kind: "fixed", gapDays: 63 });
    expect(ipad17.older).toBe(true);
  });
});

describe("export", async () => {
  const { exportRows, toCsv } = await import("../lib/export.ts");
  it("writes unknowns as empty cells and provenance columns on every row", () => {
    const f = base();
    f.release("iOS", "17.1", "2023-10-25", ["CVE-2023-1"]);
    const rows = exportRows(allTimelines(buildIndex(f.dataset())).filter((t) => t.id === "CVE-2023-1"));
    const csv = toCsv(rows, { methodology_version: "1.0.0", data_updated_at: "2026-10-06T00:00:00Z" });
    const lines = csv.trimEnd().split("\r\n");
    expect(lines[0]!.startsWith("cve_id,")).toBe(true);
    expect(lines[0]!.endsWith(",methodology_version,data_updated_at")).toBe(true);
    const line = lines.find((l) => l.startsWith("CVE-2023-1,"))!;
    expect(line).toContain(",,"); // null KEV date
    expect(line.endsWith(",1.0.0,2026-10-06T00:00:00Z")).toBe(true);
  });
});

describe("edge case: recent fix, branch whose next update is not due yet", () => {
  it("is 'no-fix-listed', not 'branch-ended', when the branch released recently", () => {
    const f = base();
    f.release("iOS", "17.6", "2026-09-14", ["CVE-2026-0001"]);
    f.release("iOS", "18.0", "2026-09-14", ["CVE-2026-0001"]);
    f.release("iOS", "18.0.1", "2026-09-28", []); // no published CVE entries
    f.release("iOS", "17.6.1", "2026-09-28", ["CVE-2026-0002"]); // asOf is 2026-10-06
    expect(outcome(f, "CVE-2026-0002", "ios-18")!.status).toEqual({ kind: "no-fix-listed" });
  });
});

describe("rule: branch first released after the earliest fix (fixed at branch release)", () => {
  it("marks an unlisted newer branch as inherited, not 'no fix listed', and keeps it out of gaps", () => {
    const f = base();
    f.release("iOS", "17.6", "2024-07-29", ["CVE-2024-0950"]);
    f.release("iOS", "18.0", "2024-09-16", ["CVE-2024-0951"]); // does not list CVE-2024-0950
    const o = outcome(f, "CVE-2024-0950", "ios-18")!;
    expect(o.status).toEqual({ kind: "fixed-at-branch-release", fixDate: "2024-09-16", releaseId: null, listed: false });
    const idx = buildIndex(f.dataset());
    const row = backportSummary(idx, allTimelines(idx), "iOS", "all").rows.find((r) => r.branch.id === "ios-18")!;
    expect(row.noFixListed).toBe(0);
    expect(row.atBranchRelease).toBe(2); // this CVE + base fixture CVE-2023-0001, both shipped before iOS 18 existed
  });

  it("does not apply when the branch existed before the fix (CVE-2026-86950 on iOS 27)", () => {
    // Real shape: iOS 27.0 shipped 2026-09-14; the fix shipped in iOS 26.7.1 on 2026-09-28;
    // iOS 27.0.1 shipped the same day with no published CVE entries.
    const f = new Fixture();
    f.release("iOS", "26.7", "2026-09-14", ["CVE-2026-0100"]);
    f.release("iOS", "27.0", "2026-09-14", ["CVE-2026-0100"]);
    f.release("iOS", "26.7.1", "2026-09-28", [{ id: "CVE-2026-86950", exploited: true }]);
    f.release("iOS", "27.0.1", "2026-09-28", []);
    expect(outcome(f, "CVE-2026-86950", "ios-27")!.status).toEqual({ kind: "no-fix-listed" });
  });
});

describe("rule: only security releases keep a branch maintained", () => {
  it("ends a branch whose only recent update has no CVE entries (iOS 12.5.8 shape)", () => {
    const f = base();
    f.release("iOS", "12.5.7", "2023-01-23", ["CVE-2023-0123"]); // last security release
    f.release("iOS", "12.5.8", "2026-01-26", []); // no published CVE entries
    f.release("iOS", "17.4", "2024-03-05", ["CVE-2024-0305"]);
    expect(outcome(f, "CVE-2024-0305", "ios-12")!.status).toEqual({ kind: "branch-ended", lastSecurityReleaseDate: "2023-01-23" });
    expect(maintainedBranchIds(buildIndex(f.dataset())).has("ios-12")).toBe(false);
  });

  it("keeps a branch maintained when its last security release is recent, even before its next one", () => {
    const f = base();
    f.release("iOS", "16.7.15", "2026-05-11", ["CVE-2026-0511"]); // 148 days before asOf
    f.release("iOS", "17.7.9", "2026-09-28", ["CVE-2026-0928"]);
    expect(outcome(f, "CVE-2026-0928", "ios-16")!.status).toEqual({ kind: "no-fix-listed" });
    expect(maintainedBranchIds(buildIndex(f.dataset())).has("ios-16")).toBe(true);
  });
});

describe("third-party components", () => {
  it("labels CVEs whose KEV vendor is not Apple", () => {
    const f = base();
    f.release("iOS", "17.5", "2024-05-13", ["CVE-2025-6558", "CVE-2024-0513"]);
    f.cve("CVE-2025-6558", { kevDateAdded: "2024-05-20", kevVendorProject: "Google" });
    f.cve("CVE-2024-0513", { kevDateAdded: "2024-05-20", kevVendorProject: "Apple" });
    const idx = buildIndex(f.dataset());
    expect(cveTimeline(idx, "CVE-2025-6558")!.thirdPartyVendor).toBe("Google");
    expect(cveTimeline(idx, "CVE-2024-0513")!.thirdPartyVendor).toBeNull();
    expect(exploitedSummary(allTimelines(idx)).thirdParty).toBe(1);
  });
});
