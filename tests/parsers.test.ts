import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseAdvisory } from "../scripts/ingest/apple-advisory.ts";
import { parseIndex } from "../scripts/ingest/apple-index.ts";
import { parseReleaseName, releaseId } from "../scripts/ingest/apple-names.ts";
import { buildDataset } from "../scripts/ingest/build.ts";
import { parseKev } from "../scripts/ingest/kev.ts";
import { parseNvdPage } from "../scripts/ingest/nvd.ts";
import { parseEnglishDate } from "../lib/dates.ts";

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");

describe("parseReleaseName", () => {
  it.each([
    ["iOS 26.7.1 and iPadOS 26.7.1", ["iOS 26.7.1", "iPadOS 26.7.1"]],
    ["iOS 26 and iPadOS 26", ["iOS 26", "iPadOS 26"]],
    ["iPadOS 17.7.11", ["iPadOS 17.7.11"]],
    ["macOS Golden Gate 27.0.1", ["macOS 27.0.1"]],
    ["macOS Ventura 13.1", ["macOS 13.1"]],
    ["Rapid Security Response iOS 16.5.1 (c) & iPadOS 16.5.1 (c)", ["iOS 16.5.1(c)", "iPadOS 16.5.1(c)"]],
    ["iOS 26.3.1 (a), iPadOS 26.3.1 (a), macOS 26.3.1 (a), macOS 26.3.2 (a)", ["iOS 26.3.1(a)", "iPadOS 26.3.1(a)", "macOS 26.3.1(a)", "macOS 26.3.2(a)"]],
    ["macOS Monterey 12.0.1 (Advisory includes security content of macOS Monterey 12.0 and macOS Monterey 12.0.1)", ["macOS 12.0.1"]],
    ["Safari 26.2", []],
    ["watchOS 26.2", []],
    ["macOS Server 5.12.2", []],
    ["Security Update 2022-005 Catalina", []],
  ])("%s", (name, expected) => {
    expect(parseReleaseName(name).map((r) => `${r.platform} ${r.version}${r.suffix ?? ""}`)).toEqual(expected);
  });

  it("keeps macOS codenames and builds stable ids", () => {
    const [r] = parseReleaseName("macOS Sonoma 14.7.2");
    expect(r).toMatchObject({ platform: "macOS", major: 14, codename: "Sonoma" });
    expect(releaseId(parseReleaseName("iOS 16.5.1 (a)")[0]!)).toBe("ios-16.5.1-a");
  });
});

describe("parseEnglishDate", () => {
  it("parses both Apple formats and rejects junk", () => {
    expect(parseEnglishDate("March 5, 2024")).toBe("2024-03-05");
    expect(parseEnglishDate("05 Mar 2024")).toBe("2024-03-05");
    expect(parseEnglishDate("31 Feb 2024")).toBeNull();
    expect(parseEnglishDate("soon")).toBeNull();
  });
});

describe("parseIndex", () => {
  const rows = parseIndex(fx("index.html"));
  it("skips the header and reads name, date, link", () => {
    expect(rows).toHaveLength(8);
    expect(rows[0]).toEqual({ name: "iOS 27.0.1 and iPadOS 27.0.1", date: "2026-09-28", url: null, noCveEntries: true });
    expect(rows[2]!.url).toBe("https://support.apple.com/en-us/127112");
    expect(rows[5]!.name).toBe("Rapid Security Response iOS 16.5.1 (c) & iPadOS 16.5.1 (c)");
  });
});

describe("parseAdvisory", () => {
  it("reads sections, CVEs, entry notes and exploitation notes; ignores prose, scripts, recognition", () => {
    const a = parseAdvisory(fx("advisory-entries.html"));
    expect(a.title).toBe("About the security content of iOS 26.2 and iPadOS 26.2");
    expect(a.sections).toHaveLength(1);
    const s = a.sections[0]!;
    expect(s.released).toBe("2025-12-12");
    expect(s.entries).toEqual([
      { cves: ["CVE-2025-46288"], entryAdded: null, entryUpdated: null, exploited: false },
      { cves: ["CVE-2025-43537"], entryAdded: "2026-02-11", entryUpdated: "2026-03-24", exploited: false },
      { cves: ["CVE-2025-14174", "CVE-2025-43529"], entryAdded: null, entryUpdated: "2026-01-09", exploited: true },
    ]);
  });

  it("splits Rapid Security Response (a)/(c) sections", () => {
    const a = parseAdvisory(fx("advisory-rsr.html"));
    expect(a.sections.map((s) => [s.heading, s.released, s.entries.length])).toEqual([
      ["iOS 16.5.1 (a) and iPadOS 16.5.1 (a)", "2023-07-10", 1],
      ["iOS 16.5.1 (c) and iPadOS 16.5.1 (c)", "2023-07-12", 0],
    ]);
    expect(a.sections[0]!.entries[0]!.exploited).toBe(true);
  });
});

describe("buildDataset", () => {
  const rows = parseIndex(fx("index.html"));
  const advisories = new Map([
    ["https://support.apple.com/kb/HT213823", parseAdvisory(fx("advisory-rsr.html"))],
    ["https://support.apple.com/en-us/126793", parseAdvisory(fx("advisory-entries.html").replaceAll("26.2", "18.7.7"))],
  ]);
  const { dataset, warnings } = buildDataset({
    rows,
    advisories,
    kev: new Map([["CVE-2023-37450", { dateAdded: "2023-07-13", dueDate: "2023-08-03" }]]),
    kevCatalogVersion: "t",
    nvdPublished: new Map([["CVE-2023-37450", "2023-07-27"]]),
    updatedAt: "2026-10-06T00:00:00Z",
  });

  it("creates one release per platform and merges re-releases", () => {
    const r = dataset.releases.find((x) => x.id === "ios-18.7.7")!;
    expect(r.releaseDate).toBe("2026-03-24");
    expect(r.rereleaseDates).toEqual(["2026-04-01"]);
    expect(dataset.releases.find((x) => x.id === "ipados-18.7.7")).toBeDefined();
    expect(dataset.releases.find((x) => x.id === "ios-27.0.1")!.hasCveEntries).toBe(false);
  });

  it("maps RSR (a) and (c) to their own advisory sections", () => {
    const a = dataset.releaseCves.filter((l) => l.releaseId === "ios-16.5.1-a");
    const c = dataset.releaseCves.filter((l) => l.releaseId === "ios-16.5.1-c");
    expect(a.map((l) => l.cveId)).toEqual(["CVE-2023-37450"]);
    expect(c).toEqual([]);
    expect(dataset.releases.find((x) => x.id === "ios-16.5.1-a")!.kind).toBe("rsr");
  });

  it("joins KEV and NVD by CVE id and leaves unknowns null", () => {
    expect(dataset.cves.find((c) => c.id === "CVE-2023-37450")).toEqual({
      id: "CVE-2023-37450",
      nvdPublished: "2023-07-27",
      kevDateAdded: "2023-07-13",
      kevDueDate: "2023-08-03",
    });
    expect(dataset.cves.find((c) => c.id === "CVE-2025-46288")).toMatchObject({ nvdPublished: null, kevDateAdded: null });
    expect(dataset.cves.some((c) => c.id.startsWith("CVE-2099"))).toBe(false);
    expect(warnings).toEqual([]);
  });

  it("ignores products out of scope", () => {
    expect(dataset.releases.some((r) => r.name.startsWith("Safari"))).toBe(false);
  });
});

describe("KEV and NVD parsing", () => {
  it("parses KEV and keeps non-Apple vendors (joined on cveID)", () => {
    const k = parseKev(JSON.stringify({ catalogVersion: "2026.10.04", vulnerabilities: [{ cveID: "CVE-2025-14174", vendorProject: "Google", dateAdded: "2025-12-12", dueDate: "2026-01-02" }] }));
    expect(k.catalogVersion).toBe("2026.10.04");
    expect(k.entries.get("CVE-2025-14174")).toEqual({ dateAdded: "2025-12-12", dueDate: "2026-01-02" });
  });

  it("rejects a KEV feed without vulnerabilities", () => {
    expect(() => parseKev("{}")).toThrow();
  });

  it("takes the UTC date of NVD published", () => {
    const p = parseNvdPage(JSON.stringify({ totalResults: 1, vulnerabilities: [{ cve: { id: "CVE-1", published: "2025-12-17T21:16:11.570" } }] }));
    expect(p.published.get("CVE-1")).toBe("2025-12-17");
  });
});
