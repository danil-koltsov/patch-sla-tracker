/** Domain types shared by ingestion, metrics and pages. Dates are UTC calendar dates "YYYY-MM-DD". */

export type Platform = "iOS" | "iPadOS" | "macOS";
export const PLATFORMS: readonly Platform[] = ["iOS", "iPadOS", "macOS"];

export type ReleaseKind = "full" | "rsr" | "bsi";

export interface Branch {
  id: string; // "ios-16", "ipados-17", "macos-14"
  platform: Platform;
  major: number;
  name: string; // "iOS 16", "macOS 14 Sonoma"
}

export interface Release {
  id: string; // "ios-16.5.1-a"
  branchId: string;
  version: string; // as Apple writes it: "16.5.1", "26"
  suffix: string | null; // "(a)"
  kind: ReleaseKind;
  releaseDate: string;
  rereleaseDates: string[];
  name: string; // Apple's display name of the index row
  advisoryUrl: string | null; // null when Apple lists "no published CVE entries"
  hasCveEntries: boolean;
}

export interface ReleaseCve {
  releaseId: string;
  cveId: string;
  entryAdded: string | null; // "Entry added <date>" on the advisory
  entryUpdated: string | null;
  exploitedNote: boolean; // advisory says "may have been (actively) exploited"
}

export interface Cve {
  id: string;
  nvdPublished: string | null;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  /** KEV "vendorProject" (e.g. "Apple", "Google"). Null when not in KEV. */
  kevVendorProject: string | null;
}

export interface DatasetMeta {
  updatedAt: string; // ISO timestamp of the ingestion run in which the data last changed
  kevCatalogVersion: string | null;
}

export interface Dataset {
  meta: DatasetMeta;
  branches: Branch[];
  releases: Release[];
  releaseCves: ReleaseCve[];
  cves: Cve[];
}
