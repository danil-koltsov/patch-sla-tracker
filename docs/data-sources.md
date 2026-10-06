# Data sources — Phase 0 findings

Inspected 2026-10-06 (UTC) against live data. All counts below are from that
snapshot and are meant to show where the problems are, not to be published.

Sources examined:

| Source | URL | Format | Snapshot |
|---|---|---|---|
| SOFA iOS feed v2 | `https://sofa.macadmins.io/v2/ios_data_feed.json` | JSON, 160 KB | `LastCheck 2026-10-06T12:50Z`, schema `2026.04.11.2` |
| SOFA macOS feed v2 | `https://sofa.macadmins.io/v2/macos_data_feed.json` | JSON, 508 KB | same |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON, 1.8 MB | `catalogVersion 2026.10.04`, 1,734 entries |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON | 5 single CVEs + bulk query by Apple CNA |
| Apple security releases index | `https://support.apple.com/en-us/100100` (+ archives `121012` for 2022–23, `120989` for 2020–21) | HTML table | 727 rows parsed |
| Apple advisory pages | `https://support.apple.com/en-us/<id>` | HTML | 3 sampled |

(SOFA v1 `…/v1/ios_data_feed.json` returns HTTP 403; v2 is the only option.)

---

## 1. SOFA v2 (iOS and macOS)

### Shape

```
{ SchemaVersion, Version, UpdateHash, LastCheck,
  OSVersions: [ { OSVersion, Latest, SecurityReleases: [Release…], SupportedModels? } ],
  Devices: { "iPhone12,1": { MarketingName } },
  BackgroundSecurityImprovements: { "<major>": [BSI…] },
  // macOS only: Models, XProtectPlistConfigData, XProtectPayloads, InstallationApps
}
```

`Release` fields (all observed keys):

| Field | Example | What it really means |
|---|---|---|
| `UpdateName` | `"iOS 26.3 and iPadOS 26.3"` | Apple's display name. Contains a non-breaking space in at least one entry (`macOS Ventura 13.1`). |
| `ProductVersion` | `"26.3"` | Version string. Major `.0` is written `"26.0"`, but Apple writes `iOS 26`. |
| `Build`, `AllBuilds` | `"24A9446"`, list | Build numbers. Several builds per version (device- or re-release-specific). |
| `ReleaseDate` | `"2025-12-12T00:00:00Z"` | Midnight-UTC date. **Not trustworthy for older macOS** (see quirks). |
| `ReleaseType` | `"OS"` | Always `"OS"` in this snapshot. |
| `SecurityInfo` | `https://support.apple.com/en-us/125884` | Advisory URL. For releases with no CVEs it points at the index page `100100`; for old macOS it uses legacy `kb/HT…` URLs (which now redirect). |
| `CVEs` | `{ "CVE-…": {} }` | Map of CVE → metadata. **Metadata is empty for 98% of entries**; only exploited CVEs get `{NISTURL, ActivelyExploited, InKEV, Severity}`. `Severity` is always `"Critical"` when present, so it is a SOFA label, not CVSS. |
| `ActivelyExploitedCVEs` | list | Same set as `CVEs[*].ActivelyExploited == true` (matched for every release). |
| `UniqueCVEsCount` | int | Equals `len(CVEs)` in every release. |
| `DaysSincePreviousRelease` | int | Computed by SOFA. Wrong wherever `ReleaseDate` is wrong. |
| `DeviceScope` | `universal` / `device-specific` | `device-specific` marks e.g. iOS 18.7.9/18.7.10, which only shipped to devices that cannot run iOS 26. |
| `SupportedDevices` | model identifiers | Lets us tell "branch kept for old hardware" apart from "branch kept for people who did not upgrade". |
| `SupersededBy` | `{ProductVersion, Build, ReleaseDate, DaysLater}` | Present on 43 iOS and 126 macOS releases. |
| `UpdateSummary` | `{Priority, Summary, Recommendation, Stats}` | SOFA's editorial summary. We should not use it. |

`BackgroundSecurityImprovements` (BSI, the successor to Rapid Security Responses):
`{Version, VersionExtra: "(a)", Build, PostingDate, PrerequisiteBuild, SupportedDevices,
SecurityInfo, CVEs: [ids], DeviceScope, SupersededBy}`. On iOS the BSI entry for 26.3.1 (a)
has **no `CVEs` and no `SecurityInfo` key**. On macOS the two BSI entries carry `CVE-2026-20643`.

### Coverage

| Feed | Branches present | Releases |
|---|---|---|
| iOS | 27, 26, 18 | 2 + 18 + 27 |
| macOS | 27 Golden Gate, 26 Tahoe, 15 Sequoia, 14 Sonoma, 13 Ventura, 12 Monterey | 2 + 17 + 24 + 31 + 31 + 27 |

**SOFA's iOS feed has no iOS 17, 16 or 15 and no iPadOS 17.** Apple's own index shows all of
these still receiving security releases in 2025–26:

- iOS 16.7.11 (2025-03-31) through iOS 16.7.16 (2026-05-11)
- iOS 15.8.4 (2025-03-31) through iOS 15.8.8 (2026-05-11)
- iPadOS 17.7.3 (2024-12-11) through iPadOS 17.7.11 (2026-05-11). This is an **iPadOS-only branch**. iPhones moved to 18, but some iPads stayed on 17.

So SOFA alone cannot answer "how long were iOS 16 users exposed". It only reaches back to
iOS 18 (Sep 2024) and macOS 12 (2021).

### Quirks found

1. **Wrong release dates on old macOS releases.** 12 of 167 macOS releases have a
   `ReleaseDate` that differs from Apple's index, by up to two years. These dates look
   like the date a page was last edited:

   | Release | SOFA | Apple index |
   |---|---|---|
   | macOS Monterey 12.2 | 2023-11-02 | 2022-01-26 |
   | macOS Monterey 12.3 | 2023-10-31 | 2022-03-14 |
   | macOS Monterey 12.6 | 2024-06-12 | 2022-09-12 |
   | macOS Ventura 13.0.1 | 2024-06-12 | 2022-11-09 |
   | macOS Ventura 13.3.1 | 2023-10-31 | 2023-04-07 |
   | … 7 more Monterey/Ventura | | |

   These errors carry straight into the metrics. With SOFA dates, CVE-2022-22587 looks
   like it was added to KEV **643 days before** its first fix. That is false: Apple shipped
   the fix on 2022-01-26 and KEV added it on 2022-01-28.
2. **Duplicate release.** iOS 18.7.7 appears twice with the same date and CVE set. Apple's
   index also lists 18.7.7 twice (2026-03-24 and 2026-04-01). That is a re-release, which
   SOFA collapses to one date.
3. **The same CVE in several releases of one branch.** 37 iOS and 31 macOS CVEs. Examples:
   CVE-2026-43661 is in iOS 26.5 and again in 26.7. CVE-2026-28969 is in macOS 26.5 and 26.7,
   and in 15.7.7 and 15.8. Either Apple shipped an incomplete fix and fixed it again, or the
   entry was re-listed. The first fix date and the complete fix date can therefore differ.
4. **A new major release "fixes" CVEs the previous branch already had.** iOS 27.0
   (2026-09-14) lists CVEs fixed in iOS 26.6 (2026-07-27). On macOS, Golden Gate 27.0
   lists CVE-2022-3437, which Ventura fixed in 2022-10. If the backport gap is computed
   naively, the newest branch looks like the slowest one. 54 macOS and 10 iOS CVEs have an
   older branch fixed before the newest one.
5. **Non-Apple CVEs.** SOFA includes CVEs whose KEV vendor is not Apple: CVE-2025-14174
   and CVE-2025-6558 (Google Chromium/ANGLE) and CVE-2022-2294 (WebRTC). KEV has to be
   joined on `cveID`, not on `vendorProject`.
6. **No "entry added" information.** SOFA lists a late-added CVE under the original
   release with no marker. There is no way to know when it actually appeared.
7. **Letter-suffix updates.** RSRs (2023: iOS 16.5.1 (a)/(c), macOS 13.4.1 (a)/(c)) are not
   in `SecurityReleases` at all. Only the BSI section covers the 2026 equivalent, and on iOS
   without CVEs.

---

## 2. CISA KEV

Top level: `title, catalogVersion, dateReleased, count, vulnerabilities[]`.

| Field | Meaning / caveat |
|---|---|
| `cveID` | Join key. |
| `vendorProject`, `product` | Free text. Apple entries say `"Apple"` with products such as `"Multiple Products"` (54 of 95), `"iOS and iPadOS"`, `"OS X"`. Shared-code bugs can be filed under Google or WebRTC. |
| `dateAdded` | Date CISA added it to the catalog. **This is not the exploitation date, and for Apple it is almost always after the patch** (see §6). |
| `dueDate` | Federal remediation deadline (usually `dateAdded` + 14 or 21 days). It is a CISA policy date, not a vendor date. |
| `knownRansomwareCampaignUse` | `"Unknown"` for all 95 Apple entries. |
| `forensicTriage`, `requiredAction`, `notes`, `cwes`, `shortDescription`, `vulnerabilityName` | Descriptive fields. `forensicTriage` is new (BOD 26-04). |

- 95 Apple-vendor entries, `dateAdded` from 2021-11-03 to 2026-09-29.
- 50 of those are in SOFA. The other 45 come from branches SOFA does not cover, or are older than 2021.
- Every CVE SOFA flags `ActivelyExploited` (53) is in KEV, and every Apple KEV CVE in SOFA is flagged. **SOFA's exploited flag is derived from KEV, so it is not a second source.**
- **Retroactive additions:** CVE-2021-30952 was fixed 2021-12-13 and added to KEV 2026-03-05, 1,543 days later. CVE-2022-48503 was fixed 2022-07-20 and added 2025-10-20. In cases like these, exploitation was discovered long after the patch.

---

## 3. NVD CVE API 2.0

Bulk access works: `?sourceIdentifier=product-security@apple.com` returns **8,700** Apple-CNA
CVEs, which is 5 pages at `resultsPerPage=2000`. Adding `hasKev` narrows it to 95.
Incremental updates are possible with `lastModStartDate/lastModEndDate`. Without an API key
the limit is 5 requests per 30 s, which is plenty for this volume.

Relevant fields of `vulnerabilities[].cve`:

| Field | Meaning / caveat |
|---|---|
| `published` | When NVD published the record. Local time without a zone, documented as UTC (`2025-12-17T21:16:11.570`). Usually the CVE.org publication time. |
| `lastModified` | Changes constantly (re-analysis). Do not use for metrics. |
| `vulnStatus` | `Analyzed`, `Awaiting Analysis`, … Recent Apple CVEs often have only the CISA-ADP CVSS score and no NVD score. |
| `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName` | Copy of KEV. Matched KEV in all samples. |
| `affected[]` | **New, and important.** Apple CNA's structured data: `{product: "iOS and iPadOS", versions: [{lessThan: "15.7.8"}]}`, one row per branch. It covers branches SOFA lacks (iOS 15/16/17, iPadOS 17, macOS 11). |
| `configurations[]` | NVD's CPE ranges (`iphone_os`, `ipados`, `macos` with `versionStartIncluding`/`versionEndExcluding`). NVD's own interpretation, which can differ from `affected`. |
| `references[]` | Apple advisory URLs (legacy `HT…` and numeric), KEV link. |
| `descriptions[0].value` | Apple's text, including "fixed in iOS 18.7.3 and iPadOS 18.7.3, …" and "Apple is aware of a report that this issue may have been exploited…". |

Quirks:
- `affected` and CPE sometimes disagree. CVE-2023-41990: `affected` says iOS `lessThan 15.7`, but the CPE and Apple say 15.7.8. Using `affected` alone put its first fix in 2022-09, which is wrong.
- `affected` on old CVEs has junk in `lessThan` (`"2020"`, `"iOS 12.1.4"`, `"macOS Mojave 10.14.3"`, Safari/Xcode versions under product `macOS`). 19 of 95 KEV CVEs had no iOS/macOS fix version I could parse.
- `published` is sometimes **before** the fix (CVE-2021-30952: published 2021-08-24, fixed 2021-12-13). These are reserved records that were published early.
- Some CVEs are listed under product `Safari` only, although Safari ships inside iOS.

---

## 4. Apple security releases index + advisories (authoritative)

**Index** (`100100` plus yearly archives): an HTML table with `Name and information link | Available for | Release date`.
- Dates are `DD Mon YYYY`, with no time and no zone. Apple means the US release day. We treat it as a UTC date.
- Rows without a link carry the text "This update has no published CVE entries."
- **Re-releases appear as two rows with the same name and link**: `iOS 18.7.7` on 24 Mar 2026 and 01 Apr 2026.
- **Letter-suffix updates:** `Rapid Security Response iOS 16.5.1 (a)` (2023-07-10) and `(c)` (2023-07-12) share one advisory with the matching macOS (a)/(c). (a) was withdrawn and replaced by (c). Both fixed CVE-2023-37450, which was exploited. **The RSR is the real first fix**, 14 days before iOS 16.6. In 2026 the equivalent is the row `Background Security Improvements for iOS, iPadOS, and macOS` (2026-03-17).
- Branches SOFA lacks are all here: iOS 15/16/17, `iPadOS 17.7.x` (iPadOS-only rows), macOS 11 Big Sur and earlier.
- Combined advisories: `macOS Monterey 12.0.1 (Advisory includes security content of macOS Monterey 12.0 and 12.0.1)`.

**Advisory pages** give, per component block: `Available for`, `Impact`, `Description`, `CVE-…`, and optionally:
- `Entry added <date>` / `Entry updated <date>` / `Entry added <date>, updated <date>`.
  iOS 26.2 (released 2025-12-12) has entries added 2026-01-09, 2026-02-11, 2026-03-24 and **2026-05-11, five months after release**.
  The iOS 16.3-era advisories (2023-01-23) had entries added in June and September 2023. One of those is CVE-2023-41990 (Operation Triangulation), which was fixed in January but disclosed in September.
- The exploitation wording: "Apple is aware of a report that this issue may have been exploited…". This is Apple's own first-party zero-day signal, dated at release time.
- Legacy `kb/HT2135xx` URLs redirect to new numeric IDs. Store the final URL, but keep the legacy one for matching against NVD references.

---

## 5. What each date really means

| Date | Source | Meaning | Use as |
|---|---|---|---|
| Release date | Apple index | Day the update became available (US). | Fix date. Prefer it over SOFA. |
| Entry added | Apple advisory | Day Apple disclosed that a past release fixed this CVE. | Disclosure date for late-added CVEs. |
| NVD `published` | NVD | Day the CVE record went public. | Disclosure-lag endpoint. |
| KEV `dateAdded` | CISA | Day CISA catalogued exploitation evidence. | **Lagging** evidence that exploitation happened. Not an exploitation start date. |
| KEV `dueDate` | CISA | Federal deadline. | Not used. |
| SOFA `ReleaseDate` | SOFA | Usually the release date. Wrong for 12 old macOS releases. | Cross-check only. |

---

## 6. Prototype numbers that contradict the brief

Computed over the 76 Apple-CNA KEV CVEs whose fix versions could be parsed, with Apple index dates.

### A. "Exploited-before-patch window" (first fix vs KEV `dateAdded`) mostly measures something else
- KEV was added **after** the first fix for 74 of 76. It was added before the fix only twice: CVE-2023-37450 (11 days, RSR era) and CVE-2023-41993 (1 day).
- So "first fix − KEV dateAdded" is negative almost every time. It measures **how long CISA took to catalogue the CVE after Apple patched it**, not how long users were exposed before a patch. The true start of exploitation is not in any public structured source.
- What the data *can* show honestly:
  1. **Zero-day at release:** Apple's own "may have been exploited" note on the release where the CVE was fixed. That means the CVE was exploited before a patch existed, but the length of that exposure is **unknown**.
  2. **Known-exploited-but-unpatched window per branch:** from the first public fix of an exploited CVE (when attackers and defenders know about it) to the fix date on each other branch. Example: CVE-2025-24085 was fixed in iOS 18.3 on 2025-01-27 and in iPadOS 17.7.6 on 2025-03-31, so iPadOS 17 users waited **63 days** on a known zero-day. This is measurable, it is the kind of answer no other site gives, and it merges metrics 1 and 2 for the cases that matter most.

### B. The backport gap needs a "branch existed" rule and an "affected" caveat
- Count a branch only if it **existed and was supported on the date of the earliest fix**. Otherwise iOS 27.0 shows up as a 49-day "gap" for CVEs that 26.6 fixed before 27 shipped (quirk 4).
- **"Not backported" cannot be told apart from "not affected".** Apple never publishes "not affected" statements. Of the 429 iOS 26 CVEs fixed before the last iOS 18 security release, **161 (38%) never appear in an iOS 18 advisory**. Some of those are features or code that iOS 18 does not have. The label has to be **"no fix listed"**, with a definition, not "not backported", or we would overstate exposure. That would break principle 6.
  One exploited case among them: CVE-2026-20700 (KEV), fixed in iOS 26.3 and never listed for iOS 18.
- On the exploited subset, iOS 16 is where the gaps are: median 49 days across 28 fixes, max 315 days. macOS 13 Ventura: median 133 days, max 315 days.

### C. Disclosure lag is near zero only since 2024
Median of NVD `published` minus first fix, by fix year (exploited subset, preliminary):
2020: 109 days · 2021: 66 · 2022: large and contaminated by late-added entries · 2023: 24.5 · 2024: 1 · 2025: 1 · 2026: 0.
It is worth showing as history. Late-added entries (§4) are the real story behind the old outliers.

### D. "Branch" is not one thing
- iOS and iPadOS split: iPadOS 17 continued alone.
- Since iOS 26, iOS 18 is served to two different groups: devices that cannot run 26 (`DeviceScope: device-specific` from 18.7.9 onward) and people who chose not to upgrade. "Older iPhones waited N days" only describes the first group.

---

## 7. Implications for the data model (input for Phase 1)

- **Fix dates come from Apple's index. CVE↔release mapping comes from Apple advisory pages. SOFA is only a cross-check.** NVD `affected` is a third cross-check and the only source of NVD `published`.
- `releases` needs: `product` (iOS / iPadOS / macOS), `branch` (major), `version`, `suffix` (`(a)`, `(c)`, null), `kind` (`full` / `rsr` / `bsi`), `release_date`, `rerelease_dates[]`, `advisory_url`, `legacy_url`, `device_scope`.
- `release_cves` needs `entry_added_date` (nullable) and `entry_updated_date`. A CVE can map to several releases in the same branch.
- `branches` needs `first_release_date` and `last_security_release_date` (derived), to separate "branch had ended" from "no fix listed".
- Every date column is nullable. A missing date is shown as "unknown".
- Keep the raw source snapshot (hash + fetch time) for every ingestion, so corrections can go into the changelog.

## 8. Open questions (need a decision before Phase 1)

1. **Primary source:** scrape Apple's HTML (authoritative, complete branches, entry-added dates, but fragile parsing) or SOFA JSON only (clean, but no iOS 15/16/17 or iPadOS 17, and bad old macOS dates)?
2. **Metric 1:** replace "first fix vs KEV dateAdded" with (a) a zero-day-at-release flag (exposure length shown as unknown) plus (b) the known-exploited-unpatched window per branch?
3. **"Not backported" label:** rename to "no fix listed" with a caveat, and/or restrict the backport-gap headline to exploited CVEs, where Apple's coverage is deliberate?
4. **Scope:** iOS + iPadOS + macOS, or iOS + iPadOS only for the MVP?
5. **Time window:** from 2021 (KEV start, and the first year Apple's index is cleanly parseable) or from 2023 (when per-branch data is dense and RSRs exist)?
