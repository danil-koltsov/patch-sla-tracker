# Decisions log

Small decisions made without asking. Larger trade-offs are raised as questions instead.

- 2026-10-06 — Phase 0 used the SOFA **v2** feeds only. v1 returns HTTP 403.
- 2026-10-06 — Join KEV to CVEs on `cveID`, never on `vendorProject`. Some CVEs that ship in Apple OSes are filed in KEV under Google/WebRTC.
- 2026-10-06 — Dates are stored as UTC calendar dates (`YYYY-MM-DD`). Apple publishes date-only US release days, so time-of-day precision would be invented.
- 2026-10-06 — Raw Phase 0 snapshots stay out of the repo, in the session scratchpad. Ingestion will add its own cache.

## Answers to the Phase 0 open questions (owner, 2026-10-06)

1. **Primary source: Apple.** Release list and dates come from Apple's security releases index. CVE↔release mapping and "Entry added" dates come from Apple's advisory pages. SOFA is not ingested. NVD supplies `published` only. KEV supplies `dateAdded`/`dueDate`.
2. **Metric 1 stays as specified for now:** first fix date vs KEV `dateAdded`, labelled as a lagging proxy. It is reported as a signed number (KEV listing relative to the patch), so the "listed after the patch" cases stay visible.
3. **"Not backported" becomes "no fix listed".** It is defined on the page as "Apple's advisories never list a fix for this branch. The branch may be unaffected." The backport headline uses exploited CVEs only.
4. **Scope:** iOS, iPadOS and macOS.
5. **Window:** CVEs whose earliest fix is on or after 2023-01-01. Releases and advisories from 2022-01-01 are still ingested, so that a CVE first fixed in 2022 is not mistaken for a 2023 first fix.

## Phase 1 small decisions

- 2026-10-06: Branch = (platform, major), where platform is iOS, iPadOS or macOS. A combined release "iOS X and iPadOS X" creates one release row per platform. iPadOS 17 (iPad-only after Dec 2024) is therefore its own branch, and its history before Dec 2024 comes from the combined releases.
- 2026-10-06: Metric logic lives in one place: pure TypeScript in `lib/metrics.ts`, unit-tested. SQL views only expose the base facts (per-CVE-per-branch first fix, branch spans). The rules are not written twice in SQL and TS.
- 2026-10-06: No Supabase SDK. The app and ingestion talk to PostgREST over `fetch`, which avoids one dependency and its transitive tree.
- 2026-10-06: Ingestion scripts run on Node ≥ 23.6 native TypeScript type stripping (`node scripts/ingest/run.ts`), so there is no `tsx`/`ts-node` dependency. Imports therefore use explicit `.ts` extensions.
- 2026-10-06: Letter-suffix releases are their own rows (`kind = rsr|bsi`). A CVE first fixed by an RSR uses the RSR date. Withdrawn RSRs ((a) replaced by (c)) still count, because the fix shipped to devices.
- 2026-10-06: Re-releases (the same name listed twice in Apple's index) are one release. The fix date is the earliest date; the later dates are kept in `rerelease_dates`.
- 2026-10-06: When a branch lacks a fix it is classified as "branch ended" only if it had **no** security release on or after the earliest fix date. Otherwise it is "no fix listed".
- 2026-10-06: A branch whose first release came after the CVE's earliest fix (for example iOS 27.0 re-listing a 26.6 fix) is shown on the CVE page, but is excluded from gap statistics.
- 2026-10-06: "Exploited" = in CISA KEV **or** Apple's advisory says "may have been (actively) exploited". Red is used only when exploitation is documented before a patch existed: Apple's note at release, or KEV `dateAdded` earlier than the first fix.
- 2026-10-06: Font: the system monospace stack. No font is downloaded, which meets "at most one self-hosted font" with zero.
- 2026-10-06: Medians of an even count are the mean of the two middle values, shown with at most one decimal.
- 2026-10-06: Internal links are plain `<a>`, not `next/link`. This avoids the client router and prefetching; pages are static documents and full page loads are cheap.
- 2026-10-06: The site has no favicon. `icons: { icon: "data:," }` stops the `/favicon.ico` request, which keeps the "no images" rule and leaves the console clean.
- 2026-10-06: CSV exports are plain RFC 4180, without `#` comment lines, which spreadsheets mis-import. `methodology_version` and `data_updated_at` are repeated as columns on every row.
- 2026-10-06: A branch is "ended" only if it shipped nothing after the earliest fix **and** nothing in the last 180 days (`ACTIVE_BRANCH_DAYS`). Before this rule, iOS 27 was mislabelled "ended" for a CVE fixed the same day as iOS 27.0.1.
- 2026-10-06: NVD single-CVE lookups that keep failing become "unknown" and are listed in the run warnings. The run is not aborted.

## Phase 1 verification (2026-10-06, local production build, real snapshot)

- Lighthouse 13.5 (headless Chrome) on `/`, `/apple`, `/cve/CVE-2025-24085`, `/methodology`: Accessibility 100, Best Practices 100, SEO 100, Performance 99–100.
- Keyboard: a skip link appears on the first Tab, the focus ring is visible, tab order follows reading order, and scrollable tables are focusable regions.
- Screen-reader structure, checked through the accessibility tree and DOM: tables have captions and `th scope`, and each SVG has `role="img"` with a title and a text description of every data point. **Not yet tested with a real screen reader (VoiceOver/NVDA).**
- No-JS: all content is in the server HTML. Verified by stripping every `<script>`.
- 404: unknown and malformed CVE IDs return HTTP 404.
- **Open: JS budget.** The App Router ships about 130–170 KB of gzipped framework JS per page, even with zero client components. The budget is under 50 KB. A decision from the owner is needed.
