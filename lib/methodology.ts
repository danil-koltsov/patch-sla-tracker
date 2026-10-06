/**
 * Methodology version. Bump MINOR for new metrics or a changed rule, PATCH for wording.
 * Every export carries this version so old numbers stay explainable.
 */
export const METHODOLOGY_VERSION = "1.0.0";

/** Only CVEs whose earliest fix (any Apple platform) is on/after this date are counted. */
export const WINDOW_START = "2023-01-01";

/**
 * A branch with no release since the earliest fix still counts as maintained ("no fix listed")
 * if its last release is at most this many days before the data date. Older branches have gone
 * up to ~6 months between updates (iOS 15.8.4 → 15.8.5).
 */
export const ACTIVE_BRANCH_DAYS = 180;

export const METHODOLOGY_HISTORY: { version: string; date: string; change: string }[] = [
  { version: "1.0.0", date: "2026-10-06", change: "First published methodology." },
];

/** Short definitions shown next to the term wherever it appears. */
export const TERMS = {
  branch:
    "A major OS version line that receives its own updates, e.g. iOS 16 or macOS 14 Sonoma. iOS and iPadOS are counted separately.",
  firstFix:
    "The release date of the earliest Apple update (including Rapid Security Responses and Background Security Improvements) whose advisory lists the CVE.",
  exploited:
    "Listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, or Apple's advisory says the issue “may have been exploited”.",
  kevProxy:
    "CISA KEV “date added” is when CISA catalogued evidence of exploitation. It is a lagging proxy: exploitation started on or before that date, usually well before.",
  backportGap:
    "For one CVE and one branch: the branch's first fix date minus the earliest fix date across all branches of the same platform.",
  noFixListed:
    "The branch is still maintained (it shipped a security update after the earliest fix, or its last security update is under 180 days old), but no Apple advisory lists this CVE for it as of the data date. The branch may be unaffected; Apple does not publish “not affected” statements.",
  branchEnded:
    "The branch shipped no security update after the earliest fix and none in the 180 days before the data date, so it is treated as ended and not counted as missing a backport. Updates without published CVE entries do not keep a branch alive.",
  atBranchRelease:
    "The branch was first released after the earliest fix, so it is not a backport and is not counted. “Listed”: its advisory names the CVE. “Inherited”: it does not, and the fix is assumed to be in the branch from its first release.",
  thirdParty:
    "CISA KEV files the CVE under a vendor other than Apple (e.g. Google for Chromium code shipped in WebKit/ANGLE). The flaw is in a component Apple ships but does not own.",
  disclosureLag:
    "NVD publication date minus the earliest fix date. Negative when the CVE record was published before the fix.",
} as const;
