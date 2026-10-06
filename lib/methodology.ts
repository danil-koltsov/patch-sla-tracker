/**
 * Methodology version. Bump MINOR for new metrics or a changed rule, PATCH for wording.
 * Every export carries this version so old numbers stay explainable.
 */
export const METHODOLOGY_VERSION = "1.0.0";

/** Only CVEs whose earliest fix (any Apple platform) is on/after this date are counted. */
export const WINDOW_START = "2023-01-01";

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
    "The branch kept receiving security updates after the earliest fix, but no Apple advisory lists this CVE for it. The branch may be unaffected; Apple does not publish “not affected” statements.",
  branchEnded:
    "The branch received no further security updates after the earliest fix, so it is not counted as missing a backport.",
  laterMajor:
    "The branch was first released after the earliest fix, so its listing of the CVE is not a backport and is not counted.",
  disclosureLag:
    "NVD publication date minus the earliest fix date. Negative when the CVE record was published before the fix.",
} as const;
