/**
 * Public changelog of data corrections. Add an entry whenever a published number changes
 * because a source was wrong, a parser was fixed, or a methodology rule changed.
 */
export interface Correction {
  date: string; // YYYY-MM-DD (UTC)
  summary: string;
  affects: string; // e.g. "CVE-2023-41990" or "iOS backport gaps"
  source?: string; // link to evidence
}

export const CORRECTIONS: Correction[] = [];
