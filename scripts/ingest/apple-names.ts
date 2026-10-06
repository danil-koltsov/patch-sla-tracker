import type { Platform } from "../../lib/types.ts";

export interface ReleaseIdentity {
  platform: Platform;
  major: number;
  version: string; // "16.5.1", "26"
  suffix: string | null; // "(a)"
  codename: string | null; // macOS only: "Sonoma"
}

const TOKEN =
  /\b(iOS|iPadOS|macOS)(?:\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?))?\s+(\d+(?:\.\d+){0,3})(?:\s*\(([a-z])\))?/g;

/**
 * Extracts every iOS/iPadOS/macOS release mentioned in an Apple release name or advisory heading.
 * Returns [] for products out of scope (Safari, watchOS, macOS Server, "Security Update …").
 */
export function parseReleaseName(raw: string): ReleaseIdentity[] {
  let name = raw.replace(/ /g, " ").replace(/\s+/g, " ").trim();
  name = name.replace(/\s*\(Advisory includes[^)]*\)/i, "");
  name = name.replace(/This update has no published CVE entries\.?/i, "").trim();
  const head = name.replace(/^Rapid Security Responses? (for )?/i, "").replace(/^Background Security Improvements? (for )?/i, "");
  if (!/^(iOS|iPadOS|macOS)\b/.test(head) || /^macOS Server\b/.test(head)) return [];

  const out: ReleaseIdentity[] = [];
  for (const m of head.matchAll(TOKEN)) {
    const platform = m[1] as Platform;
    const codename = platform === "macOS" ? (m[2] ?? null) : null;
    if (platform !== "macOS" && m[2]) continue; // e.g. "iOS Foo 1" is not a release
    const version = m[3]!;
    const major = Number.parseInt(version, 10);
    if (!Number.isFinite(major)) continue;
    const id = { platform, major, version, suffix: m[4] ? `(${m[4]})` : null, codename };
    if (!out.some((o) => o.platform === id.platform && o.version === id.version && o.suffix === id.suffix)) out.push(id);
  }
  return out;
}

export function branchId(platform: Platform, major: number): string {
  return `${platform.toLowerCase()}-${major}`;
}

export function releaseId(r: Pick<ReleaseIdentity, "platform" | "version" | "suffix">): string {
  return `${r.platform.toLowerCase()}-${r.version}${r.suffix ? `-${r.suffix.replace(/[()]/g, "")}` : ""}`;
}

export function sameRelease(a: ReleaseIdentity, b: ReleaseIdentity): boolean {
  return a.platform === b.platform && a.version === b.version && a.suffix === b.suffix;
}
