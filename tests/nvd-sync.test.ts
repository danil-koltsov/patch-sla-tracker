import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const urls: string[] = [];
const APPLE = "product-security@apple.com";
let page: { cve: { id: string; published: string; sourceIdentifier: string } }[] = [];

beforeAll(() => {
  process.env.INGEST_CACHE_DIR = join(mkdtempSync(join(tmpdir(), "nvd-")), "http");
  process.env.NVD_API_KEY = "test"; // shortest pacing
  vi.stubGlobal("fetch", async (url: string) => {
    urls.push(url);
    return new Response(JSON.stringify({ totalResults: page.length, vulnerabilities: page }), { status: 200 });
  });
});
afterAll(() => vi.unstubAllGlobals());

describe("syncNvd", () => {
  it("does a full Apple-CNA sync first, then only fetches recently modified records", async () => {
    const { syncNvd } = await import("../scripts/ingest/nvd.ts");
    const log = () => {};

    page = [{ cve: { id: "CVE-2026-0001", published: "2026-09-28T20:00:00.000", sourceIdentifier: APPLE } }];
    const first = await syncNvd(new Set(), log);
    expect(first.mode).toBe("full");
    expect(urls.at(-1)).toContain("sourceIdentifier=");
    expect(first.published.get("CVE-2026-0001")).toBe("2026-09-28");

    page = [
      { cve: { id: "CVE-2026-0002", published: "2026-10-06T10:00:00.000", sourceIdentifier: "chrome-cve-admin@google.com" } }, // tracked
      { cve: { id: "CVE-2026-0003", published: "2026-10-06T10:00:00.000", sourceIdentifier: "secalert@redhat.com" } }, // irrelevant
      { cve: { id: "CVE-2026-0004", published: "2026-10-06T11:00:00.000", sourceIdentifier: APPLE } }, // new Apple CVE
    ];
    const second = await syncNvd(new Set(["CVE-2026-0002"]), log);
    expect(second.mode).toBe("incremental");
    expect(urls.at(-1)).toContain("lastModStartDate=");
    expect(urls.at(-1)).not.toContain("sourceIdentifier=");
    expect(second.published.get("CVE-2026-0001")).toBe("2026-09-28"); // kept from state
    expect(second.published.get("CVE-2026-0002")).toBe("2026-10-06");
    expect(second.published.has("CVE-2026-0003")).toBe(false);
    expect(second.published.get("CVE-2026-0004")).toBe("2026-10-06");
    expect(second.updated).toBe(2);
  });
});
