import { loadData } from "../lib/data.ts";
import { formatUtcTimestamp } from "../lib/dates.ts";
import { METHODOLOGY_VERSION } from "../lib/methodology.ts";

export async function DataFooter() {
  let updated = "unknown";
  let updatedIso: string | undefined;
  let kev: string | null = null;
  try {
    const { dataset } = await loadData();
    if (dataset.meta.updatedAt) {
      updated = formatUtcTimestamp(dataset.meta.updatedAt);
      updatedIso = new Date(dataset.meta.updatedAt).toISOString();
    }
    kev = dataset.meta.kevCatalogVersion;
  } catch {
    // The page body reports the data error; the footer stays honest with "unknown".
  }
  return (
    <footer className="site">
      <div className="wrap">
        <p>
          Data last changed: <time dateTime={updatedIso}>{updated}</time>
          {kev ? ` · CISA KEV catalog ${kev}` : ""} · <a href="/methodology">Methodology</a> v{METHODOLOGY_VERSION}
        </p>
        <p>Sources are checked every 6 hours; the site is rebuilt when they change.</p>
        <p>
          Sources: <a href="https://support.apple.com/en-us/100100">Apple security releases</a>,{" "}
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>,{" "}
          <a href="https://nvd.nist.gov/">NVD</a>. All dates are UTC, written YYYY-MM-DD. No cookies, no tracking.
        </p>
      </div>
    </footer>
  );
}
