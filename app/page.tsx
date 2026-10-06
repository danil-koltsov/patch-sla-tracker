import { CveLink, DataError, Def, Days } from "../components/bits.tsx";
import { loadData } from "../lib/data.ts";
import { TERMS, WINDOW_START } from "../lib/methodology.ts";
import { backportSummary, disclosureSummary, exploitedSummary } from "../lib/metrics.ts";
import { formatDays } from "../lib/stats.ts";

export const revalidate = 86400; // must be a literal; equals REVALIDATE_SECONDS

export default async function Home() {
  let data;
  try {
    data = await loadData();
  } catch (e) {
    return (
      <>
        <h1>How long are Apple users exposed after a security fix exists?</h1>
        <DataError error={e} />
      </>
    );
  }
  const { timelines } = data;
  const ios = backportSummary(timelines, "iOS", "exploited");
  const ex = exploitedSummary(timelines);
  const disc = disclosureSummary(timelines);

  return (
    <>
      <h1>How long are Apple users exposed after a security fix exists?</h1>
      <p className="muted">
        Three numbers for iPhone, iPad and Mac, for flaws first fixed since {WINDOW_START}. Rebuilt daily from Apple&apos;s advisories, the CISA
        Known Exploited Vulnerabilities catalog, and NVD. Each number links to its evidence.
      </p>

      <section className="headline-block" aria-labelledby="h-backport">
        <p className="headline" id="h-backport">
          Older iPhones waited a median of <strong>{formatDays(ios.older.median)}</strong> for fixes to exploited flaws already shipped to the newest
          iOS.
        </p>
        <p className="muted">
          Worst case: {ios.older.worst ? <>{formatDays(ios.older.worst.days)} ({<CveLink id={ios.older.worst.cveId} />})</> : "unknown"}.{" "}
          {ios.older.noFixListed} older-branch cases have no fix listed at all. Based on {ios.older.n} fixes. <a href="/apple#backport">Details</a>
        </p>
        <Def term="Backport gap">{TERMS.backportGap}</Def>
      </section>

      <section className="headline-block" aria-labelledby="h-kev">
        <p className="headline" id="h-kev">
          CISA catalogued exploited Apple flaws a median of <strong>{formatDays(ex.kevAfterPatch.median)}</strong> after Apple&apos;s first patch.
        </p>
        <p className="muted">
          {ex.kevBeforePatch} of {ex.withKev} were catalogued before any patch existed; {ex.appleNote} of {ex.exploited} were already exploited when
          Apple released the fix, per Apple. <a href="/apple#exploited">Details</a>
        </p>
        <Def term="KEV date added (proxy)">{TERMS.kevProxy}</Def>
      </section>

      <section className="headline-block" aria-labelledby="h-disc">
        <p className="headline" id="h-disc">
          NVD published Apple CVEs a median of <strong>{formatDays(disc.lag.median)}</strong> after Apple&apos;s fix.
        </p>
        <p className="muted">
          Worst case: <Days n={disc.lag.worst?.days ?? null} />
          {disc.lag.worst ? (
            <>
              {" "}
              (<CveLink id={disc.lag.worst.cveId} />)
            </>
          ) : null}
          . NVD date unknown for {disc.unknown} of {disc.cves} CVEs. <a href="/apple#disclosure">Details</a>
        </p>
        <Def term="Disclosure lag">{TERMS.disclosureLag}</Def>
      </section>
    </>
  );
}
