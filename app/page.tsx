import { CveLink, DataError, Def } from "../components/bits.tsx";
import { loadData } from "../lib/data.ts";
import { TERMS, WINDOW_START } from "../lib/methodology.ts";
import { backportSummary, disclosureSummary, exploitedSummary } from "../lib/metrics.ts";
import { formatDays } from "../lib/stats.ts";

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
  const { index, timelines } = data;
  const ios = backportSummary(index, timelines, "iOS", "exploited");
  const oldest = ios.oldestMaintained;
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
        {oldest ? (
          <>
            <p className="headline" id="h-backport">
              {oldest.branch.name}, the oldest iPhone branch Apple still patches, got fixes for exploited flaws a median of{" "}
              <strong>{formatDays(oldest.fixed.median)}</strong> after Apple&apos;s first fix.
            </p>
            <p className="muted">
              Worst case:{" "}
              {oldest.fixed.worst ? (
                <>
                  {formatDays(oldest.fixed.worst.days)} (<CveLink id={oldest.fixed.worst.cveId} />)
                </>
              ) : (
                "unknown"
              )}
              . Based on {oldest.fixed.n} fixes; {oldest.noFixListed} exploited flaws have no {oldest.branch.name} fix listed.{" "}
              <a href="/apple#backport">Every branch</a>
            </p>
          </>
        ) : (
          <p className="headline" id="h-backport">
            No maintained older iOS branch has received fixes for exploited flaws in the window. <a href="/apple#backport">Every branch</a>
          </p>
        )}
        <Def term="Backport gap">{TERMS.backportGap}</Def>
      </section>

      <section className="headline-block" aria-labelledby="h-exploited">
        <p className="headline" id="h-exploited">
          <strong className="exploited">{ex.appleNote}</strong> of {ex.exploited} exploited Apple flaws were attacked before a patch existed, per
          Apple.
        </p>
        <p className="muted">
          CISA&apos;s exploited-vulnerability catalog listed them a median of {formatDays(ex.kevAfterPatch.median)} after Apple&apos;s first patch;{" "}
          {ex.kevBeforePatch} of {ex.withKev} were listed before any patch existed. <a href="/apple#exploited">Details</a>
        </p>
        <Def term="Exploited">{TERMS.exploited}</Def>
      </section>

      <section className="headline-block" aria-labelledby="h-disc">
        <p className="headline" id="h-disc">
          NVD published Apple CVEs a median of <strong>{formatDays(disc.lag.median)}</strong> after Apple&apos;s fix.
        </p>
        <p className="muted">
          Worst case:{" "}
          {disc.lag.worst ? (
            <>
              {formatDays(disc.lag.worst.days)} (<CveLink id={disc.lag.worst.cveId} />)
            </>
          ) : (
            "unknown"
          )}
          . NVD date unknown for {disc.unknown} of {disc.cves} CVEs. <a href="/apple#disclosure">Details</a>
        </p>
        <Def term="Disclosure lag">{TERMS.disclosureLag}</Def>
      </section>
    </>
  );
}
