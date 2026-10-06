import type { Metadata } from "next";
import { CveLink, DataError, DateOrUnknown, Def, Exports, relative, TableScroll, Unknown } from "../../components/bits.tsx";
import { GapStrip } from "../../components/GapStrip.tsx";
import { loadData } from "../../lib/data.ts";
import { TERMS, WINDOW_START } from "../../lib/methodology.ts";
import { backportSummary, disclosureSummary, exploitedSummary, type CveTimeline, type Stat } from "../../lib/metrics.ts";
import { formatDays } from "../../lib/stats.ts";
import { PLATFORMS } from "../../lib/types.ts";

export const metadata: Metadata = {
  title: "Apple",
  description: "Backport gaps between Apple OS branches, exploited-vulnerability timelines, and NVD disclosure lag for iOS, iPadOS and macOS.",
  alternates: { canonical: "/apple" },
};

function StatCells({ s }: { s: Stat }) {
  return (
    <>
      <td className="num">{s.median === null ? <Unknown /> : formatDays(s.median)}</td>
      <td className="num">
        {s.worst ? (
          <>
            {formatDays(s.worst.days)} (<CveLink id={s.worst.cveId} />)
          </>
        ) : (
          <Unknown />
        )}
      </td>
    </>
  );
}

export default async function ApplePage() {
  let data;
  try {
    data = await loadData();
  } catch (e) {
    return (
      <>
        <h1>Apple</h1>
        <DataError error={e} />
      </>
    );
  }
  const { index, timelines } = data;
  const ex = exploitedSummary(timelines);
  const disc = disclosureSummary(timelines);
  const exploited = timelines.filter((t) => t.inWindow && t.exploited);

  return (
    <>
      <h1>Apple: how long users stay exposed after a fix exists</h1>
      <p className="muted">
        iOS, iPadOS and macOS. CVEs whose earliest fix shipped on or after {WINDOW_START}. Median and worst case are shown; means are not.
      </p>
      <Exports base="/apple" label="every CVE × branch row behind this page" />
      <Def term="Branch">{TERMS.branch}</Def>
      <Def term="First fix">{TERMS.firstFix}</Def>
      <Def term="Exploited">{TERMS.exploited}</Def>

      <h2 id="backport">1. Backport gap for exploited flaws</h2>
      <p>How long did users of an older branch wait after the same flaw was already fixed on another branch of the same OS?</p>
      <Def term="Backport gap">{TERMS.backportGap}</Def>
      <Def term="No fix listed">{TERMS.noFixListed}</Def>
      <Def term="Branch ended">{TERMS.branchEnded}</Def>
      {PLATFORMS.map((platform) => {
        const s = backportSummary(index, timelines, platform, "exploited");
        const o = s.oldestMaintained;
        return (
          <section key={platform} aria-labelledby={`bp-${platform}`}>
            <h3 id={`bp-${platform}`}>{platform}</h3>
            {s.cves === 0 ? (
              <p>No exploited {platform} CVEs in the window.</p>
            ) : (
              <>
                {o ? (
                  <p>
                    {o.branch.name}, the oldest {platform} branch still maintained, got fixes for exploited flaws a median of{" "}
                    <strong>{formatDays(o.fixed.median)}</strong> after the earliest fix
                    {o.fixed.worst ? (
                      <>
                        {" "}
                        (worst: {formatDays(o.fixed.worst.days)}, <CveLink id={o.fixed.worst.cveId} />)
                      </>
                    ) : null}
                    , over {o.fixed.n} fixes. {o.noFixListed} exploited {platform} CVEs have no {o.branch.name} fix listed. Other branches are in the
                    table.
                  </p>
                ) : (
                  <p>No maintained older {platform} branch received fixes for exploited flaws in the window.</p>
                )}
                <TableScroll label={`${platform} backport gaps by branch`}>
                  <table>
                    <caption>
                      {platform}: backport gap per branch, exploited CVEs. Maintained: last security release under 180 days old. Branches that had ended for every CVE are
                      omitted (see export).
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Branch</th>
                        <th scope="col">Maintained</th>
                        <th scope="col" className="num">
                          Fixed
                        </th>
                        <th scope="col" className="num">
                          Same day
                        </th>
                        <th scope="col" className="num">
                          Median gap
                        </th>
                        <th scope="col" className="num">
                          Worst gap
                        </th>
                        <th scope="col" className="num">
                          No fix listed
                        </th>
                        <th scope="col" className="num">
                          Branch ended
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {s.rows.filter((r) => r.fixed.n > 0 || r.noFixListed > 0).map((r) => (
                        <tr key={r.branch.id}>
                          <th scope="row">{r.branch.name}</th>
                          <td>{r.maintained ? "yes" : "no"}</td>
                          <td className="num">{r.fixed.n}</td>
                          <td className="num">{r.sameDay}</td>
                          <StatCells s={r.fixed} />
                          <td className="num">{r.noFixListed}</td>
                          <td className="num">{r.branchEnded}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableScroll>
                <GapStrip summary={s} timelines={timelines} />
              </>
            )}
          </section>
        );
      })}

      <h2 id="exploited">2. Exploited before patch</h2>
      <p>Of the flaws known to be exploited, how many were attacked before any patch existed?</p>
      <Def term="Exploited">{TERMS.exploited}</Def>
      <p>
        <strong className="exploited">{ex.appleNote}</strong> of {ex.exploited} exploited Apple flaws were attacked before a patch existed, per
        Apple&apos;s own advisory (&ldquo;may have been exploited&rdquo;). How long before is not public.
      </p>
      <Def term="KEV date added (proxy)">{TERMS.kevProxy}</Def>
      <p>
        Secondary, KEV proxy: {ex.withKev} are in CISA KEV, listed a median of {formatDays(ex.kevAfterPatch.median)} after the first patch
        {ex.kevAfterPatch.worst ? (
          <>
            {" "}
            (longest: {formatDays(ex.kevAfterPatch.worst.days)}, <CveLink id={ex.kevAfterPatch.worst.cveId} />)
          </>
        ) : null}
        ; {ex.kevBeforePatch} were listed before any patch existed.{" "}
        {ex.unknownKev > 0 ? `${ex.unknownKev} are exploited per Apple but not in KEV (KEV date unknown).` : null}
      </p>
      <Def term="Third-party component">{TERMS.thirdParty}</Def>
      <p>{ex.thirdParty} of the exploited CVEs are in third-party components.</p>
      <ExploitedTable rows={exploited} />

      <h2 id="disclosure">3. Disclosure lag</h2>
      <p>How long after Apple&apos;s fix did the CVE appear in NVD, where most scanners and risk tools read it?</p>
      <Def term="Disclosure lag">{TERMS.disclosureLag}</Def>
      <p>
        Median <strong>{formatDays(disc.lag.median)}</strong>
        {disc.lag.worst ? (
          <>
            , worst {formatDays(disc.lag.worst.days)} (<CveLink id={disc.lag.worst.cveId} />)
          </>
        ) : null}
        , over {disc.lag.n} of {disc.cves} CVEs. NVD date unknown for {disc.unknown}. {disc.publishedBeforeFix} were published in NVD before the fix.{" "}
        {disc.lateAdvisoryEntries} CVEs were added to Apple&apos;s advisory after the release that fixed them; their fix date stays the release date.
      </p>
      <DisclosureByYear timelines={timelines} />
    </>
  );
}

function ExploitedTable({ rows }: { rows: CveTimeline[] }) {
  if (rows.length === 0) return <p>No exploited CVEs in the window.</p>;
  return (
    <TableScroll label="Exploited CVEs">
      <table>
        <caption>Exploited CVEs, newest first. Red marks exploitation documented before a patch existed.</caption>
        <thead>
          <tr>
            <th scope="col">CVE</th>
            <th scope="col">First fix</th>
            <th scope="col">KEV added</th>
            <th scope="col">KEV vs first fix</th>
            <th scope="col">Apple: exploited at release</th>
            <th scope="col">NVD published</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.id}>
              <th scope="row" className={t.exploitedBeforePatch ? "exploited" : undefined}>
                <CveLink id={t.id} />
                {t.exploitedBeforePatch ? <span className="visually-hidden"> (exploited before patch)</span> : null}
                {t.thirdPartyVendor ? <span className="tag"> third-party component ({t.thirdPartyVendor})</span> : null}
              </th>
              <td>
                <time dateTime={t.firstFixDate}>{t.firstFixDate}</time>
              </td>
              <td>
                <DateOrUnknown d={t.cve.kevDateAdded} />
              </td>
              <td>{t.kevWindowDays === null ? <Unknown /> : relative(-t.kevWindowDays, "after", "before")}</td>
              <td className={t.appleExploitedNote ? "exploited" : undefined}>{t.appleExploitedNote ? "yes" : "no"}</td>
              <td>
                <DateOrUnknown d={t.cve.nvdPublished} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

function DisclosureByYear({ timelines }: { timelines: CveTimeline[] }) {
  const years = new Map<string, CveTimeline[]>();
  for (const t of timelines) {
    if (!t.inWindow) continue;
    const y = t.firstFixDate.slice(0, 4);
    const list = years.get(y);
    if (list) list.push(t);
    else years.set(y, [t]);
  }
  const sorted = [...years.entries()].sort(([a], [b]) => a.localeCompare(b));
  if (sorted.length === 0) return <p>No CVEs in the window.</p>;
  return (
    <TableScroll label="Disclosure lag by year">
      <table>
        <caption>Disclosure lag by year of first fix</caption>
        <thead>
          <tr>
            <th scope="col">Year</th>
            <th scope="col" className="num">
              CVEs
            </th>
            <th scope="col" className="num">
              Median lag
            </th>
            <th scope="col" className="num">
              Worst lag
            </th>
            <th scope="col" className="num">
              NVD unknown
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(([y, ts]) => {
            const s = disclosureSummary(ts);
            return (
              <tr key={y}>
                <th scope="row">{y}</th>
                <td className="num">{ts.length}</td>
                <StatCells s={s.lag} />
                <td className="num">{s.unknown}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableScroll>
  );
}
