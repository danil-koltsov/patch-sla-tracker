import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { DateOrUnknown, Def, Exports, relative, TableScroll, Unknown } from "../../../components/bits.tsx";
import { CveTimelineSvg } from "../../../components/CveTimelineSvg.tsx";
import { loadData } from "../../../lib/data.ts";
import { TERMS, WINDOW_START } from "../../../lib/methodology.ts";
import { cveTimeline, type BranchStatus } from "../../../lib/metrics.ts";

export const revalidate = 86400; // must be a literal; equals REVALIDATE_SECONDS
export const dynamicParams = true;

const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

/** Pre-render exploited CVEs; the rest render on first request and are cached for a day. */
export async function generateStaticParams() {
  try {
    const { timelines } = await loadData();
    return timelines.filter((t) => t.inWindow && t.exploited).map((t) => ({ id: t.id }));
  } catch {
    return [];
  }
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return {
    title: id,
    description: `${id}: when Apple fixed it on each iOS, iPadOS and macOS branch, and how that compares with CISA KEV and NVD dates.`,
    alternates: { canonical: `/cve/${id}` },
  };
}

function statusText(s: BranchStatus): string {
  switch (s.kind) {
    case "fixed":
      return s.gapDays === 0 ? "fixed with the earliest fix" : `fixed ${s.gapDays} ${s.gapDays === 1 ? "day" : "days"} later`;
    case "no-fix-listed":
      return "no fix listed";
    case "branch-ended":
      return "branch ended";
    case "later-major":
      return "branch released later (not counted)";
  }
}

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  const { id: raw } = await params;
  const id = decodeURIComponent(raw).toUpperCase();
  if (!CVE_ID.test(id)) notFound();
  const { index } = await loadData();
  const t = cveTimeline(index, id);
  if (!t) notFound();
  const { cve } = t;

  return (
    <>
      <h1>{t.id}</h1>
      {t.exploitedBeforePatch ? (
        <p className="exploited-mark">
          Exploited before a patch existed
          {t.appleExploitedNote ? " (Apple: “may have been exploited”)" : ""}
          {t.kevWindowDays !== null && t.kevWindowDays > 0 ? ` (in CISA KEV ${t.kevWindowDays} days before the first fix)` : ""}.
        </p>
      ) : t.exploited ? (
        <p>Known exploited (listed in CISA KEV after the first fix).</p>
      ) : null}
      {!t.inWindow ? (
        <p className="muted">First fixed before {WINDOW_START}; shown for reference but not counted in the Apple-wide numbers.</p>
      ) : null}
      <Exports base={`/cve/${t.id}`} label="this CVE's branch rows" />

      <dl className="facts">
        <dt>First fix</dt>
        <dd>
          <time dateTime={t.firstFixDate}>{t.firstFixDate}</time> (
          {t.listings
            .filter((l) => l.release.releaseDate === t.firstFixDate)
            .map((l, i) => (
              <span key={l.release.id}>
                {i > 0 ? ", " : ""}
                {l.release.advisoryUrl ? <a href={l.release.advisoryUrl}>{l.release.name}</a> : l.release.name}
              </span>
            ))}
          )
        </dd>
        <dt>CISA KEV added</dt>
        <dd>
          {cve.kevDateAdded ? (
            <>
              <a href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${t.id}`}>
                <time dateTime={cve.kevDateAdded}>{cve.kevDateAdded}</time>
              </a>{" "}
              ({relative(-t.kevWindowDays!, "after the first fix", "before the first fix")})
            </>
          ) : (
            <span className="muted">not in KEV</span>
          )}
        </dd>
        <dt>NVD published</dt>
        <dd>
          <a href={`https://nvd.nist.gov/vuln/detail/${t.id}`}>
            <DateOrUnknown d={cve.nvdPublished} />
          </a>
          {t.disclosureLagDays !== null ? ` (${relative(t.disclosureLagDays, "after the first fix", "before the first fix")})` : null}
        </dd>
      </dl>
      <Def term="First fix">{TERMS.firstFix}</Def>
      <Def term="KEV date added (proxy)">{TERMS.kevProxy}</Def>

      <h2 id="branches">Fix per branch</h2>
      <Def term="Backport gap">{TERMS.backportGap}</Def>
      <Def term="No fix listed">{TERMS.noFixListed}</Def>
      <Def term="Branch ended">{TERMS.branchEnded}</Def>
      <CveTimelineSvg t={t} />
      {t.platforms.map((p) => (
        <TableScroll key={p.platform} label={`${p.platform} branches for ${t.id}`}>
          <table>
            <caption>
              {p.platform}: earliest fix <time dateTime={p.earliestFixDate}>{p.earliestFixDate}</time>
            </caption>
            <thead>
              <tr>
                <th scope="col">Branch</th>
                <th scope="col">Status</th>
                <th scope="col">First fix on branch</th>
                <th scope="col" className="num">
                  Gap
                </th>
              </tr>
            </thead>
            <tbody>
              {p.outcomes.map((o) => {
                const s = o.status;
                const fix = s.kind === "fixed" || s.kind === "later-major" ? s : null;
                const rel = fix ? index.releases.get(fix.releaseId) : undefined;
                return (
                  <tr key={o.branch.id}>
                    <th scope="row">{o.branch.name}</th>
                    <td>{statusText(s)}</td>
                    <td>
                      {fix && rel ? (
                        <>
                          <time dateTime={fix.fixDate}>{fix.fixDate}</time>{" "}
                          {rel.advisoryUrl ? <a href={rel.advisoryUrl}>{rel.name}</a> : rel.name}
                        </>
                      ) : (
                        <span className="muted">–</span>
                      )}
                    </td>
                    <td className="num">{s.kind === "fixed" ? `${s.gapDays} d` : <span className="muted">–</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      ))}

      <h2 id="sources">Every Apple listing</h2>
      <p>Each release whose advisory lists {t.id}, with Apple&apos;s own notes.</p>
      <TableScroll label={`Apple advisories listing ${t.id}`}>
        <table>
          <caption>Apple advisories listing {t.id}</caption>
          <thead>
            <tr>
              <th scope="col">Release</th>
              <th scope="col">Released</th>
              <th scope="col">Entry added</th>
              <th scope="col">Exploited note</th>
            </tr>
          </thead>
          <tbody>
            {t.listings.map((l) => (
              <tr key={l.release.id}>
                <th scope="row">{l.release.advisoryUrl ? <a href={l.release.advisoryUrl}>{l.release.name}</a> : l.release.name}</th>
                <td>
                  <time dateTime={l.release.releaseDate}>{l.release.releaseDate}</time>
                  {l.release.rereleaseDates.length ? <span className="muted"> (re-released {l.release.rereleaseDates.join(", ")})</span> : null}
                </td>
                <td>{l.entryAdded ? <time dateTime={l.entryAdded}>{l.entryAdded}</time> : <span className="muted">with release</span>}</td>
                <td className={l.exploitedNote ? "exploited" : undefined}>{l.exploitedNote ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
      {cve.nvdPublished === null ? (
        <p>
          NVD publication date: <Unknown />. The record may not exist in NVD yet.
        </p>
      ) : null}
    </>
  );
}
