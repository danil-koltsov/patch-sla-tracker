import type { Metadata } from "next";
import { TableScroll } from "../../components/bits.tsx";
import { CORRECTIONS } from "../../content/corrections.ts";
import { METHODOLOGY_HISTORY, METHODOLOGY_VERSION, TERMS, WINDOW_START } from "../../lib/methodology.ts";

export const metadata: Metadata = {
  title: "Methodology",
  description: "Definitions, sources, rules and known limitations behind the Patch SLA Tracker numbers, with version history and data corrections.",
  alternates: { canonical: "/methodology" },
};

export default function Methodology() {
  return (
    <>
      <h1>Methodology v{METHODOLOGY_VERSION}</h1>
      <p>
        This site measures how long Apple users stay exposed to a security flaw <em>after a fix for it already exists somewhere</em>. It does not
        rebuild a CVE database: it combines Apple&apos;s advisories, CISA&apos;s exploited-vulnerability catalog and NVD into three timing metrics.
      </p>

      <h2 id="sources">Sources</h2>
      <ul>
        <li>
          <a href="https://support.apple.com/en-us/100100">Apple security releases</a> (and yearly archives): every release, its date, and its
          advisory. Release dates are Apple&apos;s, as US calendar dates; we treat them as UTC dates.
        </li>
        <li>
          Apple advisories (&ldquo;About the security content of …&rdquo;): which CVEs each release fixes, &ldquo;Entry added&rdquo; dates, and
          the note &ldquo;Apple is aware of a report that this issue may have been exploited&rdquo;.
        </li>
        <li>
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA Known Exploited Vulnerabilities</a> (KEV): date added, joined
          by CVE ID (some Apple-shipped CVEs are filed under other vendors, e.g. Google).
        </li>
        <li>
          <a href="https://nvd.nist.gov/developers/vulnerabilities">NVD CVE API 2.0</a>: the record&apos;s published date (UTC).
        </li>
      </ul>
      <p>
        Ingestion runs every 6 hours. Each run re-reads Apple&apos;s index, every advisory released in the last 90 days (Apple adds CVEs to
        existing advisories weeks or months later), the full KEV catalog, and every NVD record modified since the previous run, with a full
        NVD resync weekly. Older advisories are re-read daily up to 400 days, then monthly. The dataset is a single file in the
        project&apos;s git repository; every change to it is a commit, and the site is rebuilt only when it changes. Ingestion caches every
        response and refuses to publish if the dataset would shrink by more than 10% (a sign that a source
        changed format). SOFA (sofa.macadmins.io) was evaluated and not used: it lacks iOS 15–17 and iPadOS 17, and some older macOS release
        dates in it are wrong.
      </p>

      <h2 id="definitions">Definitions</h2>
      <dl>
        {(
          [
            ["Branch", TERMS.branch],
            ["First fix", TERMS.firstFix],
            ["Exploited", TERMS.exploited],
            ["KEV date added (proxy)", TERMS.kevProxy],
            ["Backport gap", TERMS.backportGap],
            ["No fix listed", TERMS.noFixListed],
            ["Branch ended", TERMS.branchEnded],
            ["Fixed at branch release", TERMS.atBranchRelease],
            ["Third-party component", TERMS.thirdParty],
            ["Disclosure lag", TERMS.disclosureLag],
          ] as const
        ).map(([term, def]) => (
          <div key={term}>
            <dt>
              <dfn>{term}</dfn>
            </dt>
            <dd>{def}</dd>
          </div>
        ))}
      </dl>

      <h2 id="metrics">The three metrics</h2>
      <h3>1. Exploited before patch</h3>
      <p>
        Headline: how many exploited CVEs Apple itself described as &ldquo;may have been exploited&rdquo; when it released the fix, i.e.
        possibly already under attack when the fix shipped. How long before is not public. Secondary: for each exploited CVE in KEV, first fix date minus KEV date
        added. Positive means CISA had catalogued exploitation before any Apple patch existed.
        For Apple this is rare; KEV usually follows the patch by days, and sometimes by years when exploitation is discovered later. The number is
        therefore a lagging proxy, not the start of exploitation, which is not public. Apple&apos;s own &ldquo;may have been exploited&rdquo; note
        is shown alongside: it means exploitation began before the patch, for an unknown length of time.
      </p>
      <h3>2. Backport gap</h3>
      <p>
        Per CVE and platform (iOS, iPadOS, macOS separately): find the earliest fix on any branch. Each branch that existed on that date is then
        classified as <em>fixed</em> (gap = its first fix minus the earliest fix), <em>no fix listed</em>, or <em>branch ended</em>. A branch
        first released after the earliest fix is shown as <em>fixed at branch release</em> and is not counted. The headline reports one branch,
        never a mix: the oldest branch still maintained on the data date (last security release under 180 days old), with its median and worst
        gap, over exploited CVEs only, where a missing backport is least likely to mean &ldquo;not affected&rdquo;.
      </p>
      <h3>3. Disclosure lag</h3>
      <p>NVD published date minus the first fix date, over all CVEs in the window.</p>
      <p>
        Every metric reports the median (the mean of the two middle values for even counts) and the worst case, with the CVE that produced it.
        Means are not shown. Only CVEs whose earliest fix is on or after {WINDOW_START} are counted; releases since 2022 are ingested so that a
        2022 first fix is not mistaken for a 2023 one.
      </p>

      <h2 id="rules">Edge-case rules</h2>
      <ul>
        <li>A CVE listed by several releases of the same branch: the earliest of them is the branch&apos;s fix date.</li>
        <li>
          Rapid Security Responses and Background Security Improvements (letter-suffix updates such as 16.5.1 (a)) count as fixes on their date,
          including (a) releases that Apple later replaced with (c).
        </li>
        <li>A release Apple listed twice (re-release): the first date counts; later dates are shown.</li>
        <li>
          A CVE added to an advisory after the release (&ldquo;Entry added&rdquo;): the fix date stays the release date; the late entry is shown on
          the CVE page and counted under disclosure lag.
        </li>
        <li>Missing NVD or KEV dates are shown as &ldquo;unknown&rdquo; and left out of medians, never estimated.</li>
        <li>
          A branch with no <em>security</em> release after the earliest fix is &ldquo;branch ended&rdquo;, not &ldquo;no fix listed&rdquo;, unless
          its last security release is under 180 days old: then its next one may simply not be due yet, and it stays &ldquo;no fix listed&rdquo;
          as of the data date. Updates without published CVE entries (e.g. iOS 12.5.8, January 2026, which Apple lists with no published CVE entries) do not keep a branch alive.
        </li>
        <li>
          A branch first released after the earliest fix (e.g. a new major version) is &ldquo;fixed at branch release&rdquo;: listed if its
          advisory names the CVE, otherwise assumed inherited. It is never counted as a backport gap or as missing a fix.
        </li>
        <li>
          CVEs that CISA KEV files under a vendor other than Apple are labelled &ldquo;third-party component&rdquo;; they stay in all metrics,
          because Apple users are exposed until Apple ships the fix.
        </li>
        <li>An older branch fixed before the newest one: the older branch sets the earliest fix date and the newest branch gets the gap.</li>
      </ul>

      <h2 id="limitations">Known limitations</h2>
      <ul>
        <li>&ldquo;No fix listed&rdquo; cannot be told apart from &ldquo;not affected&rdquo;: Apple does not publish which branches are unaffected.</li>
        <li>
          Some branches serve two groups: devices that cannot upgrade, and users who chose not to. The numbers describe the branch, not the
          device.
        </li>
        <li>Apple advisories are HTML pages; a format change can break parsing. The shrink guard stops publication rather than publishing gaps.</li>
        <li>
          Release dates are calendar days. Two releases on the same day have a gap of 0 days even if they shipped hours apart, and time zones are
          ignored.
        </li>
        <li>watchOS, tvOS, visionOS and Safari are out of scope.</li>
      </ul>

      <h2 id="versions">Version history</h2>
      <TableScroll label="Methodology versions">
        <table>
          <caption>Methodology versions</caption>
          <thead>
            <tr>
              <th scope="col">Version</th>
              <th scope="col">Date</th>
              <th scope="col">Change</th>
            </tr>
          </thead>
          <tbody>
            {METHODOLOGY_HISTORY.map((v) => (
              <tr key={v.version}>
                <th scope="row">{v.version}</th>
                <td>
                  <time dateTime={v.date}>{v.date}</time>
                </td>
                <td className="wrap">{v.change}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>

      <h2 id="corrections">Data corrections</h2>
      {CORRECTIONS.length === 0 ? (
        <p>No corrections so far. Any change to a published number caused by a source error, parser fix or rule change is listed here.</p>
      ) : (
        <TableScroll label="Data corrections">
          <table>
            <caption>Data corrections, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Date</th>
                <th scope="col">Affects</th>
                <th scope="col">Correction</th>
              </tr>
            </thead>
            <tbody>
              {[...CORRECTIONS]
                .sort((a, b) => b.date.localeCompare(a.date))
                .map((c, i) => (
                  <tr key={i}>
                    <th scope="row">
                      <time dateTime={c.date}>{c.date}</time>
                    </th>
                    <td>{c.affects}</td>
                    <td className="wrap">{c.source ? <a href={c.source}>{c.summary}</a> : c.summary}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </TableScroll>
      )}
    </>
  );
}
