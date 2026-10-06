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
        Ingestion runs once a day, caches every response and refuses to publish if a table would shrink by more than 10% (a sign that a source
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
            ["Branch released later", TERMS.laterMajor],
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
      <h3>1. Exploited before patch (KEV proxy)</h3>
      <p>
        For each exploited CVE: first fix date minus KEV date added. Positive means CISA had catalogued exploitation before any Apple patch existed.
        For Apple this is rare; KEV usually follows the patch by days, and sometimes by years when exploitation is discovered later. The number is
        therefore a lagging proxy, not the start of exploitation, which is not public. Apple&apos;s own &ldquo;may have been exploited&rdquo; note
        is shown alongside: it means exploitation began before the patch, for an unknown length of time.
      </p>
      <h3>2. Backport gap</h3>
      <p>
        Per CVE and platform (iOS, iPadOS, macOS separately): find the earliest fix on any branch. Each branch that existed on that date is then
        classified as <em>fixed</em> (gap = its first fix minus the earliest fix), <em>no fix listed</em>, or <em>branch ended</em>. A branch
        first released after the earliest fix is not counted. &ldquo;Older branches&rdquo; are those below the newest major version that existed on
        the date of the earliest fix. Headline numbers use exploited CVEs only, where a missing backport is least likely to mean &ldquo;not
        affected&rdquo;.
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
          A branch with no update after the earliest fix is &ldquo;branch ended&rdquo;, not &ldquo;no fix listed&rdquo;, unless its last update is
          under 180 days old: then its next update may simply not be due yet, and it stays &ldquo;no fix listed&rdquo; as of the data date.
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
