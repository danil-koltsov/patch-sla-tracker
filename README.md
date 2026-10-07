# Patch SLA Tracker — Apple

How long Apple users stay exposed to security flaws **after a fix already exists somewhere**:

1. **Exploited before patch (KEV proxy)**: CISA KEV `dateAdded` relative to Apple's first fix.
2. **Backport gap**: how many days each older iOS / iPadOS / macOS branch waited after the earliest fix.
3. **Disclosure lag**: NVD publication relative to Apple's fix.

Four pages: `/`, `/apple`, `/cve/[id]`, `/methodology`. Every view has a permalink and a CSV/JSON export (`/apple/data.csv`,
`/apple/data.json`, `/cve/<id>/data.csv`, `/cve/<id>/data.json`).

Background: [docs/data-sources.md](docs/data-sources.md) (what the sources really contain) ·
[docs/decisions.md](docs/decisions.md) (why things are the way they are).

## Layout

```
app/                 Next.js App Router pages and export routes (server components only, statically exported)
components/          Server-rendered UI pieces and static SVG charts
lib/metrics.ts       The three metrics: pure functions, the only place the rules live
lib/methodology.ts   Methodology version, window start, definitions shown on pages
data/snapshot.json   The dataset, committed to git: one record per line, rewritten only when the data changes
lib/snapshot.ts      Snapshot path and its deterministic line-per-record format
lib/data.ts          Loads the snapshot at build time
scripts/strip-js.ts  Post-build: removes all JavaScript from the static export
scripts/ingest/      Ingestion every 6 hours: Apple index + advisories, CISA KEV, NVD → data/snapshot.json
tests/               Vitest: metric edge cases, parsers, NVD sync, snapshot format
content/corrections.ts  Public changelog of data corrections (shown on /methodology)
```

## Local setup

Requires Node ≥ 23.6. Ingestion runs TypeScript natively, with no build step.

```bash
npm ci
```

The dataset is already in the repository (`data/snapshot.json`), so the site runs right away:

```bash
npm run dev
```

To refresh the data from the live sources, run the ingestion below. The first run on a machine takes about 10–20 minutes because
of polite request pacing and NVD rate limits; later runs reuse `.cache/` and take a minute or two.

```bash
npm run ingest
```

The file is rewritten only if the data changed, so `git diff data/` shows exactly which releases, listings or CVEs changed.

Checks (the same ones CI runs):

```bash
npm run lint && npm run typecheck && npm test
```

## Data storage

The dataset lives in git as `data/snapshot.json`, with no database and no secrets.

- Format: deterministic JSON with one record per line (`meta`, `branches`, `releases`, `releaseCves`, `cves`), so diffs are
  readable and git's delta compression keeps history small.
- History: every data change is a commit by `github-actions[bot]`. Use `git log -p -- data/` to see what changed and when. Manual
  corrections that change published numbers are also listed in `content/corrections.ts`, which is shown on `/methodology`.
- The schema is the `Dataset` type in `lib/types.ts`.

## Ingestion

`scripts/ingest/run.ts`, run every 6 hours by `.github/workflows/ingest.yml` (00:17, 06:17, 12:17, 18:17 UTC) and on demand
through *Run workflow*.

What each run re-reads:

| Source | Refresh |
|---|---|
| Apple index (current page) | every run |
| Apple advisories released in the last 90 days | every run, because Apple adds CVEs to existing advisories later |
| Apple advisories 90–400 days old | daily |
| Older advisories, index archives | monthly / weekly |
| CISA KEV | full reload every run |
| NVD | records modified since the previous run (`lastModStartDate`), full Apple-CNA resync weekly |
| NVD single lookups (CVEs from other CNAs still without a date) | retried daily |

- Caching: responses live in `.cache/http`, NVD state in `.cache/nvd-state.json`. Both are restored between Actions runs. If the
  cache is lost, the next run does a full NVD sync.
- Change detection: each run hashes the dataset (without timestamps). If nothing changed, `data/snapshot.json` stays
  byte-identical. **"Changed" means `git diff data/` is non-empty**: only then does the workflow commit and push to `main`, and the
  push deploys the site. The footer shows "Data last changed", which is the time of the run that last changed the data.
- Rate limits: Apple is paced at 1 request per 1.5 s. NVD is paced at 1 request per 6.5 s without a key, or 0.7 s with `NVD_API_KEY`.
- Idempotent: the snapshot is rebuilt from the sources on every run, so records the sources no longer contain disappear.
- Safety: if branches, releases, CVEs or listings would shrink by more than 10% against the committed snapshot, the run fails and
  nothing is written. Re-run with `force` only after checking why.
- The workflow needs `contents: write` to push to `main`. If `main` is protected, allow `github-actions[bot]` to push to it, or
  change the workflow to open a pull request instead.

GitHub secrets: optional `NVD_API_KEY`. No other secrets are needed.

## Deploy on Vercel

The site is a **static export** that ships **no JavaScript**. `next build` writes every page and export file to `out/`, then
`scripts/strip-js.ts` removes all `<script>` tags, JS chunks and RSC payloads. The build fails if any script is left.

1. Import the GitHub repository in Vercel. `vercel.json` sets the framework to none, the build command to `npm run build`, the output
   directory to `out/`, clean URLs, and the security headers (including a CSP that allows no scripts).
2. Environment variable: `SITE_URL` (the public origin, used for canonical URLs). Nothing else is needed, because the data comes
   from the repository.
3. Production branch: `main`. Every push deploys, including the data commits from the ingest workflow, so new data goes live within
   minutes of being found.

Pages exist for every CVE first fixed since 2023-01-01. Any other address returns the 404 page, which explains that scope.

Preview the exported site locally (clean URLs and the 404 page behave as they do on Vercel):

```bash
npm run build && npm start
```

See `.env.example` for the optional variables.

## Quality gates

- CI (`.github/workflows/ci.yml`): lint, typecheck, unit tests, and a production build against `tests/fixtures/snapshot.json`.
- Lighthouse targets: Accessibility, Best Practices and SEO at 100, Performance ≥ 95. A perfect score does not prove WCAG 2.2 AA, so
  keyboard navigation and screen-reader output are also checked by hand (see the Phase 1 notes in `docs/decisions.md`).
