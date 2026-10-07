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
lib/data.ts          Loads the dataset at build time from Supabase (PostgREST) or a local JSON snapshot
scripts/strip-js.ts  Post-build: removes all JavaScript from the static export
scripts/ingest/      Ingestion every 6 hours: Apple index + advisories, CISA KEV, NVD → Supabase
supabase/migrations/ Schema, base-fact views, RLS
tests/               Vitest: metric edge cases, parsers, schema + RLS (PGlite)
content/corrections.ts  Public changelog of data corrections (shown on /methodology)
```

## Local setup

Requires Node ≥ 23.6. Ingestion runs TypeScript natively, with no build step.

```bash
npm ci
```

Build a local snapshot from the live sources without touching any database. The first run takes about 10–40 minutes because of polite request pacing and NVD rate limits; later runs reuse `.cache/http`.

```bash
npm run ingest -- --no-db --out data/snapshot.json
```

Run the site against that snapshot (dev mode; the production build is described under *Deploy*):

```bash
DATA_SNAPSHOT=data/snapshot.json npm run dev
```

Checks (the same ones CI runs):

```bash
npm run lint && npm run typecheck && npm test
```

## Supabase setup

1. Create a Supabase project.
2. Apply the schema, either by pasting `supabase/migrations/0001_init.sql` into the SQL editor or with the Supabase CLI (`supabase db push`).
3. Note three values from *Project settings → API*: the project URL, the `anon` key (read-only), and the `service_role` key (write).
4. Run a first ingestion from your machine:

   ```bash
   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npm run ingest
   ```

Access model: RLS is enabled on every table. The `anon` and `authenticated` roles can only `SELECT`, and they see only successful
ingest runs. Ingestion writes with the service role, which bypasses RLS. That key must exist only in GitHub Actions secrets and must
never reach Vercel or the browser. `tests/schema.test.ts` checks this against a real Postgres (PGlite).

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
- Change detection: each run hashes the dataset (without timestamps). If nothing changed, the tables are not rewritten and the site
  is not rebuilt. The run is still recorded in `ingest_runs` with `changed = false`.
- Rate limits: Apple is paced at 1 request per 1.5 s. NVD is paced at 1 request per 6.5 s without a key, or 0.7 s with `NVD_API_KEY`.
- Idempotent: every row is upserted with the run id, and rows the sources no longer contain are deleted afterwards.
- Safety: if any table would shrink by more than 10%, the run fails and nothing is deleted. Re-run with `force` only after checking why.

GitHub secrets: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `VERCEL_DEPLOY_HOOK_URL`, optional `NVD_API_KEY`.

## Deploy on Vercel

The site is a **static export** that ships **no JavaScript**. `next build` writes every page and export file to `out/`, then
`scripts/strip-js.ts` removes all `<script>` tags, JS chunks and RSC payloads. The build fails if any script is left.

1. Import the GitHub repository in Vercel. `vercel.json` sets the framework to none, the build command to `npm run build`, the output
   directory to `out/`, clean URLs, and the security headers (including a CSP that allows no scripts).
2. Build-time environment variables: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SITE_URL` (the public origin, used for canonical
   URLs). Do **not** add the service role key.
3. Create a Deploy Hook (*Settings → Git → Deploy Hooks*) and store it as the `VERCEL_DEPLOY_HOOK_URL` GitHub secret. The ingest
   workflow calls it whenever the data changed; without it, new data never goes live, so the workflow fails loudly.

Pages exist for every CVE first fixed since 2023-01-01. Any other address returns the 404 page, which explains that scope.

Preview the exported site locally (clean URLs and the 404 page behave as they do on Vercel):

```bash
DATA_SNAPSHOT=data/snapshot.json npm run build && npm start
```

See `.env.example` for all variables. Never commit `.env*` files with values.

## Quality gates

- CI (`.github/workflows/ci.yml`): lint, typecheck, unit tests, and a production build against `tests/fixtures/snapshot.json`.
- Lighthouse targets: Accessibility, Best Practices and SEO at 100, Performance ≥ 95. A perfect score does not prove WCAG 2.2 AA, so
  keyboard navigation and screen-reader output are also checked by hand (see the Phase 1 notes in `docs/decisions.md`).
