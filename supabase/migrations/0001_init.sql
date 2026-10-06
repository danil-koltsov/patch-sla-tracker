-- Patch SLA Tracker schema. Methodology logic lives in lib/metrics.ts;
-- SQL exposes base facts only (see docs/decisions.md).

create table public.vendors (
  id   text primary key,
  name text not null
);
insert into public.vendors (id, name) values ('apple', 'Apple');

create table public.branches (
  id        text primary key,                       -- 'ios-16'
  vendor_id text not null default 'apple' references public.vendors (id),
  platform  text not null check (platform in ('iOS', 'iPadOS', 'macOS')),
  major     integer not null check (major > 0),
  name      text not null,                          -- 'macOS 14 Sonoma'
  unique (vendor_id, platform, major)
);

create table public.releases (
  id              text primary key,                 -- 'ios-16.5.1-a'
  branch_id       text not null references public.branches (id),
  version         text not null,                    -- as Apple writes it
  suffix          text,                             -- '(a)' for RSR/BSI
  kind            text not null check (kind in ('full', 'rsr', 'bsi')),
  release_date    date not null,                    -- earliest listing in Apple's index (UTC date)
  rerelease_dates date[] not null default '{}',     -- later listings of the same release
  name            text not null,
  advisory_url    text,                             -- null: "no published CVE entries"
  has_cve_entries boolean not null,
  last_seen_run   bigint not null
);
create index releases_branch_idx on public.releases (branch_id, release_date);

create table public.cves (
  id             text primary key check (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  nvd_published  date,                              -- null = unknown
  kev_date_added date,                              -- null = not in KEV
  kev_due_date   date,
  last_seen_run  bigint not null
);

create table public.release_cves (
  release_id     text not null references public.releases (id) on delete cascade,
  cve_id         text not null references public.cves (id) on delete cascade,
  entry_added    date,                              -- "Entry added <date>" on Apple's advisory
  entry_updated  date,
  exploited_note boolean not null default false,    -- "may have been (actively) exploited"
  last_seen_run  bigint not null,
  primary key (release_id, cve_id)
);
create index release_cves_cve_idx on public.release_cves (cve_id);

create table public.ingest_runs (
  id                  bigint generated always as identity primary key,
  started_at          timestamptz not null default now(),
  finished_at         timestamptz,
  status              text not null default 'running' check (status in ('running', 'ok', 'failed')),
  methodology_version text not null,
  kev_catalog_version text,
  counts              jsonb not null default '{}',
  warnings            jsonb not null default '[]'
);

-- Base-fact views. security_invoker so RLS of the caller applies.
create view public.v_cve_branch_first_fix with (security_invoker = true) as
select rc.cve_id,
       r.branch_id,
       b.platform,
       b.major,
       min(r.release_date) as first_fix_date,
       count(*)            as listings
from public.release_cves rc
join public.releases r on r.id = rc.release_id
join public.branches b on b.id = r.branch_id
group by rc.cve_id, r.branch_id, b.platform, b.major;

create view public.v_branch_spans with (security_invoker = true) as
select b.id as branch_id,
       b.platform,
       b.major,
       min(r.release_date)                                   as first_release_date,
       max(r.release_date)                                   as last_release_date,
       max(r.release_date) filter (where r.has_cve_entries)  as last_security_release_date
from public.branches b
join public.releases r on r.branch_id = b.id
group by b.id, b.platform, b.major;

create view public.v_last_ingest with (security_invoker = true) as
select id, finished_at, methodology_version, kev_catalog_version, counts
from public.ingest_runs
where status = 'ok'
order by finished_at desc
limit 1;

-- Access: anonymous and authenticated roles may only read. Writes use the service role
-- (GitHub Actions), which bypasses RLS.
alter table public.vendors      enable row level security;
alter table public.branches     enable row level security;
alter table public.releases     enable row level security;
alter table public.cves         enable row level security;
alter table public.release_cves enable row level security;
alter table public.ingest_runs  enable row level security;

create policy read_all on public.vendors      for select to anon, authenticated using (true);
create policy read_all on public.branches     for select to anon, authenticated using (true);
create policy read_all on public.releases     for select to anon, authenticated using (true);
create policy read_all on public.cves         for select to anon, authenticated using (true);
create policy read_all on public.release_cves for select to anon, authenticated using (true);
create policy read_ok  on public.ingest_runs  for select to anon, authenticated using (status = 'ok');

revoke all on all tables in schema public from anon, authenticated;
grant select on all tables in schema public to anon, authenticated;
