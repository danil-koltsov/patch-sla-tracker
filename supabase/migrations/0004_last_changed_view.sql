-- The site shows "Data last changed": the latest successful run that actually changed the data.
-- Runs recorded before change tracking (changed is null) count as changes.
create or replace view public.v_last_ingest with (security_invoker = true) as
select id, finished_at, methodology_version, kev_catalog_version, counts
from public.ingest_runs
where status = 'ok' and coalesce(changed, true)
order by finished_at desc
limit 1;
