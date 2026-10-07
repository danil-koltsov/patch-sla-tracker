-- Ingestion runs every 6 hours; the site is rebuilt only when the data actually changed.
alter table public.ingest_runs add column content_hash text;
alter table public.ingest_runs add column changed boolean;
