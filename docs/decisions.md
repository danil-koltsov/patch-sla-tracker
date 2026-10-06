# Decisions log

Small decisions made without asking. Larger trade-offs are raised as questions instead.

- 2026-10-06 — Phase 0 used the SOFA **v2** feeds only. v1 returns HTTP 403.
- 2026-10-06 — Join KEV to CVEs on `cveID`, never on `vendorProject`. Some CVEs that ship in Apple OSes are filed in KEV under Google/WebRTC.
- 2026-10-06 — Dates are stored as UTC calendar dates (`YYYY-MM-DD`). Apple publishes date-only US release days, so time-of-day precision would be invented.
- 2026-10-06 — Raw Phase 0 snapshots stay out of the repo, in the session scratchpad. Ingestion will add its own cache.
