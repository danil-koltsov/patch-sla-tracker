-- KEV vendorProject, used to label CVEs in third-party components (e.g. Google/Chromium code shipped in WebKit/ANGLE).
alter table public.cves add column kev_vendor_project text;
