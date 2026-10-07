import type { NextConfig } from "next";

/**
 * Static export: every page and export file is generated at build time into out/, then
 * scripts/strip-js.ts removes all JavaScript. The site is rebuilt whenever the data changes
 * (the ingest workflow commits data/snapshot.json; the push deploys). Response headers live in vercel.json,
 * because a static export has no server.
 */
const config: NextConfig = {
  output: "export",
  reactStrictMode: true,
};

export default config;
