import next from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const config = [
  ...next,
  ...nextTs,
  {
    rules: {
      // Plain <a> on purpose: full page loads keep pages free of client-side router JS (see docs/decisions.md).
      "@next/next/no-html-link-for-pages": "off",
    },
  },
  { ignores: [".next/**", "node_modules/**", ".cache/**", "data/**", "next-env.d.ts"] },
];

export default config;
