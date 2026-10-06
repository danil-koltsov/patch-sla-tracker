/**
 * Post-build step for the static export: removes every script so pages ship 0 bytes of JavaScript.
 * Pages are server-rendered HTML; the scripts only hydrate React and power client-side navigation,
 * which this site does not use. Fails the build if any script survives.
 */
import { readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

const OUT = process.argv[2] ?? "out";

async function* walk(dir: string): AsyncGenerator<string> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else yield p;
  }
}

let pages = 0;
let before = 0;
let after = 0;
let removedFiles = 0;
const leftovers: string[] = [];

for await (const file of walk(OUT)) {
  if (file.endsWith(".html")) {
    const html = await readFile(file, "utf8");
    const stripped = html
      .replace(/<script\b[\s\S]*?<\/script>/gi, "")
      .replace(/<link\b[^>]*\bas="script"[^>]*>/gi, "")
      .replace(/<link\b[^>]*\brel="modulepreload"[^>]*>/gi, "");
    if (/<script\b/i.test(stripped) || /\.js["']/.test(stripped.match(/<link\b[^>]*>/gi)?.join("") ?? "")) leftovers.push(file);
    await writeFile(file, stripped);
    pages++;
    before += Buffer.byteLength(html);
    after += Buffer.byteLength(stripped);
  } else if (file.endsWith(".js") || /\/__next\.[^/]*\.txt$/.test(file) || (file.endsWith(".txt") && (await isRscPayload(file)))) {
    // JS chunks and React Server Component payloads are only used by client-side navigation.
    await rm(file);
    removedFiles++;
  }
}

async function isRscPayload(file: string): Promise<boolean> {
  if ((await stat(file)).size === 0) return false;
  const head = (await readFile(file, "utf8")).slice(0, 64);
  return /^\d+:/.test(head) || head.startsWith(":");
}

if (leftovers.length) {
  console.error(`strip-js: scripts still present in ${leftovers.length} pages, e.g. ${leftovers.slice(0, 3).join(", ")}`);
  process.exit(1);
}
console.log(`strip-js: ${pages} pages, HTML ${(before / 1024).toFixed(0)} KB → ${(after / 1024).toFixed(0)} KB, removed ${removedFiles} JS/RSC files`);
