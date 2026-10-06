/** Regenerates tests/fixtures/snapshot.json, the synthetic dataset CI builds against. */
import { writeFileSync } from "node:fs";
import { Fixture } from "./builder.ts";

const f = new Fixture();
f.release("iOS", "16.0", "2022-09-12", ["CVE-2022-0001"]);
f.release("iOS", "17.0", "2023-09-18", ["CVE-2023-0001"]);
f.release("iOS", "17.1", "2023-10-25", [{ id: "CVE-2023-1000", exploited: true }, "CVE-2023-1001"]);
f.release("iOS", "16.7.2", "2023-11-07", [{ id: "CVE-2023-1000", exploited: true }]);
f.release("iOS", "16.5.1", "2023-07-10", [{ id: "CVE-2023-37450", exploited: true }], { suffix: "(a)" });
f.release("iOS", "17.2", "2023-12-11", [{ id: "CVE-2024-0100", entryAdded: "2024-05-13" }]);
f.release("iPadOS", "17.1", "2023-10-25", [{ id: "CVE-2023-1000", exploited: true }]);
f.release("macOS", "14.1", "2023-10-25", ["CVE-2023-1001"]);
f.cve("CVE-2023-1000", { kevDateAdded: "2023-10-26", kevDueDate: "2023-11-16", nvdPublished: "2023-10-25" });
f.cve("CVE-2023-37450", { kevDateAdded: "2023-07-13", nvdPublished: "2023-07-27" });
f.cve("CVE-2024-0100", { nvdPublished: "2024-05-14" });
const ds = f.dataset();
for (const b of ds.branches) if (b.platform === "macOS") b.name = `macOS ${b.major} Sonoma`;
writeFileSync(new URL("./snapshot.json", import.meta.url), JSON.stringify(ds, null, 1) + "\n");
