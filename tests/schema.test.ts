import { readFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { beforeAll, describe, expect, it } from "vitest";

const migrations = ["0001_init.sql", "0002_kev_vendor.sql", "0003_ingest_change_tracking.sql", "0004_last_changed_view.sql"].map((f) => readFileSync(new URL(`../supabase/migrations/${f}`, import.meta.url), "utf8"));
let db: PGlite;

beforeAll(async () => {
  db = new PGlite();
  // Roles that exist in every Supabase project.
  await db.exec(`create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;`);
  for (const m of migrations) await db.exec(m);
  await db.exec(`
    insert into branches (id, platform, major, name) values ('ios-16','iOS',16,'iOS 16'), ('ios-17','iOS',17,'iOS 17');
    insert into releases (id, branch_id, version, kind, release_date, name, advisory_url, has_cve_entries, last_seen_run) values
      ('ios-17.1','ios-17','17.1','full','2023-10-25','iOS 17.1','u',true,1),
      ('ios-17.2','ios-17','17.2','full','2023-12-11','iOS 17.2','u',true,1),
      ('ios-16.7.2','ios-16','16.7.2','full','2023-11-07','iOS 16.7.2','u',true,1),
      ('ios-16.7.3','ios-16','16.7.3','full','2023-12-01','iOS 16.7.3',null,false,1);
    insert into cves (id, nvd_published, last_seen_run) values ('CVE-2023-1000','2023-10-26',1);
    insert into release_cves (release_id, cve_id, last_seen_run) values
      ('ios-17.1','CVE-2023-1000',1), ('ios-17.2','CVE-2023-1000',1), ('ios-16.7.2','CVE-2023-1000',1);
    insert into ingest_runs (methodology_version, status, finished_at) values ('1.0.0','ok',now()), ('1.0.0','failed',now());
  `);
});

describe("schema", () => {
  it("v_cve_branch_first_fix takes the first release per branch", async () => {
    const r = await db.query<{ branch_id: string; first_fix_date: string; listings: number }>(
      `select branch_id, first_fix_date::text, listings::int from v_cve_branch_first_fix order by branch_id`,
    );
    expect(r.rows).toEqual([
      { branch_id: "ios-16", first_fix_date: "2023-11-07", listings: 1 },
      { branch_id: "ios-17", first_fix_date: "2023-10-25", listings: 2 },
    ]);
  });

  it("v_branch_spans separates any release from security releases", async () => {
    const r = await db.query<{ branch_id: string; last_release_date: string; last_security_release_date: string }>(
      `select branch_id, last_release_date::text, last_security_release_date::text from v_branch_spans where branch_id = 'ios-16'`,
    );
    expect(r.rows[0]).toEqual({ branch_id: "ios-16", last_release_date: "2023-12-01", last_security_release_date: "2023-11-07" });
  });

  it("rejects malformed CVE ids and unknown platforms", async () => {
    await expect(db.exec(`insert into cves (id, last_seen_run) values ('CVE-23-1', 1)`)).rejects.toThrow();
    await expect(db.exec(`insert into branches (id, platform, major, name) values ('x','watchOS',1,'x')`)).rejects.toThrow();
  });

  it("v_last_ingest returns the last run that changed data, not the last check", async () => {
    await db.exec(`
      insert into ingest_runs (methodology_version, status, finished_at, changed) values
        ('1.0.0', 'ok', now() + interval '1 hour', true),
        ('1.0.0', 'ok', now() + interval '7 hours', false);
    `);
    const r = await db.query<{ hours: number }>(`select round(extract(epoch from finished_at - now()) / 3600)::int as hours from v_last_ingest`);
    expect(r.rows[0]!.hours).toBe(1);
  });

  describe("as anon", () => {
    it("can read data and only successful ingest runs", async () => {
      await db.exec("set role anon");
      try {
        expect((await db.query(`select * from releases`)).rows).toHaveLength(4);
        expect((await db.query(`select * from v_cve_branch_first_fix`)).rows).toHaveLength(2);
        expect((await db.query(`select * from ingest_runs where status <> 'ok'`)).rows).toHaveLength(0); // failed runs hidden
        expect((await db.query(`select * from v_last_ingest`)).rows).toHaveLength(1);
      } finally {
        await db.exec("reset role");
      }
    });

    it.each([
      `insert into cves (id, last_seen_run) values ('CVE-2024-0001', 1)`,
      `update releases set release_date = '2020-01-01'`,
      `delete from release_cves`,
      `insert into ingest_runs (methodology_version) values ('x')`,
    ])("cannot write: %s", async (sql) => {
      await db.exec("set role anon");
      try {
        await expect(db.exec(sql)).rejects.toThrow(/permission denied/);
      } finally {
        await db.exec("reset role");
      }
    });
  });
});
