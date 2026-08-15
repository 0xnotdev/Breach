import { readFile } from "node:fs/promises";
import { DataType, newDb } from "pg-mem";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { assertMigrationsCurrent, runMigrations } from "./migrations.js";
import { createMetadataStore } from "./index.js";

describe("versioned metadata migrations", () => {
  let pool: Pool;

  beforeEach(() => {
    const memory = newDb();
    memory.public.registerFunction({
      name: "pg_advisory_xact_lock",
      args: [DataType.bigint],
      returns: DataType.bool,
      implementation: () => true,
    });
    const adapter = memory.adapters.createPg();
    // pg-mem exposes a node-postgres-compatible pool without carrying its concrete type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    pool = new adapter.Pool();
  });

  afterEach(async () => {
    await pool.end();
  });

  it("applies each immutable migration once and detects changed history", async () => {
    await expect(runMigrations(pool)).resolves.toEqual({ applied: [1, 2, 3, 4, 5], currentVersion: 5 });
    await expect(runMigrations(pool)).resolves.toEqual({ applied: [], currentVersion: 5 });
    const versions = await pool.query<{ version: number; checksum: string }>("SELECT version, checksum FROM schema_migrations ORDER BY version");
    expect(versions.rows).toHaveLength(5);
    expect(versions.rows.every((row) => /^[a-f0-9]{64}$/u.test(row.checksum))).toBe(true);

    await pool.query("UPDATE schema_migrations SET checksum = $1 WHERE version = 2", ["0".repeat(64)]);
    await expect(runMigrations(pool)).rejects.toThrow(/migration history mismatch/i);
  });

  it("adopts and upgrades the previous current schema without losing metadata", async () => {
    const legacy = await readFile(new URL("../test-fixtures/legacy-current-schema.sql", import.meta.url), "utf8");
    await pool.query(legacy);
    await pool.query("INSERT INTO repository_candidates(repo_id, full_name, html_url, discovered_at, priority_score, candidate_state, selection_reason) VALUES (42, 'legacy/repository', 'https://github.com/legacy/repository', CURRENT_TIMESTAMP, 1, 'SKIPPED', 'score')");

    await expect(runMigrations(pool)).resolves.toMatchObject({ currentVersion: 5 });
    const candidate = await pool.query<{ full_name: string; selection_reason: string }>("SELECT full_name, selection_reason FROM repository_candidates WHERE repo_id = 42");
    expect(candidate.rows[0]).toEqual({ full_name: "legacy/repository", selection_reason: "score" });
    await expect(pool.query("SELECT * FROM metric_samples")).resolves.toBeDefined();
  });

  it("refuses startup before the complete migration history is present", async () => {
    await expect(assertMigrationsCurrent(pool)).rejects.toThrow("not migrated");
    await expect(createMetadataStore(pool)).rejects.toThrow("not migrated");
    await runMigrations(pool);
    await pool.query("DELETE FROM schema_migrations WHERE version = 5");
    await expect(assertMigrationsCurrent(pool)).rejects.toThrow("not current");
  });
});
