import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import type { Pool, PoolClient } from "pg";

interface Migration {
  readonly version: number;
  readonly name: string;
  readonly checksum: string;
  readonly sql: string;
}

const migrationLock = 4_248_247_326;

async function loadMigrations(): Promise<readonly Migration[]> {
  const directory = new URL("../migrations/", import.meta.url);
  const names = (await readdir(directory))
    .filter((name) => name.endsWith(".sql"))
    .sort((left, right) => left.localeCompare(right));
  const migrations = await Promise.all(names.map(async (filename) => {
    const match = /^(\d{3})_([a-z0-9_]+)\.sql$/u.exec(filename);
    if (match === null || match[1] === undefined || match[2] === undefined) {
      throw new Error(`Invalid migration filename: ${filename}`);
    }
    const version = Number(match[1]);
    const sql = await readFile(new URL(filename, directory), "utf8");
    if (sql.trim().length === 0) throw new Error(`Migration ${filename} is empty`);
    return {
      version,
      name: match[2],
      checksum: createHash("sha256").update(sql, "utf8").digest("hex"),
      sql,
    };
  }));
  migrations.forEach((migration, index) => {
    if (migration.version !== index + 1) throw new Error("Migration versions must be contiguous from 001");
  });
  if (migrations.length === 0) throw new Error("No metadata migrations found");
  return migrations;
}

async function ensureMigrationTable(pool: Pool): Promise<void> {
  const existing = await pool.query<{ present: number }>(
    `SELECT 1 AS present FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = 'schema_migrations'`,
  );
  if (existing.rows.length > 0) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY CHECK (version > 0),
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
}

async function adoptLegacySchema(pool: Pool, migrations: readonly Migration[]): Promise<number[]> {
  const result = await pool.query<{ table_name: string }>(
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
  );
  const tables = new Set(result.rows.map(({ table_name }) => table_name));
  const legacyTables = ["discovery_state", "repository_candidates", "scans", "findings", "finding_reviews", "state_events", "metric_samples"];
  if (!legacyTables.every((table) => tables.has(table))) return [];
  const columns = await pool.query<{ table_name: string; column_name: string }>(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name IN ('discovery_state', 'repository_candidates')`,
  );
  const presentColumns = new Set(columns.rows.map(({ table_name, column_name }) => `${table_name}.${column_name}`));
  for (const required of [
    "discovery_state.bootstrapped_at",
    "repository_candidates.selection_reason",
    "repository_candidates.commit_check_attempts",
    "repository_candidates.next_commit_check_at",
    "repository_candidates.first_commit_detected_at",
    "repository_candidates.head_sha",
    "repository_candidates.last_scan_status",
  ]) if (!presentColumns.has(required)) return [];

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [migrationLock]);
    for (const migration of migrations) {
      await client.query(
        `INSERT INTO schema_migrations(version, name, checksum)
         VALUES ($1, $2, $3) ON CONFLICT (version) DO NOTHING`,
        [migration.version, migration.name, migration.checksum],
      );
    }
    await client.query("COMMIT");
    return migrations.map(({ version }) => version);
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function appliedMigrations(pool: Pool | PoolClient): Promise<Array<{ version: number; name: string; checksum: string }>> {
  const result = await pool.query<{ version: number; name: string; checksum: string }>(
    "SELECT version, name, checksum FROM schema_migrations ORDER BY version",
  );
  return result.rows;
}

function verifyHistory(migrations: readonly Migration[], applied: readonly { version: number; name: string; checksum: string }[]): void {
  applied.forEach((record, index) => {
    const expected = migrations[index];
    if (
      expected === undefined ||
      record.version !== index + 1 ||
      record.name !== expected.name ||
      record.checksum !== expected.checksum
    ) throw new Error(`Migration history mismatch at version ${String(record.version)}`);
  });
}

async function applyMigration(pool: Pool, migration: Migration): Promise<boolean> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [migrationLock]);
    const existing = await client.query<{ name: string; checksum: string }>(
      "SELECT name, checksum FROM schema_migrations WHERE version = $1",
      [migration.version],
    );
    const record = existing.rows[0];
    if (record !== undefined) {
      if (record.name !== migration.name || record.checksum !== migration.checksum) {
        throw new Error(`Migration history mismatch at version ${String(migration.version)}`);
      }
      await client.query("COMMIT");
      return false;
    }
    await client.query(migration.sql);
    await client.query(
      "INSERT INTO schema_migrations(version, name, checksum) VALUES ($1, $2, $3)",
      [migration.version, migration.name, migration.checksum],
    );
    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function runMigrations(pool: Pool): Promise<{ applied: number[]; currentVersion: number }> {
  const migrations = await loadMigrations();
  await ensureMigrationTable(pool);
  const existing = await appliedMigrations(pool);
  verifyHistory(migrations, existing);
  if (existing.length === 0) {
    const adopted = await adoptLegacySchema(pool, migrations);
    if (adopted.length > 0) {
      verifyHistory(migrations, await appliedMigrations(pool));
      return { applied: adopted, currentVersion: migrations.at(-1)?.version ?? 0 };
    }
  }
  const applied: number[] = [];
  for (const migration of migrations) {
    if (await applyMigration(pool, migration)) applied.push(migration.version);
  }
  verifyHistory(migrations, await appliedMigrations(pool));
  return { applied, currentVersion: migrations.at(-1)?.version ?? 0 };
}

export async function assertMigrationsCurrent(pool: Pool): Promise<void> {
  const migrations = await loadMigrations();
  let applied: Array<{ version: number; name: string; checksum: string }>;
  try {
    applied = await appliedMigrations(pool);
  } catch {
    throw new Error("Metadata schema is not migrated; run the migration command first");
  }
  verifyHistory(migrations, applied);
  if (applied.length !== migrations.length) throw new Error("Metadata schema is not current; run the migration command first");
}
