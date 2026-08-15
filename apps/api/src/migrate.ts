import { Pool } from "pg";
import { runMigrations } from "@breach/storage/migrations";

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl === undefined) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: databaseUrl, max: 1 });
const result = await runMigrations(pool);
await pool.end();
process.stdout.write(`Metadata migration complete at version ${String(result.currentVersion)}; applied ${String(result.applied.length)}\n`);
