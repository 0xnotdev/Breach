import { Pool } from "pg";
import { createMetadataStore } from "@breach/storage";

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl === undefined) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: databaseUrl, max: 1 });
await createMetadataStore(pool);
await pool.end();
process.stdout.write("Metadata migration complete\n");
