import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";
import { runZeroRetentionCanary } from "./runtime.js";

export async function runCanaryCommand(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const databaseUrl = env.DATABASE_URL;
  const fingerprintKey = env.FINGERPRINT_HMAC_KEY;
  if (databaseUrl === undefined || fingerprintKey === undefined) {
    throw new Error("DATABASE_URL and FINGERPRINT_HMAC_KEY are required");
  }
  const fixturePath = env.CANARY_FIXTURE_PATH;
  const fixture = await readFile(
    fixturePath ?? new URL("../../../fixtures/canary-repository/credential.txt", import.meta.url),
    "utf8",
  );
  const separator = fixture.indexOf("=");
  const rawCanary = separator < 0 ? "" : fixture.slice(separator + 1).trim();
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  try {
    const report = await runZeroRetentionCanary({ pool, rawCanary, fingerprintKey });
    process.stdout.write(`${JSON.stringify({
      success: true,
      rawOccurrences: report.rawOccurrences,
      fingerprintOccurrences: report.fingerprintOccurrences,
      surfacesChecked: report.surfacesChecked,
      ephemeralBytesCleared: report.ephemeralBytesCleared,
    })}\n`);
  } finally {
    await pool.end();
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  runCanaryCommand().catch(() => {
    process.stderr.write("Runtime zero-retention canary failed\n");
    process.exitCode = 1;
  });
}
