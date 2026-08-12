import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";
import { readWorkerConfig, runWorkerCycle } from "./runtime.js";

export async function startWorker() {
  const config = readWorkerConfig(process.env); const pool = new Pool({ connectionString: config.databaseUrl, max: 4 }); let ready = false; let stopping = false;
  const health = createServer((request, response) => { const status = request.url === "/healthz" ? 200 : request.url === "/readyz" && ready ? 200 : 503; response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(JSON.stringify({ status: status === 200 ? "ok" : "not_ready" })); });
  await new Promise<void>((resolve) => health.listen(config.healthPort, "0.0.0.0", resolve));
  const cycle = async () => { try { await runWorkerCycle(config, pool); ready = true; } catch { ready = false; process.stderr.write("Breach worker cycle failed\n"); } };
  await cycle(); const timer = setInterval(() => { if (!stopping) void cycle(); }, config.pollIntervalMs);
  const stop = async () => { stopping = true; clearInterval(timer); await new Promise<void>((resolve) => health.close(() => { resolve(); })); await pool.end(); };
  process.once("SIGTERM", () => { void stop(); }); process.once("SIGINT", () => { void stop(); }); return { health, stop };
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) startWorker().catch(() => { process.stderr.write("Breach worker failed to start\n"); process.exitCode = 1; });
