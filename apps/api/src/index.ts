import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";
import type { ReviewState, SanitizedFinding } from "@breach/contracts";
import { OperatorRouter, type OperatorDataSource, type StreamEvent, type SystemMetric } from "@breach/operator";
import { createMetadataStore } from "@breach/storage";

export interface ApiConfig { databaseUrl: string; operatorToken: string; port: number }

export function readApiConfig(env: NodeJS.ProcessEnv | Readonly<Record<string, string | undefined>>): ApiConfig {
  const databaseUrl = env.DATABASE_URL ?? "";
  const operatorToken = env.OPERATOR_TOKEN ?? "";
  const port = Number(env.API_PORT ?? "8080");
  let database: URL;
  try { database = new URL(databaseUrl); } catch { throw new Error("DATABASE_URL must be a PostgreSQL URL"); }
  if (database.protocol !== "postgresql:" && database.protocol !== "postgres:") throw new Error("DATABASE_URL must be a PostgreSQL URL");
  if (new TextEncoder().encode(operatorToken).byteLength < 16) throw new Error("OPERATOR_TOKEN must be at least 16 bytes");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("API_PORT is invalid");
  return { databaseUrl, operatorToken, port };
}

export function createApiHandler(data: OperatorDataSource, token: string, readiness: () => Promise<boolean>) {
  const router = new OperatorRouter(data, token);
  return async (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname;
    if (path === "/healthz") return Response.json({ status: "live" }, { headers: { "cache-control": "no-store" } });
    if (path === "/readyz") {
      const ready = await readiness().catch(() => false);
      return Response.json({ status: ready ? "ready" : "not_ready" }, { status: ready ? 200 : 503, headers: { "cache-control": "no-store" } });
    }
    return router.handle(request);
  };
}

export class PostgresOperatorDataSource implements OperatorDataSource {
  constructor(readonly pool: Pool, readonly store: Awaited<ReturnType<typeof createMetadataStore>>) {}

  async listFindings(): Promise<readonly SanitizedFinding[]> {
    const result = await this.pool.query<{ payload: SanitizedFinding }>("SELECT payload FROM findings ORDER BY detected_at DESC LIMIT 500");
    return result.rows.map((row) => row.payload);
  }
  async getFinding(id: string): Promise<SanitizedFinding | null> { return this.store.getFinding(id); }
  async reviewFinding(id: string, state: Exclude<ReviewState, "UNREVIEWED">, note?: string): Promise<SanitizedFinding> { return this.store.reviewFinding(id, state, ...(note === undefined ? [] : [note])); }
  async listEvents(afterEventId = 0): Promise<readonly StreamEvent[]> {
    const result = await this.pool.query<{ event_id: string; repo_id: string; full_name: string; to_state: StreamEvent["state"]; occurred_at: Date }>("SELECT e.event_id, e.repo_id, c.full_name, e.to_state, e.occurred_at FROM state_events e JOIN repository_candidates c ON c.repo_id = e.repo_id WHERE e.event_id > $1 ORDER BY e.event_id LIMIT 500", [afterEventId]);
    return result.rows.map((row) => ({ eventId: Number(row.event_id), repoId: Number(row.repo_id), fullName: row.full_name, state: row.to_state, occurredAt: row.occurred_at.toISOString() }));
  }
  async getSystemMetrics(): Promise<readonly SystemMetric[]> {
    const result = await this.pool.query<{ metric_name: string; metric_value: number; labels: Record<string, string> }>("SELECT DISTINCT ON (metric_name) metric_name, metric_value, labels FROM metric_samples ORDER BY metric_name, measured_at DESC LIMIT 500");
    return result.rows.map((row) => ({ name: row.metric_name, value: row.metric_value, unit: row.labels.unit ?? "count" }));
  }
}

export function createDemoDataSource(): OperatorDataSource {
  const finding: SanitizedFinding = {
    findingId: "00000000-0000-4000-8000-000000000001", detectedAt: "2026-08-12T12:00:00.000Z",
    repository: { id: 1, fullName: "fixture/canary", url: "https://github.com/fixture/canary" }, revision: { ref: "HEAD", sha: "a".repeat(40) },
    category: "secret_exposure", severity: "critical", confidence: .98,
    secretEvidence: { type: "AWS Secret Access Key", provider: "AWS", path: "credential.txt", line: 1, fingerprint: "f".repeat(64) },
    coverage: { ref: `HEAD@${"a".repeat(40)}`, historyScanned: false, scanComplete: true, filesSeen: 1, filesAnalyzed: 1, bytesInspected: 64, skippedBinary: 0, skippedOversize: 0, skippedBudget: 0, treeTruncated: false, languagesModeled: [] }, reviewState: "UNREVIEWED",
  };
  let current = finding;
  return {
    listFindings: () => Promise.resolve([current]), getFinding: (id) => Promise.resolve(id === current.findingId ? current : null),
    reviewFinding: (_id, state) => { current = { ...current, reviewState: state }; return Promise.resolve(current); },
    listEvents: () => Promise.resolve([{ eventId: 1, repoId: 1, fullName: "fixture/canary", state: "SCANNED_FINDINGS", occurredAt: "2026-08-12T12:00:00.000Z" }]),
    getSystemMetrics: () => Promise.resolve([{ name: "zero_retention.canary", value: 1, unit: "healthy" }]),
  };
}

export async function startApi(config = readApiConfig(process.env)) {
  const pool = new Pool({ connectionString: config.databaseUrl, max: 5 });
  const store = await createMetadataStore(pool);
  const handler = createApiHandler(new PostgresOperatorDataSource(pool, store), config.operatorToken, async () => { await pool.query("SELECT 1"); return true; });
  const server = createServer((request, response) => { void serveNodeRequest(request, response, handler); });
  await new Promise<void>((resolve) => server.listen(config.port, "0.0.0.0", resolve));
  const close = async () => { await new Promise<void>((resolve, reject) => server.close((error) => { if (error) reject(error); else resolve(); })); await pool.end(); };
  process.once("SIGTERM", () => { void close(); }); process.once("SIGINT", () => { void close(); });
  return { server, pool, close };
}

async function serveNodeRequest(incoming: IncomingMessage, outgoing: ServerResponse, handler: (request: Request) => Promise<Response>) {
  try {
    const body = await readBody(incoming, 1_048_576);
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
    const requestBody = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
    const request = new Request(`http://${incoming.headers.host ?? "localhost"}${incoming.url ?? "/"}`, { method: incoming.method ?? "GET", headers, ...(body.byteLength === 0 ? {} : { body: requestBody }) });
    const result = await handler(request); outgoing.writeHead(result.status, Object.fromEntries(result.headers)); outgoing.end(Buffer.from(await result.arrayBuffer()));
  } catch { outgoing.writeHead(400, { "content-type": "application/json" }); outgoing.end('{"error":"invalid_request"}'); }
}

async function readBody(stream: IncomingMessage, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []; let size = 0;
  for await (const chunk of stream) { if (!(chunk instanceof Uint8Array)) throw new Error("invalid body chunk"); const bytes = new Uint8Array(chunk); size += bytes.byteLength; if (size > limit) throw new Error("body too large"); chunks.push(bytes); }
  const body = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; } return body;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) startApi().catch(() => { process.stderr.write("Breach API failed to start\n"); process.exitCode = 1; });
