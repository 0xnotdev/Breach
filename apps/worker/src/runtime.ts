import { Pool } from "pg";
import { SecretScanner, type OsvBatchRequest, type OsvBatchResponse, type OsvTransport } from "@breach/analyzers";
import type { CandidateState, Coverage, ReviewState, SanitizedFinding } from "@breach/contracts";
import { PassiveExploitabilityAnalyzer } from "@breach/dataflow";
import { AsyncSerialDispatcher, CandidatePolicy, CommitGate, DiscoveryCollector, type GitHubResponse, type GitHubTransport } from "@breach/github";
import { ScanOrchestrator, type LifecycleStore } from "@breach/orchestrator";
import { EgressPolicy } from "@breach/security";
import { SnapshotReader, type BlobStreamTransport } from "@breach/snapshot";
import { createMetadataStore } from "@breach/storage";

export interface WorkerConfig {
  databaseUrl: string;
  githubToken: string;
  fingerprintKey: string;
  pollIntervalMs: number;
  healthPort: number;
  discoveryMode: "live" | "historical";
  discoveryStartCursor: number | null;
}

export function readWorkerConfig(env: NodeJS.ProcessEnv | Readonly<Record<string, string | undefined>>): WorkerConfig {
  const databaseUrl = env.DATABASE_URL ?? ""; const githubToken = env.GITHUB_TOKEN ?? ""; const fingerprintKey = env.FINGERPRINT_HMAC_KEY ?? "";
  const pollIntervalMs = Number(env.POLL_INTERVAL_MS ?? "30000"); const healthPort = Number(env.WORKER_HEALTH_PORT ?? "8081");
  const discoveryMode = env.DISCOVERY_MODE ?? "live";
  const discoveryStartCursorText = env.DISCOVERY_START_CURSOR;
  const discoveryStartCursor = discoveryStartCursorText === undefined
    ? null
    : Number(discoveryStartCursorText);
  let database: URL; try { database = new URL(databaseUrl); } catch { throw new Error("DATABASE_URL must be PostgreSQL"); }
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw new Error("DATABASE_URL must be PostgreSQL");
  if (githubToken.length < 8) throw new Error("GITHUB_TOKEN is required");
  if (new TextEncoder().encode(fingerprintKey).byteLength < 32) throw new Error("FINGERPRINT_HMAC_KEY must be at least 32 bytes");
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 5_000 || pollIntervalMs > 3_600_000) throw new Error("POLL_INTERVAL_MS is invalid");
  if (!Number.isSafeInteger(healthPort) || healthPort < 1 || healthPort > 65_535) throw new Error("WORKER_HEALTH_PORT is invalid");
  if (discoveryMode !== "live" && discoveryMode !== "historical") throw new Error("DISCOVERY_MODE must be live or historical");
  if (discoveryMode === "historical" && (discoveryStartCursor === null || !Number.isSafeInteger(discoveryStartCursor) || discoveryStartCursor < 0)) throw new Error("DISCOVERY_START_CURSOR is required for historical discovery");
  if (discoveryMode === "live" && discoveryStartCursor !== null) throw new Error("DISCOVERY_START_CURSOR requires historical discovery mode");
  return { databaseUrl, githubToken, fingerprintKey, pollIntervalMs, healthPort, discoveryMode, discoveryStartCursor };
}

export class FetchGitHubTransport implements GitHubTransport {
  readonly #policy = new EgressPolicy();
  async get(target: string, headers: Readonly<Record<string, string>>): Promise<GitHubResponse> {
    const url = this.#policy.assertAllowed(target);
    const response = await fetch(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    const body = response.status === 204 ? null : await boundedJson(response, 12 * 1024 * 1024);
    return { status: response.status, body, headers: Object.fromEntries(response.headers) };
  }
}

export class FetchBlobTransport implements BlobStreamTransport {
  readonly #policy = new EgressPolicy();
  constructor(readonly token: string) {}
  async *stream(target: string, headers: Readonly<Record<string, string>>): AsyncIterable<Uint8Array> {
    const url = this.#policy.assertAllowed(target);
    const response = await fetch(url, { headers: { ...headers, authorization: `Bearer ${this.token}` }, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    if (!response.ok || response.body === null) throw new Error(`Blob request failed with status ${String(response.status)}`);
    const reader = response.body.getReader();
    try { for (;;) { const result = await reader.read(); if (result.done) break; yield result.value; } } finally { reader.releaseLock(); }
  }
}

export class FetchOsvTransport implements OsvTransport {
  readonly #policy = new EgressPolicy();
  async queryBatch(request: OsvBatchRequest): Promise<OsvBatchResponse> {
    if (request.queries.length > 100) throw new Error("OSV batch limit exceeded");
    const response = await fetch(this.#policy.assertAllowed("https://api.osv.dev/v1/querybatch"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request), redirect: "manual", signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`OSV request failed with status ${String(response.status)}`);
    return await boundedJson(response, 4 * 1024 * 1024) as OsvBatchResponse;
  }
}

async function boundedJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = Number(response.headers.get("content-length")); if (Number.isFinite(declared) && declared > maxBytes) throw new Error("Response exceeds bound");
  const bytes = new Uint8Array(await response.arrayBuffer()); if (bytes.byteLength > maxBytes) throw new Error("Response exceeds bound");
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
}

export async function runWorkerCycle(config: WorkerConfig, pool = new Pool({ connectionString: config.databaseUrl, max: 4 })) {
  const store = await createMetadataStore(pool); const dispatcher = new AsyncSerialDispatcher(new FetchGitHubTransport(), config.githubToken);
  const discovery = new DiscoveryCollector({ dispatcher, policy: new CandidatePolicy({ minimumScore: 35, capacityRatio: .07 }), sink: store });
  const cursor = await store.getDiscoveryCursor("public-repositories");
  const nextCursor = cursor === null
    ? config.discoveryMode === "live"
      ? await discovery.bootstrap()
      : await discovery.catchUp(config.discoveryStartCursor ?? 0)
    : await discovery.catchUp(cursor);
  const snapshots = new SnapshotReader(dispatcher, new FetchBlobTransport(config.githubToken));
  const orchestrator = new ScanOrchestrator({ gate: new CommitGate(dispatcher), snapshots, store, secretScanner: new SecretScanner(config.fingerprintKey), osv: new FetchOsvTransport(), dataflow: new PassiveExploitabilityAnalyzer() });
  const due = await pool.query<{ repo_id: string; full_name: string; commit_check_attempts: number }>("SELECT repo_id, full_name, commit_check_attempts FROM repository_candidates WHERE candidate_state = 'WAITING_FOR_COMMIT' AND (next_commit_check_at IS NULL OR next_commit_check_at <= CURRENT_TIMESTAMP) ORDER BY priority_score DESC, repo_id LIMIT 25");
  let processed = 0; for (const row of due.rows) { await orchestrator.process({ repoId: Number(row.repo_id), fullName: row.full_name, attempts: row.commit_check_attempts }); processed += 1; }
  return { nextCursor, processed };
}

export async function runControlledDemo(raw: string) {
  if (raw.length === 0) throw new Error("Controlled demo requires a fake canary value");
  const states: CandidateState[] = ["DISCOVERED", "WAITING_FOR_COMMIT"];
  const findings: SanitizedFinding[] = []; const metrics: Array<{ name: string; value: number }> = [];
  const store: LifecycleStore = {
    transition: (_id, state) => { states.push(state); return Promise.resolve(); }, scheduleCommitCheck: () => Promise.resolve(), claimScan: () => Promise.resolve(true),
    saveFindings: (items) => { findings.push(...items); return Promise.resolve(); }, completeScan: () => Promise.resolve(),
    recordMetric: (name, value) => { metrics.push({ name, value }); return Promise.resolve(); },
  };
  const dispatcher = new AsyncSerialDispatcher({ get: () => Promise.resolve({ status: 200, body: [{ sha: "a".repeat(40) }], headers: {} }) });
  const coverage: Coverage = { ref: `HEAD@${"a".repeat(40)}`, historyScanned: false, scanComplete: true, filesSeen: 1, filesAnalyzed: 1, bytesInspected: raw.length, skippedBinary: 0, skippedOversize: 0, skippedBudget: 0, treeTruncated: false, languagesModeled: [] };
  const orchestrator = new ScanOrchestrator({ gate: new CommitGate(dispatcher, () => new Date("2026-08-12T12:00:00.000Z")), snapshots: { read: () => Promise.resolve({ files: [{ path: "credential.txt", bytes: new TextEncoder().encode(`AWS_SECRET_ACCESS_KEY=${raw}`) }], coverage, release() { this.files[0]?.bytes.fill(0); } }) }, store, secretScanner: new SecretScanner("controlled-demo-fingerprint-key-32-bytes"), osv: { queryBatch: ({ queries }) => Promise.resolve({ results: queries.map(() => ({})) }) }, dataflow: new PassiveExploitabilityAnalyzer(), now: () => new Date("2026-08-12T12:00:00.000Z"), nowMs: () => 1 });
  await orchestrator.process({ repoId: 1, fullName: "fixture/canary", attempts: 0 });
  const finding = findings[0]; if (finding === undefined) throw new Error("Controlled demo did not emit finding");
  const reviewed: SanitizedFinding = { ...finding, reviewState: "CONFIRMED" satisfies ReviewState };
  return { states, finding: reviewed, metrics };
}
