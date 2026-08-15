import { createHmac } from "node:crypto";
import { Pool } from "pg";
import { SecretScanner, type OsvBatchRequest, type OsvBatchResponse, type OsvTransport } from "@breach/analyzers";
import type { CandidateState, Coverage, ReviewState, SanitizedFinding } from "@breach/contracts";
import { PassiveExploitabilityAnalyzer } from "@breach/dataflow";
import {
  AsyncSerialDispatcher,
  CandidatePolicy,
  CommitGate,
  DiscoveryCollector,
  GitHubQuotaTracker,
  createGitHubRequestEvent,
  type GitHubRequestEvent,
  type GitHubRequestObserver,
  type GitHubResponse,
  type GitHubTransport,
} from "@breach/github";
import { OperatorRouter, type OperatorDataSource } from "@breach/operator";
import { ScanOrchestrator, type LifecycleStore } from "@breach/orchestrator";
import { CanaryAuditor, EgressPolicy, type RetentionSurfaces } from "@breach/security";
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
  candidateMinimumScore: number;
  targetSelectionRatio: number;
  maxDiscoveryPages: number;
  maxDiscoveryRequests: number;
  maxDiscoveryElapsedMs: number;
  maxCommitChecksPerCycle: number;
  maxScansPerCycle: number;
  githubQuotaReserve: number;
}

export function readWorkerConfig(env: NodeJS.ProcessEnv | Readonly<Record<string, string | undefined>>): WorkerConfig {
  const databaseUrl = env.DATABASE_URL ?? ""; const githubToken = env.GITHUB_TOKEN ?? ""; const fingerprintKey = env.FINGERPRINT_HMAC_KEY ?? "";
  const pollIntervalMs = Number(env.POLL_INTERVAL_MS ?? "30000"); const healthPort = Number(env.WORKER_HEALTH_PORT ?? "8081");
  const discoveryMode = env.DISCOVERY_MODE ?? "live";
  const discoveryStartCursorText = env.DISCOVERY_START_CURSOR;
  const discoveryStartCursor = discoveryStartCursorText === undefined
    ? null
    : Number(discoveryStartCursorText);
  const candidateMinimumScore = Number(env.CANDIDATE_MINIMUM_SCORE ?? "60");
  const targetSelectionRatio = Number(env.TARGET_SELECTION_RATIO ?? "0.07");
  const maxDiscoveryPages = Number(env.MAX_DISCOVERY_PAGES_PER_CYCLE ?? "2");
  const maxDiscoveryRequests = Number(env.MAX_DISCOVERY_REQUESTS_PER_CYCLE ?? "2");
  const maxDiscoveryElapsedMs = Number(env.MAX_DISCOVERY_ELAPSED_MS ?? "10000");
  const maxCommitChecksPerCycle = Number(env.MAX_COMMIT_CHECKS_PER_CYCLE ?? "25");
  const maxScansPerCycle = Number(env.MAX_SCANS_PER_CYCLE ?? "5");
  const githubQuotaReserve = Number(env.GITHUB_QUOTA_RESERVE ?? "200");
  let database: URL; try { database = new URL(databaseUrl); } catch { throw new Error("DATABASE_URL must be PostgreSQL"); }
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw new Error("DATABASE_URL must be PostgreSQL");
  if (githubToken.length < 8) throw new Error("GITHUB_TOKEN is required");
  if (new TextEncoder().encode(fingerprintKey).byteLength < 32) throw new Error("FINGERPRINT_HMAC_KEY must be at least 32 bytes");
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 5_000 || pollIntervalMs > 3_600_000) throw new Error("POLL_INTERVAL_MS is invalid");
  if (!Number.isSafeInteger(healthPort) || healthPort < 1 || healthPort > 65_535) throw new Error("WORKER_HEALTH_PORT is invalid");
  if (discoveryMode !== "live" && discoveryMode !== "historical") throw new Error("DISCOVERY_MODE must be live or historical");
  if (discoveryMode === "historical" && (discoveryStartCursor === null || !Number.isSafeInteger(discoveryStartCursor) || discoveryStartCursor < 0)) throw new Error("DISCOVERY_START_CURSOR is required for historical discovery");
  if (discoveryMode === "live" && discoveryStartCursor !== null) throw new Error("DISCOVERY_START_CURSOR requires historical discovery mode");
  if (!Number.isInteger(candidateMinimumScore) || candidateMinimumScore < 0 || candidateMinimumScore > 100) throw new Error("CANDIDATE_MINIMUM_SCORE must be between 0 and 100");
  if (!Number.isFinite(targetSelectionRatio) || targetSelectionRatio <= 0 || targetSelectionRatio > 1) throw new Error("TARGET_SELECTION_RATIO must be greater than 0 and at most 1");
  for (const [name, value, maximum] of [
    ["MAX_DISCOVERY_PAGES_PER_CYCLE", maxDiscoveryPages, 100],
    ["MAX_DISCOVERY_REQUESTS_PER_CYCLE", maxDiscoveryRequests, 100],
    ["MAX_DISCOVERY_ELAPSED_MS", maxDiscoveryElapsedMs, 60_000],
    ["MAX_COMMIT_CHECKS_PER_CYCLE", maxCommitChecksPerCycle, 1_000],
    ["MAX_SCANS_PER_CYCLE", maxScansPerCycle, 100],
  ] as const) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) throw new Error(`${name} is invalid`);
  }
  if (!Number.isSafeInteger(githubQuotaReserve) || githubQuotaReserve < 0 || githubQuotaReserve > 100_000) throw new Error("GITHUB_QUOTA_RESERVE is invalid");
  return { databaseUrl, githubToken, fingerprintKey, pollIntervalMs, healthPort, discoveryMode, discoveryStartCursor, candidateMinimumScore, targetSelectionRatio, maxDiscoveryPages, maxDiscoveryRequests, maxDiscoveryElapsedMs, maxCommitChecksPerCycle, maxScansPerCycle, githubQuotaReserve };
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
  readonly #observer: GitHubRequestObserver;
  constructor(readonly token: string, observer: GitHubRequestObserver = () => undefined) {
    this.#observer = observer;
  }
  async *stream(target: string, headers: Readonly<Record<string, string>>): AsyncIterable<Uint8Array> {
    const url = this.#policy.assertAllowed(target);
    let response: Response;
    try {
      response = await fetch(url, { headers: { ...headers, authorization: `Bearer ${this.token}` }, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      await this.#observer({ family: "blob", status: 0 });
      throw error;
    }
    await this.#observer(createGitHubRequestEvent("blob", response.status, Object.fromEntries(response.headers)));
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

export function requestStatusClass(status: number): "network_error" | "2xx" | "3xx" | "4xx" | "5xx" | "other" {
  if (status === 0) return "network_error";
  if (status >= 200 && status < 300) return "2xx";
  if (status >= 300 && status < 400) return "3xx";
  if (status >= 400 && status < 500) return "4xx";
  if (status >= 500 && status < 600) return "5xx";
  return "other";
}

export interface WorkerCycleResult {
  nextCursor: number | null;
  processed: number;
  scansStarted: number;
  quotaPaused: boolean;
}

export interface WorkerRuntime {
  runCycle(): Promise<WorkerCycleResult>;
  quotaStatus(): ReturnType<GitHubQuotaTracker["snapshot"]>;
}

export interface WorkerRuntimeDependencies {
  readonly githubTransport?: GitHubTransport;
  readonly blobTransport?: BlobStreamTransport;
  readonly osvTransport?: OsvTransport;
  readonly now?: () => Date;
  readonly nowMs?: () => number;
}

export async function createWorkerRuntime(
  config: WorkerConfig,
  pool: Pool,
  dependencies: WorkerRuntimeDependencies = {},
): Promise<WorkerRuntime> {
  const store = await createMetadataStore(pool);
  const quota = new GitHubQuotaTracker(dependencies.now);
  const requestCounter = { total: 0 };
  const observeRequest = async (event: GitHubRequestEvent) => {
    requestCounter.total += 1;
    quota.observe(event);
    const labels = { family: event.family, status_class: requestStatusClass(event.status) };
    await store.recordMetric("github.requests.total", 1, labels);
    await store.recordMetric(`github.requests.${event.family}`, 1, { status_class: labels.status_class });
    if (event.remaining !== undefined) await store.recordMetric("github.rate_limit.remaining", event.remaining, {});
    if (event.limit !== undefined) await store.recordMetric("github.rate_limit.limit", event.limit, {});
    if (event.resetAt !== undefined) await store.recordMetric("github.rate_limit.reset_at", event.resetAt.getTime(), {});
    const quotaState = quota.snapshot();
    await store.recordMetric("github.rate_limit.paused", quotaState.paused ? 1 : 0, {});
    await store.recordMetric("github.rate_limit.secondary_limited", quotaState.secondaryLimited ? 1 : 0, {});
  };
  const dispatcher = new AsyncSerialDispatcher(dependencies.githubTransport ?? new FetchGitHubTransport(), config.githubToken, observeRequest);
  const discovery = new DiscoveryCollector({ dispatcher, policy: new CandidatePolicy({ minimumScore: config.candidateMinimumScore, targetSelectionRatio: config.targetSelectionRatio }), sink: store, ...(dependencies.now === undefined ? {} : { now: dependencies.now }) });
  const snapshots = new SnapshotReader(dispatcher, dependencies.blobTransport ?? new FetchBlobTransport(config.githubToken, observeRequest), undefined, dependencies.nowMs);
  const orchestrator = new ScanOrchestrator({ gate: new CommitGate(dispatcher, dependencies.now), snapshots, store, secretScanner: new SecretScanner(config.fingerprintKey), osv: dependencies.osvTransport ?? new FetchOsvTransport(), dataflow: new PassiveExploitabilityAnalyzer(), ...(dependencies.now === undefined ? {} : { now: dependencies.now }), ...(dependencies.nowMs === undefined ? {} : { nowMs: dependencies.nowMs }) });
  const discoveryLimits = { maxPages: config.maxDiscoveryPages, maxRequests: config.maxDiscoveryRequests, maxElapsedMs: config.maxDiscoveryElapsedMs };

  return {
    async runCycle() {
      const cursor = await store.getDiscoveryCursor("public-repositories");
      if (!quota.canAdmit(config.githubQuotaReserve)) {
        await store.recordMetric("github.rate_limit.paused", 1, { stage: "cycle_admission" });
        return { nextCursor: cursor, processed: 0, scansStarted: 0, quotaPaused: true };
      }
      const nextCursor = cursor === null
        ? config.discoveryMode === "live"
          ? await discovery.bootstrap()
          : await discovery.catchUp(config.discoveryStartCursor ?? 0, discoveryLimits)
        : await discovery.catchUp(cursor, discoveryLimits);
      const recovered = await store.releaseDueRateLimits(new Date());
      if (recovered > 0) {
        await store.recordMetric("github.rate_limit.recovered_candidates", recovered, {});
      }
      const due = await pool.query<{ repo_id: string; full_name: string; commit_check_attempts: number }>(
        `SELECT repo_id, full_name, commit_check_attempts FROM repository_candidates
         WHERE candidate_state = 'WAITING_FOR_COMMIT'
           AND (next_commit_check_at IS NULL OR next_commit_check_at <= $2)
         ORDER BY priority_score DESC, repo_id DESC LIMIT $1`,
        [config.maxCommitChecksPerCycle, (dependencies.now ?? (() => new Date()))()],
      );
      let processed = 0;
      let scansStarted = 0;
      for (const row of due.rows) {
        if (!quota.canAdmit(config.githubQuotaReserve)) {
          await store.recordMetric("github.rate_limit.paused", 1, { stage: "candidate_admission" });
          break;
        }
        const requestsBefore = requestCounter.total;
        const result = await orchestrator.process({ repoId: Number(row.repo_id), fullName: row.full_name, attempts: row.commit_check_attempts });
        processed += 1;
        if (result.kind === "scanned" || (result.kind === "failed" && result.reason === "analysis_failed")) {
          scansStarted += 1;
          await store.recordMetric("github.requests_per_completed_scan", requestCounter.total - requestsBefore, { outcome: result.kind });
          if (scansStarted >= config.maxScansPerCycle) break;
        }
      }
      return { nextCursor, processed, scansStarted, quotaPaused: false };
    },
    quotaStatus: () => quota.snapshot(),
  };
}

export async function runWorkerCycle(
  config: WorkerConfig,
  pool?: Pool,
): Promise<WorkerCycleResult> {
  const ownedPool = pool ?? new Pool({ connectionString: config.databaseUrl, max: 4 });
  try {
    const runtime = await createWorkerRuntime(config, ownedPool);
    return await runtime.runCycle();
  } finally {
    if (pool === undefined) await ownedPool.end();
  }
}

export interface ZeroRetentionCanaryOptions {
  readonly pool: Pool;
  readonly rawCanary: string;
  readonly fingerprintKey: string;
  readonly now?: () => Date;
  readonly collectExternalSurfaces?: (finding: SanitizedFinding) => Promise<RetentionSurfaces>;
  readonly log?: (event: Readonly<Record<string, string | number | boolean>>) => void;
}

export interface ZeroRetentionCanaryReport {
  readonly rawOccurrences: number;
  readonly fingerprintOccurrences: number;
  readonly surfacesChecked: readonly string[];
  readonly ephemeralBytesCleared: boolean;
  readonly finding: SanitizedFinding;
}

export async function runZeroRetentionCanary(options: ZeroRetentionCanaryOptions): Promise<ZeroRetentionCanaryReport> {
  if (options.rawCanary.length < 16) throw new Error("Controlled canary must be at least 16 characters");
  const now = options.now ?? (() => new Date());
  const measuredAt = now();
  if (!Number.isFinite(measuredAt.getTime())) throw new Error("Canary clock returned an invalid timestamp");
  const store = await createMetadataStore(options.pool);
  const fullName = "fixture/runtime-canary";
  const previousCanaries = await options.pool.query<{ repo_id: string }>(
    "SELECT repo_id FROM repository_candidates WHERE full_name = $1",
    [fullName],
  );
  for (const previous of previousCanaries.rows) {
    await options.pool.query("DELETE FROM finding_reviews WHERE finding_id IN (SELECT finding_id FROM findings WHERE repo_id = $1)", [previous.repo_id]);
    await options.pool.query("DELETE FROM findings WHERE repo_id = $1", [previous.repo_id]);
    await options.pool.query("DELETE FROM scans WHERE repo_id = $1", [previous.repo_id]);
    await options.pool.query("DELETE FROM state_events WHERE repo_id = $1", [previous.repo_id]);
    await options.pool.query("DELETE FROM repository_candidates WHERE repo_id = $1", [previous.repo_id]);
  }
  const latestRepository = await options.pool.query<{ repo_id: string }>(
    "SELECT repo_id FROM repository_candidates ORDER BY repo_id DESC LIMIT 1",
  );
  const latestRepositoryId = Number(latestRepository.rows[0]?.repo_id ?? 9_100_024);
  const repoId = Math.max(9_100_024, latestRepositoryId) + 1;
  if (!Number.isSafeInteger(repoId)) throw new Error("No safe repository identifier remains for the controlled canary");
  const headSha = createHmac("sha256", options.fingerprintKey)
    .update(`runtime-canary:${String(repoId)}:${measuredAt.toISOString()}`)
    .digest("hex")
    .slice(0, 40);
  const blobSha = "b".repeat(40);
  const fixtureBytes = new TextEncoder().encode(`AWS_SECRET_ACCESS_KEY=${options.rawCanary}\n`);
  const expectedFingerprint = createHmac("sha256", options.fingerprintKey)
    .update(options.rawCanary)
    .digest("hex");
  const logEntries: Array<Readonly<Record<string, string | number | boolean>>> = [];
  const log = (event: Readonly<Record<string, string | number | boolean>>) => {
    logEntries.push(event);
    options.log?.(event);
  };
  log({ event: "zero_retention_canary_started", repoId });

  await store.recordDiscoveryPage("zero-retention-runtime-canary", repoId, [{
    repoId,
    fullName,
    htmlUrl: `https://github.com/${fullName}`,
    discoveredAt: measuredAt,
    priorityScore: 100,
    candidateState: "WAITING_FOR_COMMIT",
    selectionReason: "selected",
  }]);

  const github = new AsyncSerialDispatcher({
    get: (target) => {
      const url = new URL(target);
      if (url.pathname.endsWith("/commits")) {
        return Promise.resolve({ status: 200, body: [{ sha: headSha }], headers: {} });
      }
      if (url.pathname.endsWith(`/git/trees/${headSha}`)) {
        return Promise.resolve({
          status: 200,
          body: { tree: [{ path: "credential.txt", type: "blob", sha: blobSha, size: fixtureBytes.byteLength }], truncated: false },
          headers: {},
        });
      }
      throw new Error("Controlled canary received an unexpected GitHub metadata request");
    },
  });
  const snapshotReader = new SnapshotReader(github, {
    async *stream(target) {
      if (!new URL(target).pathname.endsWith(`/git/blobs/${blobSha}`)) {
        throw new Error("Controlled canary received an unexpected GitHub blob request");
      }
      yield await Promise.resolve(fixtureBytes);
    },
  });
  const releasedBuffers: Uint8Array[] = [];
  const snapshots = {
    async read(permit: Parameters<SnapshotReader["read"]>[0]) {
      const snapshot = await snapshotReader.read(permit);
      for (const file of snapshot.files) releasedBuffers.push(file.bytes);
      return snapshot;
    },
  };
  let monotonicNow = 0;
  const orchestrator = new ScanOrchestrator({
    gate: new CommitGate(github, now),
    snapshots,
    store,
    secretScanner: new SecretScanner(options.fingerprintKey),
    osv: { queryBatch: ({ queries }) => Promise.resolve({ results: queries.map(() => ({})) }) },
    dataflow: new PassiveExploitabilityAnalyzer(),
    now,
    nowMs: () => { monotonicNow += 1; return monotonicNow; },
  });
  const outcome = await orchestrator.process({ repoId, fullName, attempts: 0 });
  if (outcome.kind !== "scanned" || outcome.findingCount < 1) {
    throw new Error("Controlled canary did not complete with a finding");
  }
  log({ event: "zero_retention_canary_scanned", repoId, outcome: outcome.state, findingCount: outcome.findingCount });

  const ephemeralBytesCleared = releasedBuffers.length > 0 && releasedBuffers.every((bytes) => bytes.every((value) => value === 0));
  if (!ephemeralBytesCleared) throw new Error("Ephemeral canary buffers were not cleared");
  fixtureBytes.fill(0);

  const findingIds = await options.pool.query<{ finding_id: string }>(
    "SELECT finding_id FROM findings WHERE repo_id = $1 ORDER BY finding_id",
    [repoId],
  );
  const findingId = findingIds.rows[0]?.finding_id;
  const finding = findingId === undefined ? null : await store.getFinding(findingId);
  if (finding === null || finding.secretEvidence?.fingerprint !== expectedFingerprint) {
    throw new Error("Controlled canary fingerprint was not persisted as sanitized metadata");
  }

  const data: OperatorDataSource = {
    listFindings: async () => {
      const ids = await options.pool.query<{ finding_id: string }>("SELECT finding_id FROM findings ORDER BY detected_at DESC");
      const findings = await Promise.all(ids.rows.map(({ finding_id }) => store.getFinding(finding_id)));
      return findings.filter((item): item is SanitizedFinding => item !== null);
    },
    getFinding: (id) => store.getFinding(id),
    reviewFinding: (id, state, note) => store.reviewFinding(id, state, ...(note === undefined ? [] : [note])),
    listEvents: () => Promise.resolve([]),
    latestEventId: () => Promise.resolve(0),
    getSystemMetrics: () => Promise.resolve([]),
  };
  const operatorToken = "runtime-canary-operator-token";
  const router = new OperatorRouter(data, operatorToken);
  const authorized = { authorization: `Bearer ${operatorToken}` };
  const [apiList, apiDetail, apiError] = await Promise.all([
    router.handle(new Request("http://canary.local/api/findings", { headers: authorized })).then((response) => response.text()),
    router.handle(new Request(`http://canary.local/api/findings/${finding.findingId}`, { headers: authorized })).then((response) => response.text()),
    router.handle(new Request("http://canary.local/api/findings/not-a-uuid", { headers: authorized })).then((response) => response.text()),
  ]);

  const tableNames = ["discovery_state", "repository_candidates", "scans", "findings", "finding_reviews", "state_events", "metric_samples"] as const;
  const durableRows: Record<string, readonly unknown[]> = {};
  for (const table of tableNames) {
    const result = await options.pool.query(`SELECT * FROM ${table}`);
    durableRows[table] = result.rows;
  }
  const external = await options.collectExternalSurfaces?.(finding) ?? {};
  const reserved = new Set(["postgresql", "applicationLogs", "apiList", "apiDetail", "errorPaths", "ephemeralBuffers"]);
  if (Object.keys(external).some((name) => reserved.has(name))) throw new Error("External canary surface name is reserved");
  const surfaces: RetentionSurfaces = {
    postgresql: JSON.stringify(durableRows),
    applicationLogs: JSON.stringify(logEntries),
    apiList,
    apiDetail,
    errorPaths: apiError,
    ephemeralBuffers: JSON.stringify(releasedBuffers),
    ...external,
  };
  const proof = new CanaryAuditor(options.rawCanary, expectedFingerprint, 8).audit(surfaces);

  await store.recordMetric("zero_retention.canary.last_run", measuredAt.getTime(), { unit: "unix_ms", source: "runtime" });
  await store.recordMetric("zero_retention.canary.success", 1, { unit: "boolean", source: "runtime" });
  await store.recordMetric("zero_retention.canary.raw_occurrences", proof.rawOccurrences, { unit: "count", source: "runtime" });
  await store.recordMetric("zero_retention.canary.fingerprint_occurrences", proof.fingerprintOccurrences, { unit: "count", source: "runtime" });
  await store.recordMetric("zero_retention.violations", proof.rawOccurrences, { unit: "count", source: "runtime" });
  await store.recordMetric("zero_retention.source_persisted", 0, { unit: "count", source: "runtime" });
  await store.recordMetric("zero_retention.credential_verification_performed", 0, { unit: "count", source: "runtime" });

  return {
    ...proof,
    surfacesChecked: Object.keys(surfaces),
    ephemeralBytesCleared,
    finding,
  };
}

export async function runControlledDemo(raw: string) {
  if (raw.length === 0) throw new Error("Controlled demo requires a fake canary value");
  const states: CandidateState[] = ["DISCOVERED", "WAITING_FOR_COMMIT"];
  const findings: SanitizedFinding[] = []; const metrics: Array<{ name: string; value: number }> = [];
  const store: LifecycleStore = {
    transition: (_id, state) => { states.push(state); return Promise.resolve(); }, scheduleCommitCheck: () => Promise.resolve(), rateLimitCandidate: () => { states.push("RATE_LIMITED"); return Promise.resolve(); }, claimScan: () => Promise.resolve(true),
    saveFindings: (items) => { findings.push(...items); return Promise.resolve(); }, completeScan: () => Promise.resolve(),
    recordMetric: (name, value) => { metrics.push({ name, value }); return Promise.resolve(); },
  };
  const dispatcher = new AsyncSerialDispatcher({ get: () => Promise.resolve({ status: 200, body: [{ sha: "a".repeat(40) }], headers: {} }) });
  const coverage: Coverage = { ref: `HEAD@${"a".repeat(40)}`, historyScanned: false, scanComplete: true, snapshotComplete: true, analysisComplete: true, analysisPartial: false, snapshotPartialReasons: [], analysisPartialReasons: [], filesSeen: 1, filesEligible: 1, filesAnalyzed: 1, bytesInspected: raw.length, skippedBinary: 0, skippedGenerated: 0, skippedOversize: 0, skippedBudget: 0, skippedUnsupported: 0, treeTruncated: false, languagesModeled: [] };
  const orchestrator = new ScanOrchestrator({ gate: new CommitGate(dispatcher, () => new Date("2026-08-12T12:00:00.000Z")), snapshots: { read: () => Promise.resolve({ files: [{ path: "credential.txt", bytes: new TextEncoder().encode(`AWS_SECRET_ACCESS_KEY=${raw}`) }], coverage, release() { this.files[0]?.bytes.fill(0); } }) }, store, secretScanner: new SecretScanner("controlled-demo-fingerprint-key-32-bytes"), osv: { queryBatch: ({ queries }) => Promise.resolve({ results: queries.map(() => ({})) }) }, dataflow: new PassiveExploitabilityAnalyzer(), now: () => new Date("2026-08-12T12:00:00.000Z"), nowMs: () => 1 });
  await orchestrator.process({ repoId: 1, fullName: "fixture/canary", attempts: 0 });
  const finding = findings[0]; if (finding === undefined) throw new Error("Controlled demo did not emit finding");
  const reviewed: SanitizedFinding = { ...finding, reviewState: "CONFIRMED" satisfies ReviewState };
  return { states, finding: reviewed, metrics };
}
