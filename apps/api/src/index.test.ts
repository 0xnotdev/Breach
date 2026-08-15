import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createApiHandler, createDemoDataSource, PostgresOperatorDataSource, readApiConfig, serveNodeRequest, startApi } from "./index.js";
import type { SanitizedFinding } from "@breach/contracts";
import type { OperatorDataSource, StreamEvent } from "@breach/operator";
import type { Pool } from "pg";
import { DataType, newDb } from "pg-mem";
import { createMetadataStore } from "@breach/storage";
import { runMigrations } from "@breach/storage/migrations";

describe("operator API runtime", () => {
  it("apiBridgeNeverBuffersStreamingResponse", async () => {
    const source = await readFile(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).not.toContain("result.arrayBuffer()");
    expect(source).toContain("result.body.getReader()");
  });

  it("systemMetricsComeFromPostgres", async () => {
    const source = (await Promise.all([readFile(new URL("./index.ts", import.meta.url), "utf8"), readFile(new URL("./system-metrics.ts", import.meta.url), "utf8")])).join("\n");
    expect(source).toContain("repository_candidates");
    expect(source).toContain("finding_reviews");
    expect(source).toContain("PERCENTILE_CONT");
    expect(source).toContain("reviewed_precision");
  });

  it("derives rates and precision only from measured rows", async () => {
    const pool = {
      query: (sql: string) => {
        if (sql.includes("system-discovery")) return Promise.resolve({ rows: [{ repositories_discovered_hour: "20", eligible_hour: "10", selected_hour: "5", waiting_for_commit: "3", commit_detected_hour: "8", failed_hour: "2", discovery_cursor: "9001", discovery_lag_seconds: "12" }] });
        if (sql.includes("system-scans")) return Promise.resolve({ rows: [{ scans_started_hour: "9", scans_completed_hour: "8", partial_hour: "2", average_bytes: "2048", average_files: "12.5", p50_latency_ms: "500", p95_latency_ms: "1250" }] });
        if (sql.includes("system-findings")) return Promise.resolve({ rows: [{ findings_hour: "4", critical_hour: "1", high_hour: "2", medium_hour: "1", exploitability_hour: "2", secrets_hour: "1", dependencies_hour: "1", config_hour: "0" }] });
        if (sql.includes("system-reviews")) return Promise.resolve({ rows: [{ reviewed: "6", confirmed: "3", false_positive: "1", uncertain: "2", exploitability: "3", secrets: "1", dependencies: "1", config: "1" }] });
        if (sql.includes("system-telemetry")) return Promise.resolve({ rows: [
          { metric_name: "github.requests.total", hour_sum: "80", hour_average: "1", latest_value: "1", latest_at: new Date("2026-08-15T12:00:00.000Z") },
          { metric_name: "github.requests_per_completed_scan", hour_sum: "40", hour_average: "5", latest_value: "4", latest_at: new Date("2026-08-15T12:00:00.000Z") },
          { metric_name: "scan.failed", hour_sum: "2", hour_average: "1", latest_value: "1", latest_at: new Date("2026-08-15T12:00:00.000Z") },
          { metric_name: "zero_retention.canary.last_run", hour_sum: "1786795200000", hour_average: "1786795200000", latest_value: "1786795200000", latest_at: new Date("2026-08-15T12:00:00.000Z") },
          { metric_name: "zero_retention.canary.success", hour_sum: "1", hour_average: "1", latest_value: "1", latest_at: new Date("2026-08-15T12:00:00.000Z") },
        ] });
        return Promise.reject(new Error("Unexpected metrics query"));
      },
    } as unknown as Pool;

    const metrics = new Map((await new PostgresOperatorDataSource(pool, {} as Awaited<ReturnType<typeof createMetadataStore>>).getSystemMetrics()).map((metric) => [metric.name, metric]));
    expect(metrics.get("reviewed_precision")?.value).toBe(0.75);
    expect(metrics.get("scan.partial_rate")?.value).toBe(0.25);
    expect(metrics.get("scan.failure_rate")?.value).toBe(0.2);
    expect(metrics.get("findings.per_1000_scans")?.value).toBe(500);
    expect(metrics.get("github.requests_per_completed_scan")?.value).toBe(5);
    expect(metrics.get("safety.canary.result")?.value).toBe(1);
    expect(metrics.get("safety.canary.last_run")?.value).toBe(1_786_795_200_000);
    expect(metrics.has("safety.retention_violations")).toBe(false);
  });

  it("omits unavailable and denominator-free system measurements", async () => {
    const nullable = {
      repositories_discovered_hour: null, eligible_hour: null, selected_hour: null, waiting_for_commit: null,
      commit_detected_hour: null, failed_hour: null, discovery_cursor: null, discovery_lag_seconds: "not-a-number",
    };
    const emptyFindings = { findings_hour: null, critical_hour: null, high_hour: null, medium_hour: null, exploitability_hour: null, secrets_hour: null, dependencies_hour: null, config_hour: null };
    const emptyReviews = { reviewed: null, confirmed: null, false_positive: null, uncertain: null, exploitability: null, secrets: null, dependencies: null, config: null };
    const pool = {
      query: (sql: string) => {
        if (sql.includes("system-discovery")) return Promise.resolve({ rows: [nullable] });
        if (sql.includes("system-scans")) return Promise.resolve({ rows: [] });
        if (sql.includes("system-findings")) return Promise.resolve({ rows: [emptyFindings] });
        if (sql.includes("system-reviews")) return Promise.resolve({ rows: [emptyReviews] });
        if (sql.includes("system-telemetry")) return Promise.resolve({ rows: [{ metric_name: "scan.failed", hour_sum: null, hour_average: null, latest_value: null, latest_at: null }] });
        return Promise.reject(new Error("Unexpected nullable metrics query"));
      },
    } as unknown as Pool;
    expect(await new PostgresOperatorDataSource(pool, {} as Awaited<ReturnType<typeof createMetadataStore>>).getSystemMetrics()).toEqual([]);

    const noRowsPool = { query: () => Promise.resolve({ rows: [] }) } as unknown as Pool;
    expect(await new PostgresOperatorDataSource(noRowsPool, {} as Awaited<ReturnType<typeof createMetadataStore>>).getSystemMetrics()).toEqual([]);

    const zeroDenominatorPool = {
      query: (sql: string) => Promise.resolve({ rows: sql.includes("system-scans") ? [{ scans_started_hour: null, scans_completed_hour: "0", partial_hour: "0", average_bytes: null, average_files: null, p50_latency_ms: null, p95_latency_ms: null }] : [] }),
    } as unknown as Pool;
    const zeroMetrics = await new PostgresOperatorDataSource(zeroDenominatorPool, {} as Awaited<ReturnType<typeof createMetadataStore>>).getSystemMetrics();
    expect(zeroMetrics.some(({ name }) => name === "scan.partial_rate")).toBe(false);
  });

  it("maps durable findings, reviews, and lifecycle events", async () => {
    const finding = createDemoDataSource().listFindings().then((items) => items[0]);
    const stored = await finding;
    if (stored === undefined) throw new Error("Demo finding missing");
    const pool = {
      query: (sql: string) => {
        if (sql.includes("FROM findings")) return Promise.resolve({ rows: [{ payload: stored }] });
        if (sql.includes("FROM state_events e")) return Promise.resolve({ rows: [{ event_id: "7", repo_id: "8", full_name: "fixture/durable", to_state: "READY", occurred_at: new Date("2026-08-15T12:00:00.000Z") }] });
        if (sql.includes("MAX(event_id)")) return Promise.resolve({ rows: [{ latest_event_id: "7" }] });
        return Promise.reject(new Error("Unexpected durable data-source query"));
      },
    } as unknown as Pool;
    const reviewed = { ...stored, reviewState: "CONFIRMED" as const };
    const store = {
      getFinding: (id: string) => Promise.resolve(id === stored.findingId ? stored : null),
      reviewFinding: () => Promise.resolve(reviewed),
    } as unknown as Awaited<ReturnType<typeof createMetadataStore>>;
    const source = new PostgresOperatorDataSource(pool, store);
    expect(await source.listFindings()).toEqual([stored]);
    expect(await source.getFinding(stored.findingId)).toEqual(stored);
    expect(await source.reviewFinding(stored.findingId, "CONFIRMED", "verified")).toEqual(reviewed);
    expect(await source.reviewFinding(stored.findingId, "CONFIRMED")).toEqual(reviewed);
    expect(await source.listEvents(3, 7)).toEqual([{ eventId: 7, repoId: 8, fullName: "fixture/durable", state: "READY", occurredAt: "2026-08-15T12:00:00.000Z" }]);
    expect(await source.latestEventId()).toBe(7);
  });

  it("streams an event written after Node response headers", async () => {
    const token = "operator-token-32-bytes-minimum";
    const events: StreamEvent[] = [];
    const data: OperatorDataSource = {
      ...createDemoDataSource(),
      listEvents: (after = 0) => Promise.resolve(events.filter((event) => event.eventId > after)),
      latestEventId: () => Promise.resolve(events.at(-1)?.eventId ?? 0),
    };
    const handler = createApiHandler(data, token, () => Promise.resolve(true), { streamPollIntervalMs: 5, streamHeartbeatIntervalMs: 50 });
    const server = createServer((request, response) => { void serveNodeRequest(request, response, handler); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (typeof address !== "object" || address === null) throw new Error("API test server did not bind");
    const controller = new AbortController();
    try {
      const response = await fetch(`http://127.0.0.1:${String(address.port)}/api/stream`, { headers: { authorization: `Bearer ${token}` }, signal: controller.signal });
      expect(response.status).toBe(200);
      const reader = response.body?.getReader();
      if (reader === undefined) throw new Error("Stream body is missing");
      events.push({ eventId: 9, repoId: 9, fullName: "fixture/node-stream", state: "SCANNING", occurredAt: "2026-08-15T12:00:00.000Z" });
      const chunk = new TextDecoder().decode((await reader.read()).value);
      expect(chunk).toContain("fixture/node-stream");
      expect(chunk).toContain("scan_started");
      controller.abort();
      await reader.cancel().catch(() => undefined);
    } finally {
      controller.abort();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => { if (error === undefined) resolve(); else reject(error); }));
    }
  });

  it("validates least-privilege runtime configuration", () => {
    expect(readApiConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", OPERATOR_TOKEN: "operator-token-32-bytes-minimum", API_PORT: "8080" })).toEqual({ databaseUrl: "postgresql://breach@postgres/breach", operatorToken: "operator-token-32-bytes-minimum", port: 8080 });
    expect(() => readApiConfig({})).toThrow("DATABASE_URL");
    expect(() => readApiConfig({ DATABASE_URL: "file:///tmp/db", OPERATOR_TOKEN: "operator-token-32-bytes-minimum" })).toThrow("DATABASE_URL");
    expect(() => readApiConfig({ DATABASE_URL: "postgresql://breach@postgres/breach" })).toThrow("OPERATOR_TOKEN");
    expect(() => readApiConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", OPERATOR_TOKEN: "operator-token-32-bytes-minimum", API_PORT: "0" })).toThrow("API_PORT");
    expect(() => readApiConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", OPERATOR_TOKEN: "operator-token-32-bytes-minimum", API_PORT: "70000" })).toThrow("API_PORT");
  });

  it("seedNeverCreatesPermanentGreenSafetyMetric", async () => {
    const source = await readFile(new URL("./seed.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/recordMetric\(["']zero_retention/u);
    expect(source).toMatch(/DEMO-SEED/u);
  });

  it("serves health/readiness and sanitized demo data through the real router", async () => {
    const fixture = await readFile(new URL("../../../fixtures/canary-repository/credential.txt", import.meta.url), "utf8");
    const raw = fixture.slice(fixture.indexOf("=") + 1).trim();
    const token = "operator-token-32-bytes-minimum";
    const handler = createApiHandler(createDemoDataSource(), token, () => Promise.resolve(true));
    expect((await handler(new Request("http://local/healthz"))).status).toBe(200);
    expect((await handler(new Request("http://local/readyz"))).status).toBe(200);
    expect((await createApiHandler(createDemoDataSource(), token, () => Promise.reject(new Error("database unavailable")))(new Request("http://local/readyz"))).status).toBe(503);
    expect((await createApiHandler(createDemoDataSource(), token, () => Promise.resolve(false))(new Request("http://local/readyz"))).status).toBe(503);
    const response = await handler(new Request("http://local/api/findings", { headers: { authorization: `Bearer ${token}` } }));
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("fixture/canary");
    expect(body).toContain("fingerprint");
    expect(body).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(body).not.toContain(raw);
    const demo = createDemoDataSource();
    expect(await demo.getFinding("00000000-0000-4000-8000-000000000099")).toBeNull();
    expect(await demo.reviewFinding("ignored", "UNCERTAIN")).toMatchObject({ reviewState: "UNCERTAIN" });
  });

  it("realDependencyEvidenceSurvivesToAPI", async () => {
    const token = "operator-token-32-bytes-minimum";
    const finding: SanitizedFinding = {
      findingId: "00000000-0000-4000-8000-000000000002",
      detectedAt: "2026-08-15T10:00:00.000Z",
      repository: { id: 2, fullName: "fixture/dependency", url: "https://github.com/fixture/dependency" },
      revision: { ref: "HEAD", sha: "b".repeat(40) },
      category: "vulnerable_dependency",
      severity: "high",
      confidence: 1,
      dependencyEvidence: { ecosystem: "npm", packageName: "lodash", version: "4.17.20", advisoryId: "GHSA-FAKE-1234", manifestPath: "package-lock.json", advisorySummary: "Prototype pollution in a bounded fixture." },
      reviewState: "UNREVIEWED",
    };
    const data: OperatorDataSource = {
      listFindings: () => Promise.resolve([finding]),
      getFinding: () => Promise.resolve(finding),
      reviewFinding: () => Promise.resolve(finding),
      listEvents: () => Promise.resolve([]),
      latestEventId: () => Promise.resolve(0),
      getSystemMetrics: () => Promise.resolve([]),
    };
    const handler = createApiHandler(data, token, () => Promise.resolve(true));
    const response = await handler(new Request(`http://local/api/findings/${finding.findingId}`, { headers: { authorization: `Bearer ${token}` } }));
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('"packageName":"lodash"');
    expect(body).toContain('"advisoryId":"GHSA-FAKE-1234"');
    expect(body).toContain('"manifestPath":"package-lock.json"');
    expect(body).not.toContain("node_modules/lodash/lodash.js");
  });

  it("starts the production API over a migrated metadata store", async () => {
    const memory = newDb();
    memory.public.registerFunction({ name: "pg_advisory_xact_lock", args: [DataType.bigint], returns: DataType.bool, implementation: () => true });
    const adapter = memory.adapters.createPg();
    // pg-mem deliberately presents a node-postgres-compatible pool.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    const pool: Pool = new adapter.Pool();
    const token = "operator-token-32-bytes-minimum";
    const signalListeners = { sigterm: process.listenerCount("SIGTERM"), sigint: process.listenerCount("SIGINT") };
    try {
      await runMigrations(pool);
      const store = await createMetadataStore(pool);
      await store.recordDiscoveryPage("api-integration", 44, [{ repoId: 44, fullName: "fixture/api-runtime", htmlUrl: "https://github.com/fixture/api-runtime", discoveredAt: new Date("2026-08-15T12:00:00.000Z"), priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
      await store.transition(44, "READY");

      const source = new PostgresOperatorDataSource(pool, store);
      expect(await source.latestEventId()).toBeGreaterThan(0);
      expect(await source.listFindings()).toEqual([]);

      const api = await startApi({ databaseUrl: "postgresql://unused/when-pool-injected", operatorToken: token, port: 0 }, { pool });
      const address = api.server.address();
      if (typeof address !== "object" || address === null) throw new Error("Production API did not bind");
      try {
        const live = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`);
        const ready = await fetch(`http://127.0.0.1:${String(address.port)}/readyz`);
        const findings = await fetch(`http://127.0.0.1:${String(address.port)}/api/findings`, { headers: { authorization: `Bearer ${token}` } });
        expect([live.status, ready.status, findings.status]).toEqual([200, 200, 200]);
        expect(await findings.json()).toEqual({ findings: [] });
      } finally {
        await api.close();
        await api.close();
      }
      expect(process.listenerCount("SIGTERM")).toBe(signalListeners.sigterm);
      expect(process.listenerCount("SIGINT")).toBe(signalListeners.sigint);
      await expect(pool.query("SELECT 1")).resolves.toMatchObject({ rowCount: 1 });
    } finally {
      await pool.end();
    }
  });
});
