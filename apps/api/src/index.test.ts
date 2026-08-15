import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createApiHandler, createDemoDataSource, readApiConfig, serveNodeRequest } from "./index.js";
import type { SanitizedFinding } from "@breach/contracts";
import type { OperatorDataSource, StreamEvent } from "@breach/operator";
import type { Pool } from "pg";
import { readPostgresSystemMetrics } from "./system-metrics.js";

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

    const metrics = new Map((await readPostgresSystemMetrics(pool)).map((metric) => [metric.name, metric]));
    expect(metrics.get("reviewed_precision")?.value).toBe(0.75);
    expect(metrics.get("scan.partial_rate")?.value).toBe(0.25);
    expect(metrics.get("scan.failure_rate")?.value).toBe(0.2);
    expect(metrics.get("findings.per_1000_scans")?.value).toBe(500);
    expect(metrics.get("github.requests_per_completed_scan")?.value).toBe(5);
    expect(metrics.get("safety.canary.result")?.value).toBe(1);
    expect(metrics.get("safety.canary.last_run")?.value).toBe(1_786_795_200_000);
    expect(metrics.has("safety.retention_violations")).toBe(false);
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
    expect(() => readApiConfig({ DATABASE_URL: "file:///tmp/db", OPERATOR_TOKEN: "short" })).toThrow();
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
    const response = await handler(new Request("http://local/api/findings", { headers: { authorization: `Bearer ${token}` } }));
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("fixture/canary");
    expect(body).toContain("fingerprint");
    expect(body).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(body).not.toContain(raw);
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
});
