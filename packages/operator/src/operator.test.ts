import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { ReviewState, SanitizedFinding } from "@breach/contracts";
import {
  OperatorRouter,
  type OperatorDataSource,
  type StreamEvent,
  type SystemMetric,
} from "./index.js";

const finding = (
  overrides: Partial<SanitizedFinding> & Pick<SanitizedFinding, "category" | "severity">,
): SanitizedFinding => ({
  findingId: randomUUID(),
  detectedAt: "2026-08-12T12:00:00.000Z",
  repository: {
    id: 1401,
    fullName: "fixture/operator",
    url: "https://github.com/fixture/operator",
  },
  revision: { ref: "HEAD", sha: "a".repeat(40) },
  confidence: 0.95,
  coverage: {
    ref: `HEAD@${"a".repeat(40)}`,
    historyScanned: false,
    scanComplete: true,
    filesSeen: 10,
    filesAnalyzed: 10,
    bytesInspected: 1_024,
    skippedBinary: 0,
    skippedOversize: 0,
    skippedBudget: 0,
    treeTruncated: false,
    languagesModeled: ["typescript"],
  },
  reviewState: "UNREVIEWED",
  ...overrides,
});

class MemoryOperatorData implements OperatorDataSource {
  readonly findings: SanitizedFinding[];
  readonly events: StreamEvent[];
  readonly metrics: SystemMetric[];

  constructor(findings: SanitizedFinding[]) {
    this.findings = findings;
    this.events = [
      {
        eventId: 1,
        repoId: 1401,
        fullName: "fixture/operator",
        state: "SCANNED_FINDINGS",
        occurredAt: "2026-08-12T12:00:00.000Z",
      },
    ];
    this.metrics = [
      { name: "repositories.scanned_hour", value: 694, unit: "count" },
      { name: "zero_retention.canary", value: 1, unit: "healthy" },
    ];
  }

  listFindings(): Promise<readonly SanitizedFinding[]> {
    return Promise.resolve(this.findings);
  }

  getFinding(id: string): Promise<SanitizedFinding | null> {
    return Promise.resolve(this.findings.find((item) => item.findingId === id) ?? null);
  }

  reviewFinding(id: string, state: Exclude<ReviewState, "UNREVIEWED">, note?: string): Promise<SanitizedFinding> {
    const index = this.findings.findIndex((item) => item.findingId === id);
    const current = this.findings[index];
    if (current === undefined) return Promise.reject(new Error("Finding not found"));
    const updated = { ...current, reviewState: state };
    this.findings[index] = updated;
    void note;
    return Promise.resolve(updated);
  }

  listEvents(): Promise<readonly StreamEvent[]> {
    return Promise.resolve(this.events);
  }

  getSystemMetrics(): Promise<readonly SystemMetric[]> {
    return Promise.resolve(this.metrics);
  }
}

const exploitability = {
  score: 96,
  level: "high_confidence_static_path" as const,
  attackerSourceIdentified: true,
  completeDataflowObserved: true,
  sanitizerObserved: false,
  authBarrierObserved: false,
  runtimeVerified: false as const,
  activeTestingPerformed: false as const,
  deploymentConfirmed: false as const,
};

const request = (path: string, init: RequestInit = {}) =>
  new Request(`http://operator.local${path}`, {
    ...init,
    headers: new Headers([
      ["authorization", "Bearer operator-test-token"],
      ...new Headers(init.headers).entries(),
    ]),
  });

describe("sanitized operator HTTP/SSE interface", () => {
  it("requires private operator authentication", async () => {
    const router = new OperatorRouter(new MemoryOperatorData([]), "operator-test-token");
    const response = await router.handle(new Request("http://operator.local/api/findings"));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "unauthorized" });
  });

  it("filters and ranks findings by severity, exploitability, and recency", async () => {
    const critical = finding({
      category: "command_injection",
      severity: "critical",
      exploitability,
      detectedAt: "2026-08-12T12:00:00.000Z",
      path: [
        { file: "routes/run.ts", line: 1, role: "source", symbol: "req.body.command" },
        { file: "utils/shell.ts", line: 5, role: "sink", symbol: "exec" },
      ],
    });
    const high = finding({
      category: "vulnerable_dependency",
      severity: "high",
      detectedAt: "2026-08-12T12:01:00.000Z",
    });
    const router = new OperatorRouter(new MemoryOperatorData([high, critical]), "operator-test-token");

    const all = await router.handle(request("/api/findings"));
    const allBody = (await all.json()) as { findings: SanitizedFinding[] };
    expect(allBody.findings.map((item) => item.findingId)).toEqual([
      critical.findingId,
      high.findingId,
    ]);

    const filtered = await router.handle(
      request("/api/findings?severity=critical&family=exploitability&level=high_confidence_static_path&language=typescript&repository=fixture%2Foperator&review=UNREVIEWED&since=2026-08-12T11%3A00%3A00.000Z"),
    );
    const filteredBody = (await filtered.json()) as { findings: SanitizedFinding[] };
    expect(filteredBody.findings).toHaveLength(1);
    expect(filteredBody.findings[0]?.findingId).toBe(critical.findingId);
  });

  it("returns investigation evidence, safe GitHub links, and review updates", async () => {
    const item = finding({
      category: "command_injection",
      severity: "critical",
      exploitability,
      path: [
        { file: "routes/run.ts", line: 1, role: "entry", symbol: "POST /run" },
        { file: "routes/run.ts", line: 1, role: "source", symbol: "req.body.command" },
        { file: "utils/shell.ts", line: 5, role: "sink", symbol: "exec" },
      ],
    });
    const router = new OperatorRouter(new MemoryOperatorData([item]), "operator-test-token");

    const detail = await router.handle(request(`/api/findings/${item.findingId}`));
    const detailBody = (await detail.json()) as { finding: SanitizedFinding; openOnGitHub: string };
    expect(detailBody.finding.exploitability).toMatchObject({ runtimeVerified: false });
    expect(detailBody.openOnGitHub).toBe(
      `https://github.com/fixture/operator/blob/${"a".repeat(40)}/routes/run.ts#L1`,
    );

    const reviewed = await router.handle(
      request(`/api/findings/${item.findingId}/review`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "CONFIRMED", note: "Path checked on GitHub." }),
      }),
    );
    expect(reviewed.status).toBe(200);
    await expect(reviewed.json()).resolves.toMatchObject({ finding: { reviewState: "CONFIRMED" } });
  });

  it("exposes sanitized state events and system metrics", async () => {
    const router = new OperatorRouter(new MemoryOperatorData([]), "operator-test-token");
    const stream = await router.handle(request("/api/stream"));
    const system = await router.handle(request("/api/system"));

    expect(stream.headers.get("content-type")).toContain("text/event-stream");
    const streamText = await stream.text();
    expect(streamText).toContain("SCANNED_FINDINGS");
    expect(streamText).not.toContain("source");
    await expect(system.json()).resolves.toEqual({
      metrics: [
        { name: "repositories.scanned_hour", value: 694, unit: "count" },
        { name: "zero_retention.canary", value: 1, unit: "healthy" },
      ],
    });
  });

  it("rejects sensitive review notes and never echoes request content in errors", async () => {
    const item = finding({ category: "secret_exposure", severity: "critical" });
    const router = new OperatorRouter(new MemoryOperatorData([item]), "operator-test-token");
    const rawCanary = "AWS_SECRET_ACCESS_KEY=CANARY_RAW_DO_NOT_ECHO";
    const response = await router.handle(
      request(`/api/findings/${item.findingId}/review`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "CONFIRMED", note: rawCanary }),
      }),
    );

    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toBe('{"error":"invalid_request"}');
    expect(text).not.toContain(rawCanary);
  });
});
