import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createApiHandler, createDemoDataSource, readApiConfig, serveNodeRequest } from "./index.js";
import type { SanitizedFinding } from "@breach/contracts";
import type { OperatorDataSource, StreamEvent } from "@breach/operator";

describe("operator API runtime", () => {
  it("apiBridgeNeverBuffersStreamingResponse", async () => {
    const source = await readFile(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).not.toContain("result.arrayBuffer()");
    expect(source).toContain("result.body.getReader()");
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
