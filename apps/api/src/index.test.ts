import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createApiHandler, createDemoDataSource, readApiConfig } from "./index.js";
import type { SanitizedFinding } from "@breach/contracts";
import type { OperatorDataSource } from "@breach/operator";

describe("operator API runtime", () => {
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
