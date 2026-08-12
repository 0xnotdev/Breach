import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createApiHandler, createDemoDataSource, readApiConfig } from "./index.js";

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
});
