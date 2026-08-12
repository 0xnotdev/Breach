import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const root = new URL("../../../", import.meta.url);
const read = (path: string) => readFile(new URL(path, root), "utf8");

describe("operational product contract", () => {
  it("ships configuration, migration, seed, CI, and all operator runbooks", async () => {
    const files = await Promise.all([".env.example", "README.md", "packages/storage/migrations/001_metadata.sql", ".github/workflows/ci.yml", "docs/runbooks/operations.md", "docs/runbooks/incident-response.md", "docs/runbooks/disclosure.md"].map(read));
    for (const content of files) expect(content.trim().length).toBeGreaterThan(100);
    expect(files[0]).toMatch(/GITHUB_TOKEN=.*read-only/i);
    expect(files[1]).toMatch(/zero.retention/i);
    expect(files[2]).toMatch(/CREATE TABLE IF NOT EXISTS findings/);
    expect(files[3]).toMatch(/test:browser/);
  });

  it("declares API, worker, web, and PostgreSQL services with health checks", async () => {
    const compose = await read("compose.yaml");
    for (const service of ["postgres", "api", "worker", "web"]) expect(compose).toMatch(new RegExp(`\\n  ${service}:`));
    expect(compose.match(/healthcheck:/g)).toHaveLength(4);
    expect(compose).toMatch(/8080:8080/);
    expect(compose).toMatch(/3000:3000/);
  });
});
