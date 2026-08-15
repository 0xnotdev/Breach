import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const root = new URL("../../../", import.meta.url);
const read = (path: string) => readFile(new URL(path, root), "utf8");

describe("operational product contract", () => {
  it("ships configuration, migration, seed, CI, and all operator runbooks", async () => {
    const files = await Promise.all([".env.example", "README.md", "packages/storage/migrations/001_initial.sql", ".github/workflows/ci.yml", "docs/runbooks/operations.md", "docs/runbooks/incident-response.md", "docs/runbooks/disclosure.md"].map(read));
    for (const content of files) expect(content.trim().length).toBeGreaterThan(100);
    expect(files[0]).toMatch(/GITHUB_TOKEN=.*read-only/i);
    expect(files[1]).toMatch(/zero.retention/i);
    expect(files[2]).toMatch(/CREATE TABLE IF NOT EXISTS findings/);
    expect(files[3]).toMatch(/test:browser/);
  });

  it("publishes compiled storage entry points while retaining source types", async () => {
    const manifest = JSON.parse(await read("packages/storage/package.json")) as { exports?: Record<string, { types?: string; development?: string; import?: string }> };
    expect(manifest.exports?.["."]).toEqual({ types: "./src/index.ts", development: "./src/index.ts", import: "./dist/index.js" });
    expect(manifest.exports?.["./migrations"]).toEqual({ types: "./src/migrations.ts", development: "./src/migrations.ts", import: "./dist/migrations.js" });
  });

  it("controlledFullStackStopsTheActualWebProcess", async () => {
    const [harness, dockerfile] = await Promise.all([read("scripts/controlled-full-stack.mjs"), read("deploy/web.Dockerfile")]);
    expect(harness).toContain("spawn(process.execPath");
    expect(harness).toContain("apps/web/node_modules/vinext/dist/cli.js");
    expect(harness).not.toContain('spawn(npmCommand, ["run", "start"');
    expect(harness).toContain('child.kill("SIGKILL")');
    expect(harness).toContain("await waitForChildExit(child, 5_000)");
    expect(dockerfile).toContain('ENTRYPOINT ["node", "apps/web/node_modules/vinext/dist/cli.js"');
  });

  it("declares API, worker, web, and PostgreSQL services with health checks", async () => {
    const compose = await read("compose.yaml");
    for (const service of ["postgres", "migrate", "api", "egress-proxy", "worker", "web"]) expect(compose).toMatch(new RegExp(`\\n  ${service}:`));
    expect(compose.match(/healthcheck:/g)).toHaveLength(5);
    expect(compose).toMatch(/8080:8080/);
    expect(compose).toMatch(/3000:3000/);
    expect(compose).toMatch(/migrate:\s*\n[\s\S]*service_completed_successfully/u);
    expect(compose).toMatch(/API_INTERNAL_URL:\s*http:\/\/api:8080/u);
  });

  it("workerHasNoDirectInternetRouteOutsideAllowlistProxy", async () => {
    const [compose, proxySource, policy, cilium] = await Promise.all([
      read("compose.yaml"),
      read("packages/security/src/proxy.ts"),
      read("deploy/network-policy.md"),
      read("deploy/cilium-egress-policy.yaml"),
    ]);
    const worker = compose.slice(compose.indexOf("\n  worker:"), compose.indexOf("\n  web:"));
    const proxy = compose.slice(compose.indexOf("\n  egress-proxy:"), compose.indexOf("\n  worker:"));
    expect(worker).toMatch(/NODE_USE_ENV_PROXY:\s*["']1["']/u);
    expect(worker).toMatch(/HTTPS_PROXY:\s*http:\/\/egress-proxy:3128/u);
    expect(worker).toMatch(/networks:\s*\[metadata, proxy_control\]/u);
    expect(worker).not.toMatch(/networks:.*egress/u);
    expect(proxy).toMatch(/networks:\s*\[proxy_control, egress\]/u);
    expect(proxySource).toMatch(/api\.github\.com/u);
    expect(proxySource).toMatch(/api\.osv\.dev/u);
    expect(policy).toMatch(/api\.github\.com:443/u);
    expect(policy).toMatch(/api\.osv\.dev:443/u);
    expect(policy).toMatch(/ordinary Docker bridge.*not.*allowlist/iu);
    expect(cilium).toMatch(/toFQDNs:[\s\S]*matchName: api\.github\.com[\s\S]*matchName: api\.osv\.dev/u);
  });
});
