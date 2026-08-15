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

  it("readmeAllowsANewOperatorToRunWithoutHiddenSteps", async () => {
    const [readme, operations, incident, disclosure, security] = await Promise.all([
      read("README.md"),
      read("docs/runbooks/operations.md"),
      read("docs/runbooks/incident-response.md"),
      read("docs/runbooks/disclosure.md"),
      read("docs/security-boundary.md"),
    ]);
    for (const heading of [
      "WHAT BREACH DOES", "ARCHITECTURE", "SAFETY MODEL", "REQUIREMENTS", "FIRST-TIME SETUP",
      "ENVIRONMENT VARIABLES", "START COMMAND", "HOW TO OPEN UI", "HOW TO VERIFY WORKER IS LIVE",
      "HOW TO RUN CANARY", "HOW TO RUN TESTS", "HOW TO RESET LOCAL DB", "HOW TO TROUBLESHOOT RATE LIMITS",
      "HOW TO READ COVERAGE", "KNOWN MVP LIMITATIONS", "NO CREDENTIAL VERIFICATION POLICY",
    ]) expect(readme).toContain(`## ${heading}`);
    expect(readme).toMatch(/docker compose up --build/u);
    expect(readme).toMatch(/docker compose down --volumes --remove-orphans/u);
    expect(readme).toMatch(/http:\/\/localhost:3000/u);
    expect(readme).toMatch(/\/readyz/u);
    expect(operations).toMatch(/fresh-volume startup/iu);
    expect(operations).toMatch(/rate.limit/iu);
    expect(incident).toMatch(/retention violation/iu);
    expect(disclosure).toMatch(/separate, explicitly authorized human process/iu);
    expect(security).toMatch(/logging/iu);
    expect(security).toMatch(/failure reason/iu);
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
    expect(dockerfile).toContain('ENTRYPOINT ["node", "/opt/breach/apps/web/node_modules/vinext/dist/cli.js"');
  });

  it("declares API, worker, web, and PostgreSQL services with health checks", async () => {
    const compose = await read("compose.yaml");
    for (const service of ["postgres", "migrate", "api", "egress-proxy", "worker", "web"]) expect(compose).toMatch(new RegExp(`\\n  ${service}:`));
    expect(compose.match(/healthcheck:/g)).toHaveLength(5);
    expect(compose).toMatch(/\$\{API_PORT:-8080\}:8080/u);
    expect(compose).toMatch(/\$\{WEB_PORT:-3000\}:3000/u);
    expect(compose).toMatch(/migrate:\s*\n[\s\S]*service_completed_successfully/u);
    expect(compose).toMatch(/API_INTERNAL_URL:\s*http:\/\/api:8080/u);
  });

  it("freshComposeSmokeUsesNoPriorVolumeOrRealGitHubCredential", async () => {
    const [compose, workflow, canaryDockerfile] = await Promise.all([read("compose.yaml"), read(".github/workflows/ci.yml"), read("deploy/canary.Dockerfile")]);
    expect(compose).toContain('127.0.0.1:${API_PORT:-8080}:8080');
    expect(compose).toContain('127.0.0.1:${WORKER_HEALTH_PORT:-8081}:8081');
    expect(compose).toContain('127.0.0.1:${WEB_PORT:-3000}:3000');
    const worker = compose.slice(compose.indexOf("\n  worker:"), compose.indexOf("\n  web:"));
    expect(worker).toMatch(/127\.0\.0\.1:8081\/readyz/u);
    expect(workflow).toMatch(/docker compose down --volumes --remove-orphans/u);
    expect(workflow).toMatch(/docker compose up --detach --wait postgres api egress-proxy web/u);
    expect(workflow).toMatch(/docker compose run --rm --build canary/u);
    expect(workflow).toMatch(/curl --fail --silent --show-error http:\/\/127\.0\.0\.1:8080\/readyz/u);
    expect(workflow).not.toMatch(/GITHUB_TOKEN:\s*\$\{\{\s*secrets\./u);
    expect(compose).toMatch(/canary:\s*\n\s+profiles:\s*\["tools"\]/u);
    expect(canaryDockerfile).toMatch(/COPY --from=build .*fixtures\/canary-repository\/credential\.txt/u);
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
