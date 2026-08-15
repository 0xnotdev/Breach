import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import process from "node:process";
import { chromium } from "@playwright/test";
import { Pool } from "pg";
import { startApi } from "../apps/api/dist/index.js";
import { createWorkerRuntime, readWorkerConfig, runZeroRetentionCanary } from "../apps/worker/dist/runtime.js";
import { createMetadataStore } from "../packages/storage/dist/index.js";
import { runMigrations } from "../packages/storage/dist/migrations.js";

const operatorToken = "controlled-full-stack-operator-token";
const fingerprintKey = "controlled-full-stack-fingerprint-key-32-bytes";
const rawScanCanary = "9vK2Lm4Np6Qr8St0Uv2Wx4Yz6Ab8Cd0Ef2Gh4Ij6";
const rawRuntimeCanary = "runtime-canary-value-never-retained-2026";
const headSha = "d".repeat(40);

function requireDatabaseUrl() {
  const configured = process.env.DATABASE_URL;
  if (configured === undefined) throw new Error("DATABASE_URL is required for controlled full-stack validation");
  const url = new URL(configured);
  if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") throw new Error("DATABASE_URL must be PostgreSQL");
  return url;
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("Could not reserve an integration port");
  await new Promise((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
  return address.port;
}

async function waitForHttp(url, child) {
  let latest;
  for (let attempt = 0; attempt < 240; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Web process exited before readiness (${String(child.exitCode)})`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
      latest = new Error(`readiness returned ${String(response.status)}`);
    } catch (error) {
      latest = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw latest instanceof Error ? latest : new Error("Web readiness timed out");
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    once(child, "exit"),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

function controlledFiles() {
  const encoder = new TextEncoder();
  const content = new Map([
    [".env", `AWS_SECRET_ACCESS_KEY=${rawScanCanary}\n`],
    ["package-lock.json", '{"packages":{"node_modules/fixture-parser":{"version":"1.2.0"}}}'],
    [".github/workflows/release.yml", "on: pull_request_target\npermissions: write-all\nsteps:\n  - uses: actions/checkout@main\n"],
    ["routes/render.ts", 'router.post("/render", (req, res) => child_process.exec(req.body.filename));\n'],
  ]);
  return new Map([...content].map(([path, text], index) => [String(index + 1).repeat(40), { path, bytes: encoder.encode(text) }]));
}

async function main() {
  const baseUrl = requireDatabaseUrl();
  const databaseName = `breach_it_${String(process.pid)}_${String(Date.now())}`;
  assert.match(databaseName, /^[a-z0-9_]+$/u);
  const adminUrl = new URL(baseUrl);
  adminUrl.pathname = "/postgres";
  const integrationUrl = new URL(baseUrl);
  integrationUrl.pathname = `/${databaseName}`;
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  let databaseCreated = false;
  let pool;
  let api;
  let web;
  let browser;
  const childOutput = [];
  const fixtureFiles = controlledFiles();
  try {
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    databaseCreated = true;
    pool = new Pool({ connectionString: integrationUrl.toString(), max: 8 });

    const firstMigration = await runMigrations(pool);
    const secondMigration = await runMigrations(pool);
    assert.deepEqual(firstMigration.applied, [1, 2, 3, 4]);
    assert.deepEqual(secondMigration.applied, []);
    assert.equal(secondMigration.currentVersion, 4);

    const config = readWorkerConfig({
      DATABASE_URL: integrationUrl.toString(),
      GITHUB_TOKEN: "controlled-read-only-token",
      FINGERPRINT_HMAC_KEY: fingerprintKey,
      DISCOVERY_MODE: "historical",
      DISCOVERY_START_CURSOR: "10003",
      MAX_DISCOVERY_PAGES_PER_CYCLE: "1",
      MAX_DISCOVERY_REQUESTS_PER_CYCLE: "1",
      MAX_DISCOVERY_ELAPSED_MS: "10000",
      MAX_COMMIT_CHECKS_PER_CYCLE: "5",
      MAX_SCANS_PER_CYCLE: "1",
      GITHUB_QUOTA_RESERVE: "200",
    });
    const runtime = await createWorkerRuntime(config, pool, {
      now: () => new Date(),
      nowMs: (() => { let value = 0; return () => { value += 1; return value; }; })(),
      githubTransport: {
        get(target) {
          const url = new URL(target);
          const headers = { "x-ratelimit-remaining": "4999", "x-ratelimit-limit": "5000" };
          if (url.pathname === "/repositories") return Promise.resolve({ status: 200, headers, body: [{ id: 10004, name: "payments-auth-api", full_name: "fixture/payments-auth-api", html_url: "https://github.com/fixture/payments-auth-api", description: "Cloud backend server deployed with Docker Kubernetes and Terraform", fork: false, owner: { type: "Organization" } }] });
          if (url.pathname.endsWith("/commits")) return Promise.resolve({ status: 200, headers, body: [{ sha: headSha }] });
          if (url.pathname.endsWith(`/git/trees/${headSha}`)) return Promise.resolve({ status: 200, headers, body: { tree: [...fixtureFiles].map(([sha, file]) => ({ path: file.path, type: "blob", sha, size: file.bytes.byteLength })), truncated: false } });
          throw new Error(`Unexpected controlled GitHub metadata path: ${url.pathname}`);
        },
      },
      blobTransport: {
        async *stream(target) {
          const sha = new URL(target).pathname.split("/").at(-1);
          const file = sha === undefined ? undefined : fixtureFiles.get(sha);
          if (file === undefined) throw new Error("Unexpected controlled blob request");
          yield await Promise.resolve(file.bytes);
        },
      },
      osvTransport: {
        queryBatch({ queries }) {
          return Promise.resolve({ results: queries.map(() => ({ vulns: [{ id: "OSV-2026-CONTROLLED", summary: "Controlled advisory for integration validation." }] })) });
        },
      },
    });
    const cycle = await runtime.runCycle();
    assert.deepEqual(cycle, { nextCursor: 10004, processed: 1, scansStarted: 1, quotaPaused: false });

    const canary = await runZeroRetentionCanary({
      pool,
      rawCanary: rawRuntimeCanary,
      fingerprintKey,
      now: () => new Date(),
    });
    assert.equal(canary.rawOccurrences, 0);
    assert.equal(canary.ephemeralBytesCleared, true);

    const findings = await pool.query("SELECT finding_id, payload FROM findings ORDER BY detected_at");
    assert.ok(findings.rows.length >= 4, "Controlled scan should persist multiple finding families");
    const serializedDatabase = JSON.stringify(findings.rows);
    assert.ok(serializedDatabase.includes("fingerprint"));
    assert.ok(serializedDatabase.includes("dependencyEvidence"));
    assert.ok(serializedDatabase.includes("configEvidence"));
    assert.ok(serializedDatabase.includes("path"));
    assert.ok(!serializedDatabase.includes(rawScanCanary));
    assert.ok(!serializedDatabase.includes(rawRuntimeCanary));
    assert.ok(!serializedDatabase.includes('child_process.exec(req.body.filename)'));

    api = await startApi({ databaseUrl: integrationUrl.toString(), operatorToken, port: 0 }, { pool });
    const apiAddress = api.server.address();
    if (typeof apiAddress !== "object" || apiAddress === null) throw new Error("Controlled API did not bind");
    const webPort = await reservePort();
    const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
    web = spawn(npmCommand, ["run", "start", "--", "--port", String(webPort), "--hostname", "127.0.0.1"], {
      cwd: new URL("../apps/web/", import.meta.url),
      env: { ...process.env, API_INTERNAL_URL: `http://127.0.0.1:${String(apiAddress.port)}`, OPERATOR_TOKEN: operatorToken },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const collectOutput = (chunk) => {
      if (childOutput.join("").length < 64_000) childOutput.push(String(chunk));
    };
    web.stdout.on("data", collectOutput);
    web.stderr.on("data", collectOutput);
    await waitForHttp(`http://127.0.0.1:${String(webPort)}/`, web);

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    const browserSurfaces = [];
    page.on("request", (request) => {
      browserSurfaces.push(JSON.stringify({ url: request.url(), method: request.method(), headers: request.headers(), postData: request.postData() }));
    });
    page.on("response", async (response) => {
      if (!["document", "fetch", "xhr", "script"].includes(response.request().resourceType())) return;
      try { browserSurfaces.push(await response.text()); } catch { /* Streaming and closed responses have no finite body. */ }
    });

    await page.goto(`http://127.0.0.1:${String(webPort)}/`);
    await page.getByRole("heading", { name: "Findings" }).waitFor();
    await page.getByText("fixture/payments-auth-api", { exact: false }).first().waitFor();
    await page.getByText("Vulnerable Dependency", { exact: true }).first().waitFor();
    await page.getByText("Configuration Risk", { exact: true }).first().waitFor();
    const search = page.getByPlaceholder("Search repository, finding, language");
    await search.fill("no-such-repository");
    await page.getByText("No surfaced finding matches these filters", { exact: false }).waitFor();
    await page.getByRole("button", { name: "Reset" }).click();
    await page.getByRole("link", { name: /Command Injection/u }).first().click();
    await page.getByRole("heading", { name: "Command Injection" }).waitFor();
    await page.getByText("req.body.filename", { exact: true }).waitFor();
    const githubLink = await page.getByRole("link", { name: /Open on GitHub/u }).getAttribute("href");
    assert.ok(githubLink?.includes(headSha));
    assert.ok(githubLink?.includes("routes/render.ts"));
    await page.getByPlaceholder(/Record judgment only/u).fill("Controlled integration review confirms the modeled path.");
    await page.getByRole("button", { name: "CONFIRMED" }).click();
    await page.getByRole("status").filter({ hasText: "Review saved as Confirmed" }).waitFor();
    await page.reload();
    await page.getByText("Current state:").waitFor();
    assert.match(await page.locator("body").innerText(), /Current state:\s*Confirmed/u);

    await page.goto(`http://127.0.0.1:${String(webPort)}/stream`);
    await page.getByRole("heading", { name: "Live state transitions" }).waitFor();
    await page.getByText("CONNECTED", { exact: true }).waitFor();
    const store = await createMetadataStore(pool);
    await store.recordDiscoveryPage("controlled-late-event", 20005, [{ repoId: 20005, fullName: "fixture/late-stream-event", htmlUrl: "https://github.com/fixture/late-stream-event", discoveredAt: new Date(), priorityScore: 0, candidateState: "SKIPPED", selectionReason: "score" }]);
    await page.getByText("fixture/late-stream-event", { exact: true }).waitFor({ timeout: 15_000 });
    await page.getByText("SKIPPED", { exact: true }).first().waitFor();

    await page.goto(`http://127.0.0.1:${String(webPort)}/system`);
    await page.getByRole("heading", { name: "System" }).waitFor();
    await page.getByText("Repositories discovered / hour", { exact: true }).waitFor();
    await page.getByText("Reviewed", { exact: true }).waitFor();
    await page.getByText("PASS", { exact: true }).waitFor();

    const storage = await page.evaluate(() => JSON.stringify({ localStorage: { ...localStorage }, sessionStorage: { ...sessionStorage } }));
    browserSurfaces.push(await page.locator("html").innerHTML(), storage);
    const serializedBrowser = browserSurfaces.join("\n");
    for (const forbidden of [operatorToken, rawScanCanary, rawRuntimeCanary, "AWS_SECRET_ACCESS_KEY="]) {
      assert.ok(!serializedBrowser.includes(forbidden), `Browser surface contained forbidden value: ${forbidden.slice(0, 12)}`);
    }

    const persistedReview = await pool.query("SELECT review_state, review_note FROM finding_reviews");
    assert.ok(persistedReview.rows.some((row) => row.review_state === "CONFIRMED" && row.review_note === "Controlled integration review confirms the modeled path."));
    console.log(`Controlled full-stack validation passed (${String(findings.rows.length)} findings, migration v${String(secondMigration.currentVersion)}).`);
  } catch (error) {
    if (childOutput.length > 0) process.stderr.write(`\nControlled web output:\n${childOutput.join("").slice(-8_000)}\n`);
    throw error;
  } finally {
    for (const file of fixtureFiles.values()) file.bytes.fill(0);
    if (browser !== undefined) await browser.close().catch(() => undefined);
    if (web !== undefined) await stopChild(web);
    if (api !== undefined) await api.close().catch(() => undefined);
    if (pool !== undefined) await pool.end().catch(() => undefined);
    if (databaseCreated) await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`).catch(() => undefined);
    await admin.end().catch(() => undefined);
  }
}

await main();
