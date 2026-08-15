import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { DataType, newDb } from "pg-mem";
import type { Pool } from "pg";
import { runZeroRetentionCanary } from "../../../worker/src/runtime.js";
import { runMigrations } from "../../../../packages/storage/src/migrations.js";

const liveFinding = {
  findingId: "76a23814-bfc1-4c15-9444-f7019803e6dd",
  detectedAt: "2026-08-15T12:00:00.000Z",
  repository: { id: 41, fullName: "fixture/live-service", url: "https://github.com/fixture/live-service" },
  revision: { ref: "refs/heads/main", sha: "a827f9c" },
  category: "command_injection",
  cwe: "CWE-78",
  severity: "critical",
  confidence: 0.96,
  exploitability: { score: 96, level: "high_confidence_static_path", attackerSourceIdentified: true, completeDataflowObserved: true, sanitizerObserved: false, authBarrierObserved: false, runtimeVerified: false, activeTestingPerformed: false, deploymentConfirmed: false },
  path: [{ file: "src/routes/render.ts", line: 42, role: "source", symbol: "req.body.filename", edge: "argument" }, { file: "src/routes/render.ts", line: 45, role: "sink", symbol: "child_process.exec", edge: "call" }],
  reviewState: "UNREVIEWED",
};
const liveSystemMetrics = [
  { name: "discovery.repositories_hour", value: 12, unit: "count" },
  { name: "scan.p95_latency_ms", value: 1250, unit: "milliseconds" },
  { name: "reviews.total", value: 3, unit: "count" },
  { name: "reviewed_precision", value: 2 / 3, unit: "ratio" },
  { name: "safety.retention_violations", value: 0, unit: "count" },
];

test("loads and filters sanitized findings through the same-origin boundary", async ({ page }) => {
  await page.route("**/api/findings?**", async (route) => route.fulfill({ json: { findings: [liveFinding] } }));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Command Injection/ })).toBeVisible();
  await expect(page.getByText("fixture/live-service", { exact: false })).toBeVisible();
  await page.getByPlaceholder("Search repository, finding, language").fill("no-such-repository");
  await expect(page.getByRole("status")).toContainText("No surfaced finding matches these filters");
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByRole("link", { name: /Command Injection/ })).toBeVisible();
});

test("navigates the live stream and system safety view", async ({ page }) => {
  await page.route("**/api/stream*", async (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: 'id: 17\nevent: state\ndata: {"eventId":17,"repoId":1417,"fullName":"fixture/streamed","state":"SCANNED_FINDINGS","occurredAt":"2026-08-15T12:00:00.000Z","reasonCode":"scan_completed_findings"}\n\n' }));
  await page.route("**/api/system", async (route) => route.fulfill({ json: { metrics: liveSystemMetrics } }));
  await page.goto("/");
  await page.getByRole("link", { name: /Stream/ }).click();
  await expect(page.getByRole("heading", { name: "Live state transitions" })).toBeVisible();
  await expect(page.getByText("SCANNED_FINDINGS", { exact: true })).toBeVisible();
  await expect(page.getByText("fixture/streamed", { exact: true })).toBeVisible();
  await expect(page.getByText("scan_completed_findings", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: /System/ }).click();
  await expect(page.getByRole("heading", { name: "System" })).toBeVisible();
  await expect(page.getByText("Repositories discovered / hour", { exact: true })).toBeVisible();
  await expect(page.getByText("12", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("1.3s", { exact: true })).toBeVisible();
  await expect(page.getByText("66.7%", { exact: true })).toBeVisible();
  await expect(page.getByText("No data yet", { exact: true }).first()).toBeVisible();
});

test("reviewPersistsAcrossReload", async ({ page }) => {
  let persistedState = "UNREVIEWED";
  let persistedNote = "";
  let browserAuthorization = "not observed";
  await page.route(`**/api/findings/${liveFinding.findingId}/review`, async (route) => {
    browserAuthorization = route.request().headers().authorization ?? "";
    const body = route.request().postDataJSON() as { state: string; note?: string };
    persistedState = body.state;
    persistedNote = body.note ?? "";
    await route.fulfill({ json: { finding: { ...liveFinding, reviewState: persistedState } } });
  });
  await page.route(`**/api/findings/${liveFinding.findingId}`, async (route) => {
    await route.fulfill({ json: { finding: { ...liveFinding, reviewState: persistedState }, openOnGitHub: "https://github.com/fixture/live-service/blob/a827f9c/src/routes/render.ts#L42" } });
  });

  await page.goto(`/findings/${liveFinding.findingId}`);
  await expect(page.getByRole("heading", { name: "Command Injection" })).toBeVisible();
  const note = page.getByPlaceholder(/Record judgment only/);
  await note.fill("AWS_SECRET_ACCESS_KEY=do-not-store-this");
  await page.getByRole("button", { name: "CONFIRMED" }).click();
  await expect(page.getByRole("status")).toContainText("Note rejected");
  await note.fill("Reachability and sink model look correct.");
  await page.getByRole("button", { name: "UNCERTAIN" }).click();
  await expect(page.getByRole("status")).toContainText("Review saved as Uncertain");
  expect(persistedNote).toBe("Reachability and sink model look correct.");
  expect(browserAuthorization).toBe("");

  await page.reload();
  await expect(page.getByText("Current state:")).toContainText("Uncertain");
});

test("renders persisted secret dependency and configuration evidence", async ({ page }) => {
  const secretFingerprint = "0123456789abcdef".repeat(4);
  const evidenceCases = [
    {
      finding: { ...liveFinding, findingId: "819193aa-4f1d-44a2-8b21-1ae3deececa4", category: "secret_exposure", path: undefined, exploitability: undefined, secretEvidence: { provider: "AWS", type: "AWS Secret Access Key", path: ".env", line: 8, fingerprint: secretFingerprint } },
      expected: ["Exposed Secret", "AWS Secret Access Key", ".env:8", "Raw value NOT RETAINED", "0123456789ab…456789abcdef"],
    },
    {
      finding: { ...liveFinding, findingId: "1db4388c-91bc-4ac3-9029-9f8599115d27", category: "vulnerable_dependency", path: undefined, exploitability: undefined, dependencyEvidence: { ecosystem: "npm", packageName: "fixture-parser", version: "1.2.0", advisoryId: "OSV-2026-0042", manifestPath: "package-lock.json" } },
      expected: ["Vulnerable Dependency", "fixture-parser", "1.2.0", "npm", "OSV-2026-0042", "package-lock.json"],
    },
    {
      finding: { ...liveFinding, findingId: "d391856a-5970-4297-9909-14259b15cdac", category: "configuration", severity: "medium", path: undefined, exploitability: undefined, configEvidence: { ruleId: "workflow.write_all", path: ".github/workflows/release.yml", line: 4, rationale: "Repository-wide write permission increases workflow compromise impact.", staticOnly: true } },
      expected: ["Configuration Risk", "workflow.write_all", ".github/workflows/release.yml:4", "Medium", "Repository-wide write permission increases workflow compromise impact."],
    },
  ];

  for (const evidenceCase of evidenceCases) {
    await page.route(`**/api/findings/${evidenceCase.finding.findingId}`, async (route) => route.fulfill({ json: { finding: evidenceCase.finding, openOnGitHub: `${evidenceCase.finding.repository.url}/commit/${evidenceCase.finding.revision.sha}` } }));
    await page.goto(`/findings/${evidenceCase.finding.findingId}`);
    for (const expected of evidenceCase.expected) await expect(page.getByText(expected, { exact: false }).first()).toBeVisible();
  }
  await expect(page.locator("body")).not.toContainText(secretFingerprint);
});

test("canaryRawValueAbsentFromAllRuntimeSurfaces", async ({ page }) => {
  const fixture = await readFile(new URL("../../../../fixtures/canary-repository/credential.txt", import.meta.url), "utf8");
  const rawCanary = fixture.slice(fixture.indexOf("=") + 1).trim();
  const memory = newDb();
  memory.public.registerFunction({ name: "pg_advisory_xact_lock", args: [DataType.bigint], returns: DataType.bool, implementation: () => true });
  const adapter = memory.adapters.createPg();
  // pg-mem exposes a node-postgres-compatible pool without carrying its concrete type.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
  const pool: Pool = new adapter.Pool();
  try {
    await runMigrations(pool);
    const report = await runZeroRetentionCanary({
      pool,
      rawCanary,
      fingerprintKey: "browser-canary-fingerprint-key-32-bytes",
      collectExternalSurfaces: async (finding) => {
        await page.route(`**/api/findings/${finding.findingId}`, async (route) => route.fulfill({
          json: {
            finding,
            openOnGitHub: `${finding.repository.url}/blob/${finding.revision.sha}/${finding.secretEvidence?.path ?? "credential.txt"}`,
          },
        }));
        await page.goto(`/findings/${finding.findingId}`);
        await expect(page.getByRole("heading", { name: "Exposed Secret" })).toBeVisible();
        const rendered = await page.locator("body").innerText();
        const browserStorage = await page.evaluate(() => ({
          local: { ...localStorage },
          session: { ...sessionStorage },
        }));
        return {
          webRenderedOutput: rendered,
          browserLocalStorage: JSON.stringify(browserStorage.local),
          browserSessionStorage: JSON.stringify(browserStorage.session),
        };
      },
    });

    expect(report.rawOccurrences).toBe(0);
    expect(report.ephemeralBytesCleared).toBe(true);
    expect(report.surfacesChecked).toEqual(expect.arrayContaining([
      "postgresql", "applicationLogs", "apiList", "apiDetail", "errorPaths",
      "webRenderedOutput", "browserLocalStorage", "browserSessionStorage",
    ]));
    await expect(page.locator("body")).not.toContainText(rawCanary);
    await expect(page.getByText("Raw value NOT RETAINED", { exact: true })).toBeVisible();
  } finally {
    await pool.end();
  }
});
