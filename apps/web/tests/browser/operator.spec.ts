import { expect, test } from "@playwright/test";

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
  await page.goto("/");
  await page.getByRole("link", { name: /Stream/ }).click();
  await expect(page.getByRole("heading", { name: "Live state transitions" })).toBeVisible();
  await expect(page.getByText("WAITING_FOR_COMMIT", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: /System/ }).click();
  await expect(page.getByRole("heading", { name: "System" })).toBeVisible();
  await expect(page.locator(".health-summary").getByText("DEGRADED", { exact: true })).toBeVisible();
  await expect(page.getByText("0 retention violations", { exact: true })).toBeVisible();
});
