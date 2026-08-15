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
  await page.route("**/api/stream*", async (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: 'id: 17\nevent: state\ndata: {"eventId":17,"repoId":1417,"fullName":"fixture/streamed","state":"SCANNED_FINDINGS","occurredAt":"2026-08-15T12:00:00.000Z","reasonCode":"scan_completed_findings"}\n\n' }));
  await page.goto("/");
  await page.getByRole("link", { name: /Stream/ }).click();
  await expect(page.getByRole("heading", { name: "Live state transitions" })).toBeVisible();
  await expect(page.getByText("SCANNED_FINDINGS", { exact: true })).toBeVisible();
  await expect(page.getByText("fixture/streamed", { exact: true })).toBeVisible();
  await expect(page.getByText("scan_completed_findings", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: /System/ }).click();
  await expect(page.getByRole("heading", { name: "System" })).toBeVisible();
  await expect(page.locator(".health-summary").getByText("DEGRADED", { exact: true })).toBeVisible();
  await expect(page.getByText("0 retention violations", { exact: true })).toBeVisible();
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
