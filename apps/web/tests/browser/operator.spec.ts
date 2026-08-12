import { expect, test } from "@playwright/test";

test("filters findings and completes a secret-safe human review", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await page.getByPlaceholder("Search repository, finding, language").fill("no-such-repository");
  await expect(page.getByRole("status")).toContainText("No surfaced finding within modeled coverage");
  await page.getByRole("button", { name: "Reset" }).click();
  await page.getByRole("link", { name: /Command Injection/ }).click();
  await expect(page.getByRole("heading", { name: "Command Injection" })).toBeVisible();
  const note = page.getByPlaceholder(/Record judgment only/);
  await note.fill("AWS_SECRET_ACCESS_KEY=do-not-store-this");
  await page.getByRole("button", { name: "CONFIRMED" }).click();
  await expect(page.getByRole("status")).toContainText("Note rejected");
  await note.fill("Reachability and sink model look correct.");
  await page.getByRole("button", { name: "UNCERTAIN" }).click();
  await expect(page.getByRole("status")).toContainText("Review saved as Uncertain");
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
