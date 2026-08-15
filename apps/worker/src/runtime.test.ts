import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { readWorkerConfig, runControlledDemo } from "./runtime.js";
import { CandidatePolicy } from "@breach/github";

async function controlledCanary(): Promise<string> {
  const fixture = await readFile(new URL("../../../fixtures/canary-repository/credential.txt", import.meta.url), "utf8");
  return fixture.slice(fixture.indexOf("=") + 1).trim();
}

describe("worker runtime", () => {
  it("validates bounded least-privilege configuration", () => {
    const config = readWorkerConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", POLL_INTERVAL_MS: "30000", WORKER_HEALTH_PORT: "8081" });
    expect(config.pollIntervalMs).toBe(30_000);
    expect(config.healthPort).toBe(8081);
    expect(config.discoveryMode).toBe("live");
    expect(config.discoveryStartCursor).toBeNull();
    expect(config).toMatchObject({ maxDiscoveryPages: 2, maxDiscoveryRequests: 2, maxDiscoveryElapsedMs: 10_000, maxCommitChecksPerCycle: 25, maxScansPerCycle: 5, githubQuotaReserve: 200 });
    expect(readWorkerConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical", DISCOVERY_START_CURSOR: "500" })).toMatchObject({ discoveryMode: "historical", discoveryStartCursor: 500 });
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "", FINGERPRINT_HMAC_KEY: "short" })).toThrow();
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical" })).toThrow("DISCOVERY_START_CURSOR");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "invalid" })).toThrow("DISCOVERY_MODE");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "live", DISCOVERY_START_CURSOR: "1" })).toThrow("historical discovery mode");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical", DISCOVERY_START_CURSOR: "-1" })).toThrow("DISCOVERY_START_CURSOR");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", CANDIDATE_MINIMUM_SCORE: "101" })).toThrow("CANDIDATE_MINIMUM_SCORE");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", TARGET_SELECTION_RATIO: "0" })).toThrow("TARGET_SELECTION_RATIO");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", MAX_DISCOVERY_PAGES_PER_CYCLE: "0" })).toThrow("MAX_DISCOVERY_PAGES_PER_CYCLE");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", GITHUB_QUOTA_RESERVE: "-1" })).toThrow("GITHUB_QUOTA_RESERVE");
  });

  it("productionCandidatePolicySelectsRealisticHighValueRepos", () => {
    const config = readWorkerConfig({
      DATABASE_URL: "postgresql://breach@postgres/breach",
      GITHUB_TOKEN: "github-read-token",
      FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long",
    });
    const policy = new CandidatePolicy({
      minimumScore: config.candidateMinimumScore,
      targetSelectionRatio: config.targetSelectionRatio,
    });
    const decisions = policy.admit([
      { id: 10_004, name: "payments-auth-api", fullName: "acme/payments-auth-api", htmlUrl: "https://github.com/acme/payments-auth-api", description: "Cloud backend server deployed with Docker Kubernetes and Terraform", fork: false, ownerType: "Organization" },
      { id: 10_003, name: "course-notes", fullName: "student/course-notes", htmlUrl: "https://github.com/student/course-notes", description: "Tutorial homework and documentation", fork: false, ownerType: "User" },
      { id: 10_002, name: "dotfiles", fullName: "user/dotfiles", htmlUrl: "https://github.com/user/dotfiles", description: "Personal notes", fork: false, ownerType: "User" },
      { id: 10_001, name: "generated-mirror", fullName: "mirror/generated-mirror", htmlUrl: "https://github.com/mirror/generated-mirror", description: "Generated mirror", fork: true, ownerType: "Organization" },
    ]);

    expect(config).toMatchObject({ candidateMinimumScore: 60, targetSelectionRatio: 0.07 });
    expect(decisions[0]).toMatchObject({ state: "WAITING_FOR_COMMIT", reason: "selected" });
    expect(decisions.slice(1).every((decision) => decision.state === "SKIPPED")).toBe(true);
  });

  it("runs discovery through review with no source persistence", async () => {
    const raw = await controlledCanary();
    const result = await runControlledDemo(raw);
    expect(result.states).toEqual(["DISCOVERED", "WAITING_FOR_COMMIT", "READY", "SCANNING", "SCANNED_FINDINGS"]);
    expect(result.finding.reviewState).toBe("CONFIRMED");
    expect(result.finding.category).toBe("secret_exposure");
    expect(result.metrics).toContainEqual({ name: "scan.findings", value: 1 });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(serialized).not.toContain(raw);
  });
});
