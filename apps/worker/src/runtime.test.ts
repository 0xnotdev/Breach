import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { readWorkerConfig, runControlledDemo } from "./runtime.js";

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
    expect(readWorkerConfig({ DATABASE_URL: "postgresql://breach@postgres/breach", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical", DISCOVERY_START_CURSOR: "500" })).toMatchObject({ discoveryMode: "historical", discoveryStartCursor: 500 });
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "", FINGERPRINT_HMAC_KEY: "short" })).toThrow();
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical" })).toThrow("DISCOVERY_START_CURSOR");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "invalid" })).toThrow("DISCOVERY_MODE");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "live", DISCOVERY_START_CURSOR: "1" })).toThrow("historical discovery mode");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", DISCOVERY_MODE: "historical", DISCOVERY_START_CURSOR: "-1" })).toThrow("DISCOVERY_START_CURSOR");
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
