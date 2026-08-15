import { describe, expect, it, vi } from "vitest";
import { readFile } from "node:fs/promises";
import { DataType, newDb } from "pg-mem";
import type { Pool } from "pg";
import { createWorkerRuntime, FetchBlobTransport, FetchGitHubTransport, FetchOsvTransport, readWorkerConfig, requestStatusClass, runControlledDemo, runZeroRetentionCanary } from "./runtime.js";
import { CandidatePolicy } from "@breach/github";
import { runMigrations } from "@breach/storage/migrations";

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
    expect(() => readWorkerConfig({})).toThrow("DATABASE_URL");
    expect(() => readWorkerConfig({ DATABASE_URL: "file:///tmp/breach", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long" })).toThrow("DATABASE_URL");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x" })).toThrow("GITHUB_TOKEN");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token" })).toThrow("FINGERPRINT_HMAC_KEY");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", POLL_INTERVAL_MS: "4999" })).toThrow("POLL_INTERVAL_MS");
    expect(() => readWorkerConfig({ DATABASE_URL: "postgresql://x", GITHUB_TOKEN: "github-read-token", FINGERPRINT_HMAC_KEY: "fingerprint-key-at-least-32-bytes-long", WORKER_HEALTH_PORT: "0" })).toThrow("WORKER_HEALTH_PORT");
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

  it("repositoryControlledUrlIsNeverFetched", async () => {
    const network = vi.spyOn(globalThis, "fetch");
    const metadata = new FetchGitHubTransport();
    const blobs = new FetchBlobTransport("test-read-only-token");
    const repositoryControlledTargets = [
      "https://github.com/owner/repository",
      "https://example.test/webhook",
      "https://registry.npmjs.org/package",
      "https://registry.terraform.io/module",
      "https://images.example.test/base-layer",
      "http://127.0.0.1:8080/admin",
    ];
    try {
      for (const target of repositoryControlledTargets) {
        await expect(metadata.get(target, {})).rejects.toThrow(/egress denied/i);
        await expect((async () => {
          await blobs.stream(target, {})[Symbol.asyncIterator]().next();
        })()).rejects.toThrow(/egress denied/i);
      }
      expect(network).not.toHaveBeenCalled();
    } finally {
      network.mockRestore();
    }
  });

  it("productionHttpTransportsBoundResponsesAndReportBlobRequests", async () => {
    const network = vi.spyOn(globalThis, "fetch");
    try {
      network.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }));
      await expect(new FetchGitHubTransport().get("https://api.github.com/repositories", {})).resolves.toMatchObject({ status: 200, body: { ok: true } });

      network.mockResolvedValueOnce(new Response(null, { status: 204 }));
      await expect(new FetchGitHubTransport().get("https://api.github.com/repositories", {})).resolves.toMatchObject({ status: 204, body: null });

      network.mockResolvedValueOnce(new Response("{}", { status: 200, headers: { "content-length": String(13 * 1024 * 1024) } }));
      await expect(new FetchGitHubTransport().get("https://api.github.com/repositories", {})).rejects.toThrow("exceeds bound");

      const observed: Array<{ family: string; status: number }> = [];
      network.mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "x-ratelimit-remaining": "4998" } }));
      const chunks: number[] = [];
      for await (const chunk of new FetchBlobTransport("read-token", (event) => { observed.push(event); }).stream(`https://api.github.com/repos/fixture/repo/git/blobs/${"a".repeat(40)}`, {})) chunks.push(...chunk);
      expect(chunks).toEqual([1, 2, 3]);
      expect(observed).toEqual([expect.objectContaining({ family: "blob", status: 200 })]);

      network.mockRejectedValueOnce(new Error("controlled network failure"));
      await expect((async () => {
        for await (const chunk of new FetchBlobTransport("read-token", (event) => { observed.push(event); }).stream(`https://api.github.com/repos/fixture/repo/git/blobs/${"b".repeat(40)}`, {})) { void chunk; }
      })()).rejects.toThrow("controlled network failure");
      expect(observed.at(-1)).toEqual({ family: "blob", status: 0 });

      network.mockResolvedValueOnce(new Response(JSON.stringify({ results: [{}] }), { status: 200 }));
      await expect(new FetchOsvTransport().queryBatch({ queries: [{ package: { ecosystem: "npm", name: "fixture" }, version: "1.0.0" }] })).resolves.toEqual({ results: [{}] });
      await expect(new FetchOsvTransport().queryBatch({ queries: Array.from({ length: 101 }, () => ({ package: { ecosystem: "npm", name: "fixture" }, version: "1.0.0" })) })).rejects.toThrow("batch limit");
      network.mockResolvedValueOnce(new Response("denied", { status: 503 }));
      await expect(new FetchOsvTransport().queryBatch({ queries: [] })).rejects.toThrow("status 503");

      network.mockResolvedValueOnce(new Response(null, { status: 200 }));
      await expect((async () => {
        for await (const chunk of new FetchBlobTransport("read-token").stream(`https://api.github.com/repos/fixture/repo/git/blobs/${"c".repeat(40)}`, {})) { void chunk; }
      })()).rejects.toThrow("status 200");
    } finally {
      network.mockRestore();
    }
  });

  it("classifies request outcomes into low-cardinality metric labels", () => {
    expect([0, 204, 304, 404, 503, 700].map(requestStatusClass)).toEqual(["network_error", "2xx", "3xx", "4xx", "5xx", "other"]);
  });

  it("productionRuntimeCompletesControlledCycle", async () => {
    const memory = newDb();
    memory.public.registerFunction({ name: "pg_advisory_xact_lock", args: [DataType.bigint], returns: DataType.bool, implementation: () => true });
    const adapter = memory.adapters.createPg();
    // pg-mem exposes a node-postgres-compatible pool without carrying its concrete type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    const pool: Pool = new adapter.Pool();
    const raw = await controlledCanary();
    const headSha = "d".repeat(40);
    const blobSha = "e".repeat(40);
    const bytes = new TextEncoder().encode(`AWS_SECRET_ACCESS_KEY=${raw}\n`);
    try {
      await runMigrations(pool);
      const config = readWorkerConfig({
        DATABASE_URL: "postgresql://breach@postgres/breach",
        GITHUB_TOKEN: "read-only-token",
        FINGERPRINT_HMAC_KEY: "production-runtime-fingerprint-key-32-bytes",
        DISCOVERY_MODE: "historical",
        DISCOVERY_START_CURSOR: "100",
        MAX_DISCOVERY_PAGES_PER_CYCLE: "1",
        MAX_DISCOVERY_REQUESTS_PER_CYCLE: "1",
      });
      const runtime = await createWorkerRuntime(config, pool, {
        now: () => new Date("2026-08-15T12:00:00.000Z"),
        nowMs: (() => { let tick = 0; return () => { tick += 1; return tick; }; })(),
        githubTransport: {
          get: (target) => {
            const url = new URL(target);
            const headers = { "x-ratelimit-remaining": "4999", "x-ratelimit-limit": "5000" };
            if (url.pathname === "/repositories") return Promise.resolve({ status: 200, headers, body: [{ id: 101, name: "payments-auth-api", full_name: "fixture/payments-auth-api", html_url: "https://github.com/fixture/payments-auth-api", description: "Cloud backend server deployed with Docker Kubernetes and Terraform", fork: false, owner: { type: "Organization" } }] });
            if (url.pathname.endsWith("/commits")) return Promise.resolve({ status: 200, headers, body: [{ sha: headSha }] });
            if (url.pathname.endsWith(`/git/trees/${headSha}`)) return Promise.resolve({ status: 200, headers, body: { tree: [{ path: ".env", type: "blob", sha: blobSha, size: bytes.byteLength }], truncated: false } });
            throw new Error("Unexpected controlled GitHub request");
          },
        },
        blobTransport: { async *stream() { yield await Promise.resolve(bytes); } },
        osvTransport: { queryBatch: ({ queries }) => Promise.resolve({ results: queries.map(() => ({})) }) },
      });

      await expect(runtime.runCycle()).resolves.toMatchObject({ nextCursor: 101, processed: 1, scansStarted: 1, quotaPaused: false });
      const candidate = await pool.query<{ candidate_state: string }>("SELECT candidate_state FROM repository_candidates WHERE repo_id = 101");
      expect(candidate.rows[0]?.candidate_state).toBe("SCANNED_FINDINGS");
      const database = JSON.stringify((await pool.query("SELECT payload FROM findings")).rows);
      expect(database).not.toContain(raw);
      expect(database).toContain("fingerprint");
      expect(runtime.quotaStatus()).toMatchObject({ remaining: 4999, limit: 5000, paused: false });
    } finally {
      bytes.fill(0);
      await pool.end();
    }
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

  it("canaryRawValueAbsentFromAllRuntimeSurfaces", async () => {
    const memory = newDb();
    memory.public.registerFunction({ name: "pg_advisory_xact_lock", args: [DataType.bigint], returns: DataType.bool, implementation: () => true });
    const adapter = memory.adapters.createPg();
    // pg-mem exposes a node-postgres-compatible pool without carrying its concrete type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    const pool: Pool = new adapter.Pool();
    const raw = await controlledCanary();
    try {
      await runMigrations(pool);
      const report = await runZeroRetentionCanary({
        pool,
        rawCanary: raw,
        fingerprintKey: "runtime-canary-fingerprint-key-32-bytes",
        now: () => new Date("2026-08-15T12:00:00.000Z"),
        collectExternalSurfaces: (finding) => Promise.resolve({
          webRenderedOutput: `<main>${finding.repository.fullName} ${finding.secretEvidence?.fingerprint.slice(0, 12) ?? ""}… Raw value NOT RETAINED</main>`,
          browserLocalStorage: "{}",
          browserSessionStorage: "{}",
        }),
      });

      expect(report.rawOccurrences).toBe(0);
      expect(report.fingerprintOccurrences).toBeGreaterThanOrEqual(1);
      expect(report.fingerprintOccurrences).toBeLessThanOrEqual(8);
      expect(report.ephemeralBytesCleared).toBe(true);
      expect(report.surfacesChecked).toEqual(expect.arrayContaining([
        "postgresql", "applicationLogs", "apiList", "apiDetail", "errorPaths",
        "webRenderedOutput", "browserLocalStorage", "browserSessionStorage",
      ]));
      expect(JSON.stringify(report)).not.toContain(raw);

      const samples = await pool.query<{ metric_name: string; metric_value: number }>(
        "SELECT metric_name, metric_value FROM metric_samples WHERE metric_name LIKE 'zero_retention.canary.%' ORDER BY metric_name",
      );
      expect(samples.rows.map((row) => [row.metric_name, row.metric_value])).toEqual([
        ["zero_retention.canary.fingerprint_occurrences", report.fingerprintOccurrences],
        ["zero_retention.canary.last_run", 1_786_795_200_000],
        ["zero_retention.canary.raw_occurrences", 0],
        ["zero_retention.canary.success", 1],
      ]);
      const durable = JSON.stringify((await pool.query("SELECT * FROM findings")).rows);
      expect(durable).not.toContain(raw);
      expect(durable).not.toContain("AWS_SECRET_ACCESS_KEY");
    } finally {
      await pool.end();
    }
  });
});
