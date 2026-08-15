import { randomUUID } from "node:crypto";
import { newDb } from "pg-mem";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { createMetadataStore, type MetadataStore } from "./index.js";

describe("metadata persistence seam", () => {
  let pool: Pool;
  let store: MetadataStore;

  beforeEach(async () => {
    const memory = newDb();
    const adapter = memory.adapters.createPg();
    // pg-mem intentionally exposes a node-postgres-compatible constructor without a safe type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    pool = new adapter.Pool();
    store = await createMetadataStore(pool);
  });

  afterEach(async () => {
    await pool.end();
  });

  it("records a discovery page before advancing its exclusive cursor", async () => {
    await store.recordDiscoveryPage("public-repositories", 102, [
      {
        repoId: 101,
        fullName: "fixture/one",
        htmlUrl: "https://github.com/fixture/one",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 7,
        candidateState: "WAITING_FOR_COMMIT",
      },
      {
        repoId: 102,
        fullName: "fixture/two",
        htmlUrl: "https://github.com/fixture/two",
        discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
        priorityScore: 1,
        candidateState: "SKIPPED",
      },
    ]);

    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(102);
    await expect(store.getCandidate(101)).resolves.toMatchObject({
      fullName: "fixture/one",
      candidateState: "WAITING_FOR_COMMIT",
    });
  });

  it("freshDatabaseBootstrapsAtCurrentFrontier", async () => {
    const bootstrappedAt = new Date("2026-08-15T10:00:00.000Z");

    await expect(
      store.bootstrapDiscovery("public-repositories", 120_004, bootstrappedAt),
    ).resolves.toEqual({ cursor: 120_004, bootstrappedAt });
    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(120_004);
    await expect(store.getCandidate(120_003)).resolves.toBeNull();
    await expect(store.getMetricSamples("discovery.bootstrap.repo_id")).resolves.toEqual([
      { value: 120_004, labels: { stream: "public-repositories" } },
    ]);
    await expect(store.getMetricSamples("discovery.bootstrap.timestamp")).resolves.toEqual([
      { value: bootstrappedAt.getTime(), labels: { stream: "public-repositories" } },
    ]);

    const laterAttempt = new Date("2026-08-15T11:00:00.000Z");
    await expect(
      store.bootstrapDiscovery("public-repositories", 999_999, laterAttempt),
    ).resolves.toEqual({ cursor: 120_004, bootstrappedAt });
    await expect(store.getMetricSamples("discovery.bootstrap.repo_id")).resolves.toHaveLength(1);
  });

  it("does not advance the cursor when a page cannot be fully recorded", async () => {
    await store.recordDiscoveryPage("public-repositories", 50, []);

    await expect(
      store.recordDiscoveryPage("public-repositories", 52, [
        {
          repoId: 51,
          fullName: "fixture/valid",
          htmlUrl: "https://github.com/fixture/valid",
          discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
          priorityScore: 5,
          candidateState: "WAITING_FOR_COMMIT",
        },
        {
          repoId: 52,
          fullName: "",
          htmlUrl: "https://github.com/fixture/invalid",
          discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
          priorityScore: 5,
          candidateState: "WAITING_FOR_COMMIT",
        },
      ]),
    ).rejects.toThrow();

    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(50);
    await expect(store.getCandidate(51)).resolves.toBeNull();
  });

  it("allows only public lifecycle transitions", async () => {
    await store.recordDiscoveryPage("public-repositories", 201, [
      {
        repoId: 201,
        fullName: "fixture/stateful",
        htmlUrl: "https://github.com/fixture/stateful",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 8,
        candidateState: "WAITING_FOR_COMMIT",
      },
    ]);

    await expect(store.transitionCandidate(201, "READY")).resolves.toMatchObject({
      candidateState: "READY",
    });
    await expect(store.transitionCandidate(201, "SCANNED_FINDINGS")).rejects.toThrow(
      "Illegal candidate transition",
    );
  });

  it("round-trips sanitized findings and rejects forbidden raw fields", async () => {
    const safeFinding = {
      findingId: randomUUID(),
      detectedAt: "2026-08-12T12:00:00.000Z",
      repository: {
        id: 301,
        fullName: "fixture/finding",
        url: "https://github.com/fixture/finding",
      },
      revision: { ref: "main", sha: "a".repeat(40) },
      category: "secret_exposure",
      cwe: "CWE-798",
      severity: "critical" as const,
      confidence: 0.98,
      secretEvidence: {
        type: "Fake canary credential",
        path: ".env",
        line: 1,
        fingerprint: "b".repeat(64),
      },
      reviewState: "UNREVIEWED" as const,
    };

    await store.saveFinding(safeFinding);
    await expect(store.getFinding(safeFinding.findingId)).resolves.toEqual(safeFinding);
    const unsafeFinding = {
      ...safeFinding,
      findingId: randomUUID(),
      rawSecret: "CANARY_RAW",
    } as unknown as Parameters<MetadataStore["saveFinding"]>[0];
    await expect(
      store.saveFinding(unsafeFinding),
    ).rejects.toThrow();
  });

  it("stores only validation review states and non-sensitive notes", async () => {
    const findingId = randomUUID();
    await store.saveFinding({
      findingId,
      detectedAt: "2026-08-12T12:00:00.000Z",
      repository: {
        id: 401,
        fullName: "fixture/review",
        url: "https://github.com/fixture/review",
      },
      revision: { ref: "main", sha: "c".repeat(40) },
      category: "command_injection",
      cwe: "CWE-78",
      severity: "critical",
      confidence: 0.96,
      reviewState: "UNREVIEWED",
    });

    await expect(store.reviewFinding(findingId, "CONFIRMED", "Path verified on GitHub.")).resolves.toMatchObject({
      reviewState: "CONFIRMED",
      reviewNote: "Path verified on GitHub.",
    });
    await expect(
      store.reviewFinding(findingId, "FALSE_POSITIVE", "AWS_SECRET_ACCESS_KEY=CANARY_RAW"),
    ).rejects.toThrow("sensitive content");
  });

  it("claims each committed HEAD once and records content-free scan telemetry", async () => {
    await store.recordDiscoveryPage("public-repositories", 501, [
      {
        repoId: 501,
        fullName: "fixture/lifecycle",
        htmlUrl: "https://github.com/fixture/lifecycle",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 8,
        candidateState: "WAITING_FOR_COMMIT",
      },
    ]);
    const headSha = "d".repeat(40);
    const startedAt = new Date("2026-08-12T12:01:00.000Z");
    const coverage = {
      ref: `HEAD@${headSha}`,
      historyScanned: false as const,
      scanComplete: true,
      filesSeen: 2,
      filesAnalyzed: 2,
      bytesInspected: 42,
      skippedBinary: 0,
      skippedOversize: 0,
      skippedBudget: 0,
      treeTruncated: false,
      languagesModeled: ["typescript" as const],
    };

    await expect(store.claimScan(501, headSha, startedAt)).resolves.toBe(true);
    await expect(store.claimScan(501, headSha, startedAt)).resolves.toBe(false);
    await store.completeScan(501, headSha, "SCANNED_NO_FINDINGS", coverage);
    await store.recordMetric("scan.completed", 1, { status: "SCANNED_NO_FINDINGS" });

    await expect(store.getScan(501, headSha)).resolves.toMatchObject({
      state: "SCANNED_NO_FINDINGS",
      coverage,
    });
    await expect(store.getMetricSamples("scan.completed")).resolves.toEqual([
      { value: 1, labels: { status: "SCANNED_NO_FINDINGS" } },
    ]);
  });

  it("rejects malformed lifecycle, review, scan, schedule, and metric inputs", async () => {
    for (const [stream, cursor, at] of [
      ["", 1, new Date()],
      ["public-repositories", 0, new Date()],
      ["public-repositories", 1.5, new Date()],
      ["public-repositories", 1, new Date("invalid")],
    ] as const) {
      await expect(store.bootstrapDiscovery(stream, cursor, at)).rejects.toThrow(
        "Invalid discovery bootstrap",
      );
    }
    await expect(store.recordDiscoveryPage("", -1, [])).rejects.toThrow("Invalid discovery cursor");
    await expect(store.getDiscoveryCursor("missing")).resolves.toBeNull();
    await expect(store.transitionCandidate(999, "READY")).rejects.toThrow("does not exist");
    await expect(store.reviewFinding(randomUUID(), "CONFIRMED")).rejects.toThrow("does not exist");
    await expect(store.scheduleCommitCheck(1, new Date("invalid"), -1)).rejects.toThrow("Invalid commit recheck");
    await expect(store.claimScan(1, "bad", new Date("invalid"))).rejects.toThrow("Invalid scan claim");
    await expect(store.getScan(1, "e".repeat(40))).resolves.toBeNull();
    for (const [name, value, labels] of [["INVALID", 1, {}], ["valid.metric", Number.NaN, {}], ["valid.metric", 1, { "Bad-Key": "x" }], ["valid.metric", 1, { safe: "x".repeat(81) }]] as const) {
      await expect(store.recordMetric(name, value, labels)).rejects.toThrow();
    }
  });

  it("supports note-free reviews, scheduling, alias transitions, batches, and label fallback", async () => {
    const repoId = 601;
    await store.recordDiscoveryPage("public-repositories", repoId, [{ repoId, fullName: "fixture/edges", htmlUrl: "https://github.com/fixture/edges", discoveredAt: new Date("2026-08-12T12:00:00.000Z"), priorityScore: 1, candidateState: "WAITING_FOR_COMMIT" }]);
    await store.scheduleCommitCheck(repoId, new Date("2026-08-12T12:05:00.000Z"), 2);
    await store.transition(repoId, "READY");
    const findingId = randomUUID();
    await store.saveFindings([{ findingId, detectedAt: "2026-08-12T12:00:00.000Z", repository: { id: repoId, fullName: "fixture/edges", url: "https://github.com/fixture/edges" }, revision: { ref: "HEAD", sha: "f".repeat(40) }, category: "configuration", severity: "medium", confidence: .8, reviewState: "UNREVIEWED" }]);
    await expect(store.reviewFinding(findingId, "UNCERTAIN")).resolves.not.toHaveProperty("reviewNote");
    await pool.query("INSERT INTO metric_samples(metric_name, measured_at, metric_value, labels) VALUES ('label.fallback', CURRENT_TIMESTAMP, 1, 'null')");
    await expect(store.getMetricSamples("label.fallback")).resolves.toEqual([{ value: 1, labels: {} }]);
  });
});
