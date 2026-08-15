import { randomUUID } from "node:crypto";
import { DataType, newDb } from "pg-mem";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { createMetadataStore, type MetadataStore } from "./index.js";
import { runMigrations } from "./migrations.js";

const incompleteCoverage = (headSha: string) => ({
  ref: `HEAD@${headSha}`,
  historyScanned: false as const,
  scanComplete: false,
  snapshotComplete: false,
  analysisComplete: false,
  analysisPartial: true,
  snapshotPartialReasons: ["blob_failed" as const],
  analysisPartialReasons: [],
  filesSeen: 0,
  filesEligible: 0,
  filesAnalyzed: 0,
  bytesInspected: 0,
  skippedBinary: 0,
  skippedGenerated: 0,
  skippedOversize: 0,
  skippedBudget: 0,
  skippedUnsupported: 0,
  treeTruncated: false,
  languagesModeled: [],
});

describe("metadata persistence seam", () => {
  let pool: Pool;
  let store: MetadataStore;

  beforeEach(async () => {
    const memory = newDb();
    memory.public.registerFunction({ name: "pg_advisory_xact_lock", args: [DataType.bigint], returns: DataType.bool, implementation: () => true });
    const adapter = memory.adapters.createPg();
    // pg-mem intentionally exposes a node-postgres-compatible constructor without a safe type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    pool = new adapter.Pool();
    await runMigrations(pool);
    store = await createMetadataStore(pool);
  });

  afterEach(async () => {
    await pool.end();
  });

  it("records a discovery page before advancing its exclusive cursor", async () => {
    await store.recordDiscoveryPage("public-repositories", 102, [
      {
        repoId: 100,
        fullName: "fixture/capacity",
        htmlUrl: "https://github.com/fixture/capacity",
        discoveredAt: new Date("2026-08-12T11:59:59.000Z"),
        priorityScore: 6,
        candidateState: "SKIPPED",
        selectionReason: "capacity",
      },
      {
        repoId: 101,
        fullName: "fixture/one",
        htmlUrl: "https://github.com/fixture/one",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 7,
        candidateState: "WAITING_FOR_COMMIT",
        selectionReason: "selected",
      },
      {
        repoId: 102,
        fullName: "fixture/two",
        htmlUrl: "https://github.com/fixture/two",
        discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
        priorityScore: 1,
        candidateState: "SKIPPED",
        selectionReason: "score",
      },
    ]);

    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(102);
    await expect(store.getCandidate(101)).resolves.toMatchObject({
      fullName: "fixture/one",
      candidateState: "WAITING_FOR_COMMIT",
      selectionReason: "selected",
    });
    await expect(store.getCandidate(100)).resolves.toMatchObject({ selectionReason: "capacity" });
    await expect(store.getMetricSamples("candidates.discovered")).resolves.toMatchObject([{ value: 3 }]);
    await expect(store.getMetricSamples("candidates.eligible")).resolves.toMatchObject([{ value: 2 }]);
    await expect(store.getMetricSamples("candidates.selected")).resolves.toMatchObject([{ value: 1 }]);
    await expect(store.getMetricSamples("candidates.skipped_capacity")).resolves.toMatchObject([{ value: 1 }]);
    await expect(store.getMetricSamples("candidates.skipped_score")).resolves.toMatchObject([{ value: 1 }]);
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
          selectionReason: "selected",
        },
        {
          repoId: 52,
          fullName: "",
          htmlUrl: "https://github.com/fixture/invalid",
          discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
          priorityScore: 5,
          candidateState: "WAITING_FOR_COMMIT",
          selectionReason: "selected",
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
        selectionReason: "selected",
      },
    ]);

    await expect(store.transitionCandidate(201, "READY")).resolves.toMatchObject({
      candidateState: "READY",
    });
    await expect(store.transitionCandidate(201, "SCANNED_FINDINGS")).rejects.toThrow(
      "Illegal candidate transition",
    );
  });

  it("rateLimitedCandidateRecoversAfterDeadline", async () => {
    const retryAt = new Date("2026-08-15T10:05:00.000Z");
    await store.recordDiscoveryPage("public-repositories", 211, [{ repoId: 211, fullName: "fixture/rate-limited", htmlUrl: "https://github.com/fixture/rate-limited", discoveredAt: new Date("2026-08-15T10:00:00.000Z"), priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);

    await store.rateLimitCandidate(211, retryAt, 2);
    await expect(store.getCandidate(211)).resolves.toMatchObject({ candidateState: "RATE_LIMITED", nextCommitCheckAt: retryAt, commitCheckAttempts: 2 });
    await expect(store.releaseDueRateLimits(new Date("2026-08-15T10:04:59.999Z"))).resolves.toBe(0);
    await expect(store.getCandidate(211)).resolves.toMatchObject({ candidateState: "RATE_LIMITED" });
    await expect(store.releaseDueRateLimits(retryAt)).resolves.toBe(1);
    await expect(store.getCandidate(211)).resolves.toMatchObject({ candidateState: "WAITING_FOR_COMMIT", nextCommitCheckAt: null });
  });

  it("initialDiscoveryWritesLifecycleEvents", async () => {
    await store.recordDiscoveryPage("public-repositories", 221, [{ repoId: 221, fullName: "fixture/events", htmlUrl: "https://github.com/fixture/events", discoveredAt: new Date("2026-08-15T10:00:00.000Z"), priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);

    await expect(store.getStateEvents(221)).resolves.toMatchObject([
      { fromState: null, toState: "DISCOVERED" },
      { fromState: "DISCOVERED", toState: "WAITING_FOR_COMMIT" },
    ]);
    await store.recordDiscoveryPage("public-repositories", 221, [{ repoId: 221, fullName: "fixture/events", htmlUrl: "https://github.com/fixture/events", discoveredAt: new Date("2026-08-15T10:00:00.000Z"), priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
    await expect(store.getStateEvents(221)).resolves.toHaveLength(2);
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

    const dependencyFinding = {
      ...safeFinding,
      findingId: randomUUID(),
      category: "vulnerable_dependency",
      severity: "high" as const,
      confidence: 1,
      dependencyEvidence: { ecosystem: "npm", packageName: "lodash", version: "4.17.20", advisoryId: "GHSA-FAKE-1234", manifestPath: "package-lock.json" },
      secretEvidence: undefined,
    } as unknown as Parameters<MetadataStore["saveFinding"]>[0];
    await store.saveFinding(dependencyFinding);
    await expect(store.getFinding(dependencyFinding.findingId)).resolves.toMatchObject({ dependencyEvidence: { packageName: "lodash", advisoryId: "GHSA-FAKE-1234" } });
  });

  it("reviewPersistsInPostgresWithoutEchoingNote", async () => {
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

    const reviewed = await store.reviewFinding(findingId, "CONFIRMED", "Path verified on GitHub.");
    expect(reviewed.reviewState).toBe("CONFIRMED");
    expect(reviewed).not.toHaveProperty("reviewNote");
    await expect(store.getFinding(findingId)).resolves.toMatchObject({ reviewState: "CONFIRMED" });
    const storedReview = await pool.query<{ review_state: string; review_note: string }>(
      "SELECT review_state, review_note FROM finding_reviews WHERE finding_id = $1",
      [findingId],
    );
    expect(storedReview.rows).toEqual([{ review_state: "CONFIRMED", review_note: "Path verified on GitHub." }]);
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
        selectionReason: "selected",
      },
    ]);
    const headSha = "d".repeat(40);
    const startedAt = new Date("2026-08-12T12:01:00.000Z");
    const coverage = {
      ref: `HEAD@${headSha}`,
      historyScanned: false as const,
      scanComplete: true,
      snapshotComplete: true,
      analysisComplete: true,
      analysisPartial: false,
      snapshotPartialReasons: [],
      analysisPartialReasons: [],
      filesSeen: 2,
      filesEligible: 2,
      filesAnalyzed: 2,
      bytesInspected: 42,
      skippedBinary: 0,
      skippedGenerated: 0,
      skippedOversize: 0,
      skippedBudget: 0,
      skippedUnsupported: 0,
      treeTruncated: false,
      languagesModeled: ["typescript" as const],
    };

    const claims = await Promise.all([
      store.claimScan(501, headSha, startedAt),
      store.claimScan(501, headSha, startedAt),
    ]);
    expect(claims.filter(Boolean)).toHaveLength(1);
    await expect(store.getCandidate(501)).resolves.toMatchObject({ candidateState: "SCANNING", firstCommitDetectedAt: startedAt, headSha });
    await expect(store.getStateEvents(501)).resolves.toMatchObject([
      { fromState: null, toState: "DISCOVERED" },
      { fromState: "DISCOVERED", toState: "WAITING_FOR_COMMIT" },
      { fromState: "WAITING_FOR_COMMIT", toState: "READY", reasonCode: "commit_observed" },
      { fromState: "READY", toState: "SCANNING", reasonCode: "scan_started" },
    ]);
    await store.completeScan(501, headSha, "SCANNED_NO_FINDINGS", coverage);
    await store.recordMetric("scan.completed", 1, { status: "SCANNED_NO_FINDINGS" });

    await expect(store.getScan(501, headSha)).resolves.toMatchObject({
      state: "SCANNED_NO_FINDINGS",
      coverage,
    });
    await expect(store.getCandidate(501)).resolves.toMatchObject({ candidateState: "SCANNED_NO_FINDINGS", lastScanStatus: "SCANNED_NO_FINDINGS" });
    await expect(store.getMetricSamples("scan.completed")).resolves.toEqual([
      { value: 1, labels: { status: "SCANNED_NO_FINDINGS" } },
    ]);
  });

  it("persists a safe reason and terminal coverage for a failed claimed scan", async () => {
    const repoId = 502;
    const headSha = "e".repeat(40);
    const startedAt = new Date("2026-08-12T12:02:00.000Z");
    await store.recordDiscoveryPage("public-repositories", repoId, [{ repoId, fullName: "fixture/failed-scan", htmlUrl: "https://github.com/fixture/failed-scan", discoveredAt: startedAt, priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
    await expect(store.claimScan(repoId, headSha, startedAt)).resolves.toBe(true);
    const coverage = {
      ref: `HEAD@${headSha}`,
      historyScanned: false as const,
      scanComplete: false,
      snapshotComplete: false,
      analysisComplete: false,
      analysisPartial: true,
      snapshotPartialReasons: ["blob_failed" as const],
      analysisPartialReasons: [],
      filesSeen: 0,
      filesEligible: 0,
      filesAnalyzed: 0,
      bytesInspected: 0,
      skippedBinary: 0,
      skippedGenerated: 0,
      skippedOversize: 0,
      skippedBudget: 0,
      skippedUnsupported: 0,
      treeTruncated: false,
      languagesModeled: [],
    };

    await store.completeScan(repoId, headSha, "FAILED", coverage, "blob_failed");

    await expect(store.getScan(repoId, headSha)).resolves.toEqual({ state: "FAILED", coverage, failureReasonCode: "blob_failed" });
    await expect(store.getCandidate(repoId)).resolves.toMatchObject({ candidateState: "FAILED", lastScanStatus: "FAILED", lifecycleReasonCode: "blob_failed" });
    await expect(store.getStateEvents(repoId)).resolves.toContainEqual(expect.objectContaining({ fromState: "SCANNING", toState: "FAILED", reasonCode: "blob_failed" }));
  });

  it("differentiates every bounded partial-scan reason", async () => {
    const cases = [
      { reason: "analysis_timeout", snapshotReasons: [], analysisReasons: ["timeout"], snapshotComplete: true, analysisComplete: false },
      { reason: "tree_truncated", snapshotReasons: ["tree_truncated"], analysisReasons: [], snapshotComplete: false, analysisComplete: true },
      { reason: "blob_oversize", snapshotReasons: ["oversized_files_excluded"], analysisReasons: [], snapshotComplete: false, analysisComplete: true },
      { reason: "budget_exhausted", snapshotReasons: ["repository_byte_budget_exhausted"], analysisReasons: [], snapshotComplete: false, analysisComplete: true },
      { reason: "scan_partial", snapshotReasons: ["binary_files_excluded"], analysisReasons: [], snapshotComplete: false, analysisComplete: true },
    ] as const;
    for (const [index, item] of cases.entries()) {
      const repoId = 520 + index;
      const headSha = String(index + 1).repeat(40);
      const startedAt = new Date(`2026-08-12T12:0${String(index)}:00.000Z`);
      await store.recordDiscoveryPage("public-repositories", repoId, [{ repoId, fullName: `fixture/partial-${String(index)}`, htmlUrl: `https://github.com/fixture/partial-${String(index)}`, discoveredAt: startedAt, priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
      await store.claimScan(repoId, headSha, startedAt);
      const coverage = {
        ref: `HEAD@${headSha}`,
        historyScanned: false as const,
        scanComplete: false,
        snapshotComplete: item.snapshotComplete,
        analysisComplete: item.analysisComplete,
        analysisPartial: !item.analysisComplete,
        snapshotPartialReasons: [...item.snapshotReasons],
        analysisPartialReasons: [...item.analysisReasons],
        filesSeen: 1,
        filesEligible: 1,
        filesAnalyzed: 1,
        bytesInspected: 1,
        skippedBinary: item.reason === "scan_partial" ? 1 : 0,
        skippedGenerated: 0,
        skippedOversize: item.reason === "blob_oversize" ? 1 : 0,
        skippedBudget: item.reason === "budget_exhausted" ? 1 : 0,
        skippedUnsupported: 0,
        treeTruncated: item.reason === "tree_truncated",
        languagesModeled: [],
      };
      await store.completeScan(repoId, headSha, "PARTIAL", coverage);
      await expect(store.getStateEvents(repoId)).resolves.toContainEqual(expect.objectContaining({ fromState: "SCANNING", toState: "PARTIAL", reasonCode: item.reason }));
    }
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
    await expect(store.recordDiscoveryPage("public-repositories", 1, [{ repoId: 1, fullName: "fixture/mismatch", htmlUrl: "https://github.com/fixture/mismatch", discoveredAt: new Date(), priorityScore: 90, candidateState: "WAITING_FOR_COMMIT", selectionReason: "score" }])).rejects.toThrow("does not match");
    await expect(store.getDiscoveryCursor("missing")).resolves.toBeNull();
    await expect(store.transitionCandidate(999, "READY")).rejects.toThrow("does not exist");
    await expect(store.reviewFinding(randomUUID(), "CONFIRMED")).rejects.toThrow("does not exist");
    await expect(store.scheduleCommitCheck(1, new Date("invalid"), -1, "empty_repo")).rejects.toThrow("Invalid commit recheck");
    await expect(store.claimScan(1, "bad", new Date("invalid"))).rejects.toThrow("Invalid scan claim");
    await expect(store.getScan(1, "e".repeat(40))).resolves.toBeNull();
    const missingHead = "e".repeat(40);
    await expect(store.completeScan(1, missingHead, "SCANNING", incompleteCoverage(missingHead))).rejects.toThrow("Invalid terminal scan state");
    await expect(store.completeScan(1, missingHead, "FAILED", incompleteCoverage(missingHead))).rejects.toThrow("requires a reason code");
    await expect(store.completeScan(1, missingHead, "FAILED", incompleteCoverage(missingHead), "blob_failed")).rejects.toThrow("Claimed scan does not exist");
    for (const [name, value, labels] of [["INVALID", 1, {}], ["valid.metric", Number.NaN, {}], ["valid.metric", 1, { "Bad-Key": "x" }], ["valid.metric", 1, { safe: "x".repeat(81) }]] as const) {
      await expect(store.recordMetric(name, value, labels)).rejects.toThrow();
    }
  });

  it("supports note-free reviews, scheduling, alias transitions, batches, and label fallback", async () => {
    const repoId = 601;
    await store.recordDiscoveryPage("public-repositories", repoId, [{ repoId, fullName: "fixture/edges", htmlUrl: "https://github.com/fixture/edges", discoveredAt: new Date("2026-08-12T12:00:00.000Z"), priorityScore: 1, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
    await store.scheduleCommitCheck(repoId, new Date("2026-08-12T12:05:00.000Z"), 2, "empty_repo");
    await expect(store.getCandidate(repoId)).resolves.toMatchObject({ commitCheckAttempts: 2, lifecycleReasonCode: "empty_repo" });
    await expect(store.getStateEvents(repoId)).resolves.toEqual(expect.arrayContaining([expect.objectContaining({ fromState: "WAITING_FOR_COMMIT", toState: "WAITING_FOR_COMMIT", reasonCode: "empty_repo" })]));
    await store.transition(repoId, "READY");
    const findingId = randomUUID();
    await store.saveFindings([{ findingId, detectedAt: "2026-08-12T12:00:00.000Z", repository: { id: repoId, fullName: "fixture/edges", url: "https://github.com/fixture/edges" }, revision: { ref: "HEAD", sha: "f".repeat(40) }, category: "configuration", severity: "medium", confidence: .8, reviewState: "UNREVIEWED" }]);
    await expect(store.reviewFinding(findingId, "UNCERTAIN")).resolves.not.toHaveProperty("reviewNote");
    await pool.query("INSERT INTO metric_samples(metric_name, measured_at, metric_value, labels) VALUES ('label.fallback', CURRENT_TIMESTAMP, 1, 'null')");
    await expect(store.getMetricSamples("label.fallback")).resolves.toEqual([{ value: 1, labels: {} }]);
  });
});
