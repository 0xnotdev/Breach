import { describe, expect, it } from "vitest";
import {
  candidateSelectionReasonSchema,
  candidateStateSchema,
  classifyExploitabilityLevel,
  coverageSchema,
  exploitabilitySchema,
  reviewStateSchema,
  sanitizedFindingSchema,
} from "./index.js";

describe("public metadata contracts", () => {
  it("accepts every pipeline state exposed to operators", () => {
    const states = [
      "DISCOVERED",
      "SKIPPED",
      "WAITING_FOR_COMMIT",
      "READY",
      "SCANNING",
      "SCANNED_NO_FINDINGS",
      "SCANNED_FINDINGS",
      "PARTIAL",
      "FAILED",
      "RATE_LIMITED",
    ];

    expect(states.map((state) => candidateStateSchema.parse(state))).toEqual(states);
  });

  it("accepts only sanitized candidate admission reasons", () => {
    const reasons = ["selected", "score", "capacity"];
    expect(reasons.map((reason) => candidateSelectionReasonSchema.parse(reason))).toEqual(reasons);
    expect(() => candidateSelectionReasonSchema.parse("repo_id_bucket")).toThrow();
  });

  it("rejects a raw secret at the finding seam", () => {
    const unsafe = {
      findingId: "018f47d5-8eb7-7a32-a20b-6f7f4af90d45",
      detectedAt: "2026-08-12T12:00:00.000Z",
      repository: {
        id: 123456789,
        fullName: "fixture/repository",
        url: "https://github.com/fixture/repository",
      },
      revision: { ref: "main", sha: "a".repeat(40) },
      category: "secret_exposure",
      cwe: "CWE-798",
      severity: "critical",
      confidence: 0.98,
      secret: "CANARY_DO_NOT_PERSIST_123456",
    };

    expect(() => sanitizedFindingSchema.parse(unsafe)).toThrow();
  });

  it("represents honest partial HEAD-only coverage", () => {
    const coverage = coverageSchema.parse({
      ref: "main@abc123",
      historyScanned: false,
      scanComplete: false,
      filesSeen: 381,
      filesAnalyzed: 224,
      bytesInspected: 2_817_734,
      skippedBinary: 102,
      skippedOversize: 4,
      treeTruncated: true,
      languagesModeled: ["typescript"],
    });

    expect(coverage.historyScanned).toBe(false);
    expect(coverage.scanComplete).toBe(false);
  });

  it("keeps static exploitability separate from runtime proof", () => {
    const result = exploitabilitySchema.parse({
      score: 94,
      level: "high_confidence_static_path",
      attackerSourceIdentified: true,
      completeDataflowObserved: true,
      sanitizerObserved: false,
      authBarrierObserved: false,
      runtimeVerified: false,
      activeTestingPerformed: false,
      deploymentConfirmed: false,
    });

    expect(result.level).toBe("high_confidence_static_path");
    expect(result.runtimeVerified).toBe(false);
  });

  it("allows only the validation MVP review decisions", () => {
    expect(
      ["UNREVIEWED", "CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"].map((state) =>
        reviewStateSchema.parse(state),
      ),
    ).toEqual(["UNREVIEWED", "CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"]);
    expect(() => reviewStateSchema.parse("FIXED")).toThrow();
  });

  it("maps worked score boundaries to the specified static evidence tiers", () => {
    expect([0, 39].map(classifyExploitabilityLevel)).toEqual(["possible", "possible"]);
    expect([40, 69].map(classifyExploitabilityLevel)).toEqual(["plausible", "plausible"]);
    expect([70, 89].map(classifyExploitabilityLevel)).toEqual(["probable", "probable"]);
    expect([90, 100].map(classifyExploitabilityLevel)).toEqual([
      "high_confidence_static_path",
      "high_confidence_static_path",
    ]);
    expect(() => classifyExploitabilityLevel(101)).toThrow("between 0 and 100");
  });
});
