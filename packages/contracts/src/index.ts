import { z } from "zod";

export const candidateStateSchema = z.enum([
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
]);

export type CandidateState = z.infer<typeof candidateStateSchema>;

export const candidateTransitionGraph: Readonly<Record<CandidateState, readonly CandidateState[]>> = {
  DISCOVERED: ["SKIPPED", "WAITING_FOR_COMMIT"],
  SKIPPED: [],
  WAITING_FOR_COMMIT: ["READY", "FAILED", "RATE_LIMITED"],
  READY: ["SCANNING", "FAILED"],
  SCANNING: ["SCANNED_NO_FINDINGS", "SCANNED_FINDINGS", "PARTIAL", "FAILED"],
  SCANNED_NO_FINDINGS: [],
  SCANNED_FINDINGS: [],
  PARTIAL: [],
  FAILED: [],
  RATE_LIMITED: ["WAITING_FOR_COMMIT", "FAILED"],
};

export const terminalCandidateStates = ["SKIPPED", "SCANNED_NO_FINDINGS", "SCANNED_FINDINGS", "PARTIAL", "FAILED"] as const satisfies readonly CandidateState[];

export function canTransitionCandidate(from: CandidateState, to: CandidateState): boolean {
  return candidateTransitionGraph[from].includes(to);
}

export const candidateSelectionReasonSchema = z.enum(["selected", "score", "capacity"]);

export const lifecycleReasonCodeSchema = z.enum([
  "repository_discovered",
  "candidate_not_admitted",
  "commit_gate_pending",
  "commit_observed",
  "scan_started",
  "scan_completed_no_findings",
  "scan_completed_findings",
  "scan_partial",
  "scan_failed",
  "empty_repo",
  "github_rate_limited",
  "github_unavailable",
  "repo_gone",
  "tree_failed",
  "tree_truncated",
  "blob_failed",
  "blob_oversize",
  "budget_exhausted",
  "parser_failed",
  "analysis_timeout",
  "database_failed",
]);

export const reviewStateSchema = z.enum([
  "UNREVIEWED",
  "CONFIRMED",
  "FALSE_POSITIVE",
  "UNCERTAIN",
]);

export const severitySchema = z.enum(["critical", "high", "medium", "low"]);

export const exploitabilityLevelSchema = z.enum([
  "possible",
  "plausible",
  "probable",
  "high_confidence_static_path",
]);

export const snapshotPartialReasonSchema = z.enum([
  "tree_truncated",
  "binary_files_excluded",
  "generated_files_excluded",
  "oversized_files_excluded",
  "unsupported_files_excluded",
  "file_count_budget_exhausted",
  "repository_byte_budget_exhausted",
  "wall_clock_budget_exhausted",
  "tree_failed",
  "blob_failed",
]);

export const analysisPartialReasonSchema = z.enum([
  "file_limit",
  "timeout",
  "graph_node_limit",
  "graph_depth_limit",
  "parser_failed",
]);

export type ExploitabilityLevel = z.infer<typeof exploitabilityLevelSchema>;

export function classifyExploitabilityLevel(score: number): ExploitabilityLevel {
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new RangeError("Exploitability score must be between 0 and 100");
  }

  if (score >= 90) return "high_confidence_static_path";
  if (score >= 70) return "probable";
  if (score >= 40) return "plausible";
  return "possible";
}

export const coverageSchema = z
  .object({
    ref: z.string().min(1).max(255),
    historyScanned: z.literal(false),
    scanComplete: z.boolean(),
    snapshotComplete: z.boolean(),
    analysisComplete: z.boolean(),
    analysisPartial: z.boolean(),
    snapshotPartialReasons: z.array(snapshotPartialReasonSchema),
    analysisPartialReasons: z.array(analysisPartialReasonSchema),
    filesSeen: z.number().int().nonnegative(),
    filesEligible: z.number().int().nonnegative(),
    filesAnalyzed: z.number().int().nonnegative(),
    bytesInspected: z.number().int().nonnegative(),
    skippedBinary: z.number().int().nonnegative(),
    skippedGenerated: z.number().int().nonnegative(),
    skippedOversize: z.number().int().nonnegative(),
    skippedBudget: z.number().int().nonnegative().default(0),
    skippedUnsupported: z.number().int().nonnegative(),
    treeTruncated: z.boolean(),
    languagesModeled: z.array(z.enum(["javascript", "typescript", "python"])),
  })
  .strict()
  .refine((value) => value.filesEligible <= value.filesSeen, {
    message: "Eligible file count cannot exceed files seen",
    path: ["filesEligible"],
  })
  .refine((value) => value.filesAnalyzed <= value.filesEligible, {
    message: "Analyzed file count cannot exceed eligible files",
    path: ["filesAnalyzed"],
  })
  .refine((value) => value.analysisPartial === !value.analysisComplete, {
    message: "Analysis partial flag must match analysis completeness",
    path: ["analysisPartial"],
  })
  .refine((value) => value.scanComplete === (value.snapshotComplete && value.analysisComplete), {
    message: "Scan completeness must combine snapshot and analysis completeness",
    path: ["scanComplete"],
  });

export const exploitabilitySchema = z
  .object({
    score: z.number().int().min(0).max(100),
    level: exploitabilityLevelSchema,
    attackerSourceIdentified: z.boolean(),
    completeDataflowObserved: z.boolean(),
    sanitizerObserved: z.boolean(),
    authBarrierObserved: z.boolean(),
    runtimeVerified: z.literal(false),
    activeTestingPerformed: z.literal(false),
    deploymentConfirmed: z.literal(false),
  })
  .strict();

export const semanticPathNodeSchema = z
  .object({
    file: z.string().min(1).max(1_024),
    line: z.number().int().positive(),
    role: z.enum(["entry", "source", "flow", "sanitizer", "auth", "sink"]),
    symbol: z.string().min(1).max(255).optional(),
    edge: z.enum(["route", "argument", "return", "call", "assignment"]).optional(),
  })
  .strict();

export const secretEvidenceSchema = z
  .object({
    type: z.string().min(1).max(120),
    provider: z.string().min(1).max(120).optional(),
    path: z.string().min(1).max(1_024),
    line: z.number().int().positive(),
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/iu),
  })
  .strict();

export const dependencyEvidenceSchema = z
  .object({
    ecosystem: z.string().min(1).max(64),
    packageName: z.string().min(1).max(255),
    version: z.string().min(1).max(128),
    advisoryId: z.string().min(1).max(160),
    manifestPath: z.string().min(1).max(1_024),
    advisorySummary: z.string().min(1).max(280).optional(),
  })
  .strict();

export const configEvidenceSchema = z
  .object({
    ruleId: z.string().regex(/^[a-z][a-z0-9_.]*$/u).max(160),
    path: z.string().min(1).max(1_024),
    line: z.number().int().positive(),
    rationale: z.string().min(1).max(280),
    staticOnly: z.literal(true),
  })
  .strict();

export const sanitizedFindingSchema = z
  .object({
    findingId: z.uuid(),
    detectedAt: z.iso.datetime({ offset: true }),
    repository: z
      .object({
        id: z.number().int().positive(),
        fullName: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
        url: z.url().startsWith("https://github.com/"),
      })
      .strict(),
    revision: z
      .object({
        ref: z.string().min(1).max(255),
        sha: z.string().regex(/^[a-f0-9]{7,64}$/iu),
      })
      .strict(),
    category: z.string().regex(/^[a-z][a-z0-9_]*$/u),
    cwe: z.string().regex(/^CWE-\d+$/u).optional(),
    severity: severitySchema,
    confidence: z.number().min(0).max(1),
    exploitability: exploitabilitySchema.optional(),
    coverage: coverageSchema.optional(),
    secretEvidence: secretEvidenceSchema.optional(),
    dependencyEvidence: dependencyEvidenceSchema.optional(),
    configEvidence: configEvidenceSchema.optional(),
    path: z.array(semanticPathNodeSchema).max(256).optional(),
    reviewState: reviewStateSchema.default("UNREVIEWED"),
  })
  .strict();

export type CandidateSelectionReason = z.infer<typeof candidateSelectionReasonSchema>;
export type LifecycleReasonCode = z.infer<typeof lifecycleReasonCodeSchema>;
export type Coverage = z.infer<typeof coverageSchema>;
export type AnalysisPartialReason = z.infer<typeof analysisPartialReasonSchema>;
export type SnapshotPartialReason = z.infer<typeof snapshotPartialReasonSchema>;
export type Exploitability = z.infer<typeof exploitabilitySchema>;
export type ReviewState = z.infer<typeof reviewStateSchema>;
export type SanitizedFinding = z.infer<typeof sanitizedFindingSchema>;
