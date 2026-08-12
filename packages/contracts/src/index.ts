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
    filesSeen: z.number().int().nonnegative(),
    filesAnalyzed: z.number().int().nonnegative(),
    bytesInspected: z.number().int().nonnegative(),
    skippedBinary: z.number().int().nonnegative(),
    skippedOversize: z.number().int().nonnegative(),
    skippedBudget: z.number().int().nonnegative().default(0),
    treeTruncated: z.boolean(),
    languagesModeled: z.array(z.enum(["javascript", "typescript", "python"])),
  })
  .strict()
  .refine((value) => value.filesAnalyzed <= value.filesSeen, {
    message: "Analyzed file count cannot exceed files seen",
    path: ["filesAnalyzed"],
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
    path: z.array(semanticPathNodeSchema).max(256).optional(),
    reviewState: reviewStateSchema.default("UNREVIEWED"),
  })
  .strict();

export type CandidateState = z.infer<typeof candidateStateSchema>;
export type Coverage = z.infer<typeof coverageSchema>;
export type Exploitability = z.infer<typeof exploitabilitySchema>;
export type ReviewState = z.infer<typeof reviewStateSchema>;
export type SanitizedFinding = z.infer<typeof sanitizedFindingSchema>;
