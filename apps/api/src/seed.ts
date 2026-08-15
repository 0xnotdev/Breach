import { Pool } from "pg";
import type { SanitizedFinding } from "@breach/contracts";
import { createMetadataStore } from "@breach/storage";

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl === undefined) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: databaseUrl, max: 1 }); const store = await createMetadataStore(pool);
await store.recordDiscoveryPage("demo", 9_000_001, [{ repoId: 9_000_001, fullName: "fixture/canary", htmlUrl: "https://github.com/fixture/canary", discoveredAt: new Date("2026-08-12T12:00:00.000Z"), priorityScore: 96, candidateState: "WAITING_FOR_COMMIT", selectionReason: "selected" }]);
const finding: SanitizedFinding = { findingId: "00000000-0000-4000-8000-000000000001", detectedAt: "2026-08-12T12:00:00.000Z", repository: { id: 9_000_001, fullName: "fixture/canary", url: "https://github.com/fixture/canary" }, revision: { ref: "HEAD", sha: "a".repeat(40) }, category: "secret_exposure", severity: "critical", confidence: .98, secretEvidence: { type: "AWS Secret Access Key", provider: "AWS", path: "credential.txt", line: 1, fingerprint: "f".repeat(64) }, coverage: { ref: `HEAD@${"a".repeat(40)}`, historyScanned: false, scanComplete: true, snapshotComplete: true, analysisComplete: true, analysisPartial: false, snapshotPartialReasons: [], analysisPartialReasons: [], filesSeen: 1, filesEligible: 1, filesAnalyzed: 1, bytesInspected: 64, skippedBinary: 0, skippedGenerated: 0, skippedOversize: 0, skippedBudget: 0, skippedUnsupported: 0, treeTruncated: false, languagesModeled: [] }, reviewState: "UNREVIEWED" };
await store.saveFinding(finding); await store.recordMetric("zero_retention.canary", 1, { unit: "healthy" }); await pool.end();
process.stdout.write("Sanitized demo metadata seeded\n");
