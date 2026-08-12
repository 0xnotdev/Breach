import type { Pool, PoolClient } from "pg";
import {
  candidateStateSchema,
  reviewStateSchema,
  sanitizedFindingSchema,
  type CandidateState,
  type ReviewState,
  type SanitizedFinding,
} from "@breach/contracts";

const migration = `
CREATE TABLE IF NOT EXISTS discovery_state (
  stream_name TEXT PRIMARY KEY,
  last_repo_id BIGINT NOT NULL CHECK (last_repo_id >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repository_candidates (
  repo_id BIGINT PRIMARY KEY CHECK (repo_id > 0),
  full_name TEXT NOT NULL CHECK (full_name <> ''),
  html_url TEXT NOT NULL CHECK (html_url <> ''),
  discovered_at TIMESTAMPTZ NOT NULL,
  priority_score INTEGER NOT NULL,
  candidate_state TEXT NOT NULL,
  commit_check_attempts INTEGER NOT NULL DEFAULT 0 CHECK (commit_check_attempts >= 0),
  next_commit_check_at TIMESTAMPTZ,
  first_commit_detected_at TIMESTAMPTZ,
  head_sha TEXT,
  last_scan_status TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  repo_id BIGINT NOT NULL REFERENCES repository_candidates(repo_id),
  head_sha TEXT NOT NULL,
  coverage JSONB NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  UNIQUE(repo_id, head_sha)
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  repo_id BIGINT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL,
  payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_reviews (
  finding_id TEXT PRIMARY KEY REFERENCES findings(finding_id) ON DELETE CASCADE,
  review_state TEXT NOT NULL,
  review_note TEXT,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS state_events (
  event_id BIGSERIAL PRIMARY KEY,
  repo_id BIGINT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS metric_samples (
  metric_name TEXT NOT NULL,
  measured_at TIMESTAMPTZ NOT NULL,
  metric_value DOUBLE PRECISION NOT NULL,
  labels JSONB NOT NULL DEFAULT '{}',
  PRIMARY KEY(metric_name, measured_at)
);
`;

export interface DiscoveredCandidate {
  repoId: number;
  fullName: string;
  htmlUrl: string;
  discoveredAt: Date;
  priorityScore: number;
  candidateState: "WAITING_FOR_COMMIT" | "SKIPPED";
}

export interface StoredCandidate extends Omit<DiscoveredCandidate, "candidateState"> {
  candidateState: CandidateState;
}

export interface ReviewedFinding extends SanitizedFinding {
  reviewNote?: string;
}

export interface MetadataStore {
  recordDiscoveryPage(
    streamName: string,
    nextCursor: number,
    candidates: readonly DiscoveredCandidate[],
  ): Promise<void>;
  getDiscoveryCursor(streamName: string): Promise<number | null>;
  getCandidate(repoId: number): Promise<StoredCandidate | null>;
  transitionCandidate(repoId: number, nextState: CandidateState): Promise<StoredCandidate>;
  saveFinding(finding: SanitizedFinding): Promise<void>;
  getFinding(findingId: string): Promise<SanitizedFinding | null>;
  reviewFinding(
    findingId: string,
    reviewState: Exclude<ReviewState, "UNREVIEWED">,
    reviewNote?: string,
  ): Promise<ReviewedFinding>;
}

const allowedTransitions: Readonly<Record<CandidateState, readonly CandidateState[]>> = {
  DISCOVERED: ["SKIPPED", "WAITING_FOR_COMMIT"],
  SKIPPED: [],
  WAITING_FOR_COMMIT: ["READY", "FAILED", "RATE_LIMITED"],
  READY: ["SCANNING", "FAILED", "RATE_LIMITED"],
  SCANNING: [
    "SCANNED_NO_FINDINGS",
    "SCANNED_FINDINGS",
    "PARTIAL",
    "FAILED",
    "RATE_LIMITED",
  ],
  SCANNED_NO_FINDINGS: [],
  SCANNED_FINDINGS: [],
  PARTIAL: [],
  FAILED: [],
  RATE_LIMITED: ["WAITING_FOR_COMMIT", "READY", "SCANNING", "FAILED"],
};

function assertSafeReviewNote(note: string | undefined): void {
  if (note === undefined) return;
  if (note.length > 1_000) throw new Error("Review note is too long");

  const looksSensitive =
    /(?:secret|password|passwd|token|api[_-]?key|private[_-]?key)\s*[:=]/iu.test(note) ||
    /\b[A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY)[A-Z0-9_]*\s*=/iu.test(note) ||
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(note) ||
    /[A-Za-z0-9_\-/+=]{48,}/u.test(note);
  if (looksSensitive) throw new Error("Review note contains sensitive content");
}

async function inTransaction<T>(pool: Pool, run: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await run(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function createMetadataStore(pool: Pool): Promise<MetadataStore> {
  await pool.query(migration);

  const store: MetadataStore = {
    async recordDiscoveryPage(streamName, nextCursor, candidates) {
      if (!streamName || nextCursor < 0) throw new Error("Invalid discovery cursor input");
      for (const candidate of candidates) {
        if (
          !Number.isSafeInteger(candidate.repoId) ||
          candidate.repoId <= 0 ||
          !/^[^/\s]+\/[^/\s]+$/u.test(candidate.fullName) ||
          !candidate.htmlUrl.startsWith("https://github.com/") ||
          !Number.isFinite(candidate.priorityScore) ||
          !Number.isFinite(candidate.discoveredAt.getTime())
        ) {
          throw new Error("Invalid discovery candidate metadata");
        }
        candidateStateSchema.parse(candidate.candidateState);
      }

      await inTransaction(pool, async (client) => {
        for (const candidate of candidates) {
          await client.query(
            `INSERT INTO repository_candidates
              (repo_id, full_name, html_url, discovered_at, priority_score, candidate_state)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (repo_id) DO NOTHING`,
            [
              candidate.repoId,
              candidate.fullName,
              candidate.htmlUrl,
              candidate.discoveredAt,
              candidate.priorityScore,
              candidate.candidateState,
            ],
          );
        }

        await client.query(
          `INSERT INTO discovery_state (stream_name, last_repo_id)
           VALUES ($1, $2)
           ON CONFLICT (stream_name) DO UPDATE
             SET last_repo_id = GREATEST(discovery_state.last_repo_id, EXCLUDED.last_repo_id),
                 updated_at = CURRENT_TIMESTAMP`,
          [streamName, nextCursor],
        );
      });
    },

    async getDiscoveryCursor(streamName) {
      const result = await pool.query<{ last_repo_id: string }>(
        "SELECT last_repo_id FROM discovery_state WHERE stream_name = $1",
        [streamName],
      );
      const row = result.rows[0];
      return row === undefined ? null : Number(row.last_repo_id);
    },

    async getCandidate(repoId) {
      const result = await pool.query<{
        repo_id: string;
        full_name: string;
        html_url: string;
        discovered_at: Date;
        priority_score: number;
        candidate_state: string;
      }>("SELECT * FROM repository_candidates WHERE repo_id = $1", [repoId]);
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        repoId: Number(row.repo_id),
        fullName: row.full_name,
        htmlUrl: row.html_url,
        discoveredAt: new Date(row.discovered_at),
        priorityScore: row.priority_score,
        candidateState: candidateStateSchema.parse(row.candidate_state),
      };
    },

    async transitionCandidate(repoId, nextState) {
      const parsedNext: CandidateState = candidateStateSchema.parse(nextState);
      const current = await store.getCandidate(repoId);
      if (current === null) throw new Error(`Candidate ${String(repoId)} does not exist`);
      if (!allowedTransitions[current.candidateState].includes(parsedNext)) {
        throw new Error(`Illegal candidate transition: ${current.candidateState} -> ${parsedNext}`);
      }

      await inTransaction(pool, async (client) => {
        await client.query(
          "UPDATE repository_candidates SET candidate_state = $1 WHERE repo_id = $2",
          [parsedNext, repoId],
        );
        await client.query(
          "INSERT INTO state_events (repo_id, from_state, to_state) VALUES ($1, $2, $3)",
          [repoId, current.candidateState, parsedNext],
        );
      });
      const updated = await store.getCandidate(repoId);
      if (updated === null) throw new Error(`Candidate ${String(repoId)} disappeared`);
      return updated;
    },

    async saveFinding(finding) {
      const sanitized = sanitizedFindingSchema.parse(finding);
      await pool.query(
        `INSERT INTO findings (finding_id, repo_id, detected_at, payload)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (finding_id) DO UPDATE SET payload = EXCLUDED.payload`,
        [
          sanitized.findingId,
          sanitized.repository.id,
          sanitized.detectedAt,
          JSON.stringify(sanitized),
        ],
      );
    },

    async getFinding(findingId) {
      const result = await pool.query<{ payload: unknown }>(
        "SELECT payload FROM findings WHERE finding_id = $1",
        [findingId],
      );
      const row = result.rows[0];
      return row === undefined ? null : sanitizedFindingSchema.parse(row.payload);
    },

    async reviewFinding(findingId, reviewState, reviewNote) {
      const parsedReview = reviewStateSchema.exclude(["UNREVIEWED"]).parse(reviewState);
      assertSafeReviewNote(reviewNote);
      const current = await store.getFinding(findingId);
      if (current === null) throw new Error(`Finding ${findingId} does not exist`);
      const updated = sanitizedFindingSchema.parse({ ...current, reviewState: parsedReview });

      await inTransaction(pool, async (client) => {
        await client.query("UPDATE findings SET payload = $1 WHERE finding_id = $2", [
          JSON.stringify(updated),
          findingId,
        ]);
        await client.query(
          `INSERT INTO finding_reviews (finding_id, review_state, review_note)
           VALUES ($1, $2, $3)
           ON CONFLICT (finding_id) DO UPDATE SET
             review_state = EXCLUDED.review_state,
             review_note = EXCLUDED.review_note,
             reviewed_at = CURRENT_TIMESTAMP`,
          [findingId, parsedReview, reviewNote ?? null],
        );
      });

      return reviewNote === undefined ? updated : { ...updated, reviewNote };
    },
  };

  return store;
}
