import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
  candidateSelectionReasonSchema,
  candidateStateSchema,
  coverageSchema,
  reviewStateSchema,
  sanitizedFindingSchema,
  type CandidateState,
  type CandidateSelectionReason,
  type Coverage,
  type ReviewState,
  type SanitizedFinding,
} from "@breach/contracts";

const migration = `
CREATE TABLE IF NOT EXISTS discovery_state (
  stream_name TEXT PRIMARY KEY,
  last_repo_id BIGINT NOT NULL CHECK (last_repo_id >= 0),
  bootstrapped_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repository_candidates (
  repo_id BIGINT PRIMARY KEY CHECK (repo_id > 0),
  full_name TEXT NOT NULL CHECK (full_name <> ''),
  html_url TEXT NOT NULL CHECK (html_url <> ''),
  discovered_at TIMESTAMPTZ NOT NULL,
  priority_score INTEGER NOT NULL,
  candidate_state TEXT NOT NULL,
  selection_reason TEXT NOT NULL DEFAULT 'selected',
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
  claim_token TEXT NOT NULL,
  coverage JSONB NOT NULL,
  state TEXT NOT NULL DEFAULT 'SCANNING',
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
ALTER TABLE discovery_state ADD COLUMN IF NOT EXISTS bootstrapped_at TIMESTAMPTZ;
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS selection_reason TEXT NOT NULL DEFAULT 'selected';
UPDATE repository_candidates SET selection_reason = 'score'
WHERE candidate_state = 'SKIPPED' AND selection_reason = 'selected';
`;

export interface DiscoveredCandidate {
  repoId: number;
  fullName: string;
  htmlUrl: string;
  discoveredAt: Date;
  priorityScore: number;
  candidateState: "WAITING_FOR_COMMIT" | "SKIPPED";
  selectionReason: CandidateSelectionReason;
}

export interface StoredCandidate extends Omit<DiscoveredCandidate, "candidateState"> {
  candidateState: CandidateState;
}

export interface ReviewedFinding extends SanitizedFinding {
  reviewNote?: string;
}

export interface MetadataStore {
  bootstrapDiscovery(
    streamName: string,
    frontierCursor: number,
    bootstrappedAt: Date,
  ): Promise<{ cursor: number; bootstrappedAt: Date }>;
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
  transition(repoId: number, nextState: CandidateState): Promise<void>;
  scheduleCommitCheck(repoId: number, nextCheckAt: Date, attempt: number): Promise<void>;
  claimScan(repoId: number, headSha: string, startedAt: Date): Promise<boolean>;
  saveFindings(findings: readonly SanitizedFinding[]): Promise<void>;
  completeScan(
    repoId: number,
    headSha: string,
    state: CandidateState,
    coverage: Coverage,
  ): Promise<void>;
  recordMetric(
    name: string,
    value: number,
    labels: Readonly<Record<string, string>>,
  ): Promise<void>;
  getScan(
    repoId: number,
    headSha: string,
  ): Promise<{ state: CandidateState; coverage: Coverage } | null>;
  getMetricSamples(
    name: string,
  ): Promise<Array<{ value: number; labels: Readonly<Record<string, string>> }>>;
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
    async bootstrapDiscovery(streamName, frontierCursor, bootstrappedAt) {
      if (
        !streamName ||
        !Number.isSafeInteger(frontierCursor) ||
        frontierCursor <= 0 ||
        !Number.isFinite(bootstrappedAt.getTime())
      ) {
        throw new Error("Invalid discovery bootstrap input");
      }

      return inTransaction(pool, async (client) => {
        await client.query(
          `INSERT INTO discovery_state (stream_name, last_repo_id, bootstrapped_at, updated_at)
           VALUES ($1, $2, $3, $3)
           ON CONFLICT (stream_name) DO NOTHING
           RETURNING stream_name`,
          [streamName, frontierCursor, bootstrappedAt],
        );
        const state = await client.query<{ last_repo_id: string; bootstrapped_at: Date | null }>(
          `SELECT last_repo_id, bootstrapped_at FROM discovery_state
           WHERE stream_name = $1`,
          [streamName],
        );
        const row = state.rows[0];
        if (row === undefined || row.bootstrapped_at === null) {
          throw new Error("Discovery bootstrap was not persisted");
        }
        const persistedAt = new Date(row.bootstrapped_at);
        const persistedCursor = Number(row.last_repo_id);
        const labels = JSON.stringify({ stream: streamName });
        for (const [name, value] of [
          ["discovery.bootstrap.repo_id", persistedCursor],
          ["discovery.bootstrap.timestamp", persistedAt.getTime()],
          ["discovery.cursor.current", persistedCursor],
        ] as const) {
          await client.query(
            `INSERT INTO metric_samples (metric_name, measured_at, metric_value, labels)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (metric_name, measured_at) DO NOTHING`,
            [name, persistedAt, value, labels],
          );
        }
        return {
          cursor: persistedCursor,
          bootstrappedAt: persistedAt,
        };
      });
    },

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
        candidateSelectionReasonSchema.parse(candidate.selectionReason);
        if ((candidate.candidateState === "WAITING_FOR_COMMIT") !== (candidate.selectionReason === "selected")) {
          throw new Error("Candidate state does not match its selection reason");
        }
      }

      await inTransaction(pool, async (client) => {
        for (const candidate of candidates) {
          await client.query(
            `INSERT INTO repository_candidates
              (repo_id, full_name, html_url, discovered_at, priority_score, candidate_state, selection_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (repo_id) DO NOTHING`,
            [
              candidate.repoId,
              candidate.fullName,
              candidate.htmlUrl,
              candidate.discoveredAt,
              candidate.priorityScore,
              candidate.candidateState,
              candidate.selectionReason,
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
        const labels = JSON.stringify({ stream: streamName });
        for (const [name, value] of [
          ["discovery.pages", 1],
          ["discovery.repositories_seen", candidates.length],
          ["discovery.cursor.current", nextCursor],
          ["candidates.discovered", candidates.length],
          ["candidates.eligible", candidates.filter(({ selectionReason }) => selectionReason !== "score").length],
          ["candidates.selected", candidates.filter(({ selectionReason }) => selectionReason === "selected").length],
          ["candidates.skipped_capacity", candidates.filter(({ selectionReason }) => selectionReason === "capacity").length],
          ["candidates.skipped_score", candidates.filter(({ selectionReason }) => selectionReason === "score").length],
        ] as const) {
          await client.query(
            `INSERT INTO metric_samples (metric_name, measured_at, metric_value, labels)
             VALUES ($1, CURRENT_TIMESTAMP, $2, $3)
             ON CONFLICT (metric_name, measured_at) DO UPDATE SET
               metric_value = CASE
                 WHEN EXCLUDED.metric_name = 'discovery.cursor.current'
                   THEN GREATEST(metric_samples.metric_value, EXCLUDED.metric_value)
                 ELSE metric_samples.metric_value + EXCLUDED.metric_value
               END`,
            [name, value, labels],
          );
        }
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
        selection_reason: string;
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
        selectionReason: candidateSelectionReasonSchema.parse(row.selection_reason),
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

    async transition(repoId, nextState) {
      await store.transitionCandidate(repoId, nextState);
    },

    async scheduleCommitCheck(repoId, nextCheckAt, attempt) {
      if (!Number.isInteger(attempt) || attempt < 0 || !Number.isFinite(nextCheckAt.getTime())) {
        throw new Error("Invalid commit recheck schedule");
      }
      await pool.query(
        `UPDATE repository_candidates
         SET commit_check_attempts = $1, next_commit_check_at = $2
         WHERE repo_id = $3`,
        [attempt, nextCheckAt, repoId],
      );
    },

    async claimScan(repoId, headSha, startedAt) {
      if (!/^[a-f0-9]{40}$/iu.test(headSha) || !Number.isFinite(startedAt.getTime())) {
        throw new Error("Invalid scan claim");
      }
      const claimToken = randomUUID();
      await pool.query(
        `INSERT INTO scans (scan_id, repo_id, head_sha, claim_token, coverage, state, started_at)
         VALUES ($1, $2, $3, $4, $5, 'SCANNING', $6)
         ON CONFLICT (repo_id, head_sha) DO NOTHING
         RETURNING scan_id`,
        [
          `${String(repoId)}:${headSha}`,
          repoId,
          headSha,
          claimToken,
          JSON.stringify({}),
          startedAt,
        ],
      );
      const claimed = await pool.query<{ claim_token: string }>(
        "SELECT claim_token FROM scans WHERE repo_id = $1 AND head_sha = $2",
        [repoId, headSha],
      );
      return claimed.rows[0]?.claim_token === claimToken;
    },

    async saveFindings(findings) {
      for (const finding of findings) await store.saveFinding(finding);
    },

    async completeScan(repoId, headSha, state, coverage) {
      const safeState = candidateStateSchema.parse(state);
      const safeCoverage = coverageSchema.parse(coverage);
      await pool.query(
        `UPDATE scans
         SET coverage = $1, state = $2, completed_at = CURRENT_TIMESTAMP
         WHERE repo_id = $3 AND head_sha = $4`,
        [JSON.stringify(safeCoverage), safeState, repoId, headSha],
      );
    },

    async recordMetric(name, value, labels) {
      if (!/^[a-z][a-z0-9_.]*$/u.test(name) || !Number.isFinite(value)) {
        throw new Error("Invalid metric sample");
      }
      const safeLabels = Object.fromEntries(
        Object.entries(labels).map(([key, label]) => {
          if (!/^[a-z][a-z0-9_]*$/u.test(key) || label.length > 80) {
            throw new Error("Invalid metric labels");
          }
          return [key, label];
        }),
      );
      await pool.query(
        `INSERT INTO metric_samples (metric_name, measured_at, metric_value, labels)
         VALUES ($1, CURRENT_TIMESTAMP, $2, $3)`,
        [name, value, JSON.stringify(safeLabels)],
      );
    },

    async getScan(repoId, headSha) {
      const result = await pool.query<{ state: string; coverage: unknown }>(
        "SELECT state, coverage FROM scans WHERE repo_id = $1 AND head_sha = $2",
        [repoId, headSha],
      );
      const row = result.rows[0];
      return row === undefined
        ? null
        : {
            state: candidateStateSchema.parse(row.state),
            coverage: coverageSchema.parse(row.coverage),
          };
    },

    async getMetricSamples(name) {
      const result = await pool.query<{ metric_value: number; labels: unknown }>(
        `SELECT metric_value, labels FROM metric_samples
         WHERE metric_name = $1 ORDER BY measured_at`,
        [name],
      );
      return result.rows.map((row) => ({
        value: row.metric_value,
        labels:
          typeof row.labels === "object" && row.labels !== null
            ? (row.labels as Readonly<Record<string, string>>)
            : {},
      }));
    },
  };

  return store;
}
