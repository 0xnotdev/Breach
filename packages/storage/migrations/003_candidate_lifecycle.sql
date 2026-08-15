ALTER TABLE discovery_state ADD COLUMN IF NOT EXISTS bootstrapped_at TIMESTAMPTZ;
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS selection_reason TEXT NOT NULL DEFAULT 'selected';
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS commit_check_attempts INTEGER NOT NULL DEFAULT 0 CHECK (commit_check_attempts >= 0);
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS next_commit_check_at TIMESTAMPTZ;
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS first_commit_detected_at TIMESTAMPTZ;
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS head_sha TEXT;
ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS last_scan_status TEXT;

UPDATE repository_candidates
SET selection_reason = 'score'
WHERE candidate_state = 'SKIPPED' AND selection_reason = 'selected';

CREATE INDEX IF NOT EXISTS candidates_due_idx
ON repository_candidates (candidate_state, next_commit_check_at, priority_score DESC);
