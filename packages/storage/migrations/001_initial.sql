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
  candidate_state TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS state_events (
  event_id BIGSERIAL PRIMARY KEY,
  repo_id BIGINT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS findings_detected_idx ON findings (detected_at DESC);
CREATE INDEX IF NOT EXISTS events_occurred_idx ON state_events (event_id, occurred_at DESC);
