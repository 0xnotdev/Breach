CREATE TABLE IF NOT EXISTS finding_reviews (
  finding_id TEXT PRIMARY KEY REFERENCES findings(finding_id) ON DELETE CASCADE,
  review_state TEXT NOT NULL,
  review_note TEXT,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
