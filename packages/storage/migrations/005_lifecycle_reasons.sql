ALTER TABLE repository_candidates ADD COLUMN IF NOT EXISTS lifecycle_reason_code TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS failure_reason_code TEXT;
ALTER TABLE state_events ADD COLUMN IF NOT EXISTS reason_code TEXT;
