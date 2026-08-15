CREATE TABLE IF NOT EXISTS metric_samples (
  metric_name TEXT NOT NULL,
  measured_at TIMESTAMPTZ NOT NULL,
  metric_value DOUBLE PRECISION NOT NULL,
  labels JSONB NOT NULL DEFAULT '{}',
  PRIMARY KEY(metric_name, measured_at)
);
