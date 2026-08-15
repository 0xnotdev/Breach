import type { Pool } from "pg";
import type { SystemMetric } from "@breach/operator";

type Numeric = string | number | null;

interface DiscoveryRow {
  readonly repositories_discovered_hour: Numeric;
  readonly eligible_hour: Numeric;
  readonly selected_hour: Numeric;
  readonly waiting_for_commit: Numeric;
  readonly commit_detected_hour: Numeric;
  readonly failed_hour: Numeric;
  readonly discovery_cursor: Numeric;
  readonly discovery_lag_seconds: Numeric;
}

interface ScanRow {
  readonly scans_started_hour: Numeric;
  readonly scans_completed_hour: Numeric;
  readonly partial_hour: Numeric;
  readonly average_bytes: Numeric;
  readonly average_files: Numeric;
  readonly p50_latency_ms: Numeric;
  readonly p95_latency_ms: Numeric;
}

interface FindingRow {
  readonly findings_hour: Numeric;
  readonly critical_hour: Numeric;
  readonly high_hour: Numeric;
  readonly medium_hour: Numeric;
  readonly exploitability_hour: Numeric;
  readonly secrets_hour: Numeric;
  readonly dependencies_hour: Numeric;
  readonly config_hour: Numeric;
}

interface ReviewRow {
  readonly reviewed: Numeric;
  readonly confirmed: Numeric;
  readonly false_positive: Numeric;
  readonly uncertain: Numeric;
  readonly exploitability: Numeric;
  readonly secrets: Numeric;
  readonly dependencies: Numeric;
  readonly config: Numeric;
}

interface TelemetryRow {
  readonly metric_name: string;
  readonly hour_sum: Numeric;
  readonly hour_average: Numeric;
  readonly latest_value: Numeric;
  readonly latest_at: Date | string | null;
}

function numeric(value: Numeric): number | null {
  if (value === null) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function add(metrics: SystemMetric[], name: string, value: Numeric, unit: string): void {
  const parsed = numeric(value);
  if (parsed !== null) metrics.push({ name, value: parsed, unit });
}

function ratio(numerator: Numeric, denominator: Numeric): number | null {
  const safeNumerator = numeric(numerator);
  const safeDenominator = numeric(denominator);
  return safeNumerator === null || safeDenominator === null || safeDenominator <= 0 ? null : safeNumerator / safeDenominator;
}

export async function readPostgresSystemMetrics(pool: Pool): Promise<readonly SystemMetric[]> {
  const [discoveryResult, scanResult, findingResult, reviewResult, telemetryResult] = await Promise.all([
    pool.query<DiscoveryRow>(`
      /* breach:system-discovery */
      SELECT
        COUNT(*) FILTER (WHERE discovered_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS repositories_discovered_hour,
        COUNT(*) FILTER (WHERE discovered_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' AND selection_reason <> 'score') AS eligible_hour,
        COUNT(*) FILTER (WHERE discovered_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' AND selection_reason = 'selected') AS selected_hour,
        COUNT(*) FILTER (WHERE candidate_state = 'WAITING_FOR_COMMIT') AS waiting_for_commit,
        COUNT(*) FILTER (WHERE first_commit_detected_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS commit_detected_hour,
        COUNT(*) FILTER (WHERE discovered_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' AND candidate_state = 'FAILED') AS failed_hour,
        (SELECT MAX(last_repo_id) FROM discovery_state) AS discovery_cursor,
        EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MAX(discovered_at)) AS discovery_lag_seconds
      FROM repository_candidates`),
    pool.query<ScanRow>(`
      /* breach:system-scans */
      SELECT
        COUNT(*) FILTER (WHERE started_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS scans_started_hour,
        COUNT(*) FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS scans_completed_hour,
        COUNT(*) FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' AND state = 'PARTIAL') AS partial_hour,
        AVG((coverage->>'bytesInspected')::double precision) FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS average_bytes,
        AVG((coverage->>'filesAnalyzed')::double precision) FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS average_files,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)
          FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS p50_latency_ms,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)
          FILTER (WHERE completed_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS p95_latency_ms
      FROM scans`),
    pool.query<FindingRow>(`
      /* breach:system-findings */
      SELECT
        COUNT(*) AS findings_hour,
        COUNT(*) FILTER (WHERE payload->>'severity' = 'critical') AS critical_hour,
        COUNT(*) FILTER (WHERE payload->>'severity' = 'high') AS high_hour,
        COUNT(*) FILTER (WHERE payload->>'severity' = 'medium') AS medium_hour,
        COUNT(*) FILTER (WHERE payload->>'category' IN ('command_injection','sql_injection','ssrf','path_traversal','code_injection','unsafe_deserialization')) AS exploitability_hour,
        COUNT(*) FILTER (WHERE payload->>'category' = 'secret_exposure') AS secrets_hour,
        COUNT(*) FILTER (WHERE payload->>'category' = 'vulnerable_dependency') AS dependencies_hour,
        COUNT(*) FILTER (WHERE payload->>'category' NOT IN ('command_injection','sql_injection','ssrf','path_traversal','code_injection','unsafe_deserialization','secret_exposure','vulnerable_dependency')) AS config_hour
      FROM findings
      WHERE detected_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'`),
    pool.query<ReviewRow>(`
      /* breach:system-reviews */
      SELECT
        COUNT(*) AS reviewed,
        COUNT(*) FILTER (WHERE r.review_state = 'CONFIRMED') AS confirmed,
        COUNT(*) FILTER (WHERE r.review_state = 'FALSE_POSITIVE') AS false_positive,
        COUNT(*) FILTER (WHERE r.review_state = 'UNCERTAIN') AS uncertain,
        COUNT(*) FILTER (WHERE f.payload->>'category' IN ('command_injection','sql_injection','ssrf','path_traversal','code_injection','unsafe_deserialization')) AS exploitability,
        COUNT(*) FILTER (WHERE f.payload->>'category' = 'secret_exposure') AS secrets,
        COUNT(*) FILTER (WHERE f.payload->>'category' = 'vulnerable_dependency') AS dependencies,
        COUNT(*) FILTER (WHERE f.payload->>'category' NOT IN ('command_injection','sql_injection','ssrf','path_traversal','code_injection','unsafe_deserialization','secret_exposure','vulnerable_dependency')) AS config
      FROM finding_reviews r
      JOIN findings f ON f.finding_id = r.finding_id`),
    pool.query<TelemetryRow>(`
      /* breach:system-telemetry */
      SELECT
        metric_name,
        SUM(metric_value) FILTER (WHERE measured_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS hour_sum,
        AVG(metric_value) FILTER (WHERE measured_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour') AS hour_average,
        (ARRAY_AGG(metric_value ORDER BY measured_at DESC))[1] AS latest_value,
        MAX(measured_at) AS latest_at
      FROM metric_samples
      WHERE metric_name IN (
        'github.requests.total', 'github.requests.discovery', 'github.requests_per_completed_scan',
        'github.rate_limited', 'github.rate_limit.remaining', 'github.rate_limit.limit', 'github.rate_limit.reset_at',
        'scan.failed', 'zero_retention.canary.last_run', 'zero_retention.canary.success',
        'zero_retention.canary.raw_occurrences', 'zero_retention.canary.fingerprint_occurrences', 'zero_retention.violations',
        'zero_retention.source_persisted', 'zero_retention.credential_verification_performed'
      )
      GROUP BY metric_name`),
  ]);

  const discovery = discoveryResult.rows[0];
  const scans = scanResult.rows[0];
  const findings = findingResult.rows[0];
  const reviews = reviewResult.rows[0];
  const telemetry = new Map(telemetryResult.rows.map((row) => [row.metric_name, row]));
  const metrics: SystemMetric[] = [];

  if (discovery !== undefined) {
    add(metrics, "discovery.repositories_hour", discovery.repositories_discovered_hour, "count");
    add(metrics, "discovery.cursor", discovery.discovery_cursor, "count");
    add(metrics, "discovery.lag_seconds", discovery.discovery_lag_seconds, "seconds");
    add(metrics, "funnel.discovered_hour", discovery.repositories_discovered_hour, "count");
    add(metrics, "funnel.eligible_hour", discovery.eligible_hour, "count");
    add(metrics, "funnel.selected_hour", discovery.selected_hour, "count");
    add(metrics, "funnel.waiting_for_commit", discovery.waiting_for_commit, "count");
    add(metrics, "funnel.commit_detected_hour", discovery.commit_detected_hour, "count");
    add(metrics, "funnel.failed_hour", discovery.failed_hour, "count");
  }
  if (scans !== undefined) {
    add(metrics, "funnel.scans_started_hour", scans.scans_started_hour, "count");
    add(metrics, "funnel.scans_completed_hour", scans.scans_completed_hour, "count");
    add(metrics, "funnel.partial_hour", scans.partial_hour, "count");
    add(metrics, "scan.scans_hour", scans.scans_completed_hour, "count");
    add(metrics, "scan.average_bytes", scans.average_bytes, "bytes");
    add(metrics, "scan.average_files", scans.average_files, "count");
    add(metrics, "scan.p50_latency_ms", scans.p50_latency_ms, "milliseconds");
    add(metrics, "scan.p95_latency_ms", scans.p95_latency_ms, "milliseconds");
    const partialRate = ratio(scans.partial_hour, scans.scans_completed_hour);
    if (partialRate !== null) add(metrics, "scan.partial_rate", partialRate, "ratio");
  }
  if (findings !== undefined) {
    add(metrics, "funnel.findings_hour", findings.findings_hour, "count");
    add(metrics, "findings.findings_hour", findings.findings_hour, "count");
    add(metrics, "findings.critical_hour", findings.critical_hour, "count");
    add(metrics, "findings.high_hour", findings.high_hour, "count");
    add(metrics, "findings.medium_hour", findings.medium_hour, "count");
    add(metrics, "findings.family.exploitability_hour", findings.exploitability_hour, "count");
    add(metrics, "findings.family.secrets_hour", findings.secrets_hour, "count");
    add(metrics, "findings.family.dependencies_hour", findings.dependencies_hour, "count");
    add(metrics, "findings.family.config_hour", findings.config_hour, "count");
    const scansCompleted = scans === undefined ? null : numeric(scans.scans_completed_hour);
    if (scansCompleted !== null && scansCompleted > 0) add(metrics, "findings.per_1000_scans", (numeric(findings.findings_hour) ?? 0) * 1_000 / scansCompleted, "count_per_1000");
  }
  if (reviews !== undefined) {
    add(metrics, "reviews.total", reviews.reviewed, "count");
    add(metrics, "reviews.confirmed", reviews.confirmed, "count");
    add(metrics, "reviews.false_positive", reviews.false_positive, "count");
    add(metrics, "reviews.uncertain", reviews.uncertain, "count");
    add(metrics, "reviews.family.exploitability", reviews.exploitability, "count");
    add(metrics, "reviews.family.secrets", reviews.secrets, "count");
    add(metrics, "reviews.family.dependencies", reviews.dependencies, "count");
    add(metrics, "reviews.family.config", reviews.config, "count");
    const confirmed = numeric(reviews.confirmed);
    const falsePositive = numeric(reviews.false_positive);
    if (confirmed !== null && falsePositive !== null && confirmed + falsePositive > 0) add(metrics, "reviewed_precision", confirmed / (confirmed + falsePositive), "ratio");
  }

  const telemetryMetric = (source: string, target: string, field: "hour_sum" | "hour_average" | "latest_value", unit: string) => {
    const row = telemetry.get(source);
    if (row !== undefined) add(metrics, target, row[field], unit);
  };
  telemetryMetric("github.requests.total", "github.requests_hour", "hour_sum", "count");
  telemetryMetric("github.requests.discovery", "discovery.api_requests_hour", "hour_sum", "count");
  telemetryMetric("github.requests_per_completed_scan", "github.requests_per_completed_scan", "hour_average", "count");
  telemetryMetric("github.rate_limited", "github.rate_limit.events_hour", "hour_sum", "count");
  telemetryMetric("github.rate_limit.remaining", "github.rate_limit.remaining", "latest_value", "count");
  telemetryMetric("github.rate_limit.limit", "github.rate_limit.limit", "latest_value", "count");
  telemetryMetric("github.rate_limit.reset_at", "github.rate_limit.reset_at", "latest_value", "unix_ms");
  const failures = numeric(telemetry.get("scan.failed")?.hour_sum ?? null);
  const completed = numeric(scans?.scans_completed_hour ?? null);
  if (failures !== null) {
    add(metrics, "scan.failed_hour", failures, "count");
    if (completed !== null && completed + failures > 0) add(metrics, "scan.failure_rate", failures / (completed + failures), "ratio");
  }

  telemetryMetric("zero_retention.canary.last_run", "safety.canary.last_run", "latest_value", "unix_ms");
  telemetryMetric("zero_retention.canary.success", "safety.canary.result", "latest_value", "boolean");
  telemetryMetric("zero_retention.violations", "safety.retention_violations", "latest_value", "count");
  telemetryMetric("zero_retention.source_persisted", "safety.source_persisted", "latest_value", "count");
  telemetryMetric("zero_retention.credential_verification_performed", "safety.credential_verification_performed", "latest_value", "count");

  return metrics;
}
