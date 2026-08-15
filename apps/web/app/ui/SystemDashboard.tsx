"use client";

import { useEffect, useMemo, useState } from "react";

interface SystemMetric {
  readonly name: string;
  readonly value: number;
  readonly unit: string;
}

interface MetricDefinition {
  readonly name: string;
  readonly label: string;
}

const groups: readonly { readonly title: string; readonly description: string; readonly metrics: readonly MetricDefinition[] }[] = [
  { title: "Discovery", description: "Recent public-repository intake and cursor progress.", metrics: [
    { name: "discovery.repositories_hour", label: "Repositories discovered / hour" }, { name: "discovery.cursor", label: "Discovery cursor" }, { name: "discovery.lag_seconds", label: "Discovery lag" }, { name: "discovery.api_requests_hour", label: "Discovery API requests / hour" },
  ] },
  { title: "Funnel", description: "Actual repository lifecycle counts; recent metrics use the last hour.", metrics: [
    { name: "funnel.discovered_hour", label: "Discovered" }, { name: "funnel.eligible_hour", label: "Eligible" }, { name: "funnel.selected_hour", label: "Selected" }, { name: "funnel.waiting_for_commit", label: "Waiting for commit" }, { name: "funnel.commit_detected_hour", label: "Commit detected" }, { name: "funnel.scans_started_hour", label: "Scans started" }, { name: "funnel.scans_completed_hour", label: "Scans completed" }, { name: "funnel.partial_hour", label: "Partial" }, { name: "funnel.failed_hour", label: "Failed" }, { name: "funnel.findings_hour", label: "Findings" },
  ] },
  { title: "Efficiency", description: "Measured admission and commit-readiness ratios for repositories discovered in the last hour.", metrics: [
    { name: "funnel.admission_ratio", label: "Candidate admission ratio" }, { name: "funnel.commit_ready_ratio", label: "Commit-ready ratio" },
  ] },
  { title: "GitHub", description: "Observed API quota and request cost; no response bodies are retained.", metrics: [
    { name: "github.rate_limit.remaining", label: "Rate limit remaining" }, { name: "github.rate_limit.limit", label: "Rate limit" }, { name: "github.rate_limit.reset_at", label: "Rate limit reset" }, { name: "github.requests_hour", label: "Requests / hour" }, { name: "github.requests_per_completed_scan", label: "Requests / completed scan" }, { name: "github.rate_limit.events_hour", label: "Rate-limit events / hour" },
  ] },
  { title: "Scan", description: "Completed bounded-scan volume, cost, latency, and outcomes in the last hour.", metrics: [
    { name: "scan.scans_hour", label: "Scans / hour" }, { name: "scan.average_bytes", label: "Average bytes / scan" }, { name: "scan.average_files", label: "Average files / scan" }, { name: "scan.p50_latency_ms", label: "p50 latency" }, { name: "scan.p95_latency_ms", label: "p95 latency" }, { name: "scan.partial_rate", label: "Partial rate" }, { name: "scan.failed_hour", label: "Failed scans / hour" }, { name: "scan.failure_rate", label: "Failure rate" },
  ] },
  { title: "Latency", description: "Mean end-to-end stage durations observed during the last hour.", metrics: [
    { name: "latency.discovery_to_commit_gate_ms", label: "Discovery to commit gate" }, { name: "latency.commit_detected_to_scan_start_ms", label: "Commit detected to scan start" }, { name: "latency.scan_duration_ms", label: "Scan duration" }, { name: "latency.discovery_to_finding_ms", label: "Discovery to finding" },
  ] },
  { title: "Findings", description: "Persisted sanitized findings from scans completed in the last hour.", metrics: [
    { name: "findings.findings_hour", label: "Findings / hour" }, { name: "findings.per_1000_scans", label: "Findings / 1,000 scanned repos" }, { name: "findings.critical_hour", label: "Critical" }, { name: "findings.high_hour", label: "High" }, { name: "findings.medium_hour", label: "Medium" }, { name: "findings.high_confidence_static_paths_hour", label: "High-confidence static paths" }, { name: "findings.family.exploitability_hour", label: "Exploitability" }, { name: "findings.family.secrets_hour", label: "Secrets" }, { name: "findings.family.dependencies_hour", label: "Dependencies" }, { name: "findings.family.config_hour", label: "Configuration" },
  ] },
  { title: "Validation", description: "Persistent human judgments across all findings.", metrics: [
    { name: "reviews.total", label: "Reviewed" }, { name: "reviews.confirmed", label: "Confirmed" }, { name: "reviews.false_positive", label: "False positive" }, { name: "reviews.uncertain", label: "Uncertain" }, { name: "reviewed_precision", label: "Reviewed precision" }, { name: "reviews.family.exploitability", label: "Reviewed exploitability" }, { name: "reviews.family.secrets", label: "Reviewed secrets" }, { name: "reviews.family.dependencies", label: "Reviewed dependencies" }, { name: "reviews.family.config", label: "Reviewed configuration" },
  ] },
  { title: "Safety", description: "Runtime canary and zero-retention assertions appear only after measurement.", metrics: [
    { name: "safety.canary.last_run", label: "Canary last run" }, { name: "safety.canary.result", label: "Canary result" }, { name: "safety.retention_violations", label: "Retention violations" }, { name: "safety.source_persisted", label: "Source persisted" }, { name: "safety.credential_verification_performed", label: "Credential verification performed" },
  ] },
];

export function SystemDashboard() {
  const [reload, setReload] = useState(0);
  const [state, setState] = useState<{ readonly kind: "loading" | "ready" | "error"; readonly metrics: readonly SystemMetric[] }>({ kind: "loading", metrics: [] });

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/system", { headers: { accept: "application/json" }, cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("System metrics unavailable");
        const value: unknown = await response.json();
        if (!isMetricResponse(value)) throw new Error("System metrics invalid");
        setState({ kind: "ready", metrics: value.metrics });
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setState({ kind: "error", metrics: [] });
      });
    return () => controller.abort();
  }, [reload]);

  const values = useMemo(() => new Map(state.metrics.map((metric) => [metric.name, metric])), [state.metrics]);
  if (state.kind === "loading") return <div className="empty-state system-loading" role="status"><strong>Loading live system metrics…</strong><p>Querying PostgreSQL aggregates through the operator API.</p></div>;
  if (state.kind === "error") return <div className="empty-state empty-error system-loading" role="alert"><strong>System metrics are unavailable</strong><p>No cached or invented values are shown.</p><button className="filter-button" type="button" onClick={() => { setState({ kind: "loading", metrics: [] }); setReload((value) => value + 1); }}>Retry</button></div>;

  return <div className="system-sections">{groups.map((group) => <section className="system-section" key={group.title} aria-labelledby={`system-${group.title.toLocaleLowerCase("en-US")}`}><header><h2 id={`system-${group.title.toLocaleLowerCase("en-US")}`}>{group.title}</h2><p>{group.description}</p></header>{group.title === "Funnel" ? <FunnelMetrics definitions={group.metrics} values={values} /> : <div className="system-grid">{group.metrics.map((definition) => <MetricCard definition={definition} key={definition.name} metric={values.get(definition.name)} />)}</div>}</section>)}</div>;
}

function MetricCard({ definition, metric }: { definition: MetricDefinition; metric?: SystemMetric }) {
  return <article className={`system-card${metric === undefined ? " system-no-data" : ""}`}><small>{definition.label}</small><strong>{metric === undefined ? "No data yet" : formatMetric(metric)}</strong><p>{metric === undefined ? "The required measurement has not been recorded." : metric.name}</p><span>{metric === undefined ? "NO DATA" : "MEASURED"}</span></article>;
}

function FunnelMetrics({ definitions, values }: { definitions: readonly MetricDefinition[]; values: ReadonlyMap<string, SystemMetric> }) {
  const maximum = Math.max(0, ...definitions.map((definition) => values.get(definition.name)?.value ?? 0));
  return <div className="funnel-panel"><div>{definitions.map((definition) => { const metric = values.get(definition.name); const width = metric === undefined || maximum <= 0 ? "0%" : `${String(Math.max(2, Math.round(metric.value / maximum * 100)))}%`; return <div className="funnel-row" key={definition.name}><span>{definition.label}</span><div><i style={{ width }} /></div><strong>{metric === undefined ? "No data yet" : formatMetric(metric)}</strong></div>; })}</div></div>;
}

function formatMetric(metric: SystemMetric): string {
  if (metric.unit === "ratio") return `${(metric.value * 100).toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;
  if (metric.unit === "milliseconds") return formatDuration(metric.value);
  if (metric.unit === "seconds") return formatDuration(metric.value * 1_000);
  if (metric.unit === "bytes") return new Intl.NumberFormat("en-US", { notation: "compact", style: "unit", unit: "byte", unitDisplay: "narrow", maximumFractionDigits: 1 }).format(metric.value);
  if (metric.unit === "unix_ms") return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "medium" }).format(metric.value);
  if (metric.unit === "boolean") return metric.value === 1 ? "PASS" : "FAIL";
  return metric.value.toLocaleString("en-US", { maximumFractionDigits: 2 });
}

function formatDuration(milliseconds: number): string {
  return milliseconds >= 1_000 ? `${(milliseconds / 1_000).toLocaleString("en-US", { maximumFractionDigits: 1 })}s` : `${milliseconds.toLocaleString("en-US", { maximumFractionDigits: 0 })}ms`;
}

function isMetricResponse(value: unknown): value is { readonly metrics: readonly SystemMetric[] } {
  if (typeof value !== "object" || value === null || !("metrics" in value) || !Array.isArray(value.metrics)) return false;
  return value.metrics.every((item) => typeof item === "object" && item !== null && "name" in item && typeof item.name === "string" && "value" in item && typeof item.value === "number" && Number.isFinite(item.value) && "unit" in item && typeof item.unit === "string");
}
