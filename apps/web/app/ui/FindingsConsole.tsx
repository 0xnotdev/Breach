"use client";

import { useEffect, useMemo, useState } from "react";
import type { SanitizedFinding } from "@breach/contracts";
import Link from "next/link";

const severities = ["all", "critical", "high", "medium", "low"] as const;
const families = ["all", "exploitability", "secrets", "dependencies", "config"] as const;
type SeverityFilter = (typeof severities)[number];
type FamilyFilter = (typeof families)[number];
type LoadState =
  | { readonly kind: "loading"; readonly findings: readonly SanitizedFinding[] }
  | { readonly kind: "ready"; readonly findings: readonly SanitizedFinding[] }
  | { readonly kind: "error"; readonly findings: readonly SanitizedFinding[] };

export function FindingsConsole() {
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [family, setFamily] = useState<FamilyFilter>("all");
  const [query, setQuery] = useState("");
  const [reload, setReload] = useState(0);
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading", findings: [] });

  useEffect(() => {
    const controller = new AbortController();
    const search = new URLSearchParams({ limit: "100" });
    if (severity !== "all") search.set("severity", severity);
    if (family !== "all") search.set("family", family);
    void fetch(`/api/findings?${search.toString()}`, {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("Finding service unavailable");
        const payload: unknown = await response.json();
        if (!isFindingList(payload)) throw new Error("Finding service returned invalid data");
        setLoadState({ kind: "ready", findings: payload.findings });
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setLoadState((current) => ({ kind: "error", findings: current.findings }));
        }
      });
    return () => controller.abort();
  }, [family, reload, severity]);

  const visible = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase("en-US");
    return loadState.findings.filter((finding) => {
      const searchable = [findingTitle(finding), finding.repository.fullName, ...findingLanguages(finding)].join(" ").toLocaleLowerCase("en-US");
      return normalized.length === 0 || searchable.includes(normalized);
    });
  }, [loadState.findings, query]);

  const criticalCount = loadState.findings.filter((finding) => finding.severity === "critical").length;
  const partialCount = loadState.findings.filter((finding) => finding.coverage !== undefined && !finding.coverage.scanComplete).length;
  const unreviewedCount = loadState.findings.filter((finding) => finding.reviewState === "UNREVIEWED").length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link className="brand" href="/" aria-label="Breach findings home"><span className="brand-mark" aria-hidden="true">B</span><span><strong>Breach</strong><small>passive analysis</small></span></Link>
        <nav aria-label="Primary navigation">
          <Link className="nav-link active" href="/" aria-current="page"><span>01</span>Findings</Link>
          <Link className="nav-link" href="/stream"><span>02</span>Stream</Link>
          <Link className="nav-link" href="/system"><span>03</span>System</Link>
        </nav>
        <div className="sidebar-note"><span className={`status-dot status-${loadState.kind}`} aria-hidden="true" /><div><strong>Operator API</strong><small>{loadState.kind === "ready" ? "Connected" : loadState.kind === "loading" ? "Loading" : "Unavailable"}</small></div></div>
        <p className="build-tag">VALIDATION MVP · HEAD ONLY</p>
      </aside>

      <main className="workspace">
        <header className="topbar"><div><p className="eyebrow">SECURITY STREAM</p><h1>Findings</h1><p className="subtitle">Meaningful static security evidence from newly committed public repositories.</p></div><div className={`live-pill live-${loadState.kind}`}><span className={`status-dot status-${loadState.kind}`} />{loadState.kind === "ready" ? "LIVE DATA" : loadState.kind.toLocaleUpperCase("en-US")}</div></header>
        <section className="metric-strip" aria-label="Loaded finding metrics">
          <Metric value={String(loadState.findings.length)} label="loaded findings" /><Metric value={String(visible.length)} label="matching filters" /><Metric value={String(criticalCount)} label="critical" tone="danger" /><Metric value={String(partialCount)} label="partial scans" /><Metric value={String(unreviewedCount)} label="unreviewed" />
        </section>
        <section className="control-row" aria-label="Finding filters">
          <label className="search-field"><span className="sr-only">Search findings</span><span aria-hidden="true">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search repository, finding, language" /></label>
          <label><span className="sr-only">Severity</span><select value={severity} onChange={(event) => { setLoadState({ kind: "loading", findings: [] }); setSeverity(event.target.value as SeverityFilter); }}>{severities.map((option) => <option key={option} value={option}>{option === "all" ? "All severity" : titleCase(option)}</option>)}</select></label>
          <label><span className="sr-only">Finding family</span><select value={family} onChange={(event) => { setLoadState({ kind: "loading", findings: [] }); setFamily(event.target.value as FamilyFilter); }}>{families.map((option) => <option key={option} value={option}>{option === "all" ? "All families" : titleCase(option)}</option>)}</select></label>
          <button className="filter-button" type="button" onClick={() => { setQuery(""); if (severity !== "all" || family !== "all") { setLoadState({ kind: "loading", findings: [] }); setSeverity("all"); setFamily("all"); } }}>Reset</button>
        </section>
        <div className="table-head" aria-hidden="true"><span>Finding / repository</span><span>Evidence</span><span>Score</span><span>Detected</span></div>
        <section className="finding-list" aria-label={`${String(visible.length)} findings`} aria-busy={loadState.kind === "loading"}>
          {visible.map((finding, index) => (
            <Link className="finding-row" href={`/findings/${finding.findingId}`} key={finding.findingId}>
              <span className="row-index">{String(index + 1).padStart(2, "0")}</span>
              <span className="finding-identity"><span className={`severity severity-${finding.severity}`}>{titleCase(finding.severity)}</span><strong>{findingTitle(finding)}</strong><small>{finding.repository.fullName} · {findingLanguages(finding).join(", ") || "language not modeled"}</small></span>
              <span className="finding-evidence"><strong>{findingEntry(finding)}</strong><small>{findingEvidence(finding)}</small></span>
              <span className="finding-score"><strong>{findingScore(finding)}<span>/100</span></strong><small>{scoreLabel(finding)}</small></span>
              <span className="finding-time"><strong>{formatDetectedAt(finding.detectedAt)}</strong><small>{titleCase(finding.reviewState.replaceAll("_", " "))}</small></span><span className="row-arrow" aria-hidden="true">↗</span>
            </Link>
          ))}
          {loadState.kind === "loading" && <div className="empty-state" role="status"><strong>Loading findings from the operator API…</strong><p>Only sanitized evidence metadata crosses this boundary.</p></div>}
          {loadState.kind === "error" && <div className="empty-state empty-error" role="alert"><strong>Findings are temporarily unavailable</strong><p>The operator API could not be reached. Existing data is not presented as current.</p><button className="filter-button" type="button" onClick={() => { setLoadState({ kind: "loading", findings: [] }); setReload((value) => value + 1); }}>Retry</button></div>}
          {loadState.kind === "ready" && visible.length === 0 && <div className="empty-state" role="status"><strong>{loadState.findings.length === 0 ? "No findings have been surfaced yet" : "No surfaced finding matches these filters"}</strong><p>{loadState.findings.length === 0 ? "The live pipeline has not persisted a finding." : "Adjust the filters. This does not mean the repository is secure."}</p></div>}
        </section>
        <footer className="coverage-footer"><span>STATIC EVIDENCE ONLY</span><p>No runtime verification · No active testing · No deployment confirmation · Source and raw secrets are not retained.</p></footer>
      </main>
    </div>
  );
}

function isFindingList(value: unknown): value is { readonly findings: readonly SanitizedFinding[] } {
  return typeof value === "object" && value !== null && "findings" in value && Array.isArray(value.findings);
}

function findingTitle(finding: SanitizedFinding): string {
  const labels: Readonly<Record<string, string>> = {
    command_injection: "Command Injection", sql_injection: "SQL Injection", ssrf: "Server-Side Request Forgery",
    path_traversal: "Path Traversal", code_injection: "Code Injection", unsafe_deserialization: "Unsafe Deserialization",
    secret_exposure: "Exposed Secret", vulnerable_dependency: "Vulnerable Dependency", configuration: "Configuration Risk",
  };
  return labels[finding.category] ?? titleCase(finding.category.replaceAll("_", " "));
}

function findingLanguages(finding: SanitizedFinding): readonly string[] {
  return finding.coverage?.languagesModeled.map(titleCase) ?? [];
}

function findingEntry(finding: SanitizedFinding): string {
  const node = finding.path?.find((item) => item.role === "entry") ?? finding.path?.[0];
  if (node !== undefined) return `${node.file}:${String(node.line)}`;
  if (finding.secretEvidence !== undefined) return `${finding.secretEvidence.path}:${String(finding.secretEvidence.line)}`;
  if (finding.dependencyEvidence !== undefined) return finding.dependencyEvidence.manifestPath;
  if (finding.configEvidence !== undefined) return `${finding.configEvidence.path}:${String(finding.configEvidence.line)}`;
  return `commit ${finding.revision.sha.slice(0, 7)}`;
}

function findingEvidence(finding: SanitizedFinding): string {
  if (finding.path !== undefined) return finding.path.map((node) => node.symbol ?? node.role).join(" → ");
  if (finding.secretEvidence !== undefined) return `${finding.secretEvidence.type} · raw value not retained`;
  if (finding.dependencyEvidence !== undefined) return `${finding.dependencyEvidence.packageName} ${finding.dependencyEvidence.version} → ${finding.dependencyEvidence.advisoryId}`;
  if (finding.configEvidence !== undefined) return finding.configEvidence.rationale;
  return "Sanitized static evidence";
}

function findingScore(finding: SanitizedFinding): number {
  return finding.exploitability?.score ?? Math.round(finding.confidence * 100);
}

function scoreLabel(finding: SanitizedFinding): string {
  return finding.exploitability?.level.replaceAll("_", " ") ?? "finding confidence";
}

function formatDetectedAt(value: string): string {
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(time) : "Unknown";
}

function titleCase(value: string): string {
  return value.toLocaleLowerCase("en-US").replace(/\b\w/gu, (letter) => letter.toLocaleUpperCase("en-US"));
}

function Metric({ value, label, tone = "default" }: { value: string; label: string; tone?: "default" | "danger" }) {
  return <div className={`metric metric-${tone}`}><strong>{value}</strong><small>{label}</small></div>;
}
