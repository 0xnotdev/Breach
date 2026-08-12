"use client";

import { useMemo, useState } from "react";
import { demoFindings } from "../data";

const severities = ["All severity", "Critical", "High", "Medium"] as const;
const families = ["All families", "Exploitability", "Secrets", "Dependencies", "Config"] as const;

export function FindingsConsole() {
  const [severity, setSeverity] = useState<(typeof severities)[number]>("All severity");
  const [family, setFamily] = useState<(typeof families)[number]>("All families");
  const [query, setQuery] = useState("");
  const visible = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase("en-US");
    return demoFindings.filter((finding) =>
      (severity === "All severity" || finding.severity === severity) &&
      (family === "All families" || finding.family === family) &&
      (normalized.length === 0 || finding.title.toLocaleLowerCase("en-US").includes(normalized) || finding.repository.toLocaleLowerCase("en-US").includes(normalized) || finding.language.toLocaleLowerCase("en-US").includes(normalized))
    );
  }, [family, query, severity]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/" aria-label="Breach findings home"><span className="brand-mark" aria-hidden="true">B</span><span><strong>Breach</strong><small>passive analysis</small></span></a>
        <nav aria-label="Primary navigation">
          <a className="nav-link active" href="/" aria-current="page"><span>01</span>Findings</a>
          <a className="nav-link" href="/stream"><span>02</span>Stream</a>
          <a className="nav-link" href="/system"><span>03</span>System</a>
        </nav>
        <div className="sidebar-note"><span className="status-dot" aria-hidden="true" /><div><strong>Collector online</strong><small>Last event 2s ago</small></div></div>
        <p className="build-tag">VALIDATION MVP · HEAD ONLY</p>
      </aside>

      <main className="workspace">
        <header className="topbar"><div><p className="eyebrow">SECURITY STREAM</p><h1>Findings</h1><p className="subtitle">Meaningful static security evidence from newly committed public repositories.</p></div><div className="live-pill"><span className="status-dot" />LIVE</div></header>
        <section className="metric-strip" aria-label="Current validation metrics">
          <Metric value="694" label="repos scanned / hr" /><Metric value="12" label="findings / hr" /><Metric value="3" label="critical" tone="danger" /><Metric value="4.8" label="requests / scan" suffix="avg" /><Metric value="0" label="retention violations" tone="healthy" />
        </section>
        <section className="control-row" aria-label="Finding filters">
          <label className="search-field"><span className="sr-only">Search findings</span><span aria-hidden="true">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search repository, finding, language" /></label>
          <label><span className="sr-only">Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value as (typeof severities)[number])}>{severities.map((option) => <option key={option}>{option}</option>)}</select></label>
          <label><span className="sr-only">Finding family</span><select value={family} onChange={(event) => setFamily(event.target.value as (typeof families)[number])}>{families.map((option) => <option key={option}>{option}</option>)}</select></label>
          <button className="filter-button" type="button" onClick={() => { setQuery(""); setSeverity("All severity"); setFamily("All families"); }}>Reset</button>
        </section>
        <div className="table-head" aria-hidden="true"><span>Finding / repository</span><span>Evidence</span><span>Score</span><span>Detected</span></div>
        <section className="finding-list" aria-label={`${String(visible.length)} findings`}>
          {visible.map((finding, index) => (
            <a className="finding-row" href={`/findings/${finding.id}`} key={finding.id}>
              <span className="row-index">{String(index + 1).padStart(2, "0")}</span>
              <span className="finding-identity"><span className={`severity severity-${finding.severity.toLocaleLowerCase("en-US")}`}>{finding.severity}</span><strong>{finding.title}</strong><small>{finding.repository} · {finding.language}</small></span>
              <span className="finding-evidence"><strong>{finding.entry}</strong><small>{finding.flow}</small></span>
              <span className="finding-score"><strong>{finding.score}<span>/100</span></strong><small>{finding.scoreLabel}</small></span>
              <span className="finding-time"><strong>{finding.detected}</strong><small>{finding.review}</small></span><span className="row-arrow" aria-hidden="true">↗</span>
            </a>
          ))}
          {visible.length === 0 && <div className="empty-state" role="status"><strong>No surfaced finding within modeled coverage</strong><p>Adjust the filters. This does not mean the repository is secure.</p></div>}
        </section>
        <footer className="coverage-footer"><span>STATIC EVIDENCE ONLY</span><p>No runtime verification · No active testing · No deployment confirmation · Source and raw secrets are not retained.</p></footer>
      </main>
    </div>
  );
}

function Metric({ value, label, suffix, tone = "default" }: { value: string; label: string; suffix?: string; tone?: "default" | "danger" | "healthy" }) {
  return <div className={`metric metric-${tone}`}><strong>{value}</strong>{suffix && <span>{suffix}</span>}<small>{label}</small></div>;
}
