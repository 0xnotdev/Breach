"use client";

import { useEffect, useState } from "react";
import type { ReviewState, SanitizedFinding } from "@breach/contracts";
import Link from "next/link";

type SubmittedReview = Exclude<ReviewState, "UNREVIEWED">;
type DetailState =
  | { readonly kind: "loading" }
  | { readonly kind: "ready"; readonly finding: SanitizedFinding; readonly openOnGitHub: string }
  | { readonly kind: "missing" }
  | { readonly kind: "error" };

const reviewOptions: readonly SubmittedReview[] = ["CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"];

export function Investigation({ findingId }: { findingId: string }) {
  const [reload, setReload] = useState(0);
  const [detail, setDetail] = useState<DetailState>({ kind: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/findings/${encodeURIComponent(findingId)}`, {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (response.status === 404) {
          setDetail({ kind: "missing" });
          return;
        }
        if (!response.ok) throw new Error("Finding service unavailable");
        const payload: unknown = await response.json();
        if (!isDetail(payload)) throw new Error("Finding detail is invalid");
        setDetail({ kind: "ready", finding: payload.finding, openOnGitHub: payload.openOnGitHub });
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setDetail({ kind: "error" });
      });
    return () => controller.abort();
  }, [findingId, reload]);

  if (detail.kind === "loading") return <DetailBoundary title="Loading investigation…" message="Requesting sanitized evidence from the operator API." />;
  if (detail.kind === "missing") return <DetailBoundary title="Finding unavailable" message="The sanitized record was not found." />;
  if (detail.kind === "error") return <DetailBoundary title="Investigation unavailable" message="The operator API could not be reached." onRetry={() => { setDetail({ kind: "loading" }); setReload((value) => value + 1); }} />;
  return <InvestigationView initialFinding={detail.finding} openOnGitHub={detail.openOnGitHub} />;
}

function InvestigationView({ initialFinding, openOnGitHub }: { initialFinding: SanitizedFinding; openOnGitHub: string }) {
  const [finding, setFinding] = useState(initialFinding);
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(next: SubmittedReview) {
    if (unsafeNote(note)) {
      setMessage("Note rejected: enter a short judgment without source, credentials, or secret-like values.");
      return;
    }
    setSaving(true);
    setMessage("");
    try {
      const response = await fetch(`/api/findings/${encodeURIComponent(finding.findingId)}/review`, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        cache: "no-store",
        body: JSON.stringify({ state: next, ...(note.trim() === "" ? {} : { note: note.trim() }) }),
      });
      if (!response.ok) {
        setMessage(response.status === 400
          ? "Review rejected: use a short judgment-only note without source or credentials."
          : "Review could not be saved. Try again.");
        return;
      }
      const payload: unknown = await response.json();
      if (!isReview(payload, finding.findingId)) throw new Error("Invalid review response");
      setFinding(payload.finding);
      setNote("");
      setMessage(`Review saved as ${reviewLabel(payload.finding.reviewState)}.`);
    } catch {
      setMessage("Review could not be saved. Try again.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="app-shell">
      <InvestigationNavigation status="Persisted evidence" statusDetail="Metadata only" />
      <main className="workspace investigation">
        <header className="topbar detail-header"><div><Link className="back-link" href="/">← Findings</Link><p className="eyebrow">Investigation</p><h1>{findingTitle(finding)}</h1><p className="subtitle">{finding.repository.fullName} · {finding.revision.sha.slice(0, 12)} · {finding.coverage?.languagesModeled.map(titleCase).join(", ") || "language not modeled"}</p></div><span className={`severity severity-${finding.severity}`}>{titleCase(finding.severity)}</span></header>
        <div className="evidence-warning"><strong>Static evidence, not runtime confirmation</strong><span>No execution · no active testing · no deployment confirmation</span></div>

        <FindingEvidence finding={finding} />

        <div className="detail-grid">
          <EvidenceList title="Reasons surfaced" items={reasons(finding)} />
          <EvidenceList title="Observed barriers" items={barriers(finding)} />
          <EvidenceList title="Coverage & limitations" items={coverageAndLimitations(finding)} />
        </div>
        <section className="review-panel" aria-labelledby="review-heading">
          <div><p className="eyebrow">HUMAN VALIDATION</p><h2 id="review-heading">Review finding</h2><p>Current state: <strong>{reviewLabel(finding.reviewState)}</strong></p></div>
          <label><span>Optional safe note</span><textarea disabled={saving} maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Record judgment only—never paste source or credentials" /></label>
          <div className="review-actions">{reviewOptions.map((option) => <button disabled={saving} key={option} type="button" onClick={() => { void submit(option); }}>{reviewLabel(option).toLocaleUpperCase("en-US")}</button>)}</div>
          <p className="review-message" role="status">{saving ? "Saving review…" : message}</p>
        </section>
        <a className="github-link" href={openOnGitHub} rel="noreferrer" target="_blank">Open on GitHub <span aria-hidden="true">↗</span></a>
      </main>
    </div>
  );
}

function FindingEvidence({ finding }: { finding: SanitizedFinding }) {
  if (finding.secretEvidence !== undefined) {
    const secret = finding.secretEvidence;
    return <section className="secret-panel" aria-label="Redacted secret evidence"><Fact label="Provider" value={secret.provider ?? "Not identified"} /><Fact label="Type" value={secret.type} /><Fact label="Location" value={`${secret.path}:${String(secret.line)}`} /><Fact label="Confidence" value={`${String(Math.round(finding.confidence * 100))}/100`} /><Fact label="HMAC fingerprint" value={`${secret.fingerprint.slice(0, 12)}…${secret.fingerprint.slice(-12)}`} /><p>Raw value NOT RETAINED</p></section>;
  }
  if (finding.dependencyEvidence !== undefined) {
    const dependency = finding.dependencyEvidence;
    return <section className="secret-panel" aria-label="Dependency advisory evidence"><Fact label="Package" value={dependency.packageName} /><Fact label="Version" value={dependency.version} /><Fact label="Ecosystem" value={dependency.ecosystem} /><Fact label="Advisory" value={dependency.advisoryId} /><Fact label="Manifest" value={dependency.manifestPath} /></section>;
  }
  if (finding.configEvidence !== undefined) {
    const config = finding.configEvidence;
    return <section className="secret-panel" aria-label="Configuration evidence"><Fact label="Rule ID" value={config.ruleId} /><Fact label="Location" value={`${config.path}:${String(config.line)}`} /><Fact label="Severity" value={titleCase(finding.severity)} /><Fact label="Confidence" value={`${String(Math.round(finding.confidence * 100))}/100`} /><Fact label="Static rationale" value={config.rationale} /></section>;
  }
  const path = finding.path ?? [];
  return <><section className="path-panel" aria-label="Semantic attack path">{path.length === 0 ? <div className="path-node"><small>PATH</small><strong>No semantic path retained</strong></div> : path.map((node, index) => <div className="path-node" key={`${node.role}-${node.file}-${String(node.line)}-${String(index)}`}><small>{node.role.toLocaleUpperCase("en-US")}</small><strong>{node.symbol ?? `${node.file}:${String(node.line)}`}</strong><em>{node.file}:{String(node.line)}</em>{index < path.length - 1 && <span aria-hidden="true">→</span>}</div>)}</section><section className="secret-panel evidence-facts" aria-label="Exploitability evidence"><Fact label="Category" value={findingTitle(finding)} /><Fact label="Confidence" value={`${String(Math.round(finding.confidence * 100))}/100`} /><Fact label="Score" value={finding.exploitability === undefined ? "Not scored" : `${String(finding.exploitability.score)}/100`} /><Fact label="Static level" value={finding.exploitability === undefined ? "Not classified" : titleCase(finding.exploitability.level.replaceAll("_", " "))} /></section></>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><small>{label}</small><strong>{value}</strong></div>;
}

function EvidenceList({ title, items }: { title: string; items: readonly string[] }) {
  return <section className="detail-card"><h2>{title}</h2><ul>{items.map((item) => <li key={item}>{item}</li>)}</ul></section>;
}

function DetailBoundary({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return <div className="app-shell"><InvestigationNavigation status="Operator API" statusDetail={onRetry === undefined ? "Loading or unavailable" : "Unavailable"} /><main className="workspace investigation"><Link className="back-link" href="/">← Findings</Link><section className="empty-state detail-empty" role="status"><h1>{title}</h1><p>{message}</p>{onRetry !== undefined && <button className="filter-button" type="button" onClick={onRetry}>Retry</button>}</section></main></div>;
}

function InvestigationNavigation({ status, statusDetail }: { status: string; statusDetail: string }) {
  return <aside className="sidebar"><Link className="brand" href="/" aria-label="Breach findings home"><span className="brand-mark" aria-hidden="true">B</span><span><strong>Breach</strong><small>passive analysis</small></span></Link><nav aria-label="Primary navigation"><Link className="nav-link active" href="/" aria-current="page"><span>01</span>Findings</Link><Link className="nav-link" href="/stream"><span>02</span>Stream</Link><Link className="nav-link" href="/system"><span>03</span>System</Link></nav><div className="sidebar-note"><span className="status-dot" aria-hidden="true" /><div><strong>{status}</strong><small>{statusDetail}</small></div></div><p className="build-tag">VALIDATION MVP · HEAD ONLY</p></aside>;
}

function reasons(finding: SanitizedFinding): readonly string[] {
  const items = [`${String(Math.round(finding.confidence * 100))}% static finding confidence`, `Category: ${findingTitle(finding)}`];
  if (finding.exploitability?.attackerSourceIdentified === true) items.push("Attacker-controlled source identified");
  if (finding.exploitability?.completeDataflowObserved === true) items.push("Complete modeled source-to-sink data flow observed");
  if (finding.dependencyEvidence !== undefined) items.push(`Exact advisory match: ${finding.dependencyEvidence.advisoryId}`);
  if (finding.configEvidence !== undefined) items.push(finding.configEvidence.rationale);
  if (finding.secretEvidence !== undefined) items.push("Provider-aware secret structure and context matched");
  return items;
}

function barriers(finding: SanitizedFinding): readonly string[] {
  const items: string[] = [];
  if (finding.exploitability?.sanitizerObserved === true) items.push("A recognized sanitizer was observed on the modeled path");
  if (finding.exploitability?.authBarrierObserved === true) items.push("An authentication barrier was observed on the modeled path");
  if (finding.exploitability !== undefined && items.length === 0) items.push("No recognized sanitizer or authentication barrier was observed on the modeled path");
  items.push("Runtime controls and deployment exposure were not verified");
  return items;
}

function coverageAndLimitations(finding: SanitizedFinding): readonly string[] {
  const coverage = finding.coverage;
  if (coverage === undefined) return ["Coverage metadata is unavailable", "History was not scanned", "Static evidence only; this is not proof of exploitability or security"];
  const items = [
    `${coverage.scanComplete ? "Complete" : "Partial"} bounded scan of ${coverage.ref}`,
    `${String(coverage.filesAnalyzed)} of ${String(coverage.filesEligible)} eligible files analyzed; ${String(coverage.filesSeen)} files observed`,
    `${String(coverage.bytesInspected)} bytes inspected`,
    `Modeled languages: ${coverage.languagesModeled.map(titleCase).join(", ") || "none"}`,
    "First observed committed HEAD only; history was not scanned",
    "Static evidence only; no runtime verification, active testing, or deployment confirmation",
  ];
  for (const reason of [...coverage.snapshotPartialReasons, ...coverage.analysisPartialReasons]) items.push(`Partial coverage: ${reason.replaceAll("_", " ")}`);
  return items;
}

function isDetail(value: unknown): value is { readonly finding: SanitizedFinding; readonly openOnGitHub: string } {
  return typeof value === "object" && value !== null && "finding" in value && "openOnGitHub" in value && typeof value.openOnGitHub === "string";
}

function isReview(value: unknown, findingId: string): value is { readonly finding: SanitizedFinding } {
  return typeof value === "object" && value !== null && "finding" in value && typeof value.finding === "object" && value.finding !== null && "findingId" in value.finding && value.finding.findingId === findingId && "reviewState" in value.finding && reviewOptions.includes(value.finding.reviewState as SubmittedReview);
}

function findingTitle(finding: SanitizedFinding): string {
  const labels: Readonly<Record<string, string>> = { command_injection: "Command Injection", sql_injection: "SQL Injection", ssrf: "Server-Side Request Forgery", path_traversal: "Path Traversal", code_injection: "Code Injection", unsafe_deserialization: "Unsafe Deserialization", secret_exposure: "Exposed Secret", vulnerable_dependency: "Vulnerable Dependency", configuration: "Configuration Risk" };
  return labels[finding.category] ?? titleCase(finding.category.replaceAll("_", " "));
}

function reviewLabel(value: ReviewState): string {
  return titleCase(value.replaceAll("_", " "));
}

function titleCase(value: string): string {
  return value.toLocaleLowerCase("en-US").replace(/\b\w/gu, (letter) => letter.toLocaleUpperCase("en-US"));
}

function unsafeNote(note: string): boolean {
  return note.length > 500 || /(?:AKIA[0-9A-Z]{16}|-----BEGIN|(?:password|token|secret|api[_-]?key|access[_-]?key)[A-Z0-9_-]*\s*[:=]|[A-Za-z0-9+/]{40,}={0,2})/iu.test(note);
}
