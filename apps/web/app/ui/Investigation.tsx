"use client";

import Link from "next/link";
import { useState } from "react";
import type { DemoFinding, FindingDetail, ReviewState } from "../data";

const reviewOptions: readonly ReviewState[] = ["Confirmed", "False positive", "Uncertain"];

export function Investigation({ finding, detail }: { finding: DemoFinding; detail: FindingDetail }) {
  const [review, setReview] = useState<ReviewState>(finding.review);
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");
  const githubUrl = `https://github.com/${finding.repository}/blob/${detail.revision}/${detail.path}#L${String(detail.line)}`;

  function submit(next: ReviewState) {
    if (unsafeNote(note)) {
      setMessage("Note rejected: enter a short judgment without source, credentials, or secret-like values.");
      return;
    }
    setReview(next);
    setMessage(`Review saved as ${next}. Validation metrics updated.`);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link className="brand" href="/" aria-label="Breach findings home"><span className="brand-mark" aria-hidden="true">B</span><span><strong>Breach</strong><small>passive analysis</small></span></Link>
        <nav aria-label="Primary navigation"><Link className="nav-link active" href="/" aria-current="page"><span>01</span>Findings</Link><Link className="nav-link" href="/stream"><span>02</span>Stream</Link><Link className="nav-link" href="/system"><span>03</span>System</Link></nav>
        <div className="sidebar-note"><span className="status-dot" aria-hidden="true" /><div><strong>Evidence retained</strong><small>Metadata only</small></div></div>
        <p className="build-tag">VALIDATION MVP · HEAD ONLY</p>
      </aside>
      <main className="workspace investigation">
        <header className="topbar detail-header"><div><Link className="back-link" href="/">← Findings</Link><p className="eyebrow">Investigation</p><h1>{finding.title}</h1><p className="subtitle">{finding.repository} · {detail.revision} · {finding.language}</p></div><span className={`severity severity-${finding.severity.toLocaleLowerCase("en-US")}`}>{finding.severity}</span></header>
        <div className="evidence-warning"><strong>Static evidence, not runtime confirmation</strong><span>No execution · no active testing · no deployment confirmation</span></div>

        {detail.secret ? <SecretEvidence detail={detail} /> : <PathEvidence detail={detail} />}

        <div className="detail-grid">
          <EvidenceList title="Reasons surfaced" items={detail.reasons} />
          <EvidenceList title="Observed barriers" items={detail.barriers} />
          <EvidenceList title="Coverage & limitations" items={[...detail.coverage, ...detail.limitations]} />
        </div>
        <section className="review-panel" aria-labelledby="review-heading">
          <div><p className="eyebrow">HUMAN VALIDATION</p><h2 id="review-heading">Review finding</h2><p>Current state: <strong>{review}</strong></p></div>
          <label><span>Optional safe note</span><textarea maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Record judgment only—never paste source or credentials" /></label>
          <div className="review-actions">{reviewOptions.map((option) => <button key={option} type="button" onClick={() => submit(option)}>{option.toLocaleUpperCase("en-US")}</button>)}</div>
          <p className="review-message" role="status">{message}</p>
        </section>
        <a className="github-link" href={githubUrl} rel="noreferrer" target="_blank">Open on GitHub <span aria-hidden="true">↗</span></a>
      </main>
    </div>
  );
}

function PathEvidence({ detail }: { detail: FindingDetail }) {
  const nodes = [{ label: "ENTRY", value: "POST /api/render" }, { label: "SOURCE", value: detail.source }, ...detail.steps.map((value) => ({ label: "FLOW", value })), { label: "SINK", value: detail.sink }];
  return <section className="path-panel" aria-label="Semantic attack path">{nodes.map((node, index) => <div className="path-node" key={`${node.label}-${node.value}`}><small>{node.label}</small><strong>{node.value}</strong>{index < nodes.length - 1 && <span aria-hidden="true">→</span>}</div>)}</section>;
}

function SecretEvidence({ detail }: { detail: FindingDetail }) {
  const secret = detail.secret!;
  return <section className="secret-panel" aria-label="Redacted secret evidence"><div><small>Type</small><strong>{secret.type}</strong></div><div><small>Location</small><strong>{secret.location}</strong></div><div><small>Confidence</small><strong>{secret.confidence}/100</strong></div><div><small>Fingerprint</small><strong>{secret.fingerprint}</strong></div><p>Raw value NOT RETAINED</p></section>;
}

function EvidenceList({ title, items }: { title: string; items: readonly string[] }) {
  return <section className="detail-card"><h2>{title}</h2><ul>{items.map((item) => <li key={item}>{item}</li>)}</ul></section>;
}

function unsafeNote(note: string) {
  return note.length > 500 || /(?:AKIA[0-9A-Z]{16}|-----BEGIN|(?:password|token|secret|api[_-]?key)\s*[:=]|[A-Za-z0-9+/]{40,}={0,2})/i.test(note);
}
