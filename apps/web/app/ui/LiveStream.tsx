"use client";

import { useEffect, useState } from "react";

const initialEvents = [
  ["DISCOVERED", "radial/http-fixture", "metadata accepted"], ["SKIPPED", "sable/empty-docs", "candidate policy"], ["WAITING_FOR_COMMIT", "ember/new-repo", "no commit observed"], ["READY", "northstar/image-service", "HEAD a827f9c"], ["SCANNING", "acme/search-api", "bounded snapshot"], ["SCANNED_NO_FINDINGS", "harbor/cli", "coverage recorded"], ["SCANNED_FINDINGS", "lantern/worker", "2 findings"], ["PARTIAL", "vector/deploy-tools", "file cap reached"], ["FAILED", "quiet/parser-fixture", "safe parser error"], ["RATE_LIMITED", "collector/github", "retry after 18s"],
] as const;

export function LiveStream() {
  const [pulse, setPulse] = useState(0);
  useEffect(() => { const timer = window.setInterval(() => setPulse((value) => value + 1), 5000); return () => window.clearInterval(timer); }, []);
  return <section className="stream-panel" aria-label="Sanitized scan state stream" aria-live="polite"><div className="stream-head"><span>State</span><span>Repository</span><span>Safe detail</span><span>Age</span></div>{initialEvents.map(([state, repository, detail], index) => <article className={`stream-event state-${state.toLocaleLowerCase("en-US")}`} key={state}><span className="event-sequence">{String(index + 1).padStart(3, "0")}</span><strong>{state}</strong><span>{repository}</span><span>{detail}</span><time>{index === 0 ? `${String(pulse * 5 + 1)}s` : `${String(index * 7)}s`}</time></article>)}</section>;
}
