import type { ReactNode } from "react";
import Link from "next/link";

export function OperatorShell({ active, children, status = "Collector online", statusDetail = "Last event 2s ago" }: { active: "Findings" | "Stream" | "System"; children: ReactNode; status?: string; statusDetail?: string }) {
  return <div className="app-shell"><aside className="sidebar"><Link className="brand" href="/" aria-label="Breach findings home"><span className="brand-mark" aria-hidden="true">B</span><span><strong>Breach</strong><small>passive analysis</small></span></Link><nav aria-label="Primary navigation">{([ ["Findings", "/"], ["Stream", "/stream"], ["System", "/system"] ] as const).map(([label, href], index) => <Link key={label} className={`nav-link${active === label ? " active" : ""}`} href={href} aria-current={active === label ? "page" : undefined}><span>0{String(index + 1)}</span>{label}</Link>)}</nav><div className="sidebar-note"><span className="status-dot" aria-hidden="true" /><div><strong>{status}</strong><small>{statusDetail}</small></div></div><p className="build-tag">VALIDATION MVP · HEAD ONLY</p></aside>{children}</div>;
}
