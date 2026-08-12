import { LiveStream } from "../ui/LiveStream";
import { OperatorShell } from "../ui/OperatorShell";

export default function StreamPage() {
  return <OperatorShell active="Stream"><main className="workspace"><header className="topbar"><div><p className="eyebrow">EVENT TELEMETRY</p><h1>Live state transitions</h1><p className="subtitle">Sanitized repository lifecycle metadata. No GitHub response bodies, source, snippets, or credentials.</p></div><div className="live-pill"><span className="status-dot" />SSE LIVE</div></header><LiveStream /><footer className="coverage-footer"><span>METADATA ONLY</span><p>Events contain repository identity, state, timestamps, bounded reason codes, and aggregate counters.</p></footer></main></OperatorShell>;
}
