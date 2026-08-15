import { LiveStream } from "../ui/LiveStream";
import { OperatorShell } from "../ui/OperatorShell";

export default function StreamPage() {
  return <OperatorShell active="Stream" status="Event stream" statusDetail="Connection shown in feed"><main className="workspace"><header className="topbar"><div><p className="eyebrow">EVENT TELEMETRY</p><h1>Live state transitions</h1><p className="subtitle">Sanitized repository lifecycle metadata. No GitHub response bodies, source, snippets, or credentials.</p></div></header><LiveStream /><footer className="coverage-footer"><span>METADATA ONLY</span><p>Events contain repository identity, state, timestamps, and bounded reason codes.</p></footer></main></OperatorShell>;
}
