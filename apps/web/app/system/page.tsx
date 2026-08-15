import { OperatorShell } from "../ui/OperatorShell";
import { SystemDashboard } from "../ui/SystemDashboard";

export default function SystemPage() {
  return <OperatorShell active="System" status="System metrics" statusDetail="Live API state shown below"><main className="workspace"><header className="topbar"><div><p className="eyebrow">VALIDATION CONTROL PLANE</p><h1>System</h1><p className="subtitle">PostgreSQL-derived operational performance, validation, and safety measurements for the passive scanner.</p></div></header><SystemDashboard /></main></OperatorShell>;
}
