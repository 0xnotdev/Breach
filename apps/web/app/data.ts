export type FindingFamily = "Exploitability" | "Secrets" | "Dependencies" | "Config";
export type Severity = "Critical" | "High" | "Medium";
export type ReviewState = "Unreviewed" | "Confirmed" | "False positive" | "Uncertain";

export interface DemoFinding {
  id: string; title: string; severity: Severity; family: FindingFamily; score: number;
  scoreLabel: string; repository: string; language: string; detected: string;
  review: ReviewState; entry: string; flow: string;
}

export interface FindingDetail {
  revision: string;
  path: string;
  line: number;
  source: string;
  steps: readonly string[];
  sink: string;
  reasons: readonly string[];
  barriers: readonly string[];
  coverage: readonly string[];
  limitations: readonly string[];
  secret?: { type: string; location: string; confidence: number; fingerprint: string };
}

export const demoFindings: readonly DemoFinding[] = [
  { id: "cmd-injection-a827f9c", title: "Command Injection", severity: "Critical", family: "Exploitability", score: 96, scoreLabel: "high-confidence static path", repository: "northstar/image-service", language: "TypeScript", detected: "14s ago", review: "Unreviewed", entry: "POST /api/render", flow: "req.body.filename → renderController → child_process.exec" },
  { id: "secret-52f7ab19", title: "Exposed AWS Credential", severity: "Critical", family: "Secrets", score: 98, scoreLabel: "finding confidence", repository: "another/repo", language: "Python", detected: "21s ago", review: "Unreviewed", entry: ".env:8", flow: "AWS Secret Access Key · raw value not retained" },
  { id: "sql-injection-71e38", title: "SQL Injection", severity: "High", family: "Exploitability", score: 87, scoreLabel: "probable static path", repository: "acme/search-api", language: "Python", detected: "1m ago", review: "Uncertain", entry: "POST /search", flow: "query → searchUsers → db.execute" },
  { id: "dependency-osv-2026", title: "Vulnerable Dependency", severity: "High", family: "Dependencies", score: 100, scoreLabel: "exact advisory match", repository: "lantern/worker", language: "JavaScript", detected: "3m ago", review: "Confirmed", entry: "package-lock.json", flow: "fixture-parser 1.2.0 → OSV-2026-0042" },
  { id: "workflow-permissions", title: "Privileged PR Workflow", severity: "Medium", family: "Config", score: 91, scoreLabel: "finding confidence", repository: "vector/deploy-tools", language: "YAML", detected: "7m ago", review: "Unreviewed", entry: ".github/workflows/release.yml:4", flow: "pull_request_target → write-all permissions" },
];

export const demoDetails: Readonly<Record<string, FindingDetail>> = {
  "cmd-injection-a827f9c": {
    revision: "a827f9c", path: "src/routes/render.ts", line: 42,
    source: "req.body.filename", steps: ["renderController", "buildRenderCommand"], sink: "child_process.exec",
    reasons: ["Network-reachable Express route", "Untrusted request field reaches a command sink", "No recognized command argument boundary"],
    barriers: ["Authentication middleware not observed on the modeled route"],
    coverage: ["First observed committed HEAD", "TypeScript route and same-repository call graph", "Tree 100% · selected blobs 100%"],
    limitations: ["No runtime verification", "No active payload delivery", "Framework aliases and dynamic dispatch may be incomplete"],
  },
  "secret-52f7ab19": {
    revision: "52f7ab1", path: ".env", line: 8,
    source: "AWS Secret Access Key", steps: ["structured detector", "context validation"], sink: "HMAC fingerprint",
    reasons: ["Provider-specific structure matched", "Credential-like assignment context", "Placeholder suppressions did not match"],
    barriers: ["The credential was never verified or used"],
    coverage: ["First observed committed HEAD", "Selected configuration blobs", "Raw byte buffer released after analysis"],
    limitations: ["Validity and deployment exposure are unknown", "History and later commits are outside validation scope"],
    secret: { type: "AWS Secret Access Key", location: ".env:8", confidence: 98, fingerprint: "9ad3…17e2" },
  },
};

export function getFinding(id: string) {
  const finding = demoFindings.find((candidate) => candidate.id === id);
  const detail = demoDetails[id];
  return finding && detail ? { finding, detail } : undefined;
}
