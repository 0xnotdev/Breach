import { createHash } from "node:crypto";
import {
  correlateOsv,
  parseDependencies,
  scanConfiguration,
  type AnalyzerFile,
  type OsvTransport,
  type SecretScanner,
} from "@breach/analyzers";
import {
  sanitizedFindingSchema,
  type CandidateState,
  type Coverage,
  type SanitizedFinding,
} from "@breach/contracts";
import type { PassiveAnalysisResult, PassiveExploitabilityAnalyzer } from "@breach/dataflow";
import type { GateCandidate, GateOutcome, ScanPermit } from "@breach/github";

export interface SnapshotHandle {
  readonly files: readonly AnalyzerFile[];
  readonly coverage: Coverage;
  release(): void;
}

export interface SnapshotAccess {
  read(permit: ScanPermit): Promise<SnapshotHandle>;
}

export interface GateAccess {
  check(candidate: GateCandidate): Promise<GateOutcome>;
}

export interface DataflowAccess {
  analyze(files: readonly AnalyzerFile[]): PassiveAnalysisResult;
}

export interface LifecycleStore {
  transition(repoId: number, state: CandidateState): Promise<void>;
  scheduleCommitCheck(repoId: number, nextCheckAt: Date, attempt: number): Promise<void>;
  claimScan(repoId: number, headSha: string, startedAt: Date): Promise<boolean>;
  saveFindings(findings: readonly SanitizedFinding[]): Promise<void>;
  completeScan(
    repoId: number,
    headSha: string,
    state: CandidateState,
    coverage: Coverage,
  ): Promise<void>;
  recordMetric(
    name: string,
    value: number,
    labels: Readonly<Record<string, string>>,
  ): Promise<void>;
}

export type ProcessResult =
  | { kind: "waiting"; nextCheckAt: Date }
  | { kind: "rate_limited"; retryAt: Date }
  | { kind: "closed" }
  | { kind: "already_scanned"; headSha: string }
  | { kind: "scanned"; state: "SCANNED_NO_FINDINGS" | "SCANNED_FINDINGS" | "PARTIAL"; findingCount: number }
  | { kind: "failed"; reason: "gate_failed" | "analysis_failed" };

interface OrchestratorOptions {
  gate: GateAccess;
  snapshots: SnapshotAccess;
  store: LifecycleStore;
  secretScanner: SecretScanner;
  osv: OsvTransport;
  dataflow: DataflowAccess | PassiveExploitabilityAnalyzer;
  now?: () => Date;
  nowMs?: () => number;
}

function deterministicUuid(seed: string): string {
  const hash = createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 32);
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20)}`;
}

function baseFinding(
  candidate: GateCandidate,
  permit: ScanPermit,
  detectedAt: string,
  identity: string,
  coverage: Coverage,
) {
  return {
    findingId: deterministicUuid(`${String(candidate.repoId)}:${permit.headSha}:${identity}`),
    detectedAt,
    repository: {
      id: candidate.repoId,
      fullName: candidate.fullName,
      url: `https://github.com/${candidate.fullName}`,
    },
    revision: { ref: "HEAD", sha: permit.headSha },
    coverage,
    reviewState: "UNREVIEWED" as const,
  };
}

async function createFindings(
  candidate: GateCandidate,
  permit: ScanPermit,
  snapshot: SnapshotHandle,
  secretScanner: SecretScanner,
  osv: OsvTransport,
  dataflow: DataflowAccess,
  detectedAt: string,
): Promise<{ findings: SanitizedFinding[]; analysisPartial: boolean }> {
  const findings: SanitizedFinding[] = [];
  const secrets = secretScanner.scan(snapshot.files);
  for (const secret of secrets) {
    findings.push(
      sanitizedFindingSchema.parse({
        ...baseFinding(
          candidate,
          permit,
          detectedAt,
          `secret:${secret.ruleId}:${secret.path}:${String(secret.line)}:${secret.fingerprint}`,
          snapshot.coverage,
        ),
        category: "secret_exposure",
        cwe: "CWE-798",
        severity: secret.severity,
        confidence: secret.confidence,
        secretEvidence: {
          type: secret.type,
          ...(secret.provider === undefined ? {} : { provider: secret.provider }),
          path: secret.path,
          line: secret.line,
          fingerprint: secret.fingerprint,
        },
      }),
    );
  }

  const dependencies = snapshot.files.flatMap((file) => parseDependencies(file.path, file.bytes));
  const dependencyFindings = await correlateOsv(dependencies, osv);
  for (const dependency of dependencyFindings) {
    findings.push(
      sanitizedFindingSchema.parse({
        ...baseFinding(
          candidate,
          permit,
          detectedAt,
          `dependency:${dependency.ecosystem}:${dependency.package}:${dependency.version}:${dependency.advisoryId}`,
          snapshot.coverage,
        ),
        category: "vulnerable_dependency",
        severity: "high",
        confidence: 1,
      }),
    );
  }

  const configurations = scanConfiguration(snapshot.files);
  for (const configuration of configurations) {
    findings.push(
      sanitizedFindingSchema.parse({
        ...baseFinding(
          candidate,
          permit,
          detectedAt,
          `configuration:${configuration.ruleId}:${configuration.path}:${String(configuration.line)}`,
          snapshot.coverage,
        ),
        category: "configuration",
        severity: configuration.severity,
        confidence: 0.9,
        path: [
          {
            file: configuration.path,
            line: configuration.line,
            role: "sink",
            symbol: configuration.ruleId,
          },
        ],
      }),
    );
  }

  const paths = dataflow.analyze(snapshot.files);
  for (const path of paths.findings) {
    findings.push(
      sanitizedFindingSchema.parse({
        ...baseFinding(
          candidate,
          permit,
          detectedAt,
          `path:${path.category}:${path.path.map((node) => `${node.file}:${String(node.line)}:${node.role}`).join("|")}`,
          snapshot.coverage,
        ),
        category: path.category,
        cwe: path.cwe,
        severity: path.severity,
        confidence: path.score / 100,
        exploitability: {
          score: path.score,
          level: path.level,
          attackerSourceIdentified: path.attackerSourceIdentified,
          completeDataflowObserved: path.completeDataflowObserved,
          sanitizerObserved: path.sanitizerObserved,
          authBarrierObserved: path.authBarrierObserved,
          runtimeVerified: false,
          activeTestingPerformed: false,
          deploymentConfirmed: false,
        },
        path: path.path,
      }),
    );
  }
  return { findings, analysisPartial: paths.diagnostics.partial };
}

export class ScanOrchestrator {
  readonly #gate: GateAccess;
  readonly #snapshots: SnapshotAccess;
  readonly #store: LifecycleStore;
  readonly #secretScanner: SecretScanner;
  readonly #osv: OsvTransport;
  readonly #dataflow: DataflowAccess;
  readonly #now: () => Date;
  readonly #nowMs: () => number;

  constructor(options: OrchestratorOptions) {
    this.#gate = options.gate;
    this.#snapshots = options.snapshots;
    this.#store = options.store;
    this.#secretScanner = options.secretScanner;
    this.#osv = options.osv;
    this.#dataflow = options.dataflow;
    this.#now = options.now ?? (() => new Date());
    this.#nowMs = options.nowMs ?? (() => performance.now());
  }

  async process(candidate: GateCandidate): Promise<ProcessResult> {
    const gate = await this.#gate.check(candidate);
    if (gate.kind === "waiting") {
      await this.#store.scheduleCommitCheck(candidate.repoId, gate.nextCheckAt, gate.attempt);
      await this.#store.recordMetric("commit_gate.waiting", 1, { outcome: "waiting" });
      return { kind: "waiting", nextCheckAt: gate.nextCheckAt };
    }
    if (gate.kind === "rate_limited") {
      await this.#store.transition(candidate.repoId, "RATE_LIMITED");
      await this.#store.recordMetric("github.rate_limited", 1, { outcome: "rate_limited" });
      return { kind: "rate_limited", retryAt: gate.retryAt };
    }
    if (gate.kind === "closed") {
      await this.#store.transition(candidate.repoId, "FAILED");
      await this.#store.recordMetric("commit_gate.closed", 1, { outcome: gate.reason });
      return { kind: "closed" };
    }
    if (gate.kind === "failed") {
      await this.#store.transition(candidate.repoId, "FAILED");
      await this.#store.recordMetric("commit_gate.failed", 1, { outcome: "failed" });
      return { kind: "failed", reason: "gate_failed" };
    }

    const { permit } = gate;
    await this.#store.transition(candidate.repoId, "READY");
    const claimed = await this.#store.claimScan(candidate.repoId, permit.headSha, this.#now());
    if (!claimed) return { kind: "already_scanned", headSha: permit.headSha };
    await this.#store.transition(candidate.repoId, "SCANNING");

    const startedAt = this.#nowMs();
    let snapshot: SnapshotHandle | null = null;
    try {
      snapshot = await this.#snapshots.read(permit);
      const created = await createFindings(
        candidate,
        permit,
        snapshot,
        this.#secretScanner,
        this.#osv,
        this.#dataflow,
        this.#now().toISOString(),
      );
      const coverage = snapshot.coverage;
      snapshot.release();
      snapshot = null;

      await this.#store.saveFindings(created.findings);
      const state: "SCANNED_NO_FINDINGS" | "SCANNED_FINDINGS" | "PARTIAL" =
        !coverage.scanComplete || created.analysisPartial
          ? "PARTIAL"
          : created.findings.length > 0
            ? "SCANNED_FINDINGS"
            : "SCANNED_NO_FINDINGS";
      await this.#store.transition(candidate.repoId, state);
      await this.#store.completeScan(candidate.repoId, permit.headSha, state, coverage);
      await this.#store.recordMetric("scan.completed", 1, { status: state });
      await this.#store.recordMetric("scan.findings", created.findings.length, { status: state });
      await this.#store.recordMetric("scan.bytes", coverage.bytesInspected, { status: state });
      await this.#store.recordMetric("scan.latency_ms", this.#nowMs() - startedAt, { status: state });
      return { kind: "scanned", state, findingCount: created.findings.length };
    } catch {
      if (snapshot !== null) snapshot.release();
      await this.#store.transition(candidate.repoId, "FAILED");
      await this.#store.recordMetric("scan.failed", 1, { stage: "analysis" });
      return { kind: "failed", reason: "analysis_failed" };
    }
  }
}
