import { describe, expect, it } from "vitest";
import { SecretScanner, type OsvBatchResponse, type OsvTransport } from "@breach/analyzers";
import { PassiveExploitabilityAnalyzer } from "@breach/dataflow";
import type { CandidateState, Coverage, SanitizedFinding } from "@breach/contracts";
import type { GateOutcome, ScanPermit } from "@breach/github";
import {
  ScanOrchestrator,
  type LifecycleStore,
  type SnapshotAccess,
  type SnapshotHandle,
} from "./index.js";

const fakeSecret = "9vK2Lm4Np6Qr8St0Uv2Wx4Yz6Ab8Cd0Ef2Gh4Ij6";
const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

const completeCoverage: Coverage = {
  ref: `HEAD@${"a".repeat(40)}`,
  historyScanned: false,
  scanComplete: true,
  filesSeen: 3,
  filesAnalyzed: 3,
  bytesInspected: 128,
  skippedBinary: 0,
  skippedOversize: 0,
  skippedBudget: 0,
  treeTruncated: false,
  languagesModeled: ["typescript"],
};

class MemoryLifecycleStore implements LifecycleStore {
  readonly transitions: CandidateState[] = [];
  readonly findings: SanitizedFinding[] = [];
  readonly metrics: Array<{ name: string; value: number; labels: Readonly<Record<string, string>> }> = [];
  readonly schedules: Array<{ nextCheckAt: Date; attempt: number }> = [];
  claimResult = true;
  completion: { state: CandidateState; coverage: Coverage } | null = null;

  transition(_repoId: number, state: CandidateState): Promise<void> {
    this.transitions.push(state);
    return Promise.resolve();
  }

  scheduleCommitCheck(_repoId: number, nextCheckAt: Date, attempt: number): Promise<void> {
    this.schedules.push({ nextCheckAt, attempt });
    return Promise.resolve();
  }

  claimScan(): Promise<boolean> {
    return Promise.resolve(this.claimResult);
  }

  saveFindings(findings: readonly SanitizedFinding[]): Promise<void> {
    this.findings.push(...findings);
    return Promise.resolve();
  }

  completeScan(
    _repoId: number,
    _headSha: string,
    state: CandidateState,
    coverage: Coverage,
  ): Promise<void> {
    this.completion = { state, coverage };
    return Promise.resolve();
  }

  recordMetric(name: string, value: number, labels: Readonly<Record<string, string>>): Promise<void> {
    this.metrics.push({ name, value, labels });
    return Promise.resolve();
  }
}

class FakeSnapshot implements SnapshotHandle {
  readonly files: Array<{ path: string; bytes: Uint8Array }>;
  readonly coverage: Coverage;
  released = false;

  constructor(coverage: Coverage = completeCoverage) {
    this.coverage = coverage;
    this.files = [
      { path: ".env", bytes: bytes(`AWS_SECRET_ACCESS_KEY=${fakeSecret}\n`) },
      {
        path: "routes/run.ts",
        bytes: bytes('router.post("/run", (req, res) => child_process.exec(req.body.command));'),
      },
      {
        path: "package-lock.json",
        bytes: bytes('{"packages":{"node_modules/fixture":{"version":"1.0.0"}}}'),
      },
    ];
  }

  release(): void {
    for (const file of this.files) file.bytes.fill(0);
    this.released = true;
  }
}

const permit: ScanPermit = {
  authorization: "commit-gate-v1",
  repoId: 1301,
  fullName: "fixture/orchestrated",
  headSha: "a".repeat(40),
  issuedAt: new Date("2026-08-12T12:00:00.000Z"),
};

const readyGate = { check: (): Promise<GateOutcome> => Promise.resolve({ kind: "ready", permit }) };

const osv: OsvTransport = {
  queryBatch(request) {
    return Promise.resolve({
      results: request.queries.map(() => ({ vulns: [{ id: "OSV-FAKE-1" }] })),
    } satisfies OsvBatchResponse);
  },
};

describe("scan orchestration lifecycle", () => {
  it("handles rate-limit, closed, and failed gates without reading snapshots", async () => {
    for (const outcome of [{ kind: "rate_limited", retryAt: new Date("2026-08-12T12:01:00.000Z") }, { kind: "closed", reason: "not_public_or_gone" }, { kind: "failed", reason: "unexpected_status" }] as const) {
      const store = new MemoryLifecycleStore(); let reads = 0;
      const orchestrator = new ScanOrchestrator({ gate: { check: () => Promise.resolve(outcome) }, snapshots: { read: () => { reads += 1; return Promise.resolve(new FakeSnapshot()); } }, store, secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"), osv, dataflow: new PassiveExploitabilityAnalyzer() });
      const result = await orchestrator.process({ repoId: 1, fullName: "fixture/gate", attempts: 0 });
      expect(result.kind).toBe(outcome.kind === "failed" ? "failed" : outcome.kind);
      expect(reads).toBe(0);
      expect(store.transitions).toContain(outcome.kind === "rate_limited" ? "RATE_LIMITED" : "FAILED");
    }
  });

  it("records a complete scan with no findings", async () => {
    const store = new MemoryLifecycleStore();
    const emptyCoverage = { ...completeCoverage, filesSeen: 0, filesAnalyzed: 0, bytesInspected: 0, languagesModeled: [] };
    const orchestrator = new ScanOrchestrator({ gate: readyGate, snapshots: { read: () => Promise.resolve({ files: [], coverage: emptyCoverage, release() {} }) }, store, secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"), osv, dataflow: new PassiveExploitabilityAnalyzer() });
    await expect(orchestrator.process({ repoId: 1301, fullName: "fixture/orchestrated", attempts: 0 })).resolves.toMatchObject({ kind: "scanned", state: "SCANNED_NO_FINDINGS", findingCount: 0 });
  });

  it("moves a committed HEAD through analysis and persists only sanitized findings", async () => {
    const store = new MemoryLifecycleStore();
    const snapshot = new FakeSnapshot();
    const snapshotAccess: SnapshotAccess = { read: () => Promise.resolve(snapshot) };
    const orchestrator = new ScanOrchestrator({
      gate: readyGate,
      snapshots: snapshotAccess,
      store,
      secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"),
      osv,
      dataflow: new PassiveExploitabilityAnalyzer(),
      now: () => new Date("2026-08-12T12:00:00.000Z"),
    });

    await expect(
      orchestrator.process({ repoId: 1301, fullName: "fixture/orchestrated", attempts: 0 }),
    ).resolves.toMatchObject({ kind: "scanned", state: "SCANNED_FINDINGS", findingCount: 3 });

    expect(store.transitions).toEqual(["READY", "SCANNING", "SCANNED_FINDINGS"]);
    expect(store.findings).toHaveLength(3);
    expect(snapshot.released).toBe(true);
    expect(snapshot.files.every((entry) => entry.bytes.every((value) => value === 0))).toBe(true);
    const persisted = JSON.stringify({ findings: store.findings, metrics: store.metrics });
    expect(persisted).not.toContain(fakeSecret);
    expect(persisted).not.toContain("router.post");
    expect(store.metrics.map((metric) => metric.name)).toContain("scan.completed");
  });

  it("parks an empty repository without touching snapshot access", async () => {
    const store = new MemoryLifecycleStore();
    let reads = 0;
    const orchestrator = new ScanOrchestrator({
      gate: {
        check: () =>
          Promise.resolve({
            kind: "waiting",
            nextCheckAt: new Date("2026-08-12T12:05:00.000Z"),
            attempt: 2,
          }),
      },
      snapshots: { read: () => { reads += 1; return Promise.resolve(new FakeSnapshot()); } },
      store,
      secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"),
      osv,
      dataflow: new PassiveExploitabilityAnalyzer(),
    });

    await expect(
      orchestrator.process({ repoId: 1302, fullName: "fixture/empty", attempts: 1 }),
    ).resolves.toEqual({ kind: "waiting", nextCheckAt: new Date("2026-08-12T12:05:00.000Z") });
    expect(reads).toBe(0);
    expect(store.schedules).toHaveLength(1);
  });

  it("claims a committed HEAD once so retries are idempotent", async () => {
    const store = new MemoryLifecycleStore();
    store.claimResult = false;
    let reads = 0;
    const orchestrator = new ScanOrchestrator({
      gate: readyGate,
      snapshots: { read: () => { reads += 1; return Promise.resolve(new FakeSnapshot()); } },
      store,
      secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"),
      osv,
      dataflow: new PassiveExploitabilityAnalyzer(),
    });

    await expect(
      orchestrator.process({ repoId: 1301, fullName: "fixture/orchestrated", attempts: 0 }),
    ).resolves.toEqual({ kind: "already_scanned", headSha: "a".repeat(40) });
    expect(reads).toBe(0);
  });

  it("releases buffers and marks failure when an analyzer throws", async () => {
    const store = new MemoryLifecycleStore();
    const snapshot = new FakeSnapshot();
    const orchestrator = new ScanOrchestrator({
      gate: readyGate,
      snapshots: { read: () => Promise.resolve(snapshot) },
      store,
      secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"),
      osv,
      dataflow: { analyze: () => { throw new Error("controlled parser failure"); } },
    });

    await expect(
      orchestrator.process({ repoId: 1301, fullName: "fixture/orchestrated", attempts: 0 }),
    ).resolves.toMatchObject({ kind: "failed" });
    expect(snapshot.released).toBe(true);
    expect(store.transitions.at(-1)).toBe("FAILED");
    expect(JSON.stringify(store.metrics)).not.toContain("controlled parser failure");
  });

  it("keeps a budget-limited scan in the PARTIAL state even when findings exist", async () => {
    const store = new MemoryLifecycleStore();
    const snapshot = new FakeSnapshot({ ...completeCoverage, scanComplete: false, skippedOversize: 1 });
    const orchestrator = new ScanOrchestrator({
      gate: readyGate,
      snapshots: { read: () => Promise.resolve(snapshot) },
      store,
      secretScanner: new SecretScanner("test-key-32-bytes-minimum-1234567890"),
      osv,
      dataflow: new PassiveExploitabilityAnalyzer(),
    });

    await expect(
      orchestrator.process({ repoId: 1301, fullName: "fixture/orchestrated", attempts: 0 }),
    ).resolves.toMatchObject({ kind: "scanned", state: "PARTIAL" });
    expect(store.completion?.state).toBe("PARTIAL");
  });
});
