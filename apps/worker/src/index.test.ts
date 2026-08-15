import { describe, expect, it, vi } from "vitest";
import { startWorker, WorkerScheduler } from "./index.js";
import type { Pool } from "pg";
import type { WorkerConfig, WorkerRuntime } from "./runtime.js";

describe("worker scheduler", () => {
  it("workerCyclesNeverOverlap", async () => {
    let active = 0;
    let maximumActive = 0;
    let calls = 0;
    let releaseFirst: (() => void) | undefined;
    const firstCycle = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const scheduler = new WorkerScheduler({
      pollIntervalMs: 5,
      cycle: async () => {
        calls += 1;
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        if (calls === 1) await firstCycle;
        active -= 1;
      },
    });

    scheduler.start();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(calls).toBe(1);
    let stopped = false;
    const stopping = scheduler.stop().then(() => {
      stopped = true;
    });
    await Promise.resolve();
    expect(stopped).toBe(false);
    releaseFirst?.();
    await stopping;

    expect(calls).toBe(1);
    expect(maximumActive).toBe(1);
    expect(scheduler.status()).toMatchObject({ phase: "stopped", cyclesCompleted: 1 });
  });

  it("serves live and ready state from the production worker entry point", async () => {
    const config: WorkerConfig = {
      databaseUrl: "postgresql://unused/when-pool-injected", githubToken: "read-token", fingerprintKey: "worker-entry-fingerprint-key-32-bytes", pollIntervalMs: 5_000, healthPort: 0,
      discoveryMode: "live", discoveryStartCursor: null, candidateMinimumScore: 60, targetSelectionRatio: 0.07, maxDiscoveryPages: 1, maxDiscoveryRequests: 1, maxDiscoveryElapsedMs: 1_000, maxCommitChecksPerCycle: 1, maxScansPerCycle: 1, githubQuotaReserve: 200,
    };
    let cycles = 0;
    const runtime: WorkerRuntime = {
      runCycle: () => { cycles += 1; return Promise.resolve({ nextCursor: null, processed: 0, scansStarted: 0, quotaPaused: false }); },
      quotaStatus: () => ({ remaining: 4_999, limit: 5_000, resetAt: null, secondaryLimited: false, paused: false }),
    };
    let ended = false;
    const pool = { end: () => { ended = true; return Promise.resolve(); } } as unknown as Pool;
    const signalListeners = { sigterm: process.listenerCount("SIGTERM"), sigint: process.listenerCount("SIGINT") };
    const worker = await startWorker({ config, pool, runtime });
    const address = worker.health.address();
    if (typeof address !== "object" || address === null) throw new Error("Worker health server did not bind");
    try {
      const live = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`);
      expect(live.status).toBe(200);
      await vi.waitFor(() => { expect(cycles).toBeGreaterThan(0); });
      const ready = await fetch(`http://127.0.0.1:${String(address.port)}/readyz`);
      expect(ready.status).toBe(200);
      await expect(ready.json()).resolves.toMatchObject({ status: "ok", quota: { remaining: 4_999 }, worker: { lastCycleSucceeded: true } });
      expect((await fetch(`http://127.0.0.1:${String(address.port)}/unknown`)).status).toBe(503);
    } finally {
      await worker.stop();
      await worker.stop();
    }
    expect(ended).toBe(false);
    expect(process.listenerCount("SIGTERM")).toBe(signalListeners.sigterm);
    expect(process.listenerCount("SIGINT")).toBe(signalListeners.sigint);
  });

  it("reports failed cycles and supports stopping before start", async () => {
    expect(() => new WorkerScheduler({ pollIntervalMs: -1, cycle: () => Promise.resolve() })).toThrow(RangeError);
    const idle = new WorkerScheduler({ pollIntervalMs: 0, cycle: () => Promise.resolve() });
    await idle.stop();
    expect(idle.status().phase).toBe("stopped");

    const errors: unknown[] = [];
    let attempted = 0;
    const scheduler = new WorkerScheduler({
      pollIntervalMs: 1,
      cycle: () => { attempted += 1; return Promise.reject(new Error("controlled cycle failure")); },
      onError: (error) => { errors.push(error); },
    });
    scheduler.start();
    scheduler.start();
    await vi.waitFor(() => { expect(attempted).toBeGreaterThan(0); });
    await scheduler.stop();
    expect(errors[0]).toMatchObject({ message: "controlled cycle failure" });
    expect(scheduler.status()).toMatchObject({ phase: "stopped", lastCycleSucceeded: false });
  });
});
