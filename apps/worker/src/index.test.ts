import { describe, expect, it } from "vitest";
import { WorkerScheduler } from "./index.js";

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
});
