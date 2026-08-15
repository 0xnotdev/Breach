import { createServer } from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";
import { createWorkerRuntime, readWorkerConfig, type WorkerConfig, type WorkerRuntime } from "./runtime.js";

export interface WorkerSchedulerStatus {
  phase: "idle" | "running" | "waiting" | "stopping" | "stopped";
  cyclesCompleted: number;
  lastCycleSucceeded: boolean | null;
  lastStartedAt: Date | null;
  lastCompletedAt: Date | null;
}

export class WorkerScheduler {
  readonly #cycle: () => Promise<unknown>;
  readonly #pollIntervalMs: number;
  readonly #now: () => Date;
  readonly #onError: (error: unknown) => void;
  #phase: WorkerSchedulerStatus["phase"] = "idle";
  #cyclesCompleted = 0;
  #lastCycleSucceeded: boolean | null = null;
  #lastStartedAt: Date | null = null;
  #lastCompletedAt: Date | null = null;
  #stopping = false;
  #loop: Promise<void> | null = null;
  #delayController: AbortController | null = null;

  constructor(options: {
    cycle: () => Promise<unknown>;
    pollIntervalMs: number;
    now?: () => Date;
    onError?: (error: unknown) => void;
  }) {
    if (!Number.isFinite(options.pollIntervalMs) || options.pollIntervalMs < 0) {
      throw new RangeError("Worker poll interval must be non-negative");
    }
    this.#cycle = options.cycle;
    this.#pollIntervalMs = options.pollIntervalMs;
    this.#now = options.now ?? (() => new Date());
    this.#onError = options.onError ?? (() => undefined);
  }

  start(): void {
    if (this.#loop !== null) return;
    this.#loop = this.#run();
  }

  async stop(): Promise<void> {
    this.#stopping = true;
    if (this.#phase !== "stopped") this.#phase = "stopping";
    this.#delayController?.abort();
    if (this.#loop !== null) await this.#loop;
    else this.#phase = "stopped";
  }

  status(): WorkerSchedulerStatus {
    return {
      phase: this.#phase,
      cyclesCompleted: this.#cyclesCompleted,
      lastCycleSucceeded: this.#lastCycleSucceeded,
      lastStartedAt: this.#lastStartedAt,
      lastCompletedAt: this.#lastCompletedAt,
    };
  }

  #shouldStop(): boolean {
    return this.#stopping;
  }

  async #run(): Promise<void> {
    while (!this.#shouldStop()) {
      this.#phase = "running";
      this.#lastStartedAt = this.#now();
      try {
        await this.#cycle();
        this.#lastCycleSucceeded = true;
      } catch (error) {
        this.#lastCycleSucceeded = false;
        this.#onError(error);
      } finally {
        this.#cyclesCompleted += 1;
        this.#lastCompletedAt = this.#now();
      }
      if (this.#shouldStop()) break;
      const elapsed = this.#lastCompletedAt.getTime() - this.#lastStartedAt.getTime();
      const delayMs = Math.max(0, this.#pollIntervalMs - elapsed);
      this.#phase = "waiting";
      this.#delayController = new AbortController();
      try {
        await sleep(delayMs, undefined, { signal: this.#delayController.signal });
      } catch (error) {
        if (!(error instanceof Error) || error.name !== "AbortError") throw error;
      } finally {
        this.#delayController = null;
      }
    }
    this.#phase = "stopped";
  }
}

export interface WorkerRuntimeDependencies {
  readonly config?: WorkerConfig;
  readonly pool?: Pool;
  readonly runtime?: WorkerRuntime;
}

export async function startWorker(dependencies: WorkerRuntimeDependencies = {}) {
  const config = dependencies.config ?? readWorkerConfig(process.env);
  const ownsPool = dependencies.pool === undefined;
  const pool = dependencies.pool ?? new Pool({ connectionString: config.databaseUrl, max: 4 });
  const runtime = dependencies.runtime ?? await createWorkerRuntime(config, pool);
  const scheduler = new WorkerScheduler({ cycle: () => runtime.runCycle(), pollIntervalMs: config.pollIntervalMs, onError: () => { process.stderr.write("Breach worker cycle failed\n"); } });
  const health = createServer((request, response) => { const worker = scheduler.status(); const ready = worker.lastCycleSucceeded === true && worker.phase !== "stopping" && worker.phase !== "stopped"; const status = request.url === "/healthz" ? 200 : request.url === "/readyz" && ready ? 200 : 503; response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(JSON.stringify({ status: status === 200 ? "ok" : "not_ready", worker, quota: runtime.quotaStatus() })); });
  await new Promise<void>((resolve) => health.listen(config.healthPort, "0.0.0.0", resolve));
  scheduler.start();
  let stopPromise: Promise<void> | null = null;
  const stop = async () => {
    if (stopPromise !== null) return stopPromise;
    stopPromise = (async () => { await scheduler.stop(); await new Promise<void>((resolve) => health.close(() => { resolve(); })); if (ownsPool) await pool.end(); })();
    return stopPromise;
  };
  process.once("SIGTERM", () => { void stop(); }); process.once("SIGINT", () => { void stop(); }); return { health, stop };
}

const invokedPath = process.argv[1];
/* v8 ignore start -- trivial process entry wrapper; startWorker is exercised through its injectable production seam. */
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) startWorker().catch(() => { process.stderr.write("Breach worker failed to start\n"); process.exitCode = 1; });
/* v8 ignore stop */
