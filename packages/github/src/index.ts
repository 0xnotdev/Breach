import type { CandidateState } from "@breach/contracts";

const apiRoot = "https://api.github.com";
const apiVersion = "2026-03-10";

export interface GitHubResponse {
  status: number;
  body: unknown;
  headers: Readonly<Record<string, string>>;
}

export interface GitHubTransport {
  get(url: string, headers: Readonly<Record<string, string>>): Promise<GitHubResponse>;
}

export class AsyncSerialDispatcher {
  readonly #transport: GitHubTransport;
  readonly #headers: Readonly<Record<string, string>>;
  #tail: Promise<void> = Promise.resolve();

  constructor(transport: GitHubTransport, token?: string) {
    this.#transport = transport;
    this.#headers = Object.freeze({
      accept: "application/vnd.github+json",
      "x-github-api-version": apiVersion,
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    });
  }

  async get(url: string): Promise<GitHubResponse> {
    const absoluteUrl = url.startsWith("https://") ? url : `${apiRoot}${url.startsWith("/") ? "" : "/"}${url}`;
    const pending = this.#tail.then(async () => this.#transport.get(absoluteUrl, this.#headers));
    this.#tail = pending.then(
      () => undefined,
      () => undefined,
    );
    return pending;
  }
}

export interface RepositoryMetadata {
  id: number;
  name: string;
  fullName: string;
  htmlUrl: string;
  description: string | null;
  fork: boolean;
}

export interface CandidateDecision {
  state: "WAITING_FOR_COMMIT" | "SKIPPED";
  score: number;
}

export class CandidatePolicy {
  readonly #minimumScore: number;
  readonly #capacityRatio: number;

  constructor(options: { minimumScore: number; capacityRatio: number }) {
    if (options.capacityRatio < 0 || options.capacityRatio > 1) {
      throw new RangeError("Capacity ratio must be between 0 and 1");
    }
    this.#minimumScore = options.minimumScore;
    this.#capacityRatio = options.capacityRatio;
  }

  classify(repository: RepositoryMetadata): CandidateDecision {
    const searchable = `${repository.name} ${repository.description ?? ""}`.toLocaleLowerCase("en-US");
    const securityTerms = [
      "api",
      "backend",
      "server",
      "auth",
      "payment",
      "cloud",
      "bot",
      "deploy",
      "docker",
      "terraform",
    ];
    const score = (repository.fork ? 0 : 1) + securityTerms.reduce(
      (total, term) => total + (searchable.includes(term) ? 2 : 0),
      0,
    );
    const capacityBucket = repository.id % 10_000;
    const withinCapacity = capacityBucket < Math.floor(this.#capacityRatio * 10_000);
    return {
      score,
      state: !repository.fork && score >= this.#minimumScore && withinCapacity
        ? "WAITING_FOR_COMMIT"
        : "SKIPPED",
    };
  }
}

export interface DiscoveryCandidateRecord {
  repoId: number;
  fullName: string;
  htmlUrl: string;
  discoveredAt: Date;
  priorityScore: number;
  candidateState: "WAITING_FOR_COMMIT" | "SKIPPED";
}

export interface DiscoverySink {
  bootstrapDiscovery(
    streamName: string,
    frontierCursor: number,
    bootstrappedAt: Date,
  ): Promise<unknown>;
  recordDiscoveryPage(
    streamName: string,
    nextCursor: number,
    candidates: readonly DiscoveryCandidateRecord[],
  ): Promise<void>;
}

function parseRepository(value: unknown): RepositoryMetadata {
  if (typeof value !== "object" || value === null) throw new Error("Invalid repository metadata");
  const row = value as Record<string, unknown>;
  if (
    typeof row.id !== "number" ||
    !Number.isSafeInteger(row.id) ||
    typeof row.name !== "string" ||
    typeof row.full_name !== "string" ||
    typeof row.html_url !== "string" ||
    (row.description !== null && typeof row.description !== "string") ||
    typeof row.fork !== "boolean"
  ) {
    throw new Error("Invalid repository metadata");
  }
  return {
    id: row.id,
    name: row.name,
    fullName: row.full_name,
    htmlUrl: row.html_url,
    description: row.description,
    fork: row.fork,
  };
}

function nextLink(headers: Readonly<Record<string, string>>): string | null {
  const link = headers.link;
  if (link === undefined) return null;
  for (const part of link.split(",")) {
    const match = /^\s*<([^>]+)>;\s*rel="next"\s*$/u.exec(part);
    if (match?.[1] !== undefined) return match[1];
  }
  return null;
}

export class DiscoveryCollector {
  readonly #dispatcher: AsyncSerialDispatcher;
  readonly #policy: CandidatePolicy;
  readonly #sink: DiscoverySink;
  readonly #now: () => Date;

  constructor(options: {
    dispatcher: AsyncSerialDispatcher;
    policy: CandidatePolicy;
    sink: DiscoverySink;
    now?: () => Date;
  }) {
    this.#dispatcher = options.dispatcher;
    this.#policy = options.policy;
    this.#sink = options.sink;
    this.#now = options.now ?? (() => new Date());
  }

  async bootstrap(): Promise<number> {
    const result = await this.#dispatcher.get(
      "/search/repositories?q=is%3Apublic&sort=created&order=desc&per_page=100",
    );
    if (result.status === 403 || result.status === 429) {
      throw new GitHubRateLimitError(result.status, retryAtFromHeaders(result.headers, this.#now()));
    }
    if (result.status !== 200 || typeof result.body !== "object" || result.body === null) {
      throw new Error(`GitHub discovery bootstrap failed with status ${String(result.status)}`);
    }
    const items = (result.body as Record<string, unknown>).items;
    if (!Array.isArray(items) || items.length === 0) {
      throw new Error("GitHub discovery bootstrap returned no repository frontier");
    }
    const repositoryIds = items.map((item) => {
      if (typeof item !== "object" || item === null) {
        throw new Error("GitHub discovery bootstrap returned invalid repository metadata");
      }
      const id = (item as Record<string, unknown>).id;
      if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) {
        throw new Error("GitHub discovery bootstrap returned invalid repository metadata");
      }
      return id;
    });
    const frontier = Math.max(...repositoryIds);
    await this.#sink.bootstrapDiscovery("public-repositories", frontier, this.#now());
    return frontier;
  }

  async catchUp(initialCursor: number): Promise<number> {
    let cursor = initialCursor;
    let url: string | null = `${apiRoot}/repositories?since=${String(cursor)}`;

    while (url !== null) {
      const result = await this.#dispatcher.get(url);
      if (result.status === 403 || result.status === 429) {
        throw new GitHubRateLimitError(result.status, retryAtFromHeaders(result.headers, this.#now()));
      }
      if (result.status !== 200 || !Array.isArray(result.body)) {
        throw new Error(`GitHub discovery failed with status ${String(result.status)}`);
      }

      const repositories = result.body.map(parseRepository);
      if (repositories.length > 0) {
        const nextCursor = Math.max(cursor, ...repositories.map((repository) => repository.id));
        const discoveredAt = this.#now();
        const candidates = repositories.map((repository) => {
          const decision = this.#policy.classify(repository);
          return {
            repoId: repository.id,
            fullName: repository.fullName,
            htmlUrl: repository.htmlUrl,
            discoveredAt,
            priorityScore: decision.score,
            candidateState: decision.state,
          } satisfies DiscoveryCandidateRecord;
        });
        await this.#sink.recordDiscoveryPage("public-repositories", nextCursor, candidates);
        cursor = nextCursor;
      }
      url = nextLink(result.headers);
    }
    return cursor;
  }
}

export class GitHubRateLimitError extends Error {
  readonly status: number;
  readonly retryAt: Date;

  constructor(status: number, retryAt: Date) {
    super(`GitHub rate limited the request with status ${String(status)}`);
    this.name = "GitHubRateLimitError";
    this.status = status;
    this.retryAt = retryAt;
  }
}

export interface GateCandidate {
  repoId: number;
  fullName: string;
  attempts: number;
}

export interface ScanPermit {
  authorization: "commit-gate-v1";
  repoId: number;
  fullName: string;
  headSha: string;
  issuedAt: Date;
}

const issuedPermits = new WeakSet<object>();

export function assertValidScanPermit(permit: ScanPermit): void {
  if (!issuedPermits.has(permit)) {
    throw new Error("Snapshot access requires a valid commit-gate permit");
  }
}

export type GateOutcome =
  | { kind: "ready"; permit: ScanPermit; rateLimitRemaining?: number }
  | { kind: "waiting"; nextCheckAt: Date; attempt: number }
  | { kind: "closed"; reason: "not_public_or_gone" | "recheck_exhausted" }
  | { kind: "rate_limited"; retryAt: Date }
  | { kind: "failed"; reason: string };

const recheckMinutes = [1, 5, 30, 120, 1_440] as const;

function retryAtFromHeaders(headers: Readonly<Record<string, string>>, now: Date): Date {
  const retryAfter = Number(headers["retry-after"]);
  if (Number.isFinite(retryAfter) && retryAfter >= 0) {
    return new Date(now.getTime() + retryAfter * 1_000);
  }
  const resetSeconds = Number(headers["x-ratelimit-reset"]);
  if (Number.isFinite(resetSeconds) && resetSeconds > 0) return new Date(resetSeconds * 1_000);
  return new Date(now.getTime() + 60_000);
}

function waitingOutcome(attempts: number, now: Date): GateOutcome {
  const delay = recheckMinutes[attempts];
  if (delay === undefined) return { kind: "closed", reason: "recheck_exhausted" };
  return {
    kind: "waiting",
    nextCheckAt: new Date(now.getTime() + delay * 60_000),
    attempt: attempts + 1,
  };
}

export class CommitGate {
  readonly #dispatcher: AsyncSerialDispatcher;
  readonly #now: () => Date;

  constructor(dispatcher: AsyncSerialDispatcher, now: () => Date = () => new Date()) {
    this.#dispatcher = dispatcher;
    this.#now = now;
  }

  async check(candidate: GateCandidate): Promise<GateOutcome> {
    if (!/^[^/\s]+\/[^/\s]+$/u.test(candidate.fullName)) {
      return { kind: "failed", reason: "invalid_repository_name" };
    }
    const result = await this.#dispatcher.get(
      `/repos/${candidate.fullName}/commits?per_page=1`,
    );
    const now = this.#now();

    if (result.status === 409) return waitingOutcome(candidate.attempts, now);
    if (result.status === 404) return { kind: "closed", reason: "not_public_or_gone" };
    if (result.status === 403 || result.status === 429) {
      return { kind: "rate_limited", retryAt: retryAtFromHeaders(result.headers, now) };
    }
    if (result.status !== 200 || !Array.isArray(result.body)) {
      return { kind: "failed", reason: `unexpected_status_${String(result.status)}` };
    }
    const first: unknown = result.body[0];
    if (first === undefined) return waitingOutcome(candidate.attempts, now);
    if (typeof first !== "object" || first === null) {
      return { kind: "failed", reason: "invalid_commit_response" };
    }
    const sha = (first as Record<string, unknown>).sha;
    if (typeof sha !== "string" || !/^[a-f0-9]{40}$/iu.test(sha)) {
      return { kind: "failed", reason: "invalid_commit_sha" };
    }
    const remainingText = result.headers["x-ratelimit-remaining"];
    const remaining = remainingText === undefined ? undefined : Number(remainingText);
    const permit: ScanPermit = {
      authorization: "commit-gate-v1",
      repoId: candidate.repoId,
      fullName: candidate.fullName,
      headSha: sha,
      issuedAt: now,
    };
    issuedPermits.add(permit);
    return {
      kind: "ready",
      permit,
      ...(remaining !== undefined && Number.isFinite(remaining)
        ? { rateLimitRemaining: remaining }
        : {}),
    };
  }
}

export type PushWakeOutcome =
  | { kind: "wake"; repoId: number; fullName: string; headSha: string }
  | { kind: "ignored" };

export function applyPushEvent(
  event: unknown,
  candidate: { repoId: number; state: CandidateState } | null,
): PushWakeOutcome {
  if (candidate === null || candidate.state !== "WAITING_FOR_COMMIT") return { kind: "ignored" };
  if (typeof event !== "object" || event === null) return { kind: "ignored" };
  const record = event as Record<string, unknown>;
  if (record.type !== "PushEvent") return { kind: "ignored" };
  const repository = record.repo;
  const payload = record.payload;
  if (
    typeof repository !== "object" ||
    repository === null ||
    typeof payload !== "object" ||
    payload === null
  ) {
    return { kind: "ignored" };
  }
  const repo = repository as Record<string, unknown>;
  const push = payload as Record<string, unknown>;
  if (
    repo.id !== candidate.repoId ||
    typeof repo.name !== "string" ||
    typeof push.head !== "string" ||
    !/^[a-f0-9]{40}$/iu.test(push.head) ||
    /^0+$/u.test(push.head)
  ) {
    return { kind: "ignored" };
  }
  return { kind: "wake", repoId: candidate.repoId, fullName: repo.name, headSha: push.head };
}
