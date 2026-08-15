import { describe, expect, it } from "vitest";
import {
  AsyncSerialDispatcher,
  CandidatePolicy,
  CommitGate,
  DiscoveryCollector,
  applyPushEvent,
  type GitHubResponse,
  type GitHubTransport,
  type RepositoryMetadata,
} from "./index.js";

class ScriptedTransport implements GitHubTransport {
  readonly requests: string[] = [];
  readonly headers: Array<Readonly<Record<string, string>>> = [];
  #responses: GitHubResponse[];

  constructor(responses: GitHubResponse[]) {
    this.#responses = [...responses];
  }

  get(url: string, headers: Readonly<Record<string, string>>): Promise<GitHubResponse> {
    this.requests.push(url);
    this.headers.push(headers);
    const response = this.#responses.shift();
    if (response === undefined) throw new Error(`Unexpected request: ${url}`);
    return Promise.resolve(response);
  }
}

const response = (
  status: number,
  body: unknown,
  headers: Readonly<Record<string, string>> = {},
): GitHubResponse => ({ status, body, headers });

describe("GitHub metadata intake and commit authorization", () => {
  it("validates policy bounds and dispatcher recovery/absolute URLs", async () => {
    expect(() => new CandidatePolicy({ minimumScore: 1, targetSelectionRatio: -0.1 })).toThrow(RangeError);
    expect(() => new CandidatePolicy({ minimumScore: 1, targetSelectionRatio: 1.1 })).toThrow(RangeError);
    expect(() => new CandidatePolicy({ minimumScore: -1, targetSelectionRatio: 0.1 })).toThrow(RangeError);
    expect(() => new CandidatePolicy({ minimumScore: 1.5, targetSelectionRatio: 0.1 })).toThrow(RangeError);
    expect(() => new CandidatePolicy({ minimumScore: 1, targetSelectionRatio: Number.NaN })).toThrow(RangeError);
    let calls = 0;
    const dispatcher = new AsyncSerialDispatcher({ get: (url) => { calls += 1; return calls === 1 ? Promise.reject(new Error("transient")) : Promise.resolve(response(200, url)); } });
    await expect(dispatcher.get("https://api.github.com/absolute")).rejects.toThrow("transient");
    await expect(dispatcher.get("relative")).resolves.toMatchObject({ body: "https://api.github.com/relative" });
  });

  it("prioritizes the highest-scoring eligible metadata before capacity", () => {
    const policy = new CandidatePolicy({ minimumScore: 20, targetSelectionRatio: 0.25 });
    const repositories = [
      {
        id: 704,
        name: "payment-auth-api",
        fullName: "fixture/payment-auth-api",
        htmlUrl: "https://github.com/fixture/payment-auth-api",
        description: "Cloud backend server with Docker and Terraform",
        fork: false,
        ownerType: "Organization",
      },
      {
        id: 703,
        name: "backend-api",
        fullName: "fixture/backend-api",
        htmlUrl: "https://github.com/fixture/backend-api",
        description: "Small server",
        fork: false,
        ownerType: "User",
      },
      {
        id: 702,
        name: "tutorial-api",
        fullName: "fixture/tutorial-api",
        htmlUrl: "https://github.com/fixture/tutorial-api",
        description: "Homework notes and docs",
        fork: false,
        ownerType: "User",
      },
      {
        id: 701,
        name: "mirror",
        fullName: "fixture/mirror",
        htmlUrl: "https://github.com/fixture/mirror",
        description: "Generated repository mirror",
        fork: true,
        ownerType: "Organization",
      },
    ] satisfies RepositoryMetadata[];

    expect(policy.admit(repositories)).toEqual([
      { state: "WAITING_FOR_COMMIT", score: 87, reason: "selected" },
      { state: "SKIPPED", score: 37, reason: "capacity" },
      { state: "SKIPPED", score: 0, reason: "score" },
      { state: "SKIPPED", score: 0, reason: "score" },
    ]);
    expect(() => new CandidatePolicy({ minimumScore: 101, targetSelectionRatio: 0.07 })).toThrow(
      "0 and 100",
    );
    expect(policy.admit([])).toEqual([]);
    const highestPriority = repositories[0];
    expect(highestPriority).toBeDefined();
    if (highestPriority === undefined) throw new Error("Missing candidate fixture");
    expect(new CandidatePolicy({ minimumScore: 0, targetSelectionRatio: 0 }).admit([highestPriority])).toEqual([
      { state: "SKIPPED", score: 87, reason: "capacity" },
    ]);
  });

  it("records every paginated discovery item before the cursor advances", async () => {
    const transport = new ScriptedTransport([
      response(
        200,
        [
          {
            id: 801,
            name: "api",
            full_name: "fixture/api",
            html_url: "https://github.com/fixture/api",
            description: "backend api",
            fork: false,
          },
        ],
        { link: '<https://api.github.com/repositories?since=801>; rel="next"' },
      ),
      response(200, [
        {
          id: 802,
          name: "docs",
          full_name: "fixture/docs",
          html_url: "https://github.com/fixture/docs",
          description: "docs",
          fork: false,
        },
      ]),
    ]);
    const pages: Array<{ cursor: number; ids: number[] }> = [];
    const collector = new DiscoveryCollector({
      dispatcher: new AsyncSerialDispatcher(transport, "test-token"),
      policy: new CandidatePolicy({ minimumScore: 5, targetSelectionRatio: 1 }),
      sink: {
        bootstrapDiscovery: () => Promise.resolve(),
        recordDiscoveryPage(_stream, cursor, candidates) {
          pages.push({ cursor, ids: candidates.map((candidate) => candidate.repoId) });
          return Promise.resolve();
        },
      },
      now: () => new Date("2026-08-12T12:00:00.000Z"),
    });

    await expect(collector.catchUp(800)).resolves.toBe(802);
    expect(pages).toEqual([
      { cursor: 801, ids: [801] },
      { cursor: 802, ids: [802] },
    ]);
    expect(transport.requests).toEqual([
      "https://api.github.com/repositories?since=800",
      "https://api.github.com/repositories?since=801",
    ]);
    expect(transport.headers[0]).toMatchObject({
      accept: "application/vnd.github+json",
      authorization: "Bearer test-token",
      "x-github-api-version": "2026-03-10",
    });
  });

  it("discoveryNeverBackfillsFromZeroByDefault", async () => {
    const bootstrappedAt = new Date("2026-08-15T10:00:00.000Z");
    const transport = new ScriptedTransport([
      response(200, {
        total_count: 2,
        incomplete_results: false,
        items: [
          { id: 120_004 },
          { id: 120_003 },
        ],
      }),
    ]);
    const initialized: Array<{ stream: string; cursor: number; at: Date }> = [];
    const collector = new DiscoveryCollector({
      dispatcher: new AsyncSerialDispatcher(transport, "test-token"),
      policy: new CandidatePolicy({ minimumScore: 5, targetSelectionRatio: 1 }),
      sink: {
        bootstrapDiscovery(stream, cursor, at) {
          initialized.push({ stream, cursor, at });
          return Promise.resolve();
        },
        recordDiscoveryPage: () => Promise.reject(new Error("bootstrap must not record candidates")),
      },
      now: () => bootstrappedAt,
    });

    await expect(collector.bootstrap()).resolves.toBe(120_004);
    expect(initialized).toEqual([
      { stream: "public-repositories", cursor: 120_004, at: bootstrappedAt },
    ]);
    expect(transport.requests).toEqual([
      "https://api.github.com/search/repositories?q=is%3Apublic&sort=created&order=desc&per_page=100",
    ]);
    expect(transport.requests.every((url) => !url.includes("since=0"))).toBe(true);
  });

  it("rejects an unavailable or malformed discovery frontier", async () => {
    const sink = {
      bootstrapDiscovery: () => Promise.resolve(),
      recordDiscoveryPage: () => Promise.resolve(),
    };
    const policy = new CandidatePolicy({ minimumScore: 0, targetSelectionRatio: 1 });
    const invalidResponses = [
      response(500, {}),
      response(200, null),
      response(200, {}),
      response(200, { items: [] }),
      response(200, { items: [null] }),
      response(200, { items: [{}] }),
      response(200, { items: [{ id: 1.5 }] }),
      response(200, { items: [{ id: 0 }] }),
    ];
    for (const invalid of invalidResponses) {
      const collector = new DiscoveryCollector({
        dispatcher: new AsyncSerialDispatcher(new ScriptedTransport([invalid])),
        policy,
        sink,
      });
      await expect(collector.bootstrap()).rejects.toThrow();
    }
    const limited = new DiscoveryCollector({
      dispatcher: new AsyncSerialDispatcher(
        new ScriptedTransport([response(429, {}, { "retry-after": "5" })]),
      ),
      policy,
      sink,
    });
    await expect(limited.bootstrap()).rejects.toMatchObject({ status: 429 });
  });

  it("serializes GitHub requests even when callers are concurrent", async () => {
    let active = 0;
    let maximum = 0;
    const transport: GitHubTransport = {
      async get() {
        active += 1;
        maximum = Math.max(maximum, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active -= 1;
        return response(200, []);
      },
    };
    const dispatcher = new AsyncSerialDispatcher(transport);

    await Promise.all([dispatcher.get("/one"), dispatcher.get("/two"), dispatcher.get("/three")]);
    expect(maximum).toBe(1);
  });

  it("turns only a successful commit check into a content scan permit", async () => {
    const now = new Date("2026-08-12T12:00:00.000Z");
    const readyTransport = new ScriptedTransport([
      response(200, [{ sha: "a".repeat(40) }], { "x-ratelimit-remaining": "4999" }),
    ]);
    const readyGate = new CommitGate(new AsyncSerialDispatcher(readyTransport), () => now);

    await expect(
      readyGate.check({ repoId: 901, fullName: "fixture/ready", attempts: 0 }),
    ).resolves.toMatchObject({
      kind: "ready",
      permit: { repoId: 901, fullName: "fixture/ready", headSha: "a".repeat(40) },
    });
    expect(readyTransport.requests).toEqual([
      "https://api.github.com/repos/fixture/ready/commits?per_page=1",
    ]);
  });

  it("parks, closes, or rate-limits without making a content request", async () => {
    const now = new Date("2026-08-12T12:00:00.000Z");
    const cases = [
      { status: 409, attempts: 0, kind: "waiting", next: "2026-08-12T12:01:00.000Z" },
      { status: 409, attempts: 1, kind: "waiting", next: "2026-08-12T12:05:00.000Z" },
      { status: 404, attempts: 0, kind: "closed", next: undefined },
      { status: 429, attempts: 0, kind: "rate_limited", next: "2026-08-12T12:02:00.000Z" },
    ];

    for (const item of cases) {
      const headers = item.status === 429 ? { "retry-after": "120" } : {};
      const transport = new ScriptedTransport([response(item.status, {}, headers)]);
      const gate = new CommitGate(new AsyncSerialDispatcher(transport), () => now);
      const outcome = await gate.check({
        repoId: 902,
        fullName: "fixture/empty",
        attempts: item.attempts,
      });

      expect(outcome.kind).toBe(item.kind);
      if ("nextCheckAt" in outcome) expect(outcome.nextCheckAt.toISOString()).toBe(item.next);
      if ("retryAt" in outcome) expect(outcome.retryAt.toISOString()).toBe(item.next);
      expect(transport.requests).toHaveLength(1);
      expect(transport.requests[0]).toContain("/commits?per_page=1");
    }
  });

  it("uses PushEvent only to accelerate an already waiting candidate", () => {
    const event = {
      type: "PushEvent",
      repo: { id: 1001, name: "fixture/waiting" },
      payload: { head: "d".repeat(40), ref: "refs/heads/main", before: "0".repeat(40) },
    };

    expect(applyPushEvent(event, { repoId: 1001, state: "WAITING_FOR_COMMIT" })).toMatchObject({
      kind: "wake",
      repoId: 1001,
      headSha: "d".repeat(40),
    });
    expect(applyPushEvent(event, { repoId: 1001, state: "SKIPPED" })).toEqual({ kind: "ignored" });
    expect(applyPushEvent(event, null)).toEqual({ kind: "ignored" });
    for (const invalid of [null, {}, { type: "Other" }, { type: "PushEvent", repo: null, payload: {} }, { type: "PushEvent", repo: { id: 1002, name: "x/y" }, payload: { head: "d".repeat(40) } }, { type: "PushEvent", repo: { id: 1001, name: "x/y" }, payload: { head: "0".repeat(40) } }]) {
      expect(applyPushEvent(invalid, { repoId: 1001, state: "WAITING_FOR_COMMIT" })).toEqual({ kind: "ignored" });
    }
  });

  it("rejects malformed discovery pages and handles empty/rate-limited discovery", async () => {
    const sink = {
      bootstrapDiscovery: () => Promise.resolve(),
      recordDiscoveryPage: () => Promise.resolve(),
    };
    const policy = new CandidatePolicy({ minimumScore: 0, targetSelectionRatio: 1 });
    for (const scripted of [response(500, []), response(200, {}), response(200, [null]), response(200, [{ id: 1, name: "x", full_name: "x/y", html_url: "https://github.com/x/y", description: 4, fork: false }])]) {
      const collector = new DiscoveryCollector({ dispatcher: new AsyncSerialDispatcher(new ScriptedTransport([scripted])), policy, sink });
      await expect(collector.catchUp(0)).rejects.toThrow();
    }
    const limited = new DiscoveryCollector({ dispatcher: new AsyncSerialDispatcher(new ScriptedTransport([response(403, [], { "x-ratelimit-reset": "2000000000" })])), policy, sink });
    await expect(limited.catchUp(0)).rejects.toMatchObject({ status: 403 });
    const empty = new DiscoveryCollector({ dispatcher: new AsyncSerialDispatcher(new ScriptedTransport([response(200, [])])), policy, sink });
    await expect(empty.catchUp(7)).resolves.toBe(7);
  });

  it("covers every commit-gate defensive outcome", async () => {
    const now = new Date("2026-08-12T12:00:00.000Z");
    const invalidName = new CommitGate(new AsyncSerialDispatcher(new ScriptedTransport([])), () => now);
    await expect(invalidName.check({ repoId: 1, fullName: "invalid", attempts: 0 })).resolves.toMatchObject({ kind: "failed" });
    const cases: Array<{ response: GitHubResponse; attempts?: number; kind: string }> = [
      { response: response(200, []), attempts: 5, kind: "closed" },
      { response: response(403, [], { "x-ratelimit-reset": "2000000000" }), kind: "rate_limited" },
      { response: response(500, []), kind: "failed" },
      { response: response(200, {}), kind: "failed" },
      { response: response(200, ["bad"]), kind: "failed" },
      { response: response(200, [{ sha: "bad" }]), kind: "failed" },
      { response: response(200, [{ sha: "b".repeat(40) }]), kind: "ready" },
    ];
    for (const item of cases) {
      const gate = new CommitGate(new AsyncSerialDispatcher(new ScriptedTransport([item.response])), () => now);
      await expect(gate.check({ repoId: 1, fullName: "fixture/repo", attempts: item.attempts ?? 0 })).resolves.toMatchObject({ kind: item.kind });
    }
  });
});
