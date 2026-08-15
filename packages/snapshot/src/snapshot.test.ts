import { describe, expect, it } from "vitest";
import {
  AsyncSerialDispatcher,
  CommitGate,
  type GitHubResponse,
  type GitHubTransport,
  type ScanPermit,
} from "@breach/github";
import { SnapshotReadError, SnapshotReader, type BlobStreamTransport } from "./index.js";

class TreeTransport implements GitHubTransport {
  readonly requests: string[] = [];
  readonly #responses: GitHubResponse[];

  constructor(responses: GitHubResponse[]) {
    this.#responses = [...responses];
  }

  get(url: string): Promise<GitHubResponse> {
    this.requests.push(url);
    const next = this.#responses.shift();
    if (next === undefined) return Promise.reject(new Error(`Unexpected request ${url}`));
    return Promise.resolve(next);
  }
}

class BlobTransport implements BlobStreamTransport {
  readonly requests: string[] = [];
  readonly #content: Readonly<Record<string, readonly Uint8Array[]>>;

  constructor(content: Readonly<Record<string, readonly Uint8Array[]>>) {
    this.#content = content;
  }

  async *stream(url: string): AsyncIterable<Uint8Array> {
    await Promise.resolve();
    this.requests.push(url);
    const chunks = this.#content[url];
    if (chunks === undefined) throw new Error(`Unexpected blob ${url}`);
    for (const chunk of chunks) yield chunk;
  }
}

const json = (status: number, body: unknown): GitHubResponse => ({ status, body, headers: {} });

async function issuePermit(treeTransport: TreeTransport): Promise<ScanPermit> {
  const gate = new CommitGate(new AsyncSerialDispatcher(treeTransport), () =>
    new Date("2026-08-12T12:00:00.000Z"),
  );
  const outcome = await gate.check({ repoId: 1101, fullName: "fixture/bounded", attempts: 0 });
  if (outcome.kind !== "ready") throw new Error("Fixture gate did not issue a permit");
  return outcome.permit;
}

describe("bounded committed-HEAD inspection", () => {
  it("rejects a forged permit before any tree or blob request", async () => {
    const tree = new TreeTransport([]);
    const blobs = new BlobTransport({});
    const reader = new SnapshotReader(new AsyncSerialDispatcher(tree), blobs);
    const forged = {
      authorization: "commit-gate-v1",
      repoId: 1101,
      fullName: "fixture/forged",
      headSha: "a".repeat(40),
      issuedAt: new Date(),
    } as ScanPermit;

    await expect(reader.read(forged)).rejects.toThrow("valid commit-gate permit");
    expect(tree.requests).toEqual([]);
    expect(blobs.requests).toEqual([]);
  });

  it("prioritizes high-value blobs and stays inside file/repository budgets", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: false,
        tree: [
          { path: "src/app.ts", type: "blob", sha: "1".repeat(40), size: 8 },
          { path: ".env", type: "blob", sha: "2".repeat(40), size: 6 },
          { path: ".github/workflows/ci.yml", type: "blob", sha: "3".repeat(40), size: 7 },
          { path: "assets/logo.png", type: "blob", sha: "4".repeat(40), size: 4 },
          { path: "dist/bundle.js", type: "blob", sha: "5".repeat(40), size: 5 },
          { path: "large.py", type: "blob", sha: "6".repeat(40), size: 50 },
          { path: "vendor", type: "tree", sha: "7".repeat(40) },
          { path: "module", type: "commit", sha: "8".repeat(40) },
        ],
      }),
    ]);
    const permit = await issuePermit(tree);
    const blobRoot = "https://api.github.com/repos/fixture/bounded/git/blobs/";
    const blobs = new BlobTransport({
      [`${blobRoot}${"2".repeat(40)}`]: [new TextEncoder().encode("A=1234")],
      [`${blobRoot}${"3".repeat(40)}`]: [new TextEncoder().encode("name: x")],
    });
    const reader = new SnapshotReader(new AsyncSerialDispatcher(tree), blobs, {
      maxFileBytes: 10,
      maxRepoBytes: 15,
      maxFiles: 2,
      wallClockMs: 30_000,
    });

    const snapshot = await reader.read(permit);

    expect(snapshot.files.map((file) => file.path)).toEqual([".env", ".github/workflows/ci.yml"]);
    expect(snapshot.coverage).toMatchObject({
      historyScanned: false,
      scanComplete: false,
      snapshotComplete: false,
      analysisComplete: true,
      filesSeen: 6,
      filesEligible: 3,
      filesAnalyzed: 2,
      bytesInspected: 13,
      skippedBinary: 1,
      skippedGenerated: 1,
      skippedOversize: 1,
      skippedBudget: 1,
      skippedUnsupported: 0,
      treeTruncated: false,
      snapshotPartialReasons: ["binary_files_excluded", "generated_files_excluded", "oversized_files_excluded", "file_count_budget_exhausted"],
      analysisPartial: false,
      analysisPartialReasons: [],
    });
    expect(blobs.requests).toEqual([
      `${blobRoot}${"2".repeat(40)}`,
      `${blobRoot}${"3".repeat(40)}`,
    ]);
  });

  it("marks an unexpectedly oversized stream partial without exposing its bytes", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: true,
        tree: [{ path: "src/app.py", type: "blob", sha: "9".repeat(40), size: 4 }],
      }),
    ]);
    const permit = await issuePermit(tree);
    const blobUrl = `https://api.github.com/repos/fixture/bounded/git/blobs/${"9".repeat(40)}`;
    const blobs = new BlobTransport({
      [blobUrl]: [new Uint8Array(8).fill(65), new Uint8Array(8).fill(66)],
    });
    const reader = new SnapshotReader(new AsyncSerialDispatcher(tree), blobs, {
      maxFileBytes: 10,
      maxRepoBytes: 20,
      maxFiles: 10,
      wallClockMs: 30_000,
    });

    const snapshot = await reader.read(permit);
    expect(snapshot.files).toEqual([]);
    expect(snapshot.coverage).toMatchObject({
      scanComplete: false,
      filesAnalyzed: 0,
      skippedOversize: 1,
      treeTruncated: true,
    });
  });

  it("uses a bounded subtree fallback when GitHub truncates the recursive tree", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: true,
        tree: [{ path: "src", type: "tree", sha: "b".repeat(40) }],
      }),
      json(200, {
        truncated: false,
        tree: [{ path: "app.ts", type: "blob", sha: "c".repeat(40), size: 4 }],
      }),
    ]);
    const permit = await issuePermit(tree);
    const blobUrl = `https://api.github.com/repos/fixture/bounded/git/blobs/${"c".repeat(40)}`;
    const blobs = new BlobTransport({ [blobUrl]: [new TextEncoder().encode("code")] });
    const reader = new SnapshotReader(new AsyncSerialDispatcher(tree), blobs);

    const snapshot = await reader.read(permit);

    expect(snapshot.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(snapshot.coverage).toMatchObject({ treeTruncated: true, filesSeen: 1, filesAnalyzed: 1 });
    expect(tree.requests.at(-1)).toContain(`/git/trees/${"b".repeat(40)}?recursive=1`);
  });

  it("overwrites held byte buffers when the ephemeral snapshot is released", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: false,
        tree: [{ path: ".env", type: "blob", sha: "e".repeat(40), size: 6 }],
      }),
    ]);
    const permit = await issuePermit(tree);
    const value = new TextEncoder().encode("SECRET");
    const blobs = new BlobTransport({
      [`https://api.github.com/repos/fixture/bounded/git/blobs/${"e".repeat(40)}`]: [value],
    });
    const snapshot = await new SnapshotReader(new AsyncSerialDispatcher(tree), blobs).read(permit);
    const held = snapshot.files[0]?.bytes;
    expect(new TextDecoder().decode(held)).toBe("SECRET");

    snapshot.release();
    snapshot.release();

    expect(held).toEqual(new Uint8Array(6));
    expect(() => snapshot.files).toThrow("released");
  });

  it("snapshotReleasedOnEveryFailurePath", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: false,
        tree: [
          { path: ".env", type: "blob", sha: "1".repeat(40), size: 6 },
          { path: "app.ts", type: "blob", sha: "2".repeat(40), size: 6 },
        ],
      }),
    ]);
    const permit = await issuePermit(tree);
    const first = new TextEncoder().encode("FIRST!");
    const second = new TextEncoder().encode("SECOND");
    const blobs: BlobStreamTransport = {
      async *stream(url) {
        await Promise.resolve();
        if (url.endsWith("1".repeat(40))) {
          yield first;
          return;
        }
        yield second;
        throw new Error("repository-controlled failure text");
      },
    };

    await expect(new SnapshotReader(new AsyncSerialDispatcher(tree), blobs).read(permit)).rejects.toEqual(expect.objectContaining<Partial<SnapshotReadError>>({ reasonCode: "blob_failed" }));
    expect(first).toEqual(new Uint8Array(6));
    expect(second).toEqual(new Uint8Array(6));
  });

  it("rejects invalid budgets and malformed Git tree responses", async () => {
    const dispatcher = new AsyncSerialDispatcher(new TreeTransport([]));
    const blobs = new BlobTransport({});

    expect(
      () =>
        new SnapshotReader(dispatcher, blobs, {
          maxFileBytes: 0,
          maxRepoBytes: 1,
          maxFiles: 1,
          wallClockMs: 1,
        }),
    ).toThrow("positive");
    expect(
      () =>
        new SnapshotReader(dispatcher, blobs, {
          maxFileBytes: 1,
          maxRepoBytes: Number.NaN,
          maxFiles: 1,
          wallClockMs: 1,
        }),
    ).toThrow("positive");

    for (const response of [json(503, {}), json(200, null), json(200, {}), json(200, { tree: [], truncated: "no" })]) {
      const tree = new TreeTransport([json(200, [{ sha: "a".repeat(40) }]), response]);
      const permit = await issuePermit(tree);
      const reader = new SnapshotReader(new AsyncSerialDispatcher(tree), blobs);
      await expect(reader.read(permit)).rejects.toEqual(expect.objectContaining<Partial<SnapshotReadError>>({ reasonCode: "tree_failed" }));
    }
  });

  it("ignores malformed and unsafe entries while modeling supported languages", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: false,
        tree: [
          null,
          { path: "../escape", type: "tree", sha: "b".repeat(40) },
          { path: "bad", type: "tree", sha: "short" },
          { path: "src", type: "tree", sha: "b".repeat(40) },
          { path: "noop", type: "commit", sha: "c".repeat(40) },
          { path: 7, type: "blob", sha: "d".repeat(40), size: 1 },
          { path: "negative.ts", type: "blob", sha: "d".repeat(40), size: -1 },
          { path: "fractional.ts", type: "blob", sha: "d".repeat(40), size: 1.5 },
          { path: "unsafe\u0000.ts", type: "blob", sha: "d".repeat(40), size: 1 },
          { path: "script.js", type: "blob", sha: "1".repeat(40), size: 2 },
          { path: "worker.py", type: "blob", sha: "2".repeat(40), size: 2 },
          { path: "view.tsx", type: "blob", sha: "3".repeat(40), size: 2 },
        ],
      }),
    ]);
    const permit = await issuePermit(tree);
    const root = "https://api.github.com/repos/fixture/bounded/git/blobs/";
    const blobs = new BlobTransport({
      [`${root}${"1".repeat(40)}`]: [new TextEncoder().encode("js")],
      [`${root}${"2".repeat(40)}`]: [new TextEncoder().encode("py")],
      [`${root}${"3".repeat(40)}`]: [new TextEncoder().encode("ts")],
    });

    const snapshot = await new SnapshotReader(new AsyncSerialDispatcher(tree), blobs).read(permit);

    expect(snapshot.files.map((file) => file.path)).toEqual(["script.js", "view.tsx", "worker.py"]);
    expect(snapshot.coverage.languagesModeled).toEqual(["javascript", "typescript", "python"]);
    expect(snapshot.coverage.filesSeen).toBe(4);
    expect(snapshot.coverage.skippedBinary).toBe(0);
    expect(snapshot.coverage.skippedUnsupported).toBe(1);
  });

  it("bounds truncated subtree fallbacks by status and elapsed time", async () => {
    const tree = new TreeTransport([
      json(200, [{ sha: "a".repeat(40) }]),
      json(200, {
        truncated: true,
        tree: [
          { path: "docs", type: "tree", sha: "1".repeat(40) },
          { path: "src", type: "tree", sha: "2".repeat(40) },
          { path: ".github", type: "tree", sha: "3".repeat(40) },
        ],
      }),
      json(404, {}),
    ]);
    const permit = await issuePermit(tree);
    const times = [0, 0, 2];
    const reader = new SnapshotReader(
      new AsyncSerialDispatcher(tree),
      new BlobTransport({}),
      { maxFileBytes: 10, maxRepoBytes: 10, maxFiles: 2, wallClockMs: 1 },
      () => times.shift() ?? 2,
    );

    const snapshot = await reader.read(permit);

    expect(snapshot.coverage).toMatchObject({ treeTruncated: true, filesSeen: 0 });
    expect(tree.requests.at(-1)).toContain(`/git/trees/${"3".repeat(40)}?recursive=1`);
  });
});
