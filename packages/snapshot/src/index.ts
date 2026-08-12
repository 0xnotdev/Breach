import { coverageSchema, type Coverage } from "@breach/contracts";
import {
  assertValidScanPermit,
  type AsyncSerialDispatcher,
  type ScanPermit,
} from "@breach/github";

export interface BlobStreamTransport {
  stream(
    url: string,
    headers: Readonly<Record<string, string>>,
  ): AsyncIterable<Uint8Array>;
}

export interface SnapshotBudgets {
  maxFileBytes: number;
  maxRepoBytes: number;
  maxFiles: number;
  wallClockMs: number;
}

export interface EphemeralFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

const defaultBudgets: SnapshotBudgets = {
  maxFileBytes: 2 * 1024 * 1024,
  maxRepoBytes: 5 * 1024 * 1024,
  maxFiles: 1_000,
  wallClockMs: 30_000,
};

const highValueNames = new Set([
  ".env",
  ".npmrc",
  ".pypirc",
  "dockerfile",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "poetry.lock",
  "pipfile.lock",
  "cargo.lock",
  "go.mod",
  "gemfile.lock",
  "pom.xml",
  "composer.lock",
  "packages.lock.json",
]);

const highValueSuffixes = [
  ".pem",
  ".key",
  ".tf",
  ".tfvars",
  ".yaml",
  ".yml",
  ".json",
  ".toml",
  ".xml",
  ".lock",
  ".txt",
  ".py",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".go",
  ".rs",
];

const binarySuffixes = [
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".gz",
  ".tar",
  ".7z",
  ".exe",
  ".dll",
  ".so",
  ".wasm",
  ".woff",
  ".woff2",
];

interface TreeBlob {
  path: string;
  sha: string;
  size: number;
}

interface TreeDirectory {
  path: string;
  sha: string;
}

function isUnsafePath(path: string): boolean {
  let hasControlCharacter = false;
  for (let index = 0; index < path.length; index += 1) {
    const codeUnit = path.charCodeAt(index);
    if (codeUnit <= 31 || codeUnit === 127) {
      hasControlCharacter = true;
      break;
    }
  }
  return (
    path.length === 0 ||
    path.startsWith("/") ||
    path.startsWith("\\") ||
    path.split(/[\\/]/u).includes("..") ||
    hasControlCharacter
  );
}

function isGeneratedOrBinary(path: string): boolean {
  const lower = path.toLocaleLowerCase("en-US");
  return (
    binarySuffixes.some((suffix) => lower.endsWith(suffix)) ||
    /(^|\/)(?:node_modules|vendor|dist|build|coverage|\.next|\.git)(?:\/|$)/u.test(lower) ||
    /(?:\.min\.js|\.map)$/u.test(lower)
  );
}

function priorityFor(path: string): number {
  const lower = path.toLocaleLowerCase("en-US");
  const name = lower.split("/").at(-1) ?? lower;
  let priority = 0;
  if (highValueNames.has(name) || name.startsWith(".env.")) priority += 100;
  if (lower.startsWith(".github/workflows/")) priority += 80;
  if (highValueSuffixes.some((suffix) => lower.endsWith(suffix))) priority += 20;
  return priority;
}

function parseTree(body: unknown): {
  blobs: TreeBlob[];
  directories: TreeDirectory[];
  truncated: boolean;
} {
  if (typeof body !== "object" || body === null) throw new Error("Invalid Git tree response");
  const record = body as Record<string, unknown>;
  if (!Array.isArray(record.tree) || typeof record.truncated !== "boolean") {
    throw new Error("Invalid Git tree response");
  }
  const blobs: TreeBlob[] = [];
  const directories: TreeDirectory[] = [];
  for (const item of record.tree) {
    if (typeof item !== "object" || item === null) continue;
    const entry = item as Record<string, unknown>;
    if (
      entry.type === "tree" &&
      typeof entry.path === "string" &&
      typeof entry.sha === "string" &&
      /^[a-f0-9]{40}$/iu.test(entry.sha) &&
      !isUnsafePath(entry.path)
    ) {
      directories.push({ path: entry.path, sha: entry.sha });
      continue;
    }
    if (entry.type !== "blob") continue;
    if (
      typeof entry.path !== "string" ||
      typeof entry.sha !== "string" ||
      !/^[a-f0-9]{40}$/iu.test(entry.sha) ||
      typeof entry.size !== "number" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0
    ) {
      continue;
    }
    blobs.push({ path: entry.path, sha: entry.sha, size: entry.size });
  }
  return { blobs, directories, truncated: record.truncated };
}

function directoryPriority(path: string): number {
  const lower = path.toLocaleLowerCase("en-US");
  if (lower === ".github" || lower.startsWith(".github/")) return 100;
  if (/^(?:src|app|server|api|backend|config|infra)(?:\/|$)/u.test(lower)) return 50;
  return 1;
}

function modeledLanguages(files: readonly EphemeralFile[]): Array<"javascript" | "typescript" | "python"> {
  const modeled = new Set<"javascript" | "typescript" | "python">();
  for (const file of files) {
    const lower = file.path.toLocaleLowerCase("en-US");
    if (lower.endsWith(".py")) modeled.add("python");
    else if (lower.endsWith(".ts") || lower.endsWith(".tsx")) modeled.add("typescript");
    else if (lower.endsWith(".js") || lower.endsWith(".jsx")) modeled.add("javascript");
  }
  return [...modeled];
}

export class EphemeralSnapshot {
  readonly coverage: Coverage;
  #files: EphemeralFile[];
  #released = false;

  constructor(files: EphemeralFile[], coverage: Coverage) {
    this.#files = files;
    this.coverage = coverage;
  }

  get files(): readonly EphemeralFile[] {
    if (this.#released) throw new Error("Ephemeral snapshot has been released");
    return this.#files;
  }

  release(): void {
    if (this.#released) return;
    for (const file of this.#files) file.bytes.fill(0);
    this.#files = [];
    this.#released = true;
  }
}

export class SnapshotReader {
  readonly #treeDispatcher: AsyncSerialDispatcher;
  readonly #blobs: BlobStreamTransport;
  readonly #budgets: SnapshotBudgets;
  readonly #nowMs: () => number;

  constructor(
    treeDispatcher: AsyncSerialDispatcher,
    blobs: BlobStreamTransport,
    budgets: SnapshotBudgets = defaultBudgets,
    nowMs: () => number = () => performance.now(),
  ) {
    for (const value of Object.values(budgets)) {
      if (!Number.isFinite(value) || value <= 0) throw new Error("Snapshot budgets must be positive");
    }
    this.#treeDispatcher = treeDispatcher;
    this.#blobs = blobs;
    this.#budgets = budgets;
    this.#nowMs = nowMs;
  }

  async read(permit: ScanPermit): Promise<EphemeralSnapshot> {
    assertValidScanPermit(permit);
    const startedAt = this.#nowMs();
    const treeResult = await this.#treeDispatcher.get(
      `/repos/${permit.fullName}/git/trees/${permit.headSha}?recursive=1`,
    );
    if (treeResult.status !== 200) {
      throw new Error(`Git tree request failed with status ${String(treeResult.status)}`);
    }
    const tree = parseTree(treeResult.body);
    const discoveredBlobs = [...tree.blobs];
    if (tree.truncated && tree.directories.length > 0) {
      const selectedDirectories = [...tree.directories]
        .sort(
          (left, right) =>
            directoryPriority(right.path) - directoryPriority(left.path) ||
            left.path.localeCompare(right.path),
        )
        .slice(0, Math.min(25, this.#budgets.maxFiles));
      for (const directory of selectedDirectories) {
        if (this.#nowMs() - startedAt >= this.#budgets.wallClockMs) break;
        const subtreeResult = await this.#treeDispatcher.get(
          `/repos/${permit.fullName}/git/trees/${directory.sha}?recursive=1`,
        );
        if (subtreeResult.status !== 200) continue;
        const subtree = parseTree(subtreeResult.body);
        for (const blob of subtree.blobs) {
          const path = `${directory.path}/${blob.path}`;
          if (!isUnsafePath(path)) discoveredBlobs.push({ ...blob, path });
        }
      }
    }
    let skippedBinary = 0;
    let skippedOversize = 0;
    let skippedBudget = 0;
    const candidates: Array<TreeBlob & { priority: number }> = [];

    for (const blob of discoveredBlobs) {
      if (isUnsafePath(blob.path) || isGeneratedOrBinary(blob.path)) {
        skippedBinary += 1;
        continue;
      }
      if (blob.size > this.#budgets.maxFileBytes) {
        skippedOversize += 1;
        continue;
      }
      const priority = priorityFor(blob.path);
      if (priority > 0) candidates.push({ ...blob, priority });
    }
    candidates.sort((left, right) => right.priority - left.priority || left.path.localeCompare(right.path));

    const files: EphemeralFile[] = [];
    let bytesInspected = 0;
    for (const candidate of candidates) {
      if (
        files.length >= this.#budgets.maxFiles ||
        bytesInspected + candidate.size > this.#budgets.maxRepoBytes ||
        this.#nowMs() - startedAt >= this.#budgets.wallClockMs
      ) {
        skippedBudget += 1;
        continue;
      }

      const chunks: Uint8Array[] = [];
      let actualBytes = 0;
      let exceeded = false;
      const url = `${apiRootForPermit(permit)}/git/blobs/${candidate.sha}`;
      for await (const incoming of this.#blobs.stream(url, {
        accept: "application/vnd.github.raw+json",
        "x-github-api-version": apiVersion,
      })) {
        const chunk = incoming.slice();
        actualBytes += chunk.byteLength;
        if (
          actualBytes > this.#budgets.maxFileBytes ||
          bytesInspected + actualBytes > this.#budgets.maxRepoBytes
        ) {
          chunk.fill(0);
          exceeded = true;
          break;
        }
        chunks.push(chunk);
      }

      if (exceeded) {
        for (const chunk of chunks) chunk.fill(0);
        skippedOversize += 1;
        continue;
      }

      const bytes = new Uint8Array(actualBytes);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
        chunk.fill(0);
      }
      files.push({ path: candidate.path, bytes });
      bytesInspected += actualBytes;
    }

    const scanComplete =
      !tree.truncated &&
      skippedBinary === 0 &&
      skippedOversize === 0 &&
      skippedBudget === 0 &&
      files.length === discoveredBlobs.length;
    const coverage = coverageSchema.parse({
      ref: `HEAD@${permit.headSha}`,
      historyScanned: false,
      scanComplete,
      filesSeen: discoveredBlobs.length,
      filesAnalyzed: files.length,
      bytesInspected,
      skippedBinary,
      skippedOversize,
      skippedBudget,
      treeTruncated: tree.truncated,
      languagesModeled: modeledLanguages(files),
    });
    return new EphemeralSnapshot(files, coverage);
  }
}

const apiVersion = "2026-03-10";

function apiRootForPermit(permit: ScanPermit): string {
  return `https://api.github.com/repos/${permit.fullName}`;
}
