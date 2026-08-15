import { timingSafeEqual } from "node:crypto";
import {
  reviewStateSchema,
  sanitizedFindingSchema,
  type CandidateState,
  type ReviewState,
  type SanitizedFinding,
} from "@breach/contracts";

export interface StreamEvent {
  readonly eventId: number;
  readonly repoId: number;
  readonly fullName: string;
  readonly state: CandidateState;
  readonly occurredAt: string;
}

export interface SystemMetric {
  readonly name: string;
  readonly value: number;
  readonly unit: string;
}

export interface OperatorDataSource {
  listFindings(): Promise<readonly SanitizedFinding[]>;
  getFinding(id: string): Promise<SanitizedFinding | null>;
  reviewFinding(
    id: string,
    state: Exclude<ReviewState, "UNREVIEWED">,
    note?: string,
  ): Promise<SanitizedFinding>;
  listEvents(afterEventId?: number): Promise<readonly StreamEvent[]>;
  getSystemMetrics(): Promise<readonly SystemMetric[]>;
}

const severityRank: Readonly<Record<SanitizedFinding["severity"], number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const exploitabilityFamilies = new Set([
  "command_injection",
  "sql_injection",
  "ssrf",
  "path_traversal",
  "code_injection",
  "unsafe_deserialization",
]);

function safeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function invalidRequest(): Response {
  return json({ error: "invalid_request" }, 400);
}

function hasSensitiveContent(note: string): boolean {
  return (
    note.length > 1_000 ||
    /(?:secret|password|passwd|token|api[_-]?key|private[_-]?key)\s*[:=]/iu.test(note) ||
    /\b[A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY)[A-Z0-9_]*\s*=/u.test(note) ||
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(note) ||
    /[A-Za-z0-9_\-/+=]{48,}/u.test(note)
  );
}

function findingFamily(finding: SanitizedFinding): string {
  if (exploitabilityFamilies.has(finding.category)) return "exploitability";
  if (finding.category === "secret_exposure") return "secrets";
  if (finding.category === "vulnerable_dependency") return "dependencies";
  return "config";
}

function matchesFilters(finding: SanitizedFinding, search: URLSearchParams): boolean {
  const severity = search.get("severity");
  if (severity !== null && finding.severity !== severity) return false;
  const family = search.get("family");
  if (family !== null && findingFamily(finding) !== family) return false;
  const level = search.get("level");
  if (level !== null && finding.exploitability?.level !== level) return false;
  const language = search.get("language");
  if (language !== null && !finding.coverage?.languagesModeled.includes(language as never)) return false;
  const repository = search.get("repository");
  if (repository !== null && finding.repository.fullName !== repository) return false;
  const review = search.get("review");
  if (review !== null && finding.reviewState !== review) return false;
  const since = search.get("since");
  if (since !== null) {
    const sinceMs = Date.parse(since);
    if (!Number.isFinite(sinceMs) || Date.parse(finding.detectedAt) < sinceMs) return false;
  }
  return true;
}

function findingPage(search: URLSearchParams): { limit: number; offset: number } | null {
  const parse = (name: "limit" | "offset", fallback: number, minimum: number, maximum: number) => {
    const values = search.getAll(name);
    if (values.length === 0) return fallback;
    const value = values[0];
    if (values.length !== 1 || value === undefined || !/^\d+$/u.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
  };
  const limit = parse("limit", 100, 1, 250);
  const offset = parse("offset", 0, 0, 1_000_000);
  return limit === null || offset === null ? null : { limit, offset };
}

function safeGitHubLink(finding: SanitizedFinding): string {
  const node = finding.path?.find((item) => item.role === "source") ?? finding.path?.[0];
  const base = `${finding.repository.url}/commit/${finding.revision.sha}`;
  if (node === undefined || !/^[^/\\].*$/u.test(node.file) || node.file.includes("..")) return base;
  const encodedPath = node.file.split("/").map(encodeURIComponent).join("/");
  return `${finding.repository.url}/blob/${finding.revision.sha}/${encodedPath}#L${String(node.line)}`;
}

function sanitizeEvent(value: StreamEvent): StreamEvent {
  if (
    !Number.isSafeInteger(value.eventId) ||
    !Number.isSafeInteger(value.repoId) ||
    !/^[^/\s]+\/[^/\s]+$/u.test(value.fullName) ||
    !Number.isFinite(Date.parse(value.occurredAt))
  ) {
    throw new Error("Invalid event metadata");
  }
  return {
    eventId: value.eventId,
    repoId: value.repoId,
    fullName: value.fullName,
    state: value.state,
    occurredAt: value.occurredAt,
  };
}

function sanitizeMetric(value: SystemMetric): SystemMetric {
  if (
    !/^[a-z][a-z0-9_.]*$/u.test(value.name) ||
    !Number.isFinite(value.value) ||
    !/^[a-z][a-z0-9_/]*$/u.test(value.unit)
  ) {
    throw new Error("Invalid system metric");
  }
  return { name: value.name, value: value.value, unit: value.unit };
}

export class OperatorRouter {
  readonly #data: OperatorDataSource;
  readonly #token: string;

  constructor(data: OperatorDataSource, token: string) {
    if (new TextEncoder().encode(token).byteLength < 16) {
      throw new Error("Operator token must be at least 16 bytes");
    }
    this.#data = data;
    this.#token = token;
  }

  async handle(request: Request): Promise<Response> {
    const presented = request.headers.get("authorization")?.replace(/^Bearer\s+/iu, "") ?? "";
    if (!safeEqual(presented, this.#token)) return json({ error: "unauthorized" }, 401);

    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/api/findings") {
        const page = findingPage(url.searchParams);
        if (page === null) return invalidRequest();
        const findings = (await this.#data.listFindings())
          .map((item) => sanitizedFindingSchema.parse(item))
          .filter((item) => matchesFilters(item, url.searchParams))
          .sort(
            (left, right) =>
              severityRank[right.severity] - severityRank[left.severity] ||
              (right.exploitability?.score ?? 0) - (left.exploitability?.score ?? 0) ||
              Date.parse(right.detectedAt) - Date.parse(left.detectedAt),
          )
          .slice(page.offset, page.offset + page.limit);
        return json({ findings });
      }

      if (request.method === "GET" && url.pathname === "/api/stream") {
        const afterText = url.searchParams.get("after");
        const after = afterText === null ? undefined : Number(afterText);
        if (after !== undefined && (!Number.isSafeInteger(after) || after < 0)) return invalidRequest();
        const events = await this.#data.listEvents(after);
        const body = events
          .map(sanitizeEvent)
          .map((event) => `id: ${String(event.eventId)}\nevent: state\ndata: ${JSON.stringify(event)}\n\n`)
          .join("");
        return new Response(body, {
          headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-store",
            connection: "keep-alive",
            "x-content-type-options": "nosniff",
          },
        });
      }

      if (request.method === "GET" && url.pathname === "/api/system") {
        const metrics = (await this.#data.getSystemMetrics()).map(sanitizeMetric);
        return json({ metrics });
      }

      const detailMatch = /^\/api\/findings\/([0-9a-f-]+)$/iu.exec(url.pathname);
      if (request.method === "GET" && detailMatch?.[1] !== undefined) {
        const finding = await this.#data.getFinding(detailMatch[1]);
        if (finding === null) return json({ error: "not_found" }, 404);
        const safe = sanitizedFindingSchema.parse(finding);
        return json({ finding: safe, openOnGitHub: safeGitHubLink(safe) });
      }

      const reviewMatch = /^\/api\/findings\/([0-9a-f-]+)\/review$/iu.exec(url.pathname);
      if (request.method === "POST" && reviewMatch?.[1] !== undefined) {
        const body: unknown = await request.json();
        if (typeof body !== "object" || body === null) return invalidRequest();
        const record = body as Record<string, unknown>;
        const state = reviewStateSchema.exclude(["UNREVIEWED"]).safeParse(record.state);
        const note = record.note;
        if (!state.success || (note !== undefined && typeof note !== "string")) return invalidRequest();
        if (typeof note === "string" && hasSensitiveContent(note)) return invalidRequest();
        const updated = await this.#data.reviewFinding(
          reviewMatch[1],
          state.data,
          ...(typeof note === "string" ? [note] : []),
        );
        return json({ finding: sanitizedFindingSchema.parse(updated) });
      }

      return json({ error: "not_found" }, 404);
    } catch {
      return invalidRequest();
    }
  }
}
