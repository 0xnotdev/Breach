import {
  reviewStateSchema,
  sanitizedFindingSchema,
  type SanitizedFinding,
} from "@breach/contracts";

const forwardedFindingFilters = new Set([
  "severity",
  "family",
  "level",
  "language",
  "repository",
  "review",
  "since",
  "limit",
  "offset",
]);
const maximumResponseBytes = 2 * 1024 * 1024;
const maximumReviewBytes = 4 * 1024;

interface FindingListPayload {
  readonly findings: readonly SanitizedFinding[];
}

interface FindingDetailPayload {
  readonly finding: SanitizedFinding;
  readonly openOnGitHub: string;
}

class OperatorProxyError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code);
  }
}

function operatorConfig(): { baseUrl: URL; token: string } {
  const configuredUrl = process.env.API_INTERNAL_URL;
  const token = process.env.OPERATOR_TOKEN;
  if (configuredUrl === undefined || token === undefined || new TextEncoder().encode(token).byteLength < 16) {
    throw new OperatorProxyError(503, "operator_api_unavailable");
  }
  const baseUrl = new URL(configuredUrl);
  if (!new Set(["http:", "https:"]).has(baseUrl.protocol) || baseUrl.username !== "" || baseUrl.password !== "") {
    throw new OperatorProxyError(503, "operator_api_unavailable");
  }
  baseUrl.search = "";
  baseUrl.hash = "";
  return { baseUrl, token };
}

function safeJson(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function proxyFailure(error: unknown): Response {
  return error instanceof OperatorProxyError
    ? safeJson({ error: error.code }, error.status)
    : safeJson({ error: "operator_api_unavailable" }, 503);
}

async function operatorJson(path: string, init: { method: "GET" | "POST"; body?: string }): Promise<unknown> {
  const { baseUrl, token } = operatorConfig();
  const target = new URL(path, baseUrl);
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: init.method,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        ...(init.body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(init.body === undefined ? {} : { body: init.body }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new OperatorProxyError(503, "operator_api_unavailable");
  }

  const body = await upstream.text();
  if (new TextEncoder().encode(body).byteLength > maximumResponseBytes) {
    throw new OperatorProxyError(502, "upstream_response_too_large");
  }
  let parsed: unknown;
  if (upstream.headers.get("content-type")?.split(";", 1)[0]?.trim().toLocaleLowerCase("en-US") !== "application/json") {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  if (!upstream.ok) {
    if (upstream.status === 400) throw new OperatorProxyError(400, "invalid_request");
    if (upstream.status === 404) throw new OperatorProxyError(404, "not_found");
    throw new OperatorProxyError(502, "operator_api_unavailable");
  }
  return parsed;
}

function parseFindingList(value: unknown): FindingListPayload {
  if (typeof value !== "object" || value === null || !("findings" in value) || !Array.isArray(value.findings)) {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  try {
    return { findings: value.findings.map((finding) => sanitizedFindingSchema.parse(finding)) };
  } catch {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
}

function parseFinding(value: unknown): SanitizedFinding {
  if (typeof value !== "object" || value === null || !("finding" in value)) {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  try {
    return sanitizedFindingSchema.parse(value.finding);
  } catch {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
}

function parseFindingDetail(value: unknown): FindingDetailPayload {
  const finding = parseFinding(value);
  if (typeof value !== "object" || value === null || !("openOnGitHub" in value) || typeof value.openOnGitHub !== "string") {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  let github: URL;
  try {
    github = new URL(value.openOnGitHub);
  } catch {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  if (
    github.protocol !== "https:" ||
    github.hostname !== "github.com" ||
    github.username !== "" ||
    github.password !== "" ||
    !value.openOnGitHub.startsWith(`${finding.repository.url}/`)
  ) {
    throw new OperatorProxyError(502, "invalid_upstream_response");
  }
  return { finding, openOnGitHub: value.openOnGitHub };
}

function safeFindingId(id: string): string | null {
  const parsed = sanitizedFindingSchema.shape.findingId.safeParse(id);
  return parsed.success ? parsed.data : null;
}

async function readReview(request: Request): Promise<{ state: "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN"; note?: string }> {
  const mediaType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLocaleLowerCase("en-US");
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (mediaType !== "application/json" || !Number.isSafeInteger(declaredLength) || declaredLength < 0 || declaredLength > maximumReviewBytes) {
    throw new OperatorProxyError(400, "invalid_request");
  }
  const reader = request.body?.getReader();
  if (reader === undefined) throw new OperatorProxyError(400, "invalid_request");
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > maximumReviewBytes) {
      await reader.cancel();
      throw new OperatorProxyError(400, "invalid_request");
    }
    text += decoder.decode(chunk.value, { stream: true });
  }
  text += decoder.decode();
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new OperatorProxyError(400, "invalid_request");
  }
  if (typeof value !== "object" || value === null) throw new OperatorProxyError(400, "invalid_request");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "state" && key !== "note")) throw new OperatorProxyError(400, "invalid_request");
  const state = reviewStateSchema.exclude(["UNREVIEWED"]).safeParse(record.state);
  const note = record.note;
  if (!state.success || (note !== undefined && (typeof note !== "string" || note.length > 500))) {
    throw new OperatorProxyError(400, "invalid_request");
  }
  return { state: state.data, ...(typeof note === "string" ? { note } : {}) };
}

export async function proxyFindingList(request: Request): Promise<Response> {
  try {
    const incoming = new URL(request.url);
    const target = new URL("http://operator.local/api/findings");
    for (const [name, value] of incoming.searchParams) {
      if (!forwardedFindingFilters.has(name) || target.searchParams.has(name) || value.length > 1_024) {
        return safeJson({ error: "invalid_request" }, 400);
      }
      target.searchParams.set(name, value);
    }
    return safeJson(parseFindingList(await operatorJson(`${target.pathname}${target.search}`, { method: "GET" })), 200);
  } catch (error) {
    return proxyFailure(error);
  }
}

export async function proxyFindingDetail(id: string): Promise<Response> {
  try {
    const findingId = safeFindingId(id);
    if (findingId === null) return safeJson({ error: "not_found" }, 404);
    return safeJson(parseFindingDetail(await operatorJson(`/api/findings/${encodeURIComponent(findingId)}`, { method: "GET" })), 200);
  } catch (error) {
    return proxyFailure(error);
  }
}

export async function proxyFindingReview(request: Request, id: string): Promise<Response> {
  try {
    const findingId = safeFindingId(id);
    if (findingId === null) return safeJson({ error: "not_found" }, 404);
    const review = await readReview(request);
    const value = await operatorJson(`/api/findings/${encodeURIComponent(findingId)}/review`, {
      method: "POST",
      body: JSON.stringify(review),
    });
    return safeJson({ finding: parseFinding(value) }, 200);
  } catch (error) {
    return proxyFailure(error);
  }
}

export async function proxyEventStream(request: Request): Promise<Response> {
  const abort = new AbortController();
  const stop = () => { abort.abort(); };
  request.signal.addEventListener("abort", stop, { once: true });
  const connectionTimer = setTimeout(stop, 10_000);
  try {
    const incoming = new URL(request.url);
    if ([...incoming.searchParams.keys()].some((name) => name !== "after") || incoming.searchParams.getAll("after").length > 1) {
      clearTimeout(connectionTimer);
      request.signal.removeEventListener("abort", stop);
      return safeJson({ error: "invalid_request" }, 400);
    }
    const after = incoming.searchParams.get("after");
    const lastEventId = request.headers.get("last-event-id");
    for (const cursor of [after, lastEventId]) {
      if (cursor !== null && (!/^\d+$/u.test(cursor) || !Number.isSafeInteger(Number(cursor)))) {
        clearTimeout(connectionTimer);
        request.signal.removeEventListener("abort", stop);
        return safeJson({ error: "invalid_request" }, 400);
      }
    }
    const { baseUrl, token } = operatorConfig();
    const target = new URL("/api/stream", baseUrl);
    if (after !== null) target.searchParams.set("after", after);
    const upstream = await fetch(target, {
      headers: {
        accept: "text/event-stream",
        authorization: `Bearer ${token}`,
        ...(lastEventId === null ? {} : { "last-event-id": lastEventId }),
      },
      cache: "no-store",
      redirect: "error",
      signal: abort.signal,
    });
    clearTimeout(connectionTimer);
    if (!upstream.ok || upstream.body === null) {
      await upstream.body?.cancel();
      if (upstream.status === 400) {
        request.signal.removeEventListener("abort", stop);
        return safeJson({ error: "invalid_request" }, 400);
      }
      throw new OperatorProxyError(502, "operator_api_unavailable");
    }
    if (upstream.headers.get("content-type")?.split(";", 1)[0]?.trim().toLocaleLowerCase("en-US") !== "text/event-stream") {
      await upstream.body.cancel();
      throw new OperatorProxyError(502, "invalid_upstream_response");
    }
    const reader = upstream.body.getReader();
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const chunk = await reader.read();
          if (chunk.done) {
            request.signal.removeEventListener("abort", stop);
            controller.close();
          } else {
            controller.enqueue(chunk.value);
          }
        } catch (error) {
          request.signal.removeEventListener("abort", stop);
          controller.error(error);
        }
      },
      async cancel(reason) {
        stop();
        request.signal.removeEventListener("abort", stop);
        await reader.cancel(reason);
      },
    });
    return new Response(body, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
        "x-content-type-options": "nosniff",
      },
    });
  } catch (error) {
    clearTimeout(connectionTimer);
    request.signal.removeEventListener("abort", stop);
    return proxyFailure(error);
  }
}
