import { sanitizedFindingSchema, type SanitizedFinding } from "@breach/contracts";

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

interface FindingListPayload {
  readonly findings: readonly SanitizedFinding[];
}

function operatorConfig(): { baseUrl: URL; token: string } {
  const configuredUrl = process.env.API_INTERNAL_URL;
  const token = process.env.OPERATOR_TOKEN;
  if (configuredUrl === undefined || token === undefined || new TextEncoder().encode(token).byteLength < 16) {
    throw new Error("Operator API is not configured");
  }
  const baseUrl = new URL(configuredUrl);
  if (!new Set(["http:", "https:"]).has(baseUrl.protocol) || baseUrl.username !== "" || baseUrl.password !== "") {
    throw new Error("Operator API URL is invalid");
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

function parseFindingList(value: unknown): FindingListPayload {
  if (typeof value !== "object" || value === null || !("findings" in value) || !Array.isArray(value.findings)) {
    throw new Error("Operator API returned an invalid finding list");
  }
  return { findings: value.findings.map((finding) => sanitizedFindingSchema.parse(finding)) };
}

export async function proxyFindingList(request: Request): Promise<Response> {
  try {
    const { baseUrl, token } = operatorConfig();
    const incoming = new URL(request.url);
    const target = new URL("/api/findings", baseUrl);
    for (const [name, value] of incoming.searchParams) {
      if (!forwardedFindingFilters.has(name) || value.length > 1_024) return safeJson({ error: "invalid_request" }, 400);
      target.searchParams.append(name, value);
    }

    const upstream = await fetch(target, {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${token}` },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    const body = await upstream.text();
    if (new TextEncoder().encode(body).byteLength > maximumResponseBytes) {
      return safeJson({ error: "upstream_response_too_large" }, 502);
    }
    const parsed: unknown = JSON.parse(body);
    if (!upstream.ok) {
      return safeJson(
        upstream.status >= 400 && upstream.status < 500 ? parsed : { error: "operator_api_unavailable" },
        upstream.status >= 400 && upstream.status < 500 ? upstream.status : 502,
      );
    }
    return safeJson(parseFindingList(parsed), 200);
  } catch {
    return safeJson({ error: "operator_api_unavailable" }, 503);
  }
}
