import { proxySystemMetrics } from "../../server/operator-api";

export const dynamic = "force-dynamic";

export function GET(): Promise<Response> {
  return proxySystemMetrics();
}
