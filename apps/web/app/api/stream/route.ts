import { proxyEventStream } from "../../server/operator-api";

export const dynamic = "force-dynamic";

export function GET(request: Request): Promise<Response> {
  return proxyEventStream(request);
}
