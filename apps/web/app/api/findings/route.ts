import { proxyFindingList } from "../../server/operator-api";

export const dynamic = "force-dynamic";

export function GET(request: Request): Promise<Response> {
  return proxyFindingList(request);
}
