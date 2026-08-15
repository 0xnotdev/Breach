import { proxyFindingDetail } from "../../../server/operator-api";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  return proxyFindingDetail(id);
}
