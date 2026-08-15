import { proxyFindingReview } from "../../../../server/operator-api";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  return proxyFindingReview(request, id);
}
