import { Investigation } from "../../ui/Investigation";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <Investigation findingId={id} />;
}
