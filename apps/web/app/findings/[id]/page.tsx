import { getFinding } from "../../data";
import { Investigation } from "../../ui/Investigation";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const result = getFinding(id);
  if (!result) return <main className="not-found"><h1>Finding unavailable</h1><p>The sanitized record was not found.</p></main>;
  return <Investigation finding={result.finding} detail={result.detail} />;
}
