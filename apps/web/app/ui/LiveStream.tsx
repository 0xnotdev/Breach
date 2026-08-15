"use client";

import { useEffect, useState } from "react";

const candidateStates = new Set(["DISCOVERED", "SKIPPED", "WAITING_FOR_COMMIT", "READY", "SCANNING", "SCANNED_NO_FINDINGS", "SCANNED_FINDINGS", "PARTIAL", "FAILED", "RATE_LIMITED"]);
type ConnectionState = "CONNECTED" | "RECONNECTING" | "DISCONNECTED";

interface PublicStreamEvent {
  readonly eventId: number;
  readonly repoId: number;
  readonly fullName: string;
  readonly state: string;
  readonly occurredAt: string;
  readonly reasonCode: string;
}

export function LiveStream() {
  const [connection, setConnection] = useState<ConnectionState>("RECONNECTING");
  const [events, setEvents] = useState<readonly PublicStreamEvent[]>([]);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.onopen = () => setConnection("CONNECTED");
    source.onerror = () => setConnection(source.readyState === EventSource.CLOSED ? "DISCONNECTED" : "RECONNECTING");
    const receive = (message: Event) => {
      if (!(message instanceof MessageEvent) || typeof message.data !== "string") return;
      try {
        const value: unknown = JSON.parse(message.data);
        if (!isStreamEvent(value)) return;
        setEvents((current) => [...current.filter((event) => event.eventId !== value.eventId), value].sort((left, right) => right.eventId - left.eventId).slice(0, 100));
      } catch {
        // Invalid event data is ignored and never rendered or logged.
      }
    };
    source.addEventListener("state", receive);
    return () => {
      source.removeEventListener("state", receive);
      source.close();
    };
  }, []);

  return <><div className={`stream-status connection-${connection.toLocaleLowerCase("en-US")}`} role="status"><span className="status-dot" aria-hidden="true" /><strong>{connection}</strong><small>{connection === "CONNECTED" ? "Receiving sanitized lifecycle metadata" : connection === "RECONNECTING" ? "Waiting for the event stream; the cursor will resume automatically" : "The browser closed the event stream"}</small></div><section className="stream-panel" aria-label="Sanitized scan state stream" aria-live="polite"><div className="stream-head"><span>State</span><span>Repository</span><span>Reason code</span><span>Timestamp</span></div>{events.map((event) => <article className={`stream-event state-${event.state.toLocaleLowerCase("en-US")}`} key={event.eventId}><span className="event-sequence">{String(event.eventId).padStart(3, "0")}</span><strong>{event.state}</strong><span>{event.fullName}</span><span>{event.reasonCode}</span><time dateTime={event.occurredAt}>{formatTimestamp(event.occurredAt)}</time></article>)}{events.length === 0 && <div className="empty-state"><strong>No lifecycle events received yet</strong><p>The connection remains open for persisted metadata-only transitions.</p></div>}</section></>;
}

function isStreamEvent(value: unknown): value is PublicStreamEvent {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return Number.isSafeInteger(record.eventId) && Number(record.eventId) > 0 && Number.isSafeInteger(record.repoId) && Number(record.repoId) > 0 && typeof record.fullName === "string" && /^[^/\s]+\/[^/\s]+$/u.test(record.fullName) && typeof record.state === "string" && candidateStates.has(record.state) && typeof record.occurredAt === "string" && Number.isFinite(Date.parse(record.occurredAt)) && typeof record.reasonCode === "string" && /^[a-z][a-z0-9_]{0,79}$/u.test(record.reasonCode);
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "medium" }).format(Date.parse(value));
}
