import { randomUUID } from "node:crypto";
import { newDb } from "pg-mem";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { createMetadataStore, type MetadataStore } from "./index.js";

describe("metadata persistence seam", () => {
  let pool: Pool;
  let store: MetadataStore;

  beforeEach(async () => {
    const memory = newDb();
    const adapter = memory.adapters.createPg();
    // pg-mem intentionally exposes a node-postgres-compatible constructor without a safe type.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
    pool = new adapter.Pool();
    store = await createMetadataStore(pool);
  });

  afterEach(async () => {
    await pool.end();
  });

  it("records a discovery page before advancing its exclusive cursor", async () => {
    await store.recordDiscoveryPage("public-repositories", 102, [
      {
        repoId: 101,
        fullName: "fixture/one",
        htmlUrl: "https://github.com/fixture/one",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 7,
        candidateState: "WAITING_FOR_COMMIT",
      },
      {
        repoId: 102,
        fullName: "fixture/two",
        htmlUrl: "https://github.com/fixture/two",
        discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
        priorityScore: 1,
        candidateState: "SKIPPED",
      },
    ]);

    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(102);
    await expect(store.getCandidate(101)).resolves.toMatchObject({
      fullName: "fixture/one",
      candidateState: "WAITING_FOR_COMMIT",
    });
  });

  it("does not advance the cursor when a page cannot be fully recorded", async () => {
    await store.recordDiscoveryPage("public-repositories", 50, []);

    await expect(
      store.recordDiscoveryPage("public-repositories", 52, [
        {
          repoId: 51,
          fullName: "fixture/valid",
          htmlUrl: "https://github.com/fixture/valid",
          discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
          priorityScore: 5,
          candidateState: "WAITING_FOR_COMMIT",
        },
        {
          repoId: 52,
          fullName: "",
          htmlUrl: "https://github.com/fixture/invalid",
          discoveredAt: new Date("2026-08-12T12:00:01.000Z"),
          priorityScore: 5,
          candidateState: "WAITING_FOR_COMMIT",
        },
      ]),
    ).rejects.toThrow();

    await expect(store.getDiscoveryCursor("public-repositories")).resolves.toBe(50);
    await expect(store.getCandidate(51)).resolves.toBeNull();
  });

  it("allows only public lifecycle transitions", async () => {
    await store.recordDiscoveryPage("public-repositories", 201, [
      {
        repoId: 201,
        fullName: "fixture/stateful",
        htmlUrl: "https://github.com/fixture/stateful",
        discoveredAt: new Date("2026-08-12T12:00:00.000Z"),
        priorityScore: 8,
        candidateState: "WAITING_FOR_COMMIT",
      },
    ]);

    await expect(store.transitionCandidate(201, "READY")).resolves.toMatchObject({
      candidateState: "READY",
    });
    await expect(store.transitionCandidate(201, "SCANNED_FINDINGS")).rejects.toThrow(
      "Illegal candidate transition",
    );
  });

  it("round-trips sanitized findings and rejects forbidden raw fields", async () => {
    const safeFinding = {
      findingId: randomUUID(),
      detectedAt: "2026-08-12T12:00:00.000Z",
      repository: {
        id: 301,
        fullName: "fixture/finding",
        url: "https://github.com/fixture/finding",
      },
      revision: { ref: "main", sha: "a".repeat(40) },
      category: "secret_exposure",
      cwe: "CWE-798",
      severity: "critical" as const,
      confidence: 0.98,
      secretEvidence: {
        type: "Fake canary credential",
        path: ".env",
        line: 1,
        fingerprint: "b".repeat(64),
      },
      reviewState: "UNREVIEWED" as const,
    };

    await store.saveFinding(safeFinding);
    await expect(store.getFinding(safeFinding.findingId)).resolves.toEqual(safeFinding);
    const unsafeFinding = {
      ...safeFinding,
      findingId: randomUUID(),
      rawSecret: "CANARY_RAW",
    } as unknown as Parameters<MetadataStore["saveFinding"]>[0];
    await expect(
      store.saveFinding(unsafeFinding),
    ).rejects.toThrow();
  });

  it("stores only validation review states and non-sensitive notes", async () => {
    const findingId = randomUUID();
    await store.saveFinding({
      findingId,
      detectedAt: "2026-08-12T12:00:00.000Z",
      repository: {
        id: 401,
        fullName: "fixture/review",
        url: "https://github.com/fixture/review",
      },
      revision: { ref: "main", sha: "c".repeat(40) },
      category: "command_injection",
      cwe: "CWE-78",
      severity: "critical",
      confidence: 0.96,
      reviewState: "UNREVIEWED",
    });

    await expect(store.reviewFinding(findingId, "CONFIRMED", "Path verified on GitHub.")).resolves.toMatchObject({
      reviewState: "CONFIRMED",
      reviewNote: "Path verified on GitHub.",
    });
    await expect(
      store.reviewFinding(findingId, "FALSE_POSITIVE", "AWS_SECRET_ACCESS_KEY=CANARY_RAW"),
    ).rejects.toThrow("sensitive content");
  });
});
