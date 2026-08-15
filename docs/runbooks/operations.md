# Operations runbook

Copy `.env.example` to `.env`, replace every placeholder, then run `docker compose up --build`. The one-shot `migrate` service applies every pending checksummed migration transactionally before API or worker startup; no separate first-run command is required. Check API `http://localhost:8080/readyz`, worker readiness through `docker compose ps`, and the private console at `http://localhost:3000`. Optional visibly labeled sanitized demo metadata is explicit only: `docker compose run --rm api node apps/api/dist/seed.js`.

`schema_migrations` is the source of truth. Never edit an applied SQL file: add the next contiguous numbered file. Startup fails on a missing, reordered, renamed, or checksum-mismatched migration. To inspect versions, query `SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`. The runner recognizes the one pre-versioned Breach schema for an explicit checksum adoption; partial/unknown schemas fail instead of being silently rewritten.

Use a fine-grained GitHub token restricted to read-only public repository metadata/contents. Give PostgreSQL and the operator API separate credentials. Rotate the GitHub token, HMAC key, operator token, and database password independently; rotating the HMAC key intentionally changes future secret fingerprints.

Monitor discovery cursor movement, selection ratio, GitHub remaining quota, requests/bytes per scan, p95 latency, partial/failure rate, review precision, and the zero-retention canary. Stop the worker on any retention violation. Under quota pressure, the worker serializes requests and marks rate-limited candidates instead of bypassing the gate.

Lifecycle recovery is explicit: `RATE_LIMITED` returns to `WAITING_FOR_COMMIT` only after its persisted deadline. `READY` and `SCANNING` are non-terminal claimed-scan states. `SKIPPED`, `SCANNED_NO_FINDINGS`, `SCANNED_FINDINGS`, `PARTIAL`, and `FAILED` are terminal for the validation MVP's first observed committed HEAD. A failed claimed scan is finalized with bounded coverage plus one sanitized reason code; it must never remain ambiguously `SCANNING`.

Back up only PostgreSQL metadata. Never add source volumes, Docker socket mounts, core dumps, heap snapshots, or repository archive caches. Verify host swap is disabled or encrypted before production operation. Upgrade by running the complete verification suite, rebuilding images, migrating, then replacing API/web before the worker.
