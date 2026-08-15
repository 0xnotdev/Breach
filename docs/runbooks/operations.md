# Operations runbook

## First startup

Copy `.env.example` to `.env`, replace the GitHub, HMAC, operator, and PostgreSQL placeholders with independent values, and keep `DISCOVERY_MODE=live`. Run `docker compose up --build`, or `docker compose up --build --detach --wait`. The one-shot `migrate` service applies every pending checksummed migration transactionally before API or worker startup; no separate first-run command is required. Normal startup never seeds demo records.

Check API `http://localhost:8080/readyz`, worker `http://localhost:8081/readyz`, the healthy service set with `docker compose ps`, and the private console at `http://localhost:3000`. Worker `/healthz` proves only that the process serves HTTP. Worker `/readyz` performs a current PostgreSQL probe and proves an initialized cycle has completed successfully, the scheduler is not stopped, and a running cycle has not exceeded the five-minute fatal-stall bound.

## Fresh-volume startup and reset

The clean fresh-volume startup acceptance sequence is:

```sh
docker compose down --volumes --remove-orphans
docker compose up --build --detach --wait
curl --fail http://localhost:8080/readyz
curl --fail http://localhost:8081/readyz
curl --fail http://localhost:3000/
```

Removing the volume permanently deletes local findings, reviews, metrics, and lifecycle state. Do not run it against production. CI performs a fresh-volume operator-stack startup without a real GitHub credential, validates API/web health, and runs the deterministic canary; live worker/GitHub validation remains a manual credentialed gate.

## Migrations

`schema_migrations` is the source of truth. Never edit an applied SQL file: add the next contiguous numbered file. Startup fails on a missing, reordered, renamed, or checksum-mismatched migration. Inspect versions with `SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`. The runner recognizes the one pre-versioned Breach schema for explicit checksum adoption; partial or unknown schemas fail instead of being silently rewritten.

## Runtime canary and demo data

Run `docker compose run --rm --build canary` against a started stack. The one-shot, metadata-network-only image contains the controlled nonfunctional fixture and persists measured zero-retention metrics only after the complete audit passes. Stop the worker immediately if it reports any raw occurrence or uncleared ephemeral buffer.

Optional sanitized demo metadata is explicit only: `docker compose run --rm api node apps/api/dist/seed.js`. It is visibly labeled `DEMO-SEED`, is not part of normal startup or live validation, and never creates a green safety metric.

## Credentials and upgrades

Use a fine-grained GitHub token restricted to read-only public repository metadata and contents. Give PostgreSQL and the operator API separate credentials. Rotate the GitHub token, HMAC key, operator token, and database password independently; rotating the HMAC key intentionally changes future secret fingerprints.

Back up only PostgreSQL metadata. Never add source volumes, Docker socket mounts, core dumps, heap snapshots, repository archives, SSH keys, or cloud credentials. Verify host swap is disabled or encrypted before production operation. Upgrade by running the complete verification suite, rebuilding images, applying migrations, replacing API/web, and only then resuming the worker.

## Monitoring and rate limits

Monitor discovery cursor/lag, admission and commit-ready ratios, GitHub remaining quota/reset, requests per hour/scan, bytes/files per scan, stage and p95 latency, partial/failure rates, review precision, and the runtime canary. Under quota pressure the serial dispatcher stops new admission at the configured reserve and persists sanitized retry state.

For a rate limit, verify the System metrics and candidate reason code, check the host clock, and wait until authoritative `Retry-After` or reset time. `RATE_LIMITED` returns to `WAITING_FOR_COMMIT` only after its deadline. Never add token sharding, log a response body, or bypass the commit gate. Sustained secondary limiting warrants stopping the worker and reducing per-cycle bounds after the reset.

## Lifecycle and coverage

`RATE_LIMITED` is recoverable. `READY` and `SCANNING` are non-terminal claimed-scan states. `SKIPPED`, `SCANNED_NO_FINDINGS`, `SCANNED_FINDINGS`, `PARTIAL`, and `FAILED` are terminal for the first observed committed HEAD. A failed claimed scan is finalized with bounded coverage plus one sanitized reason code and must never remain ambiguously `SCANNING`.

Treat coverage as an observation boundary, not a security claim. Review tree/blob/analysis partial reasons, byte/file counts, modeled languages, and `historyScanned=false` before interpreting a finding or empty result.
