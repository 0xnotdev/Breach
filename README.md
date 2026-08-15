# Breach

Breach is a private passive-exploitability validation MVP for newly created public GitHub repositories. It discovers metadata, selects a bounded subset, confirms a real commit before content access, reads only capped Git trees/blobs, analyzes in memory, and stores redacted evidence metadata. It never clones, executes repository code, installs repository dependencies, verifies credentials, probes deployments, or contacts maintainers.

## Architecture

The npm/TypeScript workspace separates GitHub discovery and the mandatory commit gate, bounded snapshots, secret/dependency/config analyzers, passive JS/TS/Python data flow, orchestration, PostgreSQL metadata storage, the authenticated HTTP/SSE operator API, hardened worker/API processes, and a four-route operator console. `spec.md` is the acceptance contract; `progress.md` is the build ledger.

Repository bytes exist only in bounded network/process/parser buffers and are released on every terminal path. Durable data contains repository identity, revision, semantic path nodes, coverage, redacted secret metadata with HMAC-SHA256 fingerprint, review state, state events, and aggregate metrics. An empty result means no finding within modeled coverage—not “secure.”

## Local setup

Requirements: Node 24, npm 11, Docker/Compose, and Chromium for browser tests. Copy `.env.example` to `.env` and replace all placeholders. Use a fine-grained read-only GitHub token; do not grant write, administration, organization, workflow, or secret access.

Run `npm ci --ignore-scripts`, `npm run verify`, and `npx playwright install chromium`. Start the stack with `docker compose up --build`. The console is on port 3000 and the authenticated API on port 8080. Run the migration/seed commands documented in `docs/runbooks/operations.md`. The seed contains sanitized demo metadata only.

## Testing

`npm test` covers domain, persistence, gates, inspection, analyzers, exploitability, orchestration, API, worker, zero-retention, and operations. `npm run test --workspace @breach/web` verifies server rendering. `npm run test:browser --workspace @breach/web` runs operator journeys against a production server, including the scanner-produced canary finding, rendered DOM, and browser-storage audit. `npm run lint`, `npm run typecheck`, `npm run build`, and `docker compose config --quiet` are required gates.

After building, run the reproducible canary against the intended metadata database with `npm run canary --workspace @breach/worker`. It requires `DATABASE_URL` and `FINGERPRINT_HMAC_KEY`, emits only counts/surface names, and persists real canary measurements. The demo seed is visibly labeled `DEMO-SEED` and never writes a green safety metric.

## Interpretation and limits

Scores describe confidence in static evidence, never probability of successful exploitation. Investigation shows entry/source/flow/sink metadata, surfaced reasons, observed barriers, coverage, and limitations. Runtime verification, active testing, and deployment confirmation are always false. The validation MVP scans only the first observed committed HEAD and prioritizes JavaScript/TypeScript/Python plus exact dependency/config formats; dynamic dispatch, aliases, unsupported frameworks, history, later commits, generated/binary/oversized files, and exhausted budgets can reduce coverage.

## Safe operation and troubleshooting

Read `docs/security-boundary.md` before deployment. Keep root filesystems read-only, tmpfs bounded, swap disabled/encrypted, core/heap dumps off, and network policy aligned to GitHub API, OSV, and internal metadata services only. If readiness fails, verify PostgreSQL and migrations. If discovery stalls, inspect sanitized quota/reset metrics. If partials rise, inspect coverage reason counts rather than source. Any zero-retention canary failure requires immediate worker shutdown and the incident runbook.

## Disclosure

This product does not automate notification or remediation. Human review is private validation. Any disclosure requires separate authorization and must retain the static-evidence/coverage caveats; see `docs/runbooks/disclosure.md`.
