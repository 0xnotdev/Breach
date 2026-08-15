# Breach

## WHAT BREACH DOES

Breach is a private validation MVP that passively inspects newly created public GitHub repositories. It starts at GitHub's current public-repository frontier, ranks candidates, requires a real committed HEAD, fetches only bounded Git trees and selected blobs, analyzes bytes in memory, and retains sanitized metadata for human review.

It finds credential-shaped material without verifying it, exact vulnerable dependency versions, security-relevant configuration, and statically modeled attacker-source-to-dangerous-sink paths. It never clones or checks out repositories, executes repository code, installs repository dependencies, probes deployments, contacts maintainers, or publishes findings.

## ARCHITECTURE

The TypeScript/npm workspace separates public GitHub discovery, candidate admission, the mandatory commit gate, bounded snapshot acquisition, analyzers, orchestration, PostgreSQL metadata, the authenticated operator API/SSE stream, and the server-side authenticated web console. The worker is the only component that receives `GITHUB_TOKEN`; API and web share only the operator credential they need. `spec.md` is the acceptance contract and `progress.md` is the append-only engineering ledger.

The default flow is:

`current frontier → bounded discovery → scored admission → commit gate → bounded tree/blobs → in-memory analysis → sanitized PostgreSQL records → API/SSE → operator UI`

## SAFETY MODEL

Repository content is hostile and ephemeral. The zero-retention boundary permits transient bytes in TLS/network buffers, bounded Node buffers, process RAM, and parser structures, but never writes them to PostgreSQL, logs, queues, host mounts, or source volumes. Snapshot buffers are overwritten on success and every failure path. Durable evidence is limited to repository/revision identity, bounded semantic path nodes, coverage and reason codes, dependency/config metadata, HMAC-SHA256 secret fingerprints, reviews, lifecycle events, and aggregate metrics.

Containers run non-root with read-only filesystems, bounded `noexec,nosuid` tmpfs, dropped capabilities, no privilege escalation, core dumps disabled, and CPU/memory/PID/file-descriptor limits. The worker has no direct external network; its CONNECT proxy allows only `api.github.com:443` and `api.osv.dev:443`. Read [the security boundary](docs/security-boundary.md) before production use.

## REQUIREMENTS

For the one-command product stack:

- Git, Docker Engine, and Docker Compose v2.
- A fine-grained GitHub token limited to read-only public repository metadata and contents.
- Four independently generated secrets: GitHub token, HMAC key, operator token, and PostgreSQL password.
- Host swap disabled, or encrypted and separately audited, for production validation.

For host-side development and tests, also install Node.js 24, npm 11, and Chromium through Playwright.

## FIRST-TIME SETUP

```sh
git clone https://github.com/0xnotdev/Breach.git
cd Breach
cp .env.example .env
```

On PowerShell, use `Copy-Item .env.example .env`. Edit `.env` and replace the four `replace-with-...` values. Do not reuse keys. Leave `DISCOVERY_MODE=live`; that default bootstraps at the current frontier and never backfills from repository ID 0.

Migrations require no manual first-run command. Compose starts PostgreSQL, runs every checksummed migration once, then permits API/worker startup only after the schema is current.

## ENVIRONMENT VARIABLES

| Variable | Purpose | Default/constraint |
|---|---|---|
| `GITHUB_TOKEN` | Worker-only GitHub API authentication | Required; fine-grained read-only |
| `FINGERPRINT_HMAC_KEY` | One-way secret evidence fingerprinting | Required; at least 32 random bytes |
| `OPERATOR_TOKEN` | Server-side API/web authentication | Required; at least 16 characters |
| `POSTGRES_PASSWORD` | Local metadata database password | Required outside throwaway development |
| `DISCOVERY_MODE` | Frontier or explicit replay mode | `live`; use `historical` only deliberately |
| `DISCOVERY_START_CURSOR` | Historical replay start | Valid only with `DISCOVERY_MODE=historical` |
| `CANDIDATE_MINIMUM_SCORE` | Candidate-quality floor | `60` |
| `TARGET_SELECTION_RATIO` | Bounded admission target | `0.07` |
| `MAX_DISCOVERY_PAGES_PER_CYCLE` | Discovery page budget | `2` |
| `MAX_DISCOVERY_REQUESTS_PER_CYCLE` | Discovery request budget | `2` |
| `MAX_DISCOVERY_ELAPSED_MS` | Discovery wall-clock budget | `10000` |
| `MAX_COMMIT_CHECKS_PER_CYCLE` | Commit-gate budget | `25` |
| `MAX_SCANS_PER_CYCLE` | Scan admissions per cycle | `5` |
| `GITHUB_QUOTA_RESERVE` | Requests preserved before new admission stops | `200` |
| `POLL_INTERVAL_MS` | Worker cycle interval | `30000` |
| `API_PORT` | Loopback API host port | `8080` |
| `WORKER_HEALTH_PORT` | Loopback worker health host port | `8081` |
| `WEB_PORT` | Loopback console host port | `3000` |

## START COMMAND

```sh
docker compose up --build
```

Normal startup is intentionally unseeded. Wait for `postgres`, `api`, `egress-proxy`, `worker`, and `web` to report healthy; `migrate` should exit successfully. Detached operation is `docker compose up --build --detach --wait`.

## HOW TO OPEN UI

Open [http://localhost:3000](http://localhost:3000), or the configured `WEB_PORT`. Findings, Investigation, Stream, and System use the real PostgreSQL/API path. `OPERATOR_TOKEN` is injected only by the web server and must never appear in browser JavaScript, HTML, storage, or network responses.

## HOW TO VERIFY WORKER IS LIVE

Process liveness is `http://localhost:8081/healthz`. Readiness is `http://localhost:8081/readyz` and becomes HTTP 200 only after a successful initialized cycle. For example:

```sh
curl --fail http://localhost:8081/readyz
docker compose ps
```

PowerShell equivalent: `Invoke-RestMethod http://localhost:8081/readyz`. Readiness performs a current PostgreSQL probe and fails if the scheduler is stopped, its last cycle failed, or a running cycle exceeds the five-minute fatal-stall bound. API health/readiness are `/healthz` and `/readyz` on port 8080. A worker that is alive but not ready needs investigation; do not treat `/healthz` alone as proof of functional discovery.

## HOW TO RUN CANARY

With the stack running, launch the isolated one-shot canary image:

```sh
docker compose run --rm --build canary
```

It uses the controlled nonfunctional fixture, the real commit-gate/snapshot/analyzer/store/operator path, and the configured HMAC key. Success reports counts and checked surface names only. It must report zero raw occurrences, at least one expected fingerprint representation, and cleared ephemeral buffers. It persists measured safety metrics; the optional demo seed never does. On any failure, stop the worker and follow [incident response](docs/runbooks/incident-response.md).

## HOW TO RUN TESTS

```sh
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run verify
```

`verify` runs lint, strict typecheck, coverage, every build, server-rendered web tests, Chromium operator journeys, the high/critical production dependency audit, and tracked-secret audit. CI additionally uses real PostgreSQL for idempotent migrations and the deterministic controlled full-stack test, then validates a fresh Compose volume and production images.

## HOW TO RESET LOCAL DB

This irreversibly deletes local Breach metadata and reviews:

```sh
docker compose down --volumes --remove-orphans
docker compose up --build
```

Never use this reset against a production metadata volume. Back up PostgreSQL metadata first when retention is required.

## HOW TO TROUBLESHOOT RATE LIMITS

Open System and inspect measured `github.rate_limit.remaining`, limit, reset time, pause/secondary-limit events, requests per hour, and requests per completed scan. A rate-limited candidate is persisted as `RATE_LIMITED` and returns to `WAITING_FOR_COMMIT` only after its authoritative retry deadline. Do not add token sharding or lower the quota reserve blindly. Confirm the system clock, wait through `Retry-After`/reset, and inspect only sanitized reason codes—never GitHub response bodies.

## HOW TO READ COVERAGE

Coverage describes what the bounded scan observed, not whether a repository is secure. `filesSeen` is the tree population, `filesEligible` passed path/type selection, `filesAnalyzed` reached analyzers, and `bytesInspected` is the transient byte budget consumed. `snapshotComplete`/`analysisComplete` and partial reason arrays explain omissions such as tree truncation, binaries, generated/oversized/unsupported files, byte/file/time budgets, parser failure, or analysis timeout. Every finding means `First observed committed HEAD`; `historyScanned` is always false.

## KNOWN MVP LIMITATIONS

- Only the first observed committed HEAD is scanned; later commits and full history are not monitored.
- Exploitability is static evidence, not runtime proof, successful exploitation probability, or deployment confirmation.
- Framework, language, alias, dynamic-dispatch, sanitizer, and interprocedural modeling are deliberately bounded.
- Binary, generated, oversized, unsupported, and budget-exhausted inputs may be excluded and reported as partial.
- No automatic disclosure, notification, remediation, or maintainer contact exists.
- Docker Compose's bridge/proxy separation is a local control, not a production FQDN firewall; apply the documented CNI/gateway policy.

An empty finding set means no finding within modeled coverage, never “secure.”

## NO CREDENTIAL VERIFICATION POLICY

Breach never authenticates with, redeems, calls a provider using, or otherwise verifies a discovered credential. It records only provider/type/location metadata and an HMAC-SHA256 fingerprint. A human review note must contain judgment only—never a secret, source excerpt, authorization header, or credential test result. Any disclosure is a separate, explicitly authorized human process governed by [the disclosure runbook](docs/runbooks/disclosure.md).
