# Breach MVP Build Specification

Status: Active build contract  
Source of truth: `D:\deep-research-report-passive-exploitability-mvp-with-ui-scope.md`  
Source SHA-256: `D9E59A9CF188786892D0CC0D1F6FF5AFDA48A181BF5EB0D88945BD56CDE97C55`  
Prepared: 2026-08-12

## 1. Product outcome

Breach is a private operator system that continuously observes newly created public GitHub repositories as metadata, selects a small high-value subset, refuses all content access until a Git commit is confirmed, inspects the first observed committed HEAD through bounded GitHub tree/blob reads, and emits only redacted security-finding metadata.

It detects secrets, vulnerable dependencies, risky CI/Docker/IaC configuration, and selected JavaScript/TypeScript/Python vulnerabilities. For supported code paths it reconstructs passive static attacker-source-to-dangerous-sink evidence and assigns an explicitly non-probabilistic exploitability confidence score. Operators review findings in a dense desktop console with Findings, Stream, and System destinations and a dedicated Investigation detail route.

The system never clones repositories, checks out or durably stores source, executes repository code, installs repository dependencies, verifies credentials, probes deployments, sends exploit payloads, or contacts maintainers.

## 2. Non-negotiable invariants

1. Creation discovery is metadata intake only. It must not trigger content reads.
2. Only selected candidates are commit-checked.
3. Tree/blob/content/archive access is impossible before a successful commit gate.
4. Only the first observed committed HEAD is scanned in the validation MVP.
5. Repository bytes may exist only in bounded network buffers, bounded process memory, and bounded parser state.
6. Repository source, raw secrets, raw matches, snippets, raw ASTs, and raw GitHub bodies never enter durable storage, queues, logs, telemetry, browser state, or API responses.
7. Secrets cross the detection seam only as type, safe metadata, and an HMAC-SHA256 fingerprint.
8. Repository content is never executed or used to determine a network destination.
9. External calls are limited to GitHub, OSV, and the system's own metadata services.
10. Static exploitability is always labeled as static evidence. Runtime verification, deployment confirmation, and active testing remain false.
11. An absence of findings is never represented as “secure”; every scan exposes coverage and limitations.
12. Repository-controlled strings are safely escaped before logs or UI rendering.

## 3. Scope

### Included

- Creation-ordered GitHub public repository discovery with a transactional monotonic cursor.
- Metadata-only prioritization with a configurable 5–8% target and adaptive quota pressure.
- Durable candidate states and sparse empty-repository backoff (1m, 5m, 30m, 2h, 24h, then close).
- Mandatory commit gate with conservative 200/404/409/403/429 behavior.
- Serialized, rate-aware GitHub request dispatch and optional PushEvent wake-up correlation.
- Recursive Git tree inventory after the gate and priority-based blob selection.
- Default bounds: 2 MiB/file, 5 MiB/repository, 1,000 files, 30 seconds, bounded graph nodes/depth.
- Secret detection using structured patterns, keyword/context, entropy, placeholder suppression, and HMAC fingerprints.
- In-memory exact-version dependency parsing and OSV batch correlation for the report's prioritized ecosystems.
- CI/CD, Docker, Terraform, Kubernetes, and related configuration heuristics.
- JavaScript, TypeScript, and Python syntax modeling, entry points, attacker sources, sanitizers/barriers, dangerous sinks, cross-function/cross-file semantic flow, and exploitability scoring.
- Three independent scores: repository priority, finding severity/confidence, and exploitability confidence.
- Redacted PostgreSQL persistence for discovery, candidates, scan coverage, findings, attack paths, reviews, state events, and aggregate telemetry only.
- Sanitized HTTP/SSE operator interface.
- Operator console with Findings, Investigation, Stream, System, required filters, and the three-state human review loop.
- Controlled fake-canary and vulnerability fixtures plus automated zero-retention checks.
- Containerized local/production-like operation with hardened worker settings and operational documentation.

### Explicitly excluded

- Clone/checkout, durable source storage, builds, package installation, source execution, browser execution of scanned code, credential verification/use, runtime probing, port scanning, exploit delivery, automatic disclosure, maintainer contact, remediation PRs, customer onboarding, multitenancy, billing, alert routing/integrations, RBAC, mobile-first UX, later-commit/history scanning, and token sharding.
- Report items marked P2 or Later are recorded as extension points, not validation-MVP completion requirements: broad framework/language expansion, streamed tar backend, incremental later-commit scans, selective history, and owner alerts. The optional PushEvent correlator is included because it can be built without weakening completeness.

## 4. Architecture and deep module interfaces

The implementation is a TypeScript monorepo. Interfaces are deliberately small; implementations hide rate limiting, bounded parsing, storage, sanitization, and framework-specific modeling.

```text
GitHub metadata -> Intake -> Candidate gate -> Bounded snapshot -> Analysis
                                                            -> Redaction
                                                            -> Metadata store
                                                            -> Operator API/SSE
                                                            -> React console
```

Primary modules:

- `Discovery`: `poll(cursor) -> DiscoveryPage`; metadata only.
- `CandidatePolicy`: `classify(repository, capacity) -> CandidateDecision`.
- `CommitGate`: `check(candidate) -> GateOutcome`; the only authority that can create a scan permit.
- `SnapshotReader`: `read(scanPermit, budgets) -> EphemeralSnapshot`; rejects missing/invalid permits.
- `Analyzer`: `analyze(snapshot, context) -> SanitizedFindingDraft[]`; content dies inside this seam.
- `SecretRedactor`: `fingerprint(rawMatch) -> SecretEvidence`; no raw value is returned.
- `FindingStore`: metadata-only write/read/review interface with runtime rejection of forbidden keys.
- `ScanOrchestrator`: `process(candidate) -> ScanResult`; coordinates states, budgets, cleanup, and telemetry.
- `OperatorQuery`: sanitized findings, investigation, stream, system, and review commands.

## 5. Confirmed public test seams

The source report defines the behaviors and interfaces below; these are the agreed seams for TDD. Tests must cross these interfaces and must not inspect private helpers or mock internal modules.

| Seam | Observable behavior under test | Boundary adapters allowed in tests |
|---|---|---|
| Discovery HTTP -> candidate repository | Cursor transactionality, pagination, deduplication, metadata-only writes | Fake GitHub HTTP server, test Postgres |
| Candidate policy | Deterministic selection/skip and capacity degradation from public inputs | Fixed clock/config |
| Commit gate -> scan permit | 200 permits one HEAD; 409 parks; 404 closes; 403/429 reschedules; no content read on non-200 | Fake GitHub HTTP server, fixed clock |
| Scan permit -> bounded snapshot | Tree/blob order, priority, byte/file/time limits, truncation/partial coverage, serialized requests | Fake GitHub/stream adapter, fixed clock |
| Ephemeral snapshot -> analyzer results | Expected redacted findings for known-good fixtures | Fake OSV only; real analyzers/parsers |
| Secret redaction | Provider/type/location/fingerprint emitted; raw canary absent | Fixed HMAC key |
| Program model -> attack paths | Worked JS/TS/Python source-to-sink examples, barriers, cross-file flow, score tiers | Real parsers, fixed budgets |
| Sanitized finding store | Round-trip safe metadata and rejection of forbidden/raw content fields | Test Postgres |
| Orchestrator | Public state transitions, coverage, cleanup, no prohibited interactions | Fake GitHub/OSV, test Postgres, fixed clock |
| Operator HTTP/SSE | Filters, ranking, detail, review transition, metrics, stream events, redacted schemas | In-process server + test Postgres |
| Operator browser | User-visible navigation, finding comprehension, review action, live stream, system health, no raw secret/source | Playwright against full local stack |
| Zero-retention audit | Raw fake canary appears zero times; its HMAC appears only in bounded intended sanitized metadata representations | Controlled fixture and test environment |

Mocks/fakes are permitted only at true system seams: GitHub, OSV, time, persistence, process limits, and browser network transport. Internal modules are exercised together.

## 6. Checkpoints and acceptance criteria

Every checkpoint follows a vertical red -> green cycle: add one failing behavior test, implement only enough to pass, repeat. A checkpoint is complete only when its tests, typecheck/lint/build, progress log, commit, and remote push all succeed.

### CP00 — Build contract and repository baseline

- `spec.md` captures the complete validation-MVP boundary, interfaces, seams, checkpoints, and definition of done.
- `progress.md` is initialized and updated for every material red/green/verification/commit event.
- Repository baseline, branch, remote, toolchain, and source-report hash are recorded.

### CP01 — Workspace, domain language, and quality gates

- npm workspaces for `apps/api`, `apps/worker`, `apps/web`, and shared packages.
- Strict TypeScript, formatting/linting, Vitest, integration test harness, Playwright, coverage, build, and CI scripts.
- Domain states, value objects, redacted schemas, coverage, scoring tiers, and forbidden-data vocabulary.
- Public schema tests establish valid/invalid metadata without implementing business flows.

### CP02 — Metadata persistence and mandatory sanitization

- PostgreSQL migrations for cursor, candidates, scans/coverage, findings/path nodes, reviews, events, and aggregate metrics.
- Transactional repositories and deterministic migrations.
- Runtime allowlist schemas reject raw content/secret fields and unsafe review notes.
- Integration tests prove cursor atomicity, dedupe, valid state transitions, review states, and sanitized round trips.

### CP03 — Discovery, prioritization, and commit gate

- Serialized GitHub client with headers, auth, pagination, rate metadata, Retry-After/reset behavior, and bounded retry.
- Metadata-only discovery persists all items before advancing the exclusive cursor.
- Candidate scoring is independent from finding/exploitability scoring and responds to capacity pressure.
- Gate outcomes implement the full schedule and never invoke content access before a commit.
- Optional PushEvent only wakes an already waiting candidate and never replaces gate/poll completeness.

### CP04 — Bounded, non-cloning HEAD inspection

- A valid scan permit is required by the snapshot reader.
- Recursive tree classification and high-value blob ordering operate before content retrieval.
- Generated/binary/LFS/submodule/unsafe paths are skipped and represented in coverage.
- Raw blobs stream into bounded memory; file, repository, file-count, graph, and wall-clock limits terminate predictably.
- Truncated trees produce honest partial coverage and selected subtree fallback within budget.
- Tests prove no clone/archive/checkout/package/build command exists in the execution path.

### CP05 — Secrets and dependency analysis

- Structured provider/private-key/connection-string rules plus keyword/entropy/context and placeholder suppression.
- Secret result contains no raw characters and uses deterministic keyed fingerprinting.
- Exact dependencies parsed without package managers from prioritized JS, Python, Go, Rust, Ruby, Java, PHP, and .NET formats where the report lists them.
- OSV queries batch at <=100, use exact package/ecosystem/version tuples, and return sanitized advisory metadata.
- Controlled fixtures cover true positives, placeholders, integrity hashes, generated files, malformed manifests, and OSV failures.

### CP06 — CI, Docker, cloud, and IaC analysis

- GitHub Actions: broad permissions, unpinned actions, unsafe `pull_request_target`, secret/shell interpolation, and untrusted privileged execution.
- Docker: credential ARG/ENV, root, permissive modes, and downloaded-script execution.
- Terraform/Kubernetes/cloud/config: public exposure, public storage, hardcoded credentials, privileged workloads, TLS/CORS/auth risks.
- Every result is a rule/location/semantic metadata record without source snippets.

### CP07 — JS/TS/Python passive exploitability engine

- Safe bounded parsers build in-memory program models without dynamic imports/evaluation.
- Framework-aware entry points and attacker sources cover representative Express/Next-style, Flask, and FastAPI fixtures.
- Dangerous sinks cover command, SQL, SSRF, filesystem/path traversal, eval/exec, deserialization, template, and relevant auth/TLS cases.
- Cross-function and cross-file call/data-flow tracing is bounded and emits location/edge metadata only.
- Sanitizer, parameterization, normalization, authentication, and authorization barriers reduce/stop paths.
- Worked fixtures independently establish possible/plausible/probable/high-confidence tiers at 0–39/40–69/70–89/90–100.
- All results keep runtime/deployment/active-testing claims false.

### CP08 — Orchestration, lifecycle, and operational metrics

- Workers transition DISCOVERED/SKIPPED/WAITING_FOR_COMMIT/READY/SCANNING/SCANNED_NO_FINDINGS/SCANNED_FINDINGS/PARTIAL/FAILED/RATE_LIMITED correctly.
- One committed HEAD is scanned at most once; retried jobs are idempotent.
- Ephemeral buffers and program models are released at the analysis seam on success, limit, timeout, and failure.
- Metrics cover the complete funnel, requests, bytes, latency, quota, partials/timeouts/failures, and finding/review rates without content.
- Graceful stop/degrade occurs under sustained API pressure.

### CP09 — Sanitized operator HTTP and live-event interface

- Private operator authentication gate and secure defaults.
- Findings query supports every required filter and severity/exploitability/recency ranking.
- Investigation response includes repository/revision, semantic path, barriers, limitations, coverage, and safe GitHub links.
- Review command enforces UNREVIEWED -> CONFIRMED/FALSE_POSITIVE/UNCERTAIN with non-sensitive note validation.
- SSE exposes sanitized state transitions; System exposes all required validation/safety metrics.
- Contract tests assert forbidden keys/values never reach JSON, SSE, errors, logs, or telemetry.

### CP10 — Findings console

- Desktop-first dark, restrained, high-density shell with exactly Findings, Stream, System top-level destinations.
- Findings is the default route with required metrics, filters, ranked cards/rows, clear severity/family/exploitability/recency, loading/empty/error states, keyboard access, and responsive minimum behavior.
- No unescaped HTML/Markdown and no source/secret frontend logging or persistence.

### CP11 — Investigation and human review

- Dedicated detail route renders semantic entry -> source -> flow -> sink evidence, reasons surfaced, barriers, limitations, and first-class coverage.
- Static evidence is visibly distinguished from runtime confirmation.
- Secret detail exposes only type, location, confidence, truncated fingerprint, and `Raw value NOT RETAINED`.
- Review actions update the record and validation metrics; notes reject likely secrets/source payloads.
- Safe “Open on GitHub” URL is revision/path/line anchored.

### CP12 — Stream and System console

- Stream updates near real time and renders every required public state without raw payloads.
- System shows throughput, funnel, quota, cost, latency, precision, partial/failure, and canary status with obvious degraded/unsafe states.
- Browser tests prove navigation, filters, investigation comprehension, review, stream updates, and system health.

### CP13 — Threat-model hardening and zero-retention proof

- Hardened worker/container: non-root, read-only root, tmpfs/no source volume, no host/Docker socket, disabled privilege escalation, resource/process/file-descriptor limits, core dumps off, documented swap requirement, and no direct external route outside an exact GitHub/OSV CONNECT proxy plus production FQDN-aware policy.
- Parser defenses: safe YAML, XXE/network-disabled XML, depth/size bounds, defensive Unicode, terminal/control escaping, URL non-following.
- Controlled fake canary repository contains no functional credential.
- A reproducible runtime audit runs the fixture through commit gate, bounded snapshot, analyzers, PostgreSQL, API serialization, rendered web output, and browser storage; it proves zero raw occurrences, cleared ephemeral snapshot buffers, and only bounded intended HMAC fingerprint representations.
- Successful runtime proof records `zero_retention.canary.last_run`, `zero_retention.canary.success`, `zero_retention.canary.raw_occurrences`, and `zero_retention.canary.fingerprint_occurrences`; seed data never creates a safety metric.
- Tests prove discovered credentials are never verified and repository URLs never cause egress.

### CP14 — Complete runnable product and operations

- Local compose stack, migrations, seed/demo metadata, health/readiness, configuration example, credential-minimization guidance, and runbooks.
- README documents architecture, safe operating model, setup, testing, limits, report interpretation, disclosure boundary, and troubleshooting.
- CI runs lint, typecheck, unit/integration, security invariants, browser tests, and production builds.
- A controlled end-to-end scan demonstrates discovery -> gate -> bounded analysis -> redacted finding -> review -> metric without source persistence.

### CP15 — Final verification and delivery

- Clean install succeeds from lockfile.
- All tests, lint, typecheck, migration checks, builds, and container configuration validation pass.
- Coverage targets: 90% branches/functions/lines/statements in domain/security-critical packages; meaningful browser coverage for every UI acceptance criterion.
- Dependency and secret checks show no known build blocker or committed credential.
- `progress.md` maps every acceptance criterion to evidence and ends with no unexplained TODO/FIXME, skipped required test, or unresolved checkpoint.
- Every checkpoint is committed and pushed; local HEAD equals remote branch HEAD and the worktree is clean.

## 7. Test fixture policy

- All credentials are syntactically representative but provably fake/non-functional and labeled as fixtures.
- Expected results are fixed literals derived from this specification, not recomputed using implementation logic.
- Fixtures include malformed, oversized, binary, generated, truncated, timed-out, Unicode/control-character, and adversarial parser inputs.
- Integration tests use local fake HTTP endpoints and a disposable database; no test scans unrelated live repositories.
- Live GitHub validation, if enabled manually, is read-only and targets only the controlled public fixture.

## 8. Progress and commit protocol

- `progress.md` is append-only except for the summary/checkpoint table.
- Each material entry records UTC/IST timestamp, checkpoint, red/green/verification result, files or capability changed, and commit/push evidence when available.
- Commit messages use `checkpoint NN: <outcome>` and each completed checkpoint is pushed immediately to `origin`.
- A failed check is logged before its fix; it is not erased from history.

## 9. Definition of done

The build is complete only when CP00–CP15 are complete, the full validation suite passes from a clean install, safety invariants are demonstrated by tests and the canary audit, the operator UI meets all eight report acceptance criteria, all required documentation is current, all work is pushed to GitHub, the worktree is clean, and the remote commit is verified.
