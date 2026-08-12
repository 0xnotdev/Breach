# Breach Build Progress

This ledger records material specification, TDD, verification, commit, and push events. Times are Asia/Calcutta unless marked UTC. Failed checks remain recorded.

## Current status

| Checkpoint | State | Evidence |
|---|---|---|
| CP00 Build contract | Complete | `spec.md`; ledger initialized; `git diff --check` passed |
| CP01 Workspace/domain | Complete | 6 contract tests; lint/typecheck/test/build passed |
| CP02 Persistence/sanitization | Complete | 5 integration behaviors; 11 total tests; all gates passed |
| CP03 Discovery/gate | Complete | 6 GitHub seam tests; 17 total tests; all gates passed |
| CP04 Bounded inspection | Complete | 5 snapshot tests; 22 total tests; all gates passed |
| CP05 Secrets/dependencies | Complete | 4 analyzer behaviors across 13 formats; 26 total tests |
| CP06 CI/Docker/IaC | Complete | 14 semantic rule results; 27 total tests |
| CP07 Passive exploitability | Complete | 8 worked path behaviors; 35 total tests |
| CP08 Orchestration/metrics | Complete | 5 lifecycle + durable claim/metric behavior; 41 tests |
| CP09 Operator interface | Complete | 5 HTTP/SSE behaviors; 46 total tests |
| CP10 Findings UI | Complete | 2 server-render/artifact tests; all gates passed |
| CP11 Investigation/review | Pending | — |
| CP12 Stream/System UI | Pending | — |
| CP13 Hardening/canary | Pending | — |
| CP14 Runnable product/ops | Pending | — |
| CP15 Final verification | Pending | — |

## Progress log

### 2026-08-12 17:58 IST — Goal and environment audit

- Confirmed the active persistent goal exactly matches the requested full build, spec-driven/TDD process, continuous progress ledger, and GitHub publication.
- Read the complete TDD workflow and its testing/mocking references.
- Consulted the deep-module design vocabulary required for selecting public test seams.
- Read the GitHub publication workflow. GitHub CLI is not installed, so its PR-specific path is unavailable; direct authenticated Git commits/pushes remain in scope and will be verified.
- Cloned `https://github.com/0xnotdev/Breach.git` into `D:\Breach`; Git reported that the remote repository is empty.
- Verified `origin`, `main`, Git author configuration, Node 24.14.1, npm 11.11.0, pnpm 11.16.0, and Docker 29.5.2.

### 2026-08-12 18:01 IST — Source scope audit

- Read the 2,332-line source report end-to-end and re-read the architecture, analysis, operator UI, threat model, schemas, prototype stages, success criteria, included boundary, and explicit non-goals in focused sections.
- Recorded source report SHA-256 `D9E59A9CF188786892D0CC0D1F6FF5AFDA48A181BF5EB0D88945BD56CDE97C55`.
- Derived the public test seams from report-defined behaviors. These seams are now confirmed in `spec.md` before any test or implementation code.
- Selected a TypeScript monorepo, PostgreSQL metadata store, HTTP/SSE operator interface, and React operator console as the implementation shape.
- Consulted the Sites build workflow because the required operator console is a multi-route web application. The user-mandated specification artifacts are being completed before site initialization.

### 2026-08-12 18:05 IST — CP00 specification created

- Created `spec.md` as the build contract.
- Divided the validation MVP into CP00–CP15 with acceptance criteria, test seams, non-negotiable safety invariants, test fixture policy, commit protocol, and a strict definition of done.
- Created `progress.md` before implementation. No production code or test code existed at this point.

### 2026-08-12 18:07 IST — CP00 verification

- Verified both artifacts exist and are non-empty (`spec.md` 19,698 bytes; `progress.md` 3,068 bytes before this entry).
- `git diff --check` passed with no whitespace errors.
- CP00 accepted. Next action is the first repository commit and remote push, followed by CP01 red tests.

### 2026-08-12 18:10 IST — CP00 published / CP01 scaffold

- Committed CP00 as `7256e1f` (`checkpoint 00: define build contract`) and pushed `main` to `origin`.
- Verified local and remote `main` both resolve to `7256e1f41fbe8331e516a4f325b36e7b9ea496c1`; worktree was clean.
- Initialized the required web-console starter at `apps/web`, installed its dependencies, started its retained local preview, verified HTTP 200 at `http://localhost:3000`, and opened it in the Codex browser panel. The site workflow caused this initialization; product UI has not yet been implemented.
- Added the root npm-workspace/TypeScript/Vitest/ESLint scaffold and the first contract behavior tests.

### 2026-08-12 18:12 IST — CP01 RED: public metadata contracts

- Ran `npm test -- --run packages/contracts/src/contracts.test.ts`.
- Expected failure observed: the public contract module `packages/contracts/src/index.ts` did not exist, so the suite could not load `./index.js`.
- No implementation was added before this red result.

### 2026-08-12 18:14 IST — CP01 GREEN / RED: schemas and score tiers

- Implemented strict public metadata schemas for pipeline/review states, coverage, static exploitability, semantic path nodes, secret evidence, and sanitized findings.
- The initial five contract tests passed.
- Added a second behavior slice for the specification's exact exploitability tier boundaries.
- Expected red result observed: 5 tests passed and the new boundary test failed because `classifyExploitabilityLevel` was not implemented.

### 2026-08-12 18:16 IST — CP01 GREEN: score tiers

- Implemented the minimal 0–100 score classifier with exact `possible`, `plausible`, `probable`, and `high_confidence_static_path` boundaries.
- All 6 public contract behavior tests passed.
- Strict TypeScript compilation passed.
- The first lint verification failed: typed linting attempted to parse root configuration outside the project, and Zod v4 flagged three deprecated chained validators. Tests and typecheck remained green.
- Corrected lint scoping and replaced the deprecated validators with Zod v4 top-level validators.
- A second combined shell run still reported lint configuration errors for `vitest.config.ts`; because later commands succeeded, the shell's final exit code was zero. This was treated as a failed lint check, not a successful verification.
- Excluded build-tool configuration from source linting and reran every gate independently in parallel.

### 2026-08-12 18:19 IST — CP01 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 1 file, 6 tests.
- `npm run build` passed for `@breach/web` (five vinext build stages) and `@breach/contracts`.
- Root npm workspaces, strict compiler settings, lint/test/build scripts, web workspace, domain vocabulary, coverage/static-evidence contracts, and lockfile are now established.
- CP01 accepted and ready to commit/push.

### 2026-08-12 18:21 IST — CP01 published / CP02 started

- Committed CP01 as `8c52af9` (`checkpoint 01: establish typed workspace`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `8c52af9b83a2e4ed8c2bea249139f2695a89e198`; worktree was clean.
- Began CP02 with the metadata-store public interface and integration behavior tests; implementation remains intentionally absent for the red run.

### 2026-08-12 18:23 IST — CP02 RED: metadata persistence seam

- Added five integration behaviors covering transactional discovery/cursor persistence, rollback, legal lifecycle transitions, sanitized finding round trips, and safe review notes.
- Ran `npm test -- --run packages/storage/src/storage.test.ts`.
- Expected failure observed: `packages/storage/src/index.ts` did not exist, so no persistence implementation loaded.

### 2026-08-12 18:25 IST — CP02 GREEN iterations

- Implemented PostgreSQL metadata migrations and the `MetadataStore` interface for discovery cursor/candidates, scans/coverage, sanitized findings, review records, lifecycle events, and metric samples.
- Added transactional page recording, monotonic cursor advancement, candidate pre-validation, legal transition enforcement, strict finding parsing, and sensitive review-note rejection.
- First implementation run failed all 5 tests because the in-memory PostgreSQL adapter does not provide `char_length`; replaced those constraints with portable non-empty checks.
- Second run passed 3/5. The rollback fixture exposed the adapter's incomplete transaction emulation, and the note filter missed compound environment-variable names. Moved complete candidate validation before the transaction (also reducing partial-write risk) and expanded the secret-assignment guard.
- Storage behavior suite then passed all 5 tests.
- First typecheck failed on a narrowed candidate extension, object-method `this` inference, and an intentionally unsafe test object. Corrected the stored type, closed over the store interface, added explicit parsing types, and kept the runtime rejection fixture through an `unknown` cast.
- First lint verification failed on numeric error interpolation and the deliberately untyped `pg-mem` adapter constructor. Corrected the messages and constrained the lint exception to that one external adapter line.

### 2026-08-12 18:28 IST — CP02 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 2 files, 11 tests.
- `npm run build` passed for web, contracts, and storage workspaces.
- CP02 accepted and ready to commit/push.

### 2026-08-12 18:30 IST — CP02 published / CP03 started

- Committed CP02 as `3a13b41` (`checkpoint 02: enforce sanitized metadata persistence`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `3a13b4110a4e77656c21d6e007afd899300a87a6`; worktree was clean.
- Began CP03 with public behaviors for metadata-only candidate policy, paginated discovery recording, serialized GitHub dispatch, mandatory gate outcomes/backoff, and safe PushEvent acceleration.

### 2026-08-12 18:32 IST — CP03 RED: GitHub intake and commit authorization

- Added seven behavior tests across the public GitHub seam.
- Ran `npm test -- --run packages/github/src/github.test.ts`.
- Expected failure observed: `packages/github/src/index.ts` did not exist, so none of the intake/gate interfaces loaded.

### 2026-08-12 18:34 IST — CP03 GREEN: intake, dispatcher, gate, accelerator

- Implemented deterministic metadata-only candidate policy with quota-capacity buckets independent of later finding/exploitability scores.
- Implemented creation-feed pagination with official GitHub headers and page-at-a-time sink commits before cursor advancement.
- Implemented a single-flight serialized request dispatcher so concurrent callers never create concurrent GitHub REST requests.
- Implemented commit-gate outcomes for 200/empty/409/404/403/429/unexpected responses, the 1m/5m/30m/2h/24h recheck schedule, Retry-After/reset handling, and a branded scan permit available only from a valid commit SHA.
- Implemented PushEvent correlation that wakes only the matching `WAITING_FOR_COMMIT` candidate and never replaces discovery/gate completeness.
- All 6 new behavior tests passed on the first green implementation run.
- Verification initially found three lint issues confined to async test fakes and an `unknown` response-array read; corrected them without changing behavior.

### 2026-08-12 18:36 IST — CP03 verification

- `npm run lint` passed after the focused corrections.
- `npm run typecheck` passed.
- `npm test` passed: 3 files, 17 tests.
- `npm run build` passed for web, contracts, GitHub, and storage workspaces.
- Gate tests prove every non-ready outcome performs exactly one commit request and no content request.
- CP03 accepted and ready to commit/push.

### 2026-08-12 18:38 IST — CP03 published / CP04 started

- Committed CP03 as `dc4416c` (`checkpoint 03: gate GitHub content access`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `dc4416c977d76f9c476541f44275a8904f1cbe2b`; worktree was clean.
- Began CP04 with tests for unforgeable gate permits, high-value tree classification, streamed blob budgets, honest coverage, and explicit buffer release.

### 2026-08-12 18:40 IST — CP04 RED: bounded committed-HEAD snapshot

- Added four behavior tests covering forged permits, priority/budget selection, unexpectedly oversized streams, truncated-tree coverage, and byte-buffer overwriting.
- Ran `npm test -- --run packages/snapshot/src/snapshot.test.ts`.
- Expected failure observed: `packages/snapshot/src/index.ts` did not exist.

### 2026-08-12 18:42 IST — CP04 GREEN / RED: core snapshot and subtree fallback

- Implemented process-bound unforgeable scan permits, bounded tree/blob inspection, path/type classification, priority ordering, raw stream limits, coverage accounting, and explicit buffer overwriting/release.
- Initial four snapshot behaviors passed.
- Added the required truncated-tree subtree fallback as a separate red slice.
- Expected red result observed: 4 tests passed and the new fallback test failed because no subtree traversal existed.

### 2026-08-12 18:44 IST — CP04 GREEN: truncated-tree fallback

- Implemented priority-ranked, one-level recursive subtree fallback capped at 25 directories and bounded by the existing file/time budgets.
- All 5 snapshot behaviors passed, including honest `treeTruncated` coverage even when selected subtree recovery succeeds.
- Full verification initially found two lint issues: a control-character regex and an await-free async test generator. Replaced the regex with an explicit code-unit guard and made the test seam explicitly asynchronous.
- A follow-up lint run found the string-spread Unicode rule; replaced it with indexed code-unit iteration.

### 2026-08-12 18:46 IST — CP04 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 4 files, 22 tests.
- `npm run build` passed for all five workspaces.
- Runtime source audit found no clone, archive, package-install, process-execution, or build command in the snapshot path; the only textual `exec(` match is `RegExp.exec` in Link parsing.
- Forged permits produce zero requests; only a live process-issued gate permit can reach Trees/Blobs.
- CP04 accepted and ready to commit/push.

### 2026-08-12 18:48 IST — CP04 published / CP05 started

- Committed CP04 as `f4c4119` (`checkpoint 04: bound ephemeral HEAD inspection`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `f4c411995d426f176e5f98f0e62f790d0aec133f`; worktree was clean.
- Began CP05 using only fake non-functional credential fixtures and exact dependency literals.

### 2026-08-12 18:50 IST — CP05 RED: secrets, manifests, and OSV

- Added four behaviors covering raw-secret exclusion, deterministic fingerprints, placeholder/integrity suppression, eight representative ecosystems, unresolved-range rejection, malformed input, and 100-item OSV batches.
- Ran `npm test -- --run packages/analyzers/src/analyzers.test.ts`.
- Expected failure observed: `packages/analyzers/src/index.ts` did not exist.

### 2026-08-12 18:52 IST — CP05 GREEN / RED: core analyzers and remaining formats

- Implemented structured/contextual secret detection, placeholder/generated/integrity suppression, HMAC-only output, exact manifest parsing, and OSV batching/correlation.
- Three syntax corrections were required before collection: numeric separators and unescaped Unicode-mode bracket literals in regex quantifiers/classes.
- The original 4 behavior tests then passed.
- Expanded the manifest acceptance table with Go sum, Cargo manifest, pyproject, pnpm, and Yarn lock fixtures.
- Expected red result observed: the format table failed first at unsupported `go.sum`; the other 3 behaviors remained green.

### 2026-08-12 18:54 IST — CP05 GREEN: complete prioritized formats

- Added exact-version parsing for Go sums, Cargo manifests, and PEP 621/Poetry pyproject dependencies; pnpm and Yarn fixtures also passed the existing parsers.
- The expanded format table passed across npm lock/manifest, pnpm, Yarn, requirements, Pipfile/Poetry/uv paths, Go mod/sum, Cargo manifest/lock, Gemfile lock, Maven/Gradle, Composer, and NuGet implementations.
- Added an explicit generic high-entropy credential fixture; the result remains fingerprint-only and the raw fixture is absent from serialized output.
- First full verification: all 26 tests passed, but lint found unnecessary `match.index` fallbacks and typecheck/build found string key length handling. Removed the unnecessary fallbacks and measured string keys as encoded bytes.

### 2026-08-12 18:56 IST — CP05 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 5 files, 26 tests.
- `npm run build` passed for all six workspaces.
- OSV tests prove 205 exact packages produce batches of 100/100/5 and only advisory/package metadata returns.
- No package manager, dependency installation, credential validation, or credential use occurs in the analyzer interface.
- CP05 accepted and ready to commit/push.

### 2026-08-12 18:58 IST — CP05 published / CP06 started

- Committed CP05 as `9cf2ba8` (`checkpoint 05: detect secrets and vulnerable dependencies`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `9cf2ba8b667d8e54a106777d56d712a0bf551cd1`; worktree was clean.
- Began CP06 with controlled CI, Docker, Terraform, Kubernetes, TLS, and CORS fixtures.

### 2026-08-12 19:00 IST — CP06 RED: configuration semantics

- Added a behavior fixture spanning GitHub Actions, Docker, Terraform, Kubernetes, TLS, and credentialed CORS.
- Ran the analyzer suite; 4 existing behaviors passed and the new configuration behavior failed because `scanConfiguration` was not implemented.

### 2026-08-12 19:02 IST — CP06 GREEN: configuration semantics

- Implemented location-only semantic rules for risky `pull_request_target`, write-all workflow permissions, unpinned Actions, secrets interpolated into shell steps, Docker credential ARG/ENV, downloaded scripts piped to shells, world-writable modes, and root execution.
- Implemented public sensitive Terraform ingress/public storage rules, privileged Kubernetes/privilege escalation rules, disabled TLS verification, and wildcard credentialed CORS.
- The controlled fixture emitted the expected 14 ordered rule/location records and no snippet, repository string, secret name, or arbitrary URL.

### 2026-08-12 19:04 IST — CP06 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 5 files, 27 tests.
- `npm run build` passed for all six workspaces.
- CP06 accepted and ready to commit/push.

### 2026-08-12 19:06 IST — CP06 published / CP07 started

- Committed CP06 as `c5f81dd` (`checkpoint 06: analyze CI Docker and IaC risk`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `c5f81dda20ead2e21ec89e4fb6cb4ea5c1cd86b7`; worktree was clean.
- Began CP07 with worked Express and FastAPI source-to-sink paths plus negative/barrier cases.

### 2026-08-12 19:08 IST — CP07 RED: passive attack paths

- Added five behavior tests for cross-file Express command injection, cross-file FastAPI SSRF, sanitizer/auth downranking, parameterized SQL suppression, and disconnected-sink uncertainty.
- Ran `npm test -- --run packages/dataflow/src/dataflow.test.ts`.
- Expected failure observed: `packages/dataflow/src/index.ts` did not exist.

### 2026-08-12 19:10 IST — CP07 GREEN / RED: core paths and framework expansion

- Implemented bounded TypeScript syntax-tree parsing, indentation-aware Python function parsing, entry/source/call/sink models, taint propagation, aliases, sanitizer/auth evidence, parameterized-query suppression, bounded cross-file traversal, and score construction.
- The original 5 worked behaviors passed on the first implementation run.
- Added Next route, Flask decorator, additional sink-family, and graph-depth behaviors.
- Seven of 8 tests passed; expected red result remained for Next/Flask entry modeling because the Next handler was treated as a disconnected primitive.

### 2026-08-12 19:12 IST — CP07 GREEN: framework and bounds expansion

- Added Next App Router `route.ts` entry modeling with dynamic path normalization and request parameters, plus Flask `@app.route(..., methods=[...])` modeling.
- All 8 data-flow behaviors passed.
- The engine now exercises command injection, SQL injection, SSRF, path traversal, dynamic code, unsafe deserialization, parameterized-query suppression, sanitizer/auth barriers, Express, Next, FastAPI, Flask, cross-file flow, all four confidence tiers, and graph-depth termination.
- Full verification initially found one lint-only route-segment narrowing issue. Simplified the control-flow guard; lint then passed.

### 2026-08-12 19:14 IST — CP07 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 6 files, 35 tests.
- `npm run build` passed for all seven workspaces.
- Attack paths contain only semantic location/symbol/edge metadata; worked tests assert source expressions/snippets are absent from serialized results.
- Every result hard-codes runtime verification, active testing, and deployment confirmation to false.
- CP07 accepted and ready to commit/push.

### 2026-08-12 19:16 IST — CP07 published / CP08 started

- Committed CP07 as `b6df3f6` (`checkpoint 07: reconstruct passive attack paths`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `b6df3f6967ffbf6f1f65712985a4ec3cd98d4445`; worktree was clean.
- Began CP08 with end-to-end worker lifecycle, idempotence, cleanup, partial/failure, and content-free metric behaviors.

### 2026-08-12 19:18 IST — CP08 RED: scan lifecycle

- Added five orchestration behaviors for a complete scan, empty-repository parking, at-most-once HEAD claims, analyzer failure cleanup, and partial coverage precedence.
- Ran `npm test -- --run packages/orchestrator/src/orchestrator.test.ts`.
- Expected failure observed: `packages/orchestrator/src/index.ts` did not exist.

### 2026-08-12 19:20 IST — CP08 GREEN / RED: orchestration and durable claims

- Implemented gate-to-scan orchestration, deterministic sanitized finding IDs, all analyzer composition, at-most-once claims, final-state precedence, aggregate metrics, and buffer release on success/failure.
- Four of 5 orchestration tests passed initially. The remaining assertion incorrectly rejected `req.body.command`, which is explicitly permitted semantic source metadata; corrected it to reject the actual `router.post` source snippet. All 5 orchestration tests then passed.
- Added a durable lifecycle slice to the storage seam for at-most-once HEAD claims and content-free scan/metric retrieval.
- Expected red result observed: 5 storage behaviors passed and the new lifecycle behavior failed because `claimScan` did not exist.

### 2026-08-12 19:22 IST — CP08 GREEN: durable lifecycle

- Extended the metadata store with the orchestrator-compatible transition/scheduling/claim/bulk-findings/completion/metric interface.
- The first claim implementation exposed a `pg-mem` row-count incompatibility: a conflict-free result still reported a positive row count. Replaced row-count reliance with a per-attempt random claim token and a subsequent exact-owner read; this remains atomic under PostgreSQL's unique `(repo_id, head_sha)` constraint.
- All 6 storage behaviors passed, including duplicate-HEAD rejection and safe coverage/metric round trips.

### 2026-08-12 19:24 IST — CP08 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 7 files, 41 tests.
- `npm run build` passed for all eight workspaces.
- Successful, waiting, duplicate, failed, and partial lifecycles are covered; every acquired snapshot is released on all terminal paths.
- Metrics accept only bounded names, finite values, and short sanitized label values; errors/source content never enter labels.
- CP08 accepted and ready to commit/push.

### 2026-08-12 19:26 IST — CP08 published / CP09 started

- Committed CP08 as `f3d9b9d` (`checkpoint 08: orchestrate safe scan lifecycle`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `f3d9b9ded9f86bb2a046bbddea59e559718d4671`; worktree was clean.
- Began CP09 at the HTTP/SSE interface with authentication, filters, detail, review, metrics, and forbidden-data behaviors.

### 2026-08-12 19:28 IST — CP09 RED: operator HTTP/SSE

- Added five HTTP-level behaviors for authentication, ranking/filters, investigation/review, stream/system, and redacted errors.
- Ran `npm test -- --run packages/operator/src/operator.test.ts`.
- Expected failure observed: `packages/operator/src/index.ts` did not exist.

### 2026-08-12 19:30 IST — CP09 GREEN: operator HTTP/SSE

- Implemented constant-time bearer authentication, no-store/security response headers, all required finding filters, severity/exploitability/recency ranking, sanitized detail responses, revision-anchored GitHub links, review validation, state-event SSE, and system metrics.
- Errors are fixed codes and never echo request values. Review notes reject likely assignments, private-key markers, long high-entropy spans, and oversized text.
- All 5 interface behaviors passed.
- First full verification found one lint issue in test header composition; replaced object spread with a `Headers` instance.

### 2026-08-12 19:32 IST — CP09 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 8 files, 46 tests.
- `npm run build` passed for all nine workspaces.
- JSON/SSE tests verify forbidden raw values and source snippets are absent while allowed semantic source symbols remain available for investigation.
- CP09 accepted and ready to commit/push.

### 2026-08-12 19:34 IST — CP09 published / CP10 started

- Committed CP09 as `cee3e7c` (`checkpoint 09: expose sanitized operator interface`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `cee3e7c53620215675c4c48ee2e4191e57f3fbf3`; worktree was clean.
- Began CP10 by replacing the starter render contract with Findings-console acceptance checks before product UI implementation.

### 2026-08-12 19:36 IST — CP10 RED: Findings console

- Replaced starter tests with product-specific server-render assertions and disposable-artifact checks.
- Ran the web test command. The build succeeded and both new tests failed against the still-present starter title, skeleton markup, preview metadata, and `_sites-preview` directory.
- No product UI was implemented before this red result.

### 2026-08-12 19:40 IST — CP10 GREEN: Findings console

- Replaced the disposable starter with a dense, responsive, findings-first operator console.
- Added repository/finding/language search, severity and family filters, explicit reset, deterministic ranking cues, required navigation, live/status metrics, coverage-aware empty-state wording, and a static-evidence-only boundary.
- Added five sanitized demonstration findings spanning exploitability, secrets, dependencies, and configuration without embedding raw repository content or secret values.
- Removed the starter preview implementation, loading-skeleton dependency, and unused starter icons.
- The first green run exposed two acceptance-test mistakes: the empty state is conditional and an empty directory is not a shipped artifact. Tightened the tests to verify the conditional source branch and concrete artifact absence. The web build and both UI tests then passed.

### 2026-08-12 19:42 IST — CP10 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 8 files, 46 domain/service tests.
- `npm run build` passed for the web application and all eight library workspaces.
- `npm test` in `apps/web` passed both server-render and starter-removal behaviors.
- CP10 accepted and ready to commit/push.
