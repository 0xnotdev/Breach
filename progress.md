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
| CP11 Investigation/review | Complete | 2 detail-route behaviors; 4 web tests; all gates passed |
| CP12 Stream/System UI | Complete | 6 render + 2 browser behaviors; all gates passed |
| CP13 Hardening/canary | Complete | 7 security behaviors; Compose valid; all gates passed |
| CP14 Runnable product/ops | Complete | 6 runtime/ops tests; 3 images; real DB/API/web smoke; all gates passed |
| CP15 Final verification | Complete | Clean lockfile install; 72 tests; 90%+ coverage; UI/browser, DB, image, audit gates passed |

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

### 2026-08-12 19:44 IST — CP10 published / CP11 started

- Committed CP10 as `3665401` (`checkpoint 10: build findings operator console`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `3665401ec231b3cc804df0db03535f0c7bad4339`; the worktree was clean.
- Began CP11 with server-render contracts for exploitability investigation and secret-safe detail routes.

### 2026-08-12 19:46 IST — CP11 RED: investigation and review

- Added route-level behaviors for semantic entry/source/flow/sink evidence, reasons, barriers, coverage/limitations, static-evidence labeling, three-state review controls, revision-anchored GitHub navigation, and secret-safe details.
- Ran the web test command. The existing two behaviors passed; both new detail-route behaviors failed with the expected HTTP 404 because no investigation route existed.

### 2026-08-12 19:49 IST — CP11 GREEN: investigation and review

- Added a dedicated dynamic investigation route with repository/revision identity, severity, static-evidence boundary, semantic attack-path nodes, reasons surfaced, observed barriers, coverage, and limitations.
- Added a redacted secret investigation mode exposing only type, location, confidence, truncated HMAC fingerprint, and `Raw value NOT RETAINED`.
- Added revision/path/line-anchored GitHub links using system-owned finding metadata.
- Added the three review decisions, local state feedback, validation-metric confirmation, bounded notes, and rejection of assignments, private-key markers, provider key shapes, and long encoded spans.
- All four web behaviors passed.

### 2026-08-12 19:51 IST — CP11 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 8 files, 46 domain/service tests.
- `npm run build` passed for the web application and all eight library workspaces.
- `npm test` in `apps/web` passed all four server-render and artifact behaviors.
- CP11 accepted and ready to commit/push.

### 2026-08-12 19:53 IST — CP11 published / CP12 started

- Committed CP11 as `0234400` (`checkpoint 11: add investigation and review`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `0234400eefcd860f8e9e1ddf270cd927afe5626d`; the worktree was clean.
- Began CP12 with route-level acceptance contracts for the complete public scan-state vocabulary and required system validation/safety metrics.

### 2026-08-12 19:55 IST — CP12 RED: Stream and System

- Added server-render behaviors requiring all ten sanitized scan states plus throughput, funnel, quota, cost, latency, precision, partial/failure, canary, degraded, and safe indicators.
- Ran the web test command. Four existing behaviors passed; Stream and System failed with the expected HTTP 404 because neither route existed.

### 2026-08-12 19:58 IST — CP12 GREEN routes / RED browser journeys

- Implemented the live Stream with all public lifecycle states, sanitized detail fields, an `aria-live` update pulse, and a metadata-only contract.
- Implemented System with required metrics, selection funnel, explicit `DEGRADED` latency, `SAFE` safety status, and zero-retention/canary evidence.
- Five of six server-render behaviors passed on the first run. The remaining test used case-sensitive `Metadata only` against the intentional uppercase boundary label; corrected the assertion to verify semantics without presentation casing.
- Added browser journeys for filtering/empty state, investigation comprehension, rejected unsafe review notes, successful review, Stream navigation, and System safety health.
- Expected browser red observed: `@playwright/test` was not yet installed.

### 2026-08-12 20:02 IST — CP12 browser integration diagnosis

- Installed the pinned Playwright test runner and Chromium, then ran both journeys against a production build/server.
- The first run found that vinext client interception left navigation on the originating page. Replaced internal framework links with standards-native anchors, preserving accessible names and making route changes reliable without JavaScript navigation support.
- The second run reached every route and exposed a real review-validation gap: `AWS_SECRET_ACCESS_KEY=...` was not rejected because characters followed the word `SECRET`. Broadened assignment-key detection to cover compound credential identifiers.
- Also scoped the `DEGRADED` browser assertion to the overall health summary because both the summary and latency card intentionally expose that status.

### 2026-08-12 20:05 IST — CP12 GREEN: browser journeys

- Both Chromium journeys passed against the built production server: Findings filtering/empty state, Investigation navigation, unsafe-note rejection, successful review, Stream navigation/state comprehension, and System degraded/safety comprehension.
- Added `test:browser` as a repeatable workspace command and pinned the browser-test dependency in the lockfile.

### 2026-08-12 20:07 IST — CP12 verification

- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 8 files, 46 domain/service tests.
- `npm run build` passed for the web application and all eight library workspaces.
- Web server-render tests passed: 6 of 6.
- Chromium browser journeys passed: 2 of 2.
- CP12 accepted and ready to commit/push.

### 2026-08-12 20:09 IST — CP12 published / CP13 started

- Committed CP12 as `12b2cf9` (`checkpoint 12: complete stream and system console`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `12b2cf995080022bf211f5f146d7ef437ca62525`; the worktree was clean.
- Began CP13 with security-boundary tests for egress allowlisting, safe bounded YAML/XML parsing, control/Unicode handling, and whole-surface fake-canary retention proof.

### 2026-08-12 20:11 IST — CP13 RED: security boundary

- Added five behaviors plus a controlled, nonfunctional canary repository fixture.
- Ran the targeted suite. Collection failed with the expected missing `packages/security/src/index.ts`; no hardening implementation existed.

### 2026-08-12 20:13 IST — CP13 GREEN iteration: bounded security primitives

- Implemented exact GitHub API/OSV/internal-service egress allowlisting with protocol, hostname, and userinfo checks; repository-controlled GitHub/web/file URLs are denied.
- Implemented byte/depth/control-bounded YAML and XML parsing, denying YAML aliases/custom tags and all XML DTD/entity/system/public declarations.
- Implemented NFC normalization, visible terminal/control escaping, bounded display text, and a multi-surface canary auditor requiring zero raw occurrences and exactly one full HMAC fingerprint.
- Four of five behaviors passed. The canary assertion incorrectly split its Base64-like value on every `=` and omitted padding; corrected fixture extraction to slice after the first assignment delimiter.

### 2026-08-12 20:15 IST — CP13 RED: container boundary

- Added explicit credential non-verification and hardened-container contract behaviors.
- Six of seven security behaviors passed. The container behavior failed with the expected missing `compose.yaml` before any deployment declaration existed.

### 2026-08-12 20:17 IST — CP13 GREEN: hardened worker declaration

- Added a non-root multi-stage worker image, source/canary-excluding build context, read-only runtime, 64 MiB noexec/nosuid tmpfs, all-capability drop, no-new-privileges, init, core dump/file descriptor/process/CPU/memory limits, internal metadata network, and separate egress network.
- All seven security behaviors passed.
- Docker Compose validation then caught a portability conflict between service-level `pids_limit` and the deployment resource block. Moved the process cap into `deploy.resources.limits.pids` so all resource limits share one valid declaration and updated the contract accordingly.

### 2026-08-12 20:20 IST — CP13 verification

- Added the operational security-boundary document, including the production network-policy mirror requirement, host swap/encryption requirement, crash/heap dump prohibition, parser policy, and canary proof contract.
- `docker compose config --quiet` passed with controlled validation-only environment values.
- `npm run lint` passed.
- `npm run typecheck` passed.
- `npm test` passed: 9 files, 53 tests.
- `npm run build` passed for the web application and all nine library workspaces.
- CP13 accepted and ready to commit/push.

### 2026-08-12 20:22 IST — CP13 publication correction

- Committed and pushed the initial CP13 hardening implementation as `d70bd05` and verified local/remote equality.
- The post-push tracked-file audit found the root `.env` ignore rule also excluded the controlled canary fixture. Renamed the fixture to non-ignored `credential.txt`, updated the proof test, and prepared a corrective checkpoint commit so the reproducible fixture is present on GitHub.

### 2026-08-12 20:25 IST — CP13 correction published / CP14 started

- Committed the tracked-fixture correction as `52b07e5` and pushed it to `origin/main`; local and remote `main` match and `git ls-files fixtures` lists the canary.
- Began CP14 with executable API/worker runtime contracts: strict configuration, health/readiness, sanitized seeded API data, and a controlled discovery-to-review demonstration.

### 2026-08-12 20:27 IST — CP14 RED: runnable processes

- Added API and worker workspace contracts before implementation.
- Ran both targeted suites. Collection failed on the expected missing API `index.ts` and worker `runtime.ts` modules.

### 2026-08-12 20:33 IST — CP14 GREEN iteration: API and worker entrypoints

- Implemented strict API/worker environment parsing, live/readiness endpoints, graceful shutdown, bounded request/response bodies, fixed safe failure logs, and a real PostgreSQL-backed operator data source.
- Implemented GitHub/OSV fetch adapters with manual redirects, exact egress policy, response/time bounds, serialized GitHub dispatch, discovery, due-candidate commit gates, bounded snapshots, analyzers, orchestration, and periodic worker cycles.
- Added a controlled full orchestration demo that passes a fake committed HEAD through bounded analysis, redacted persistence seams, human confirmation, and aggregate metrics.

### 2026-08-12 20:36 IST — CP14 RED: operations surface

- Added operational contract tests requiring configuration, a versioned migration, sanitized seed path, pinned CI, three runbooks, four healthy Compose services, and published ports.
- Both behaviors failed as expected: `.env.example` and the supporting artifacts were absent, while Compose contained only PostgreSQL and the worker.

### 2026-08-12 20:40 IST — CP14 GREEN operations / container build failure

- Added the environment template, versioned SQL migration, executable migration and sanitized seed, four-service Compose stack, non-root API/web images, health checks, pinned least-privilege CI, architecture/setup/limits/troubleshooting README, and operations/incident/disclosure runbooks.
- Both operational contract behaviors passed; lint and strict typecheck passed after removing void-expression and body-buffer ambiguities.
- `docker compose config --quiet` passed. The initial image build failed reproducibly: host `tsconfig.tsbuildinfo` entered the context while `dist` was excluded, causing TypeScript to consider the container build current without emitting `apps/api/dist`.
- Excluded all TypeScript and web build caches from Docker context and narrowed the worker image build to its referenced workspace graph before retrying.

### 2026-08-12 20:44 IST — CP14 container portability iteration

- The clean-context retry built the API image successfully.
- The web image then failed because npm's Windows-generated lockfile omitted Rolldown's Linux native optional binding. Declared the exact `@rolldown/binding-linux-x64-gnu@1.0.1` package explicitly and pinned every Node base stage to the digest resolved during the build.

### 2026-08-12 20:47 IST — CP14 clean-clone web iteration

- The native binding fix succeeded and the web build reached Vite configuration.
- Docker then exposed an import of gitignored generated `apps/web/build/sites-vite-plugin.ts`; that helper could never exist in a clean clone or CI checkout.
- Replaced the preview/generated-site configuration with a tracked minimal vinext production configuration, eliminating the hidden build dependency.

### 2026-08-12 20:50 IST — CP14 cross-platform CSS iteration

- The tracked Vite configuration passed local web tests and the clean Docker build advanced into CSS processing.
- The image then exposed the same cross-platform optional-dependency issue in an unused Tailwind/PostCSS stack (`lightningcss` Linux binding). Breach uses authored plain CSS, so removed the unused PostCSS config and Tailwind dependencies instead of expanding the native dependency surface.

### 2026-08-12 20:53 IST — CP14 plain-CSS correction

- The worker compiled successfully inside Docker and advanced to image export.
- The web build then identified one remaining starter-era `@import "tailwindcss"` at the top of the otherwise plain-CSS stylesheet. Removed that import to complete the dependency removal.

### 2026-08-12 20:56 IST — CP14 dependency/context minimization

- The subsequent build was interrupted by an npm registry `ECONNRESET` while fetching unused Wrangler.
- Removed all remaining disposable Cloudflare/D1/Drizzle/starter auth/example/worker configuration and packages from the private console. This reduces clean-install and container surface to the framework, React, lint/type tooling, and Playwright actually used by Breach.

### 2026-08-12 20:59 IST — CP14 Vite native-binding correction

- The minimized install completed and the worker compiled inside Docker.
- Vite itself uses Lightning CSS for production minification, independent of the removed PostCSS stack; the Windows lockfile omitted that Linux binding too. Added the exact Vite-compatible `lightningcss-linux-x64-gnu@1.32.0` optional dependency.

### 2026-08-12 21:03 IST — CP14 images green / runtime mount correction

- Worker and web images built successfully; together with the earlier API result, all three application images now build from the tracked clean context.
- The PostgreSQL image pulled and became healthy. The first migration container was rejected because flow-style YAML split the comma-delimited tmpfs option into invalid mount paths. Quoted the complete API/web tmpfs mount strings and pinned PostgreSQL to the pulled digest.

### 2026-08-12 21:06 IST — CP14 runtime entrypoint correction

- Real PostgreSQL migration and sanitized demo seed both completed successfully; the API started and passed its readiness health check.
- Web startup failed because its entrypoint assumed a root-hoisted vinext binary. Inspected the built image, confirmed npm installed vinext under `apps/web/node_modules`, and changed the entrypoint to invoke that exact tracked dependency through Node.

### 2026-08-12 21:10 IST — CP14 production-like runtime green

- Rebuilt the web image with the corrected entrypoint.
- Ran real PostgreSQL, executed the migration and sanitized seed in the API image, and started API/web with their read-only/non-root Compose settings; all three service health checks reported healthy.
- Verified inside the isolated Docker network that the authenticated API returned exactly one sanitized finding, the web root rendered Breach, and neither the fake canary assignment nor raw value appeared in the API response.
- Docker Desktop did not expose the published ports to the Windows host despite correct port bindings, so the smoke assertion ran from inside each healthy container. The Compose services were then stopped; the named metadata volume remains recoverable.
- Removed the redundant nested web lockfile so clean installs have one authoritative root lock, and extended the root `verify` command to include server-render and Chromium journeys.

### 2026-08-12 21:13 IST — CP14 verification

- `npm run verify` passed end to end: lint, strict typecheck, 12 test files/59 tests, all 12 workspaces built, 6 server-render behaviors, and 2 Chromium journeys.
- The controlled discovery-to-review demonstration passed and its serialized output contained neither the canary assignment nor raw value.
- `docker compose config --quiet` passed.
- API, worker, and web images built from the tracked Linux context; real migration, seed, health, authenticated API, and web checks passed against PostgreSQL.
- CP14 accepted and ready to commit/push.

### 2026-08-12 21:15 IST — CP14 published / CP15 started

- Committed CP14 as `6f96f39` (`checkpoint 14: ship runnable product and operations`) and pushed it to `origin/main`.
- Verified local and remote `main` both resolve to `6f96f39ed3d6f3c6a429bfb9723d49b92214ff3d`; the worktree was clean.
- Began CP15 with dependency audit and coverage/clean-install planning.

### 2026-08-12 21:17 IST — CP15 dependency audit finding

- `npm audit --omit=dev --audit-level=high` reported a critical set of XML parser advisories in `fast-xml-parser@5.2.5` and a moderate deep-nesting advisory in `yaml@2.8.1`.
- Updated to the audit-recommended fixed releases `fast-xml-parser@5.10.1` and `yaml@2.9.0`; the existing DTD/entity/depth denial tests remain the acceptance contract.

### 2026-08-12 21:20 IST — CP15 coverage RED/GREEN iterations

- Added defensive branch contracts for invalid GitHub responses and policy bounds, operator inputs and metadata, lifecycle/scheduling storage bounds, parser/display/canary edge cases, terminal orchestrator outcomes, and snapshot tree/path/budget/cleanup behavior.
- Fixed strict lint/type errors exposed by the new tests without weakening compiler or lint rules.
- The first measured package run was below the required branch gate at 88.66%; added missing bounded-snapshot behaviors before changing the threshold.
- The next run passed all 72 service/domain tests at 96.18% statements, 90.10% branches, 98.60% functions, and 96.18% lines.
- Enforced 90% for all four dimensions in `vitest.config.ts` and replaced CI's unmeasured test command with `test:coverage`.

### 2026-08-12 21:24 IST — CP15 zero-retention and dependency audit

- Removed the controlled canary value duplicated in worker/API test source. The demo and tests now read the single labeled fixture and inject it through the public demo seam.
- Added a tracked-file credential audit that permits only the documented fake fixture/token shapes, proves the raw canary exists in exactly one controlled fixture, and rejects provider-shaped tokens or complete private-key material elsewhere.
- `npm audit --omit=dev --audit-level=high` passed with zero production vulnerabilities after the parser upgrades.
- The full toolchain audit initially exposed six high-severity advisories. Upgraded React/RSC, Vite, vinext, Vite plugins, TypeScript ESLint, Babel transitive dependencies, and related lockfile entries; the complete verification suite remained green.
- The full audit now has one bounded upstream exception: vinext's build-only `image-size@2.0.2` dependency is covered by two parser denial-of-service advisories for ICNS/JXL/HEIF and has no fixed release. Breach never accepts, sizes, or parses repository/operator images; the package is absent from the production audit path. This is not a production or build blocker and is recorded rather than hidden.
- `npm run audit:secrets` passed across all tracked paths: no committed credential and no duplicate canary value.

### 2026-08-12 21:28 IST — CP15 clean-install and complete verification

- Ran `npm ci --ignore-scripts --no-audit --no-fund` from the authoritative root lockfile after all upgrades; 555 packages installed successfully.
- Ran `npm run verify` from that clean install. Lint and strict typecheck passed; 12 test files/72 tests passed with enforced coverage; all 12 workspaces built; 6 server-render criteria and 2 Chromium journeys passed; production dependency and tracked-secret audits passed.
- Rebuilt API, worker, and web Linux images from the tracked context on the upgraded lockfile; all three images passed clean npm install and production build stages.
- `docker compose config --quiet` passed with controlled validation values.

### 2026-08-12 21:31 IST — CP15 migration check diagnosis and GREEN

- The first migration command appended an argument to the API image entrypoint and started the API instead; it failed safely without altering the migration.
- Retried with an explicit Node entrypoint. PostgreSQL rejected the connection because the retained CP14 development volume had been initialized with a different password, confirming volume persistence rather than a migration defect.
- Repeated the check in isolated Compose project `breach-cp15` with a fresh disposable volume. PostgreSQL became healthy and the API image printed `Metadata migration complete`; the temporary container, network, and volume were then removed.
- Added the same pinned PostgreSQL service and executable migration step to CI so future checkouts validate the schema against a real database.

### UI acceptance evidence matrix

| Report criterion | Reproducible evidence |
|---|---|
| 1. New sanitized finding appears in Findings | API sanitization behavior; `apps/web/tests/rendered-html.test.mjs`; first Chromium journey |
| 2. Feed explains severity, exploitability, and family | Findings server-render behavior and browser filter journey |
| 3. Detail explains entry/source/flow/sink, barriers, limits, coverage | Investigation server-render behavior and first Chromium journey |
| 4. Confirmed/false-positive/uncertain review feeds metrics | Operator review contracts, Investigation behavior, browser rejection/success journey, System validation metrics |
| 5. Stream exposes near-real-time metadata-only transitions | Operator SSE/stream contracts, Stream render behavior, second Chromium journey |
| 6. System exposes throughput, quota, latency, precision, zero retention | System render behavior and second Chromium journey |
| 7. Secret findings never expose the raw credential | Analyzer redaction tests, API/UI tests, controlled demo, canary auditor, tracked-secret audit |
| 8. Frontend telemetry/errors/logs contain no source or raw secret | Security canary surface audit, metadata-only browser assertions, controlled demo serialization proof |

### 2026-08-12 21:34 IST — CP15 acceptance

- Scanned tracked project sources for unresolved task markers and focused/skipped required tests; no unexplained TODO/FIXME, `.only`, or skipped test was found.
- `git diff --check` passed and no unmerged path exists.
- CP00–CP15 are complete. Final publication and local/remote/worktree equality evidence will be appended by the publication commit.

### 2026-08-12 21:36 IST — CP15 published

- Committed CP15 as `e5716cc` (`checkpoint 15: verify and deliver complete build`) and pushed it to `origin/main`.
- Fetched the remote and independently checked the local commit, remote-tracking commit, and `git ls-remote` result; all three resolved to `e5716ccc0e4bcb537662e7e86b19e3ae2a15b02c`.
- This closing ledger entry is the only change after the verified checkpoint and will be committed/pushed as the final documentation closure.

### 2026-08-12 21:38 IST — GitHub validation GREEN

- GitHub Actions run `31584986581` completed successfully for the final ledger commit.
- The independent Ubuntu job passed pinned checkout/setup, clean npm install, lint, strict typecheck, enforced coverage, all production builds, real PostgreSQL migration, 6 server-render behaviors, 2 Chromium journeys, production dependency audit, tracked-secret audit, Compose validation, and cleanup.
- This is the final external acceptance gate. The evidence entry is being published as a documentation-only `[skip ci]` closure so it does not create an infinite validation/ledger cycle.

## Final productionization audit

This section is append-only. It records the red/green evidence for the productionization checkpoints that follow CP15.

### 2026-08-15 16:02 IST — untouched baseline and architecture audit

- Audited the complete build instruction and every tracked source, test, deployment, workflow, runbook, configuration, and package artifact before modifying the repository. Local `main`, `origin/main`, and the worktree were equal and clean at `af5ea4a826a71dfd3a236eadfc016ffd607d27db`.
- Untouched `npm run verify` passed lint, strict typecheck, 72 service/domain tests with the existing coverage gate, all workspace builds, 6 rendered-HTML tests, 2 Chromium tests, the production dependency audit, and the tracked-secret audit. This is the baseline, not production acceptance: the UI/browser checks consume hard-coded demo data instead of PostgreSQL and the operator API.
- `npm audit --omit=dev --audit-level=high` passed. The complete development-tool audit still reports two high-severity image parser advisories through vinext's build-only `image-size` dependency; runtime scanning never invokes that parser.
- `docker compose config --quiet` passed with a controlled placeholder during audit. Docker Desktop's Linux engine is not currently running, so real fresh-volume Compose validation is deferred until the engine is available.
- No `.env` file and no process `GITHUB_TOKEN` are present. All locally controllable production work will proceed; the required live read-only GitHub validation remains an explicit external acceptance gate until a token is supplied through the environment.
- Tight production repro: the configured candidate policy (`minimumScore: 35`, `capacityRatio: 0.07`) returned `{ score: 21, state: "SKIPPED" }` for the strongest possible repository, proving the production threshold is unreachable. A collector with no stored cursor requested `https://api.github.com/repositories?since=0`, proving there is no recent-repository bootstrap.
- Discovery defects: unbounded pagination follows every GitHub `Link`; candidate metadata lacks normalized owner/negative-term signals; the modulo bucket is not a priority queue; discovery inserts no initial metadata event.
- Scheduling defects: an async `setInterval` permits overlapping worker cycles; shutdown does not await active work; rate-limited scans receive no due retry; admission has no reserve-aware GitHub quota accounting or request telemetry.
- Snapshot/analysis defects: coverage omits eligible/generated/unsupported counters, stable reason codes, and distinct snapshot-versus-analysis completeness; generated files are conflated with binary files; dependency evidence is discarded; configuration evidence has no dedicated contract or impact rationale.
- Dataflow defects: functions are resolved globally by name instead of module/file plus symbol; Python `async def` entry points are unsupported; Next request-body/query-source handling is incomplete.
- Operator defects: the SSE response is pre-rendered and immediately closed; the Node bridge buffers every body with `arrayBuffer()`; reconnect cursors, backlog, heartbeat, and later-event delivery are absent; error/media-type/cache hardening is incomplete.
- Web defects: Findings, Investigation, Stream, and System import demo data or hard-code metrics/events; reviews only update React state; there is no server-only authenticated proxy, durable review round-trip, real EventSource, or live empty/loading/error behavior.
- Safety/operations defects: the canary audit covers synthetic strings rather than runtime stores and surfaces; migration SQL is duplicated and auto-applied without `schema_migrations`; Compose has no one-shot migration service, internal web credentials, or complete resource/readiness hardening; the bridge network is documented as if it enforced egress; CI does not build images or exercise the real DB/API/UI stack; runtime application paths are excluded from coverage.
- Ranked root-cause predictions: production-only configuration was not covered; runtime seams are not controllable under tests; the web app was validated as a standalone prototype; persistence remained a bootstrap scaffold; and verification scope excluded end-to-end runtime behavior. Each checkpoint will add a failing public-seam regression before changing implementation.

### 2026-08-15 16:09 IST — fix 16 discovery bootstrap RED/GREEN

- RED: focused tests failed because `DiscoveryCollector.bootstrap` and `MetadataStore.bootstrapDiscovery` did not exist and production configuration had no live-versus-historical mode. The failures reproduced the default `since=0` backfill path without using the network.
- GREEN: added a single bounded GitHub repository-search frontier request, strict response validation, atomic/idempotent cursor and bootstrap-timestamp persistence, discovery cursor/page/repository metrics, and a default `DISCOVERY_MODE=live`. Historical replay now requires both `DISCOVERY_MODE=historical` and an explicit non-negative `DISCOVERY_START_CURSOR`.
- The acceptance tests `discoveryNeverBackfillsFromZeroByDefault` and `freshDatabaseBootstrapsAtCurrentFrontier` prove a realistic non-zero frontier, no candidate insertion during bootstrap, original-frontier preservation on repeat initialization, and no request containing `since=0` in default mode.
- An idempotency regression initially duplicated bootstrap telemetry because the test PostgreSQL adapter reports conflict row counts differently. Reworked telemetry to key off the persisted frontier/timestamp and use conflict-safe inserts; the repeat-bootstrap test then passed.
- The first full verification attempt failed rather than weakening policy: global branch coverage was 89.51% after adding the defensive paths. Added malformed-frontier, rate-limit, invalid-bootstrap, and invalid-mode behaviors; the unchanged gate passed at 90.27% branch coverage.
- Final checkpoint verification passed: lint, strict typecheck, 12 test files/75 tests, 96.22% statements and lines, 90.27% branches, 98.62% functions, all workspace builds, 6 rendered-HTML checks, 2 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 16:18 IST — fix 16 published / fix 17 candidate admission RED/GREEN

- Published fix 16 as `9df6e883166fb4b7e0b02097d2c06edb4bd39519` (`fix 16: repair live discovery bootstrap`). Direct `git push`, fetch, remote-tracking resolution, and `git ls-remote` all proved exact equality on `origin/main`; the worktree was clean.
- RED: `productionCandidatePolicySelectsRealisticHighValueRepos` and the ordered-admission behavior both failed with `policy.admit is not a function`. This preserved the exact production defect: the old score maximum was 21 while production required 35 and capacity was an ID-modulo bucket rather than a priority queue.
- GREEN: replaced the implicit score with an explicitly bounded 0–100 metadata-only model. It rewards API/backend/auth/payment/cloud/infrastructure/deployment/bot/server/database/Docker/Kubernetes/Terraform/serverless/web/developer-tool/security/network signals, applies a small organization metadata bonus without another request, penalizes tutorial/homework/notes/dotfiles/docs/mirror/generated/example/course/learning signals, and forces forks to zero.
- Candidate admission now ranks score-descending and repository-ID-descending, selects the configured top share, and records `selected`, `score`, or `capacity` as a sanitized reason. Production defaults are validated as `CANDIDATE_MINIMUM_SCORE=60` and `TARGET_SELECTION_RATIO=0.07`; invalid or theoretically impossible thresholds are rejected at startup.
- Persistence now round-trips the admission reason and writes real funnel samples for discovered, eligible, selected, skipped-capacity, and skipped-score counts. Upgrade compatibility defaults existing active candidates to selected and existing skipped candidates to score-rejected.
- The exact production configuration selects a realistic organization payments/auth/API/cloud/backend/server/Docker/Kubernetes/Terraform repository at score 96 while skipping tutorial, dotfiles, generated, mirror, and fork fixtures. A lower-threshold batch proves that a score-87 candidate wins the sole capacity slot over a score-37 eligible candidate.
- The first full verification attempt caught a forbidden non-null assertion in the new test; it was removed without changing lint policy. Final verification passed lint, strict typecheck, 12 test files/77 tests, 96.19% statements/lines, 90.02% branches, 98.63% functions, all builds, 6 HTML checks, 2 Chromium journeys, production dependency audit, and tracked-secret audit.

### 2026-08-15 16:28 IST — fix 17 published / fix 18 single-flight and quota RED/GREEN

- Published fix 17 as `486af09d662ee188cf26e9c98b87f60bb182f302` (`fix 17: repair candidate admission policy`). Direct push, fetch, remote-tracking resolution, and advertised-remote resolution all matched; the worktree was clean.
- RED: `workerCyclesNeverOverlap` failed because no scheduler module existed; `quotaReserveStopsNewScanAdmission` failed because no quota tracker existed; the bounded catch-up test consumed two pages instead of the configured one.
- GREEN: added a single-flight scheduler with one awaited cycle, elapsed-time-aware delay, observable phase/timestamps/outcome, abortable idle wait, error isolation, idempotent stop, and shutdown ordering that waits for the active cycle before closing health and the database pool. A deliberately slow fake cycle exceeded its poll interval but never overlapped, and stop waited for that cycle without starting another.
- The worker now creates one long-lived runtime per process. Its serialized GitHub dispatcher and blob transport emit metadata-only request events; the persistent quota tracker therefore retains reserve/pause/reset state across cycles instead of being recreated every poll.
- Added low-cardinality accounting for total, discovery, commit-gate, tree, subtree, blob, and other request families; remaining/limit/reset/pause/secondary-limit samples; and requests per completed scan. Network failures count as status class `network_error`; neither URLs nor response bodies become labels.
- New scan admission stops when `GITHUB_QUOTA_RESERVE` is reached, while an already admitted scan may consume the reserve to finish. Successful responses clear pauses; primary reset or secondary-limit delay expiry permits one new request to refresh quota state. Worker health now exposes sanitized scheduler and quota status.
- Discovery catch-up is bounded by validated page, request, and elapsed-time limits and resumes from its transactionally persisted cursor next cycle. Commit-check and scan counts are independently bounded and configurable.
- The first coverage run failed at 89.36% branches after adding quota/error/reset paths. Added transport-failure, endpoint-family, quota-pause/reset, reserve-validation, and invalid discovery-budget behaviors; the unchanged gate passed at 90.44%.
- A full verification attempt caught two scheduler control-flow lint errors; the state observation was moved behind its public predicate without weakening lint. Final verification passed lint, strict typecheck, 13 test files/82 tests, 96.36% statements/lines, 90.44% branches, 98.08% functions, all builds, 6 HTML checks, 2 Chromium journeys, production dependency audit, and tracked-secret audit.

### 2026-08-15 16:33 IST — fix 18 published / fix 19 retry lifecycle RED/GREEN

- Published fix 18 as `8b6af2ce761e25d6fa10faf8e839b07535683c6c` (`fix 18: make worker single-flight and quota aware`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `rateLimitedCandidateRecoversAfterDeadline` failed because storage had no rate-limit scheduling/recovery operation; `initialDiscoveryWritesLifecycleEvents` failed because discovery emitted no persisted events.
- GREEN: a 403/429 commit-gate outcome now atomically writes `RATE_LIMITED`, the header-derived deadline in `next_commit_check_at`, the unchanged commit-check attempt, and its lifecycle event. This removes the prior crash window between a state transition and a schedule write.
- `releaseDueRateLimits(now)` holds candidate row locks, leaves candidates unselectable before their deadline, and atomically transitions each due candidate back to `WAITING_FOR_COMMIT` with a recovery event and a cleared deadline. The worker runs this recovery before its priority-ordered due query and records the recovered count.
- Discovery now writes `null -> DISCOVERED -> WAITING_FOR_COMMIT|SKIPPED` events in the same cursor/candidate transaction. Candidate row locking and event-existence checks make repeated discovery-page persistence idempotent; the exact initial event pair is not duplicated.
- The orchestrator regression proves a rate-limited gate never touches snapshot access and delegates the exact retry timestamp/attempt to the atomic persistence operation. The storage regression proves no selection one millisecond before the deadline and eligibility exactly at the deadline.
- The first full verification attempt caught unused parameters in the controlled-demo adapter; the adapter was simplified without suppressing lint. Final verification passed lint, strict typecheck, 13 test files/84 tests, 96.31% statements/lines, 90.21% branches, 98.12% functions, all builds, 6 HTML checks, 2 Chromium journeys, production dependency audit, and tracked-secret audit.

### 2026-08-15 16:44 IST — fix 19 published / fix 20 evidence and coverage RED/GREEN

- Published fix 19 as `55d277641b1a99a3b5bd1aa5696c7c015332a4a5` (`fix 19: repair rate-limit retry lifecycle`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: dependency and configuration regressions proved the orchestrator discarded analyzer evidence; snapshot regression proved generated and binary files were conflated and the completeness contract lacked eligible/generated/unsupported and separate snapshot/analysis fields. Data-flow regressions proved unrelated same-name functions were globally connected and Python `async def` routes were ignored.
- GREEN: added strict bounded `dependencyEvidence` (ecosystem, package, version, advisory ID, manifest path, sanitized 280-character summary) and `configEvidence` (rule, path, line, rationale, static-only marker). Orchestrator, storage round-trip, and authenticated API detail tests prove evidence survives end to end without lockfile/source snippets.
- OSV summaries now have markup/control characters removed, whitespace normalized, and length bounded before they reach the finding contract. Every configuration rule now owns a static bounded rationale explaining its security impact; the matched source line remains absent.
- Coverage now distinguishes `filesSeen`, `filesEligible`, `filesAnalyzed`, binary/generated/oversize/budget/unsupported exclusions, stable snapshot reason codes, analysis reason codes, `snapshotComplete`, `analysisComplete`, and `analysisPartial`. `scanComplete` is contractually required to equal snapshot-and-analysis completeness; `historyScanned` remains literal false and the ref remains the exact permitted HEAD SHA.
- Snapshot classification now counts generated and binary files independently, identifies unsupported model inputs, and records which file-count/repository-byte/wall-clock bound caused omissions. The orchestrator merges real data-flow diagnostics into final coverage before attaching it to every finding or completing a scan.
- TypeScript/JavaScript function resolution now prefers same-file symbol identity or a uniquely resolved explicit relative import; it no longer chooses the first global function with a matching name. Cross-file fixtures now include real imports, and an unrelated duplicate-`run` regression proves no invented high-confidence path. Python parsing now supports `async def`; Next JSON/form-data/URL-search-param and Flask/FastAPI paths remain passive and green.
- The first two full verification attempts caught prohibited control-character regex and string-spread patterns in summary sanitization; both were replaced with an explicit bounded code-unit pass without lint suppression. Final verification passed lint, strict typecheck, 13 test files/92 tests, 97.08% statements/lines, 90.35% branches, 98.21% functions, all builds, 6 HTML checks, 2 Chromium journeys, production dependency audit, and tracked-secret audit.

### 2026-08-15 16:58 IST — fix 20 published / fix 21 live findings UI RED/GREEN

- Published fix 20 as `dcd50dbcd348c903e0671e7f2d927be05b864cff` (`fix 20: preserve complete finding evidence`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `frontendNeverImportsDemoFindingsInProduction` failed on the production import and filtering of `demoFindings`. The server-render test also encoded demo command-injection content as if it came from a live service. A focused pagination regression proved `/api/findings?limit=1&offset=1` returned the entire unbounded list.
- GREEN: Findings now load sanitized persisted records from a same-origin `/api/findings` route with explicit loading, empty, filter-empty, failure, and retry states. Severity and family are forwarded as server filters; text search remains local to the bounded response. Display titles, evidence summaries, confidence/exploitability score, review state, modeled language, partial-scan count, and timestamps are derived from the real finding contract.
- Added a server-only operator boundary with a fixed upstream path, an allowlist of query fields, 10-second timeout, no redirects, a 2 MiB response ceiling, strict `sanitizedFindingSchema` validation, no-store/nosniff response headers, and generic availability errors. `OPERATOR_TOKEN` is injected only into the internal request; a built-client-asset scan proves the variable name, a runtime canary token, and test tokens are absent from browser artifacts.
- The operator finding API now defaults to 100 results, permits an explicit maximum of 250, validates a bounded offset, rejects duplicate/invalid pagination values, and slices only after sanitization, filtering, and deterministic security ranking.
- Removed the Findings page's invented collector time, scan throughput, finding throughput, request-cost, and retention metrics. Its status reflects the actual request lifecycle, while the metric strip contains only counts computed from the bounded live response.
- A mocked internal HTTP service proves the production web route injects authentication server-side and never lets the browser choose an upstream target. The browser journey proves live-boundary data renders and filters without any demo import.
- The first full gate exposed a Reset state-machine bug: resetting an already-default filter entered loading without changing an effect dependency. The handler now preserves the ready response when only clearing local text, and the reproduced browser path passes.
- Final verification passed lint, strict typecheck, 13 test files/93 tests, 97.16% statements/lines, 90.50% branches, 98.23% functions, all workspace builds, 9 production web tests, 2 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 17:11 IST — fix 21 published / fix 22 persistent investigation review RED/GREEN

- Published fix 21 as `b284444d70c0a41943a338b5c205649f628a5d7c` (`fix 21: connect findings UI to live API`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `frontendNeverImportsDemoDetailsInProduction` found the production detail page and Investigation component importing `getFinding`, `DemoFinding`, and `FindingDetail` from the demo module. `reviewPersistsAcrossReload` could not load a UUID-backed record. `reviewPersistsInPostgresWithoutEchoingNote` proved the storage method returned the stored judgment note as an extra field.
- That extra field exposed a cross-layer correctness failure: PostgreSQL committed a safe review and then the operator's strict finding schema rejected the response, causing a successful write with a note to appear as an HTTP 400. Storage now persists the note in `finding_reviews`, updates the finding payload's review state in the same transaction, and returns only the strict sanitized finding.
- GREEN: deleted `app/data.ts` and every production dependency on `demoFindings`/`demoDetails`. Investigation now loads the real UUID through a same-origin detail route and shows explicit loading, missing, unavailable, and retry states.
- Added fixed-path detail and review proxy operations. They validate UUIDs, bound review bodies to 4 KiB and notes to 500 characters, accept only the three review states, reject extra fields/media types, enforce a 10-second upstream timeout and 2 MiB response ceiling, validate upstream JSON and strict finding contracts, and reduce upstream failures to generic error codes.
- GitHub links are accepted only when HTTPS, credential-free, hosted on `github.com`, and rooted beneath the validated repository URL supplied by the sanitized record. The UI never constructs a path from browser-controlled values.
- Real investigation rendering now covers semantic entry/source/flow/sink nodes with file and line, confidence, exploitability score/level, modeled barriers, complete/partial coverage counters and reasons, and the explicit static-only limitations. Secret fingerprints are shortened at both ends and marked `Raw value NOT RETAINED`; dependency evidence shows package/version/ecosystem/advisory/manifest; configuration evidence shows rule/location/severity/static rationale.
- Reviews POST through the same-origin route, do not optimistically change state, show pending/rejected/failed/saved outcomes, clear the note after success, and reload the persisted API state. The browser request carries no operator authorization credential; the server injects it only on the internal hop.
- The production route test proves a judgment note is accepted upstream but absent from the response and subsequent detail state remains reviewed. The PostgreSQL test independently proves the state and note are stored while the returned object has no note. Browser journeys prove sensitive local rejection, a safe persisted review across reload, and all four evidence families without a full secret fingerprint.
- The first full verification attempt caught an unsafe test matcher; the assertion was rewritten with a typed result. The next reached the secret audit after all functional tests passed, where the deliberately deleted but unstaged demo path was still present in Git's index. Staging only that deletion made the audit evaluate the intended tree without changing policy.
- Final verification passed lint, strict typecheck, 13 test files/93 tests, 97.16% statements/lines, 90.48% branches, 98.23% functions, all workspace builds, 11 production web tests, 4 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 17:24 IST — fix 22 published / fix 23 true live SSE RED/GREEN

- Published fix 22 as `8226bf6e6880aa3655d3be703472810f41515dc5` (`fix 22: persist investigation reviews`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `streamConnectionReceivesLaterEvent` received an already-closed body when an event was inserted after the connection opened. `apiBridgeNeverBuffersStreamingResponse` found `result.arrayBuffer()` in the Node bridge. The same-origin `/api/stream` production route did not exist and returned 404.
- GREEN: `/api/stream` now owns a cancellable `ReadableStream`. It captures a connection high-water mark, sends at most the configured recent 500-event backlog, honors `Last-Event-ID` or one validated `after` cursor, polls PostgreSQL for later records, emits ordered metadata-only `state` events, writes heartbeat comments during idle periods, and closes promptly on request abort or reader cancellation.
- Each public stream event is revalidated and contains only positive event/repository IDs, a bounded `owner/repository` name, a recognized lifecycle state, an ISO timestamp, and a low-cardinality reason code derived from that state. It never carries GitHub response data, source, snippets, or secret material.
- Added a latest-event high-water query and an upper-bound parameter to backlog reads. The initial query therefore cannot be displaced by concurrent newer writes; older history outside the reconnect window is intentionally skipped while events created after connection continue to drain in bounded batches.
- Replaced the API HTTP bridge's buffered response conversion with chunk-by-chunk `ReadableStream` reading, Node write-backpressure handling, early header flushing, and an abort signal tied to client disconnect. An actual loopback Node server test proves an event written after headers reaches the client.
- Added a same-origin streaming proxy that validates cursors, forwards `Last-Event-ID`, injects `OPERATOR_TOKEN` only on the internal hop, times out connection establishment without imposing a lifetime on a healthy stream, validates the upstream event-stream media type, disables transformation/buffering, and propagates cancellation upstream.
- The Stream UI now uses browser `EventSource`, native automatic reconnect/cursor behavior, bounded/deduplicated in-memory events, strict client-side event validation, absolute safe timestamps, low-cardinality reason codes, and truthful `CONNECTED`, `RECONNECTING`, or `DISCONNECTED` state. The ten fabricated repository/state/detail rows and fake age ticker were deleted.
- Tests prove later-event delivery, heartbeat emission, Last-Event-ID resumption, bounded recent backlog, invalid/duplicate cursor rejection, invalid stream configuration rejection, Node bridge streaming after headers, proxy authentication and cursor forwarding, no frontend hard-coded event fixture, and a browser-rendered real SSE event.
- Final verification passed lint, strict typecheck, 13 test files/97 tests, 97.24% statements/lines, 90.44% branches, 97.79% functions, all workspace builds, 12 production web tests, 4 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 17:36 IST — fix 23 published / fix 24 real system metrics RED/GREEN

- Published fix 23 as `325c033f72eb6459e18c33331ff0b45094fbab3f` (`fix 23: deliver true live event streaming`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `systemMetricsComeFromPostgres` failed because `/api/system` selected only the latest generic metric samples and did not query candidates, scans, findings, or reviews. `systemDashboardNeverHardCodesMetrics` failed on the production page's fabricated throughput, quota, latency, precision, and safety values.
- GREEN: the operator data source now calculates discovery, funnel, scan, finding, and validation measurements from PostgreSQL. It uses one bounded aggregate per domain, one grouped telemetry query, real one-hour windows, persisted coverage counters, actual scan durations with `PERCENTILE_CONT` p50/p95, and durable review joins.
- Derived ratios are emitted only when their denominator exists and is positive: partial rate, failure rate, findings per 1,000 completed scans, and reviewed precision. Missing quota, request, failure, or canary telemetry produces no metric rather than a zero or invented fallback.
- GitHub measurements now expose observed remaining/limit/reset, requests per hour, requests per completed scan, and rate-limit events. Safety measurements expose only persisted runtime canary result/time, retention violations, source-persistence observations, and credential-verification observations.
- Added a strict server-only `/api/system` proxy with fixed upstream path, authorization injection, timeout/size/error hardening, and a maximum 100-metric response contract. The browser never receives or chooses the operator credential or upstream URL.
- Replaced every hard-coded System value with a client dashboard that fetches the same-origin boundary, renders the full Discovery/Funnel/GitHub/Scan/Findings/Validation/Safety catalog, displays explicit loading and failure states, and says `No data yet` for any measurement the API did not return. Funnel bars and all displayed rates are calculated only from returned values.
- The focused API regression proves the PostgreSQL queries and formulas, including 75% reviewed precision, 25% partial rate, 20% failure rate, 500 findings per 1,000 completed scans, and five GitHub requests per completed scan. It also proves absent retention telemetry stays absent. Web route tests prove server-only authentication and exact payload forwarding; the browser test proves live values, formatting, and no-data rendering.
- One server-render assertion initially rejected the legitimate label `Retention violations` instead of only the retired fake value. Tightening it to target the fabricated status/value markup preserved the safety catalog and made the intended boundary precise.
- Final verification passed lint, strict typecheck, 13 test files/99 tests, 97.24% statements/lines, 90.44% branches, 97.79% functions, all workspace builds, 13 production web tests, 4 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 17:50 IST — fix 24 published / fix 25 runtime zero-retention RED/GREEN

- Published fix 24 as `b4ee67ba3dc86d787ce0eec02fc29b969aa4f055` (`fix 24: replace fabricated system metrics`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `canaryRawValueAbsentFromAllRuntimeSurfaces` failed because `runZeroRetentionCanary` did not exist. The audit confirmed the old test manually assembled sanitized strings, `runControlledDemo` bypassed the real snapshot reader and PostgreSQL, and the seed wrote `zero_retention.canary=1` without performing any proof.
- GREEN: added a reproducible runtime canary that sends the controlled nonfunctional fixture through the real commit gate, `SnapshotReader` Git tree/blob boundary, secret/dependency/config/data-flow analyzers, `ScanOrchestrator`, PostgreSQL-compatible metadata store, and `OperatorRouter` list/detail/error serialization. GitHub and OSV remain deterministic external-seam fakes; scanner internals are real.
- The runner captures references to the actual ephemeral snapshot buffers and fails unless release overwrote every byte. It zeros its controlled transport buffer, then audits the complete PostgreSQL tables, structured application events, API list/detail output, sanitized API error output, cleared ephemeral buffers, and any externally supplied surfaces.
- The Chromium regression supplies the scanner-produced finding to the production Investigation UI and adds rendered DOM plus browser local/session storage to the same audit. The raw canary occurs zero times; the full HMAC is permitted only in the bounded sanitized PostgreSQL/API representations, while the browser shows only a shortened fingerprint and `Raw value NOT RETAINED`.
- Runtime proof is written only after the audit succeeds as the exact measurements `zero_retention.canary.last_run`, `.success`, `.raw_occurrences`, and `.fingerprint_occurrences`, plus measured zero retention/source-persistence/credential-verification observations. The System API now consumes these real names and has no compatibility fallback to the retired synthetic metric.
- Added `npm run canary --workspace @breach/worker` for an operator to run the same proof against the configured PostgreSQL database. Its stdout contains only success/count/surface metadata; its failure output is generic. Repeated runs replace only metadata belonging to the reserved `fixture/runtime-canary` identity while retaining aggregate proof samples.
- The seed is now visibly labeled `DEMO-SEED`, writes sanitized demo metadata only, and cannot write any `zero_retention` metric. The API's test/demo data source also returns no fabricated system metric.
- Updated the specification and security documentation to state the technically honest invariant: repository data necessarily exists transiently in bounded TLS/network, Node, RAM, and parser buffers; the guarantee is no durable source retention. Docker writable-layer/tmpfs inspection is not claimed locally because the Docker engine remains unavailable; it stays part of the real-container acceptance gate.
- During final review, two placeholder Docker/tmpfs surface names were removed from the test rather than claiming an inspection that had not occurred. The complete gate was rerun after that correction.
- Final verification passed lint, strict typecheck, 13 test files/101 tests, 97.25% statements/lines, 90.47% branches, 97.79% functions, all workspace builds, 13 production web tests, 5 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit.

### 2026-08-15 17:59 IST — fix 25 published / fix 26 hardened egress RED/GREEN

- Published fix 25 as `3a77b1ccd74045c4ef0e563044ac819152175448` (`fix 25: strengthen runtime zero-retention proof`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: `workerHasNoDirectInternetRouteOutsideAllowlistProxy` failed because the worker joined the ordinary external `egress` bridge directly and no proxy/policy artifacts existed. `egressProxyAllowsOnlyNamedTlsDestinations` failed because there was no executable allowlist proxy. This reproduced the gap between the existing application guard and a deployable network boundary.
- GREEN: added a minimal non-root Node CONNECT proxy whose parser accepts exactly `api.github.com:443` and `api.osv.dev:443`. It rejects HTTP forwarding, alternate ports, IP literals, userinfo, trailing-dot/suffix lookalikes, paths, and all other authorities. Tunnels retain end-to-end TLS; the proxy never parses repository payloads.
- Compose now places the worker only on internal `metadata` and `proxy_control` networks. The proxy alone joins `proxy_control` plus the external bridge. Node 24 is configured with `NODE_USE_ENV_PROXY=1`, fixed `HTTP(S)_PROXY`, and internal/loopback `NO_PROXY`; the proxy is read-only, capability-free, no-new-privileges, non-root, health-checked, and not host-published.
- Tightened the in-process `EgressPolicy` to the two HTTPS services on default/explicit port 443. The production GitHub metadata and blob transports reject representative repository/webhook/registry/Terraform/image/loopback URLs before global `fetch` is called.
- `repositoryControlledUrlIsNeverFetchedByStaticAnalyzers` runs secret, dependency, and configuration analyzers over source, Docker, manifest, GitHub-API-shaped, OSV-shaped, webhook, image, and registry URL strings while spying on global `fetch`; no network operation occurs. This complements transport-level denial and preserves passive static-only behavior.
- A loopback socket regression proves an approved CONNECT request creates exactly one intended upstream attempt and receives 200, while an unapproved authority receives 403 with no second upstream attempt.
- Added `deploy/network-policy.md` with exact worker/proxy/PostgreSQL/DNS rules, local limitations, verification steps, and an explicit statement that an ordinary Docker bridge is not an allowlist. Added a deployable default-deny `CiliumNetworkPolicy` example: worker-to-PostgreSQL/proxy/DNS only, proxy ingress from worker only, and proxy egress through exact `toFQDNs.matchName` entries on TCP 443.
- Compose interpolation/config validation passed with controlled placeholders. The Docker daemon remains unavailable, so image build, live tunnel denial from inside the container, and network-membership inspection remain part of fix 27's fresh-stack gate rather than being falsely claimed here.
- Full verification passed lint, strict typecheck, 14 test files/106 tests, 97.25% statements/lines, 90.49% branches, 97.79% functions, all workspace builds, 13 production web tests, 5 Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit. After staging the five new deployment/proxy files, the tracked-secret audit was rerun over all 110 indexed files and passed.

### 2026-08-15 18:29 IST — fix 26 published / fix 27 migrations and controlled full-stack validation RED/GREEN

- Published fix 26 as `d86344ecc488b287fe666b43f127d4e8a29f6688` (`fix 26: enforce worker egress allowlist`). Local, remote-tracking, and advertised `main` matched after direct push/fetch; the worktree was clean.
- RED: versioned-migration tests failed because `@breach/storage/migrations` did not exist. A production worker-cycle regression then reproduced a PostgreSQL-compatible due-date comparison problem, and the expanded production coverage gate failed at 86.31% branches/86.19% functions before the new runtime entry paths were exercised.
- GREEN: replaced the monolithic startup DDL with immutable checksummed migrations `001`–`004`, a durable `schema_migrations` history, advisory transaction locking, sequential application, idempotent reruns, mismatch refusal, and explicit startup refusal when migrations are absent or incomplete. An exact fixture adopts the prior complete schema without losing metadata; incomplete legacy layouts are upgraded normally.
- The API migration command is now the sole schema writer. Compose includes a one-shot `migrate` service, and API/worker wait for its successful completion. CI runs the migration command twice against fresh PostgreSQL to prove the second invocation is a no-op.
- Added injectable production seams for the API pool, worker runtime/pool, and worker GitHub/blob/OSV transports. These keep production defaults unchanged while letting tests execute the real server, scheduler, discovery, gate, snapshot, analyzers, orchestrator, store, and quota accounting with deterministic external responses.
- Added `scripts/controlled-full-stack.mjs`: it creates and later drops an isolated PostgreSQL database, applies and re-applies real migrations, runs a production-config worker cycle over controlled secret/dependency/config/exploitability blobs, runs the zero-retention canary, starts the real API and production web server, and drives headless Chromium without request interception. It verifies findings/filtering, semantic evidence and GitHub link, persisted review across reload, an SSE event inserted after connection, real System metrics, sanitized PostgreSQL rows, browser network/DOM/storage surfaces, and server-only operator authentication.
- CI now runs that full-stack harness after build and migration and builds all four production images. Compose configuration validates with controlled placeholders. The local Docker engine and PostgreSQL server are unavailable, so local claims are limited to configuration validation; real PostgreSQL/browser integration and image construction are delegated to the fresh GitHub Actions service/runner after this commit is pushed.
- Expanded coverage now includes every `packages/**/src/**/*.ts` file plus API and worker production index/runtime files. Added behavioral coverage for lockfile variants, advisory sanitization, data-flow syntax/budgets/timeouts, network bounds/outcomes, scheduler/server lifecycle, nullable metrics, migration refusal, proxy gateway failure, and real worker persistence. Only documented trivial process-invocation guards are ignored.
- The first full verification run reached the final tracked-secret audit but the audit read the deleted old migration still present in the unstaged Git index. Staging the intended migration rename fixed that audit-state edge; the complete gate was rerun from the staged checkpoint.
- Final local verification passed lint, strict typecheck, 15 test files/124 tests, 97.99% statements/lines, 90.00% branches, 93.81% functions, all workspace builds, 13 production web tests, 5 isolated Chromium journeys, zero high/critical production dependency vulnerabilities, and the tracked-secret audit over 117 indexed files. The controlled full-stack harness has passed static syntax/build validation and awaits its fresh PostgreSQL CI execution.

### 2026-08-15 18:34 IST — fix 27 published / fix 28 cross-platform shutdown RED/GREEN

- Published fix 27 as `b7d8d4ed6501a0b7a9ab119023deffcbc27dc7ca` (`fix 27: add production migrations and full-stack validation`). Direct push/fetch proved local, remote-tracking, and advertised `main` equality; the worktree was clean.
- GitHub Actions run `31886044674` passed checkout, install, Playwright installation, lint, typecheck, and all 124 tests with the 90% branch result, but failed the coverage step on one post-test unhandled rejection: Linux Vitest worker shutdown delivered a signal to an API listener retained after the production server had already closed, causing `ERR_SERVER_NOT_RUNNING`. All later fresh-PostgreSQL, integration, and image-build steps were correctly skipped.
- RED: production API/worker entry tests reproduced the lifecycle defect by closing twice and requiring SIGTERM/SIGINT listener counts to return to their baseline. API close threw `Server is not running`; worker close left one listener for each signal.
- GREEN: API and worker shutdown are now single-flight and idempotent, remove their own signal hooks before teardown, preserve injected-pool ownership, and convert signal-path teardown failures into generic operational errors instead of unhandled rejections. Repeated explicit close/stop succeeds and both listener counts return exactly to baseline.
- Full local verification passed again: lint, strict typecheck, 15 files/124 tests, 98.00% statements/lines, 90.07% branches, 93.16% functions, all builds, 13 production web checks, 5 Chromium journeys, dependency audit, and the 117-file tracked-secret audit.
