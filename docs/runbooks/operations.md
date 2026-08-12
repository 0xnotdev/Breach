# Operations runbook

Copy `.env.example` to `.env`, replace every placeholder, then run `docker compose up --build`. Check API `http://localhost:8080/readyz`, worker health through `docker compose ps`, and the private console at `http://localhost:3000`. Run migrations with `docker compose run --rm api node apps/api/dist/migrate.js`; optional sanitized demo metadata uses `seed.js`.

Use a fine-grained GitHub token restricted to read-only public repository metadata/contents. Give PostgreSQL and the operator API separate credentials. Rotate the GitHub token, HMAC key, operator token, and database password independently; rotating the HMAC key intentionally changes future secret fingerprints.

Monitor discovery cursor movement, selection ratio, GitHub remaining quota, requests/bytes per scan, p95 latency, partial/failure rate, review precision, and the zero-retention canary. Stop the worker on any retention violation. Under quota pressure, the worker serializes requests and marks rate-limited candidates instead of bypassing the gate.

Back up only PostgreSQL metadata. Never add source volumes, Docker socket mounts, core dumps, heap snapshots, or repository archive caches. Verify host swap is disabled or encrypted before production operation. Upgrade by running the complete verification suite, rebuilding images, migrating, then replacing API/web before the worker.
