# Breach operator console

This workspace is the private Breach validation console. It renders Findings, Investigation, Stream, and System views from the same-origin server routes under `app/api`. Those routes inject `OPERATOR_TOKEN` only on the server and forward to the internal operator API configured by `API_INTERNAL_URL`.

The browser receives sanitized finding contracts, lifecycle metadata, and aggregate metrics only. It never receives GitHub API bodies, raw scanned source, raw secret values, review notes, database credentials, or the operator token. There is no analytics or third-party telemetry.

From the repository root:

- `npm run build --workspace @breach/web` builds the production console.
- `npm run test --workspace @breach/web` runs server/rendered-route contracts.
- `npm run test:browser --workspace @breach/web` runs isolated Chromium UI behavior.
- `npm run test:integration` runs the real PostgreSQL/API/web controlled-stack acceptance test after all workspaces are built.

For normal operation, use the root `compose.yaml`; its web service receives only `API_INTERNAL_URL` and `OPERATOR_TOKEN` and waits for API readiness.
