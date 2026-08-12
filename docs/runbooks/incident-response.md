# Incident response runbook

For a retention violation, stop the worker immediately, preserve metadata-only audit records, revoke GitHub/operator credentials, and isolate the database. Do not collect heap/core dumps. Identify the affected writable surface, destroy transient container layers, rotate the HMAC key if fingerprint material is implicated, and rerun the controlled canary proof before restart.

For rate-limit exhaustion, pause discovery and commit checks until the authoritative reset time. Do not add token sharding. For parser or memory pressure, keep the candidate partial/failed, retain only bounded reason codes, and lower byte/file/node/time budgets before resuming. For database unavailability, readiness must fail and worker cycles must remain stopped; restore metadata from the last known safe backup.

Document timestamps, state transitions, sanitized metric names, affected component versions, and corrective checks. Never paste repository content, raw GitHub bodies, credentials, source snippets, or canary values into tickets, chat, logs, or the review note field.
