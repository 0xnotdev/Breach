# Security boundary

The validation worker treats all repository metadata and bytes as hostile. It never clones, checks out, executes, builds, installs, verifies credentials, follows repository URLs, or derives a network destination from repository content.

## Egress

The application egress policy admits only HTTPS requests to `api.github.com` and `api.osv.dev`, plus explicitly configured internal service hostnames. It rejects userinfo, redirects to unapproved hosts, GitHub repository web URLs, arbitrary HTTP(S), and non-network schemes. Network policy in production must mirror this allowlist; the Compose `egress` network alone is not a firewall.

## Runtime isolation

The worker runs as UID/GID 10001 with a read-only root filesystem, no Linux capabilities, no privilege escalation, bounded CPU/memory/PIDs/file descriptors, core dumps disabled, and only a 64 MiB `noexec,nosuid` tmpfs. No source, host, Docker socket, or canary fixture is mounted into the worker. Repository buffers are released on every terminal path.

Disable host swap for production workers, or use an encrypted and separately audited swap device. Compose cannot reliably enforce a host-wide swap policy; operators must verify it before launch. Crash dumps and diagnostic heap snapshots must remain disabled because they can retain transient repository bytes.

## Parser boundary

YAML and XML inputs are byte/depth bounded. YAML custom tags and aliases are denied. XML DTD, entity, `SYSTEM`, and `PUBLIC` declarations are denied and entity processing is disabled. Display/log text is NFC-normalized, bounded, and control characters are visibly escaped.

## Canary proof

The controlled fixture contains a structurally valid but nonfunctional value. `npm run canary --workspace @breach/worker` runs it through the real commit gate, Git tree/blob snapshot reader, analyzers, PostgreSQL store, and operator serializer. The Chromium acceptance test adds rendered DOM plus local/session storage to the same audit. The audit fails unless the raw value occurs zero times across every inspected surface, transient snapshot buffers are cleared, and the full HMAC-SHA256 fingerprint occurs only within the bounded sanitized metadata representations expected for that run.

The runtime command requires `DATABASE_URL` and `FINGERPRINT_HMAC_KEY`; `CANARY_FIXTURE_PATH` may override the controlled fixture location. It records `zero_retention.canary.last_run`, `.success`, `.raw_occurrences`, and `.fingerprint_occurrences` only after a successful runtime audit. It also records zero source-persistence, retention-violation, and credential-verification observations for that measured run. The seed command never writes safety metrics. Fingerprint keys must be at least 32 random bytes and supplied through the runtime secret mechanism.

This is a no-durable-source-retention claim, not a zero-memory claim. Repository bytes necessarily exist transiently in TLS/network buffers, bounded Node buffers, process RAM, and parser structures. Host swap must therefore remain disabled or separately encrypted and audited.
