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

The controlled fixture contains a structurally valid but nonfunctional value. The audit fails unless the raw value occurs zero times across database, logs, output, errors, browser data, queues, and writable layers, and the full HMAC-SHA256 fingerprint occurs exactly once. Fingerprint keys must be at least 32 random bytes and supplied through the runtime secret mechanism.
