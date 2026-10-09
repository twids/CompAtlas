# Operations and recovery

## Daily operation

Monitor the Operations view for failed/retried jobs, expired leases and stale intelligence. Monitor the Windows Service and IIS independently. SQL connectivity is necessary but does not establish successful discovery, collection or analysis. Verify a known repository's revision, SBOM hash, completed analysis and expected findings as the end-to-end check.

Confirm that a disposable collector pool is consuming jobs. The central worker intentionally does not execute collection tooling. Provision at least two independent runner slots if the measured workload requires that concurrency; `ConcurrentJobs` controls central analysis/discovery concurrency, not VM provisioning.

Compare last seen/discovery state with expected project/repository access. A removed/restricted repository is retained for history; disappearance is not interpreted as deletion. Investigate stale coverage and lost read permission. Rotate machine credentials before their 90-day expiry and revoke old credentials after verification.

Source freshness is independent of snapshot freshness. A new analysis timestamp does not prove external advisory feeds updated successfully. Monitor Dependency-Track's configured intelligence feeds directly as well as CompAtlas's findings retrieval/OpenSSF timestamps.

## Proxy and allowlist

Web needs SQL access and authenticated intranet clients; it does not need internet. Worker needs SQL, configured Azure collection URLs, Dependency-Track and the approved local dataset. Dataset refresh needs `github.com` and Git transport endpoints approved by your proxy. Collectors need CompAtlas, read-only Azure Git and existing internal package feeds; approved scanners may need additional metadata endpoints that must be listed before enablement.

Dependency-Track's own intelligence-source allowlist and outgoing component data must be reviewed separately. Do not infer that self-hosting makes third-party analysis offline. Disable providers that violate the organization's data policy. Keep all TLS verification enabled and provision internal CA trust through normal OS/runtime mechanisms.

Logs use fixed summaries for upstream failures to avoid retaining credentials/untrusted source content. Job IDs and exception types support correlation. Detailed upstream investigation belongs in restricted infrastructure diagnostics; do not enable EF sensitive-data logging or broad HTTP body logging.

## Retention

Routine snapshots are eligible after 90 days and build/release snapshots after 365 days, configurable upward. Latest successful/current inventories, snapshots with active findings/reviews, and pending synchronization work are protected. Because evidence gaps remain active, retention is deliberately conservative and can retain more than the configured minimum. Capacity planning must account for this.

Completed/failed jobs are removed after 90 days. Audit and review records are retained indefinitely by this initial implementation; controlled archival after at least one year is a DBA operation, not a runtime deletion permission. Dependency-Track version retention is independently managed; do not remove projects with active CompAtlas mappings or outstanding review jobs.

## Backup and restore

Back up SQL Server with the organization's full/differential/log policy. Include protected deployment configuration, Data Protection keys where persistence is configured, and the separately operated Dependency-Track database/configuration. Do not export secrets into documentation.

Restore to an isolated environment first, with outbound integrations and collectors disabled. Verify schema/migration history, project bindings, immutable SBOM hashes, audit continuity, open findings, active exceptions and pending jobs. Ensure restored service identities cannot accidentally update production Dependency-Track projects. Resume workers only after endpoints and credentials have been reviewed. Expired leases are retried with a new owner; max-attempt jobs become failed rather than silently disappearing.

Automated SQL Server backup/restore tests verify that pending review synchronization jobs survive a real backup and can be claimed after restoration. They do not prove the organization's production backup schedule, encryption, offsite retention or RPO/RTO.

## Assessment conflicts

Conflicting upstream changes remain visible on the finding. Refresh the source analysis, inspect both decisions, then submit a new justified review with the latest review ID. Never repair conflicts by overwriting SQL rows or silently suppressing findings. Configure Dependency-Track human accounts read-only so CompAtlas remains the only assessment writer.
