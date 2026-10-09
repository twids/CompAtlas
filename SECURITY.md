# Security model

Security defects must be reported through your organization's private security-reporting channel. Do not place credentials, source inventories or exploit details in public GitHub issues.

## Enforced application boundaries

- Authentication is required by default. There is no development login bypass.
- AD group SIDs grant project roles; administrators do not inherit findings/review access.
- Report queries, searches, explicit snapshot requests and CSV exports filter by authorized project IDs.
- Project-scoped, expiring, revocable machine tokens are stored as SHA-256 hashes; generated secrets contain 256 bits of entropy. Machine identities cannot use interactive reporting/review policies.
- Interactive writes require antiforgery validation. Razor encoding is retained; repository content is never rendered as raw HTML.
- Strict CSP disallows scripts, framing and object content. Responses use no-store and MIME-sniffing protection.
- CycloneDX input is limited to 10 MiB, depth 64 and 20,000 components. Duplicate references, traversal paths, malformed revisions and embedded credentials in reference URLs are rejected. XML collection prohibits DTD/external entity resolution.
- HTTPS endpoints reject embedded credentials. Upstream clients do not follow redirects or disable certificate validation.
- Scanner execution is absent from the web and orchestration processes. Collector child environments exclude upload tokens and ambient secret variables.
- SQL jobs use revision checks and credential/lease ownership. Audit has application guards and a SQL Server append-only trigger; runtime SQL permissions deny modification/deletion.
- Original snapshot evidence is immutable in the application; manual component identification creates a new snapshot with reviewer audit evidence.

## Infrastructure responsibilities

Application controls complement domain hardening, IIS configuration, network egress rules, database permissions and disposable execution environments. A directory boundary, scanner hash or `COMPATLAS_ISOLATED_JOB` flag does not establish isolation. Restrict filesystem access and remove ambient credentials from scanner identities. Disable unapproved Git credential helpers, filters, hooks and global configuration on collector images. Repository tooling is untrusted code, including restore hooks and build targets.

Use OS certificate stores for approved internal CAs. Never set `TrustServerCertificate=true`, disable TLS verification or use cleartext production database connections. Protect ASP.NET Core Data Protection keys with the IIS identity and approved filesystem ACLs/DPAPI policy. Avoid shared key directories with collector identities.

The web and worker identities must not be SQL sysadmin/db_owner. Database administrators can alter triggers and records; application append-only protection is not tamper-proof storage against privileged operators. Export audit events to your protected central logging service when stronger retention/integrity is required.

## External integration limits

Only operator-allowlisted Azure hosts can be configured through the UI. Enforce DNS/network allowlists as well; hostname validation alone does not prevent DNS or infrastructure compromise. Source inventories can contain internal package names and component URLs; configure Dependency-Track outbound analysis providers according to your data-handling policy.

Dependency-Track assessment updates are compare-before-write, not atomic compare-and-swap. Use CompAtlas as the sole review writer to close this operational race. Conflicts are exposed instead of silently resolved.

Review synchronization never uses permanent suppression for temporary risk acceptance. A reviewed component's identity is a human assertion backed by preserved file/hash evidence, not cryptographic verification of the upstream publisher.

## Required deployment verification

Validate actual domain Windows Authentication, AD group changes/revocation, SPNs/Extended Protection, SQL runtime permissions, source/data egress, disposable-runner isolation and restricted logging before production use. Run authorized penetration testing against the deployed configuration. Automated tests use test-only identities and cannot prove these infrastructure properties.
