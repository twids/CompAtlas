# Deployment

## Prerequisites

- Patched .NET 10 Hosting Bundle, IIS with Windows Authentication and an internal HTTPS certificate.
- SQL Server with encrypted connections and a trusted server certificate.
- Separately provisioned Dependency-Track with an HTTPS endpoint and scoped API credentials.
- Read-only Azure DevOps collection access and restricted disposable collector identities.
- AD groups for administration, portfolio reading and per-project reading/reviewing.
- An approved outbound proxy, internal CA trust and host/network allowlists.

CompAtlas does not install or configure the organization's Dependency-Track service. Its API contract must be checked against the exact installed version before pilot acceptance.

## Build and publish

```powershell
dotnet restore CompAtlas.sln --locked-mode
dotnet publish src/CompAtlas.Web -c Release --no-restore -o artifacts/web
dotnet publish src/CompAtlas.Worker -c Release --no-restore -o artifacts/worker
dotnet publish src/CompAtlas.Collector -c Release --no-restore -o artifacts/collector
```

Copy web and worker distributions to approved, separately ACL-protected locations. Deploy pipeline scripts with the collector in your approved tools feed. The worker is a Windows Service; register it through the normal service-provisioning process using its executable, a restricted identity and a working directory containing its configuration. Enable automatic restart and service monitoring.

## Configuration

Use deployment-managed environment variables or ACL-protected configuration outside the repository. Never commit tokens or credentials. Both Web and Worker need the same SQL database; only Worker needs Dependency-Track and Azure credentials.

| Setting | Purpose |
|---|---|
| `ConnectionStrings__CompAtlas` | SQL Server connection, preferably Integrated Security |
| `CompAtlas__DependencyTrackUrl` | Worker-only trusted HTTPS base URL |
| `CompAtlas__DependencyTrackApiKey` | Worker-only analysis/review API credential |
| `CompAtlas__AllowedAzureHosts__0` | Exact Azure DevOps host allowed when creating collection connections |
| `CompAtlas__AzureUseDefaultCredentials` | Use worker Windows identity for Azure API calls; default true |
| `CompAtlas__AzureTokens__<connection-guid>` | Optional read-only Azure PAT instead of Windows credentials |
| `CompAtlas__ProxyUrl` | Optional HTTP/HTTPS corporate proxy URL, without embedded credentials; upstream TLS validation remains enabled |
| `CompAtlas__MalwareDirectory` | Read-only approved OpenSSF checkout, including freshness manifest |
| `CompAtlas__ConcurrentJobs` | Concurrent orchestration jobs, default 2; bounded 1–8 |
| `CompAtlas__NightlyHourUtc` | UTC nightly boundary, default 01:00 |
| `CompAtlas__SnapshotRetentionDays` | Routine snapshot minimum retention, default 90 |
| `CompAtlas__ReleaseRetentionDays` | Build/release minimum retention, default 365 |
| `AllowedHosts` | Set exact CompAtlas DNS names; do not use a wildcard |

Apply migrations with a separate deployment identity, not a runtime db_owner login:

```powershell
.\CompAtlas.Web.exe --migrate
.\CompAtlas.Web.exe --bootstrap-sid S-1-5-21-REPLACE-WITH-REAL-GROUP-SID
```

Bootstrap is a local command and only works when no bindings exist. The sample SID is intentionally invalid; supply a real AD group SID. Apply `scripts/SqlServer-RuntimePermissions.sql` and provision the runtime users into `CompAtlasRuntime`. Maintain separate migration/backup identities.

## IIS authentication

Enable Windows Authentication. Also allow anonymous requests to reach ASP.NET Core so machine bearer requests can reach the dedicated machine policy; the application requires authentication on every dynamic endpoint. Do not grant anonymous access at the application authorization layer. Verify this exact combination on your IIS build.

Configure IIS request filtering with a body limit of 12 MiB or less, matching the application's bound. Only publish HTTPS bindings. Retain strict certificate validation and HSTS. Set and validate SPNs, provider order, Extended Protection and any reverse-proxy constraints under your domain standards. Do not forward arbitrary client-supplied identity headers. Kestrel/header-based test identities exist only in the test project and are never production configuration.

Test Windows group SID claims with an actual domain account before provisioning project bindings. No groups means no project access. Configure portfolio readers and reviewers explicitly; administrator status does not grant either.

## Dependency-Track permissions

Grant only BOM upload/project creation, portfolio/component/finding/policy-result reads and vulnerability analysis/assessment operations used by the worker. Do not grant system or user administration. Scope access to CompAtlas-created projects where the installed version permits it. Configure organizational license policies there; CompAtlas initially reports declared licenses and review requirements rather than claiming compliance by default.

## Disposable collectors

Run `Invoke-CompAtlasIsolatedJob.ps1` once per disposable restricted environment. Provide a new empty workspace, the allowed clone host and a project credential with collection permission. Set `COMPATLAS_ISOLATED_JOB=1` only after the provisioner has established isolation.

The default conservative collector reads files. To use cdxgen, provision a pinned, reviewed tool distribution outside the checkout and invoke `collect` with `--scanner`, optional `--scanner-entrypoint` (for Node), and `--scanner-sha256`. Hash validation covers the supplied entrypoint; the provisioner must validate the full distribution, dependencies and runtime. The child receives an explicit environment allowlist and no CompAtlas token. Use read-only feed credentials in temporary isolated package configuration where a restore requires them. Recreate the whole environment after every job.
