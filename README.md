# CompAtlas

Internal, advisory software composition and supply-chain reporting for Azure DevOps Server.

CompAtlas connects Azure DevOps projects, Git repositories, applications, commits, builds and releases to CycloneDX inventories and Dependency-Track findings. It reports vulnerabilities, license-policy issues, known malicious packages, evidence gaps and time-limited review decisions.

## Stack

- .NET 10 / ASP.NET Core Razor Pages with English, server-rendered HTML.
- IIS Windows Authentication; project access through AD group SIDs.
- EF Core and SQL Server for CompAtlas, including durable jobs and append-only audit protection.
- An independently operated Dependency-Track service, integrated exclusively through its API.
- A Windows Service orchestrator and a collector CLI for disposable environments and pipelines.

## Build and test

```powershell
dotnet restore CompAtlas.sln --locked-mode
dotnet build CompAtlas.sln --no-restore -c Release
dotnet test CompAtlas.sln --no-restore -c Release
```

For the real SQL Server migration/concurrency/backup tests, set `COMPATLAS_TEST_SQLSERVER` to a test-server connection string. Tests create and remove uniquely named `CompAtlas_Test_*` databases. Production connection strings are never test inputs.

```powershell
$env:COMPATLAS_TEST_SQLSERVER = 'Server=(localdb)\MSSQLLocalDB;Integrated Security=true;Encrypt=false'
dotnet test CompAtlas.sln --no-restore
```

The encryption exception above is for local SQL test infrastructure only. Production defaults require encrypted SQL connections with certificate validation.

## Start here

- [Deployment and configuration](docs/deployment.md)
- [Architecture and data ownership](docs/architecture.md)
- [Security boundaries](SECURITY.md)
- [Collection support and limitations](docs/support-matrix.md)
- [API and pipeline integration](docs/integration.md)
- [Operations and recovery](docs/operations.md)
- [Validation and pilot acceptance](docs/validation.md)

## Reporting behaviour

The portfolio and project/repository views use the latest successful default-branch inventories. Failed and pending collections remain visible in coverage. Build/release selection exposes retained snapshots. Package search separates ecosystems and supports exact versions and documented intervals. CSV exports enforce the same project permissions as the web pages and neutralize spreadsheet formulas.

Reviews are scoped to an application snapshot and package occurrence. Exceptions expire independently of assessment state and never hide accepted findings. Administrators require an additional reader/reviewer role to access findings or make review decisions.

**No package feed, build or deployment is blocked.** Artifact signatures, cryptographic provenance, reachability and unknown malware detection are not implied by a clean vulnerability result. Unavailable evidence is reported as unknown/not assessed.

## Release readiness

This repository contains the implementation and automated tests. Production pilot acceptance requires real Azure DevOps/Dependency-Track connection details, disposable runner provisioning and representative repositories. A WCAG 2.2 AA target is not a conformance claim; manual NVDA/Edge and domain/IIS validation remain required. See the validation checklist for the exact remaining deployment evidence.
