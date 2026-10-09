# Collection support

There are two collection paths. Conservative file inventory is included and explicitly partial. A pinned external CycloneDX generator or build-produced SBOM provides resolved/transitive evidence where the ecosystem supports it. CompAtlas never upgrades partial coverage into a claim of completeness.

| Ecosystem/input | Included conservative collector | Full collection path |
|---|---|---|
| .NET `packages.config` | Declared exact package versions, secure XML parsing | Restore/build and approved CycloneDX generator in disposable Windows worker |
| SDK/legacy `.csproj` | Literal PackageReference versions; variables/ranges remain unknown | Resolved project assets / packages.lock.json with approved generator |
| Central package management | Not resolved by file fallback | Restore/build SBOM required |
| npm lockfile v1/v2/v3 | Locked versions, including nested dependencies | Build generator supplies graph, license and origin evidence |
| npm package.json | Declared exact versions; ranges remain unknown | npm ci/approved generator, with scripts disabled where supported |
| Yarn/pnpm | Fallback cannot resolve their lockfiles; partial warning remains | Approved generator/build SBOM |
| Bower | Declared references identified as Bower, never silently treated as npm | Reviewed manual identity for evidenced library files |
| Vendored/bundled JavaScript | SHA-256 and path; no guessed version or third-party attribution | Reviewer declares verified package identity/version against preserved file evidence |
| Python pinned requirements | Exact pins; markers not evaluated | Generator in project environment to resolve transitive/platform-specific dependencies |
| Python pyproject/Poetry/uv/Pipenv | Fallback does not resolve lockfiles | Approved generator/build SBOM |
| Other ecosystems | CycloneDX import preserves package URL ecosystem | Extend generator adapter/toolchain, then validate representative input |

Unknown licenses become evidence findings. Known license expressions remain declared evidence until organizational policies have been configured in Dependency-Track. CompAtlas imports license violations and does not substitute a simplistic universal allowed-license list.

## Application boundaries

Central collection defaults to a single whole-repository application. Add `compatlas.applications.json` with explicit name/path pairs for independent, non-overlapping applications; see `examples/compatlas.applications.json`. Paths are relative and cannot traverse outside the checkout. Pipeline submissions should use the same paths. Do not define both a root application and its nested application unless duplicated inventory is intentional.

## Versions and graphs

Search supports exact `=version` and interval syntax such as `[1.0.0,2.0.0)`. NuGet/npm use numeric semantic-version ordering; Python uses supported PEP 440 public-version ordering including epochs and pre/post/dev releases. Local Python versions require exact matching. Native npm caret/tilde expressions and pip requirement syntax are not accepted. Unknown/unsupported versions do not match a range; search without a version filter to inspect them.

CycloneDX dependency references are retained. Direct/transitive classification is only shown when a root dependency graph exists. Otherwise classification is unknown. Nested component trees are flattened into searchable occurrences while the original SBOM preserves containment evidence. The component limit covers the full tree.

## Known malicious packages

The worker imports the locally approved OpenSSF dataset. It matches ecosystem/name, exact affected versions and supported OSV SEMVER/ECOSYSTEM event intervals. Unsupported ranges or uncertain versions become review-required evidence rather than a confirmed malware verdict. This does not detect novel malware, prove benign package behaviour or establish publisher provenance.

The dataset checkout needs a `compatlas-source.json` freshness manifest; `scripts/Sync-MaliciousPackages.ps1` produces it after a successful approved refresh. Importing an old checkout does not update its fetchedAt time. Show source freshness independently of scan freshness.

## Validated integration versions

| System | Status |
|---|---|
| .NET | 10.0.12 packages; SDK selected by global.json |
| SQL Server | LocalDB provider migration/concurrency/backup tests available; production instance unverified |
| Azure DevOps Server | REST negotiation 7.1 → 7.0 → 6.0; installed production build not yet provided |
| Dependency-Track | `/api/v1` contract tests; exact live deployment/version not yet validated |
| cdxgen/toolchains | Operator-pinned external distribution; production version/hash not yet provided |

Record pilot versions, settings and representative scan evidence here before declaring deployment acceptance.
