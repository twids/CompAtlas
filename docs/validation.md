# Validation and acceptance

## Automated checks

The solution includes relational SQLite service tests, HTTP integration tests with test-only Windows identities and real machine authentication, upstream API contract fixtures, and opt-in real SQL Server migration/concurrency/backup tests. Synthetic scale tests exercise 100 repositories and approximately 10,000 component occurrences.

Coverage includes project filtering, hidden snapshot IDs, reader/admin separation, machine project boundaries, invalid credentials, CSRF rejection, fixed security headers, CSV injection, XML external entities, SBOM limits, traversal, duplicate submissions, retries, expired leases, external review conflicts, exception expiry, manual hash-backed declarations, version comparisons and known-malicious-package matching.

Run release build/tests with warnings as errors and NuGet auditing enabled. Lockfiles are committed; CI restores with `--locked-mode`. Keep SDK/runtime/Hosting Bundle patched alongside package references.

To capture actual Razor output with synthetic test data and run axe/keyboard/reflow checks:

```powershell
$env:COMPATLAS_PREVIEW_OUTPUT = "$PWD/artifacts/preview"
dotnet test CompAtlas.sln -c Release --no-restore
npm ci --ignore-scripts
npx playwright install chromium
npm run test:accessibility
```

Screenshots and machine-readable results are written to `artifacts/preview`. These browser checks render HTTP-test output, not a production-authenticated session. They cover all five views at desktop and 320px widths. Remaining axe incomplete results require human review. The test-only identity handler is compiled solely into the test assembly.

## Pilot evidence required

- Record actual Azure DevOps Server build, supported negotiated APIs and collection count.
- Record Dependency-Track version, permissions, BOM/analysis-chain behaviour, finding/violation payloads and review round-trip semantics.
- Scan real modern .NET, legacy .NET Framework, old SharePoint JavaScript and Python projects. Compare direct/transitive inventory with independently resolved package evidence.
- Verify package feeds are unchanged and YAML/Classic tasks leave application pipelines advisory during collection/upload outages.
- Verify build/release traceability using actual artifact metadata. Leave signatures as Not assessed until a real verification mechanism exists.
- Validate disposable-runner identity, network and filesystem isolation; prove scanners cannot reach web/worker secrets or SQL.
- Test actual domain users, group membership changes, revoked machine credentials, SPNs, IIS providers and Extended Protection.
- Measure a full nightly scan of the real 100-repository portfolio; acceptance target is eight hours. The synthetic reporting test does not establish scanning throughput.
- Perform a production-like SQL/Dependency-Track restore rehearsal and verify pending work, active exceptions and audit records.

## Accessibility

WCAG 2.2 AA is the target. Automated HTML/HTTP checks verify semantic structural features; they do not establish conformance. Test every view and form manually using Edge/NVDA and keyboard only: skip link, focus order, navigation, filters, scrollable tables, errors, review submission, expiry input and one-time token issuance. Test 200%/400% zoom, 320 CSS-pixel reflow, contrast, focus visibility and status announcement. Charts must retain table equivalents if introduced later.

Record actual results and remediate issues before claiming accessibility acceptance. No production conformance, real scan coverage or eight-hour completion is asserted merely because automated tests pass.
