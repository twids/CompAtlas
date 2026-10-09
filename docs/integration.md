# API and pipeline integration

All endpoints require HTTPS and authentication. JSON bodies use camelCase. UUIDs are CompAtlas IDs unless explicitly called Azure IDs. Request body limit is 12 MiB; embedded CycloneDX JSON limit is 10 MiB. Machine endpoints are limited to 120 requests per minute per credential, with no queue.

## Interactive reporting

Windows-authenticated users can call:

| Method/path | Parameters/purpose |
|---|---|
| `GET /api/v1/coverage` | Authorized repository coverage |
| `POST /api/v1/collections?repository=<guid>` | Reviewer-triggered collection; antiforgery required |
| `GET /api/v1/collections/{id}` | Project-scoped job receipt/status |
| `GET /api/v1/findings` | Optional `project`, `repository`, `snapshot` GUIDs |
| `GET /api/v1/packages` | Optional `ecosystem`, `name`, `version`, `repository`, `snapshot` |
| `GET /api/v1/reports/findings.csv` | Same scope filters as findings |
| `POST /api/v1/findings/{id}/reviews` | Assessment, reason, optional acceptedUntil and previousReviewId |

Review API calls require a valid antiforgery request token/cookie pair as well as Windows credentials; use the rendered review form for ordinary interactive operation. Unknown or inaccessible findings return 404. Outdated previousReviewId returns 409. An exception requires a future expiry within one year; the UI defaults to 30 days. A null acceptedUntil means no temporary acceptance.

## Machine submission

Use `Authorization: Bearer <project-token>`. A token is issued once through Administration and expires after 90 days; it can be revoked immediately. Store it as a secret pipeline variable, never in YAML, arguments, URLs or SBOM references.

`POST /api/v1/sboms` accepts:

```json
{
  "repositoryId": "00000000-0000-0000-0000-000000000000",
  "application": "Web",
  "relativePath": "src/Web",
  "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "branch": "refs/heads/main",
  "buildId": "42",
  "releaseId": null,
  "bomJson": "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}"
}
```

The response is 202 with `{id,status}` and a project-scoped status location at `GET /api/v1/submissions/{id}`. Duplicate identical submissions return the same receipt. Retry a 409 concurrent-submission response with the identical body. UUID possession never grants access to another project's receipt.

Collector-enabled credentials can call `POST /api/v1/collection/claim`, receiving a revision, clone URL, lease owner and expiry, or 204 when no work exists. `POST /api/v1/collection/{id}/complete` accepts `{leaseOwner,success}` and checks project, credential, active lease and submitted revision evidence. Never treat an expired lease as successful.

## YAML and Classic Releases

Use `scripts/Invoke-CompAtlasPipeline.ps1`; the YAML example passes secrets through environment variables. Add the step after the application build. Supply `-BomPath` for an existing approved build SBOM; otherwise the wrapper produces a conservative partial inventory. Call once per application boundary.

Classic Release tasks use the same PowerShell wrapper with `-Commit`, `-Branch` and `-BuildId` taken from the selected artifact's build metadata, plus the Classic `-ReleaseId`. Do not substitute the release pipeline's unrelated source revision. The worker verifies build repository/commit and Classic artifact project/build linkage using Azure DevOps APIs. YAML builds use build/repository/commit linkage; cryptographic provenance and deployed binary identity remain unassessed.

Collection/upload errors emit a fixed Azure warning and return exit code 0. Set `failOnStderr: false`; the wrapper also suppresses collector stderr so upstream content cannot inject agent logging commands. Standalone collector commands retain non-zero failures for job-controller use. If upload cannot reach CompAtlas, the pipeline warning is the immediate evidence; the central report subsequently shows stale/missing inventory rather than claiming to have received an unavailable event.

## Example collector use

```powershell
CompAtlas.Collector.exe collect --path C:\Disposable\checkout --output C:\Disposable\bom.json
$env:COMPATLAS_URL = 'https://compatlas.example.internal/'
# Supply COMPATLAS_TOKEN from the approved secret store, never as a command-line argument.
CompAtlas.Collector.exe submit --bom C:\Disposable\bom.json --repository <guid> --application Web --relative-path src/Web --commit <full-sha> --branch refs/heads/main --build 42
```

Use custom internal trusted CA certificates in OS/tool stores. Do not add certificate-bypass switches to these scripts.
