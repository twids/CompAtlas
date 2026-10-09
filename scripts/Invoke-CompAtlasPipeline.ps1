[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Collector,
    [Parameter(Mandatory)][guid]$RepositoryId,
    [Parameter(Mandatory)][string]$Application,
    [Parameter(Mandatory)][string]$Checkout,
    [string]$RelativePath = '.',
    [string]$BomPath,
    [string]$Commit = $env:BUILD_SOURCEVERSION,
    [string]$Branch = $env:BUILD_SOURCEBRANCH,
    [string]$BuildId = $env:BUILD_BUILDID,
    [string]$ReleaseId = $env:RELEASE_RELEASEID
)
$ErrorActionPreference = 'Stop'
try {
    if ([string]::IsNullOrWhiteSpace($Commit) -or [string]::IsNullOrWhiteSpace($Branch)) {
        throw 'Explicit artifact commit and branch are required in Classic Releases.'
    }
    if (-not $BomPath) {
        $BomPath = Join-Path ([IO.Path]::GetTempPath()) ('compatlas-' + [guid]::NewGuid() + '.json')
        & $Collector collect --path $Checkout --output $BomPath 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Collection failed.' }
    }
    $arguments = @('submit', '--bom', $BomPath, '--repository', $RepositoryId.ToString(), '--application', $Application,
        '--relative-path', $RelativePath, '--commit', $Commit, '--branch', $Branch)
    if ($BuildId) { $arguments += @('--build', $BuildId) }
    if ($ReleaseId) { $arguments += @('--release', $ReleaseId) }
    & $Collector @arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Submission failed.' }
} catch {
    # Fixed text: never echo upstream messages, tokens or untrusted repository names into agent commands.
    Write-Host '##vso[task.logissue type=warning]CompAtlas analysis is unavailable. Review the coverage report and restricted collector diagnostics.'
} finally {
    # Advisory by contract, including when the caller enables failOnStderr.
    $global:LASTEXITCODE = 0
}
exit 0
