[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Collector,
    [Parameter(Mandatory)][string]$Workspace,
    [Parameter(Mandatory)][string]$AllowedCloneHost
)
$ErrorActionPreference = 'Stop'
$claim = $null
$success = $false
try {
    # Provision this runner outside CompAtlas in a disposable VM/container with a restricted identity.
    # This script does not itself create a security sandbox.
    if ($env:COMPATLAS_ISOLATED_JOB -ne '1') { throw 'An externally isolated job is required.' }
    $workspacePath = [IO.Path]::GetFullPath($Workspace)
    if (Test-Path -LiteralPath $workspacePath) {
        if ((Get-Item -LiteralPath $workspacePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Workspace must not be a reparse point.' }
        if (Get-ChildItem -LiteralPath $workspacePath -Force | Select-Object -First 1) { throw 'Workspace must be empty.' }
    } else { New-Item -ItemType Directory -Path $workspacePath | Out-Null }
    $output = & $Collector claim
    if ($LASTEXITCODE -ne 0) { throw 'Claim failed.' }
    if (-not $output) { return }
    $claim = ($output -join "`n") | ConvertFrom-Json
    $uri = [uri]$claim.cloneUrl
    if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Host -ne $AllowedCloneHost -or $claim.commit -notmatch '^[a-fA-F0-9]{40}$') { throw 'Untrusted clone metadata.' }
    $checkout = Join-Path $workspacePath 'checkout'
    & git -c core.hooksPath=NUL -c protocol.file.allow=never -c protocol.ext.allow=never clone --no-checkout --no-local -- $uri.AbsoluteUri $checkout
    if ($LASTEXITCODE -ne 0) { throw 'Checkout failed.' }
    & git -c core.hooksPath=NUL -c protocol.file.allow=never -c protocol.ext.allow=never -C $checkout checkout --detach $claim.commit
    if ($LASTEXITCODE -ne 0) { throw 'Revision unavailable.' }
    # Configure read-only Azure Git access on this disposable identity. Do not place PATs in clone URLs.
    # Explicit boundaries avoid double-counting nested applications through overlapping discovery roots.
    $applications = @(@{ name = 'Repository'; path = '.' })
    $applicationConfig = Join-Path $checkout 'compatlas.applications.json'
    if (Test-Path -LiteralPath $applicationConfig) {
        if ((Get-Item -LiteralPath $applicationConfig).Length -gt 65536) { throw 'Application configuration is too large.' }
        $applications = @((Get-Content -LiteralPath $applicationConfig -Raw | ConvertFrom-Json).applications)
        if ($applications.Count -eq 0 -or $applications.Count -gt 100) { throw 'Invalid application boundaries.' }
    }
    foreach ($application in $applications) {
        $relative = [string]$application.path
        if (-not $relative -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative.Contains(':')) { throw 'Invalid application path.' }
        $root = [IO.Path]::GetFullPath((Join-Path $checkout $relative))
        if ($root -ne $checkout -and -not $root.StartsWith($checkout + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Application escapes checkout.' }
        $current = $checkout
        foreach ($segment in ([IO.Path]::GetRelativePath($checkout, $root) -split '[\\/]')) {
            if ($segment -eq '.') { continue }
            $current = Join-Path $current $segment
            if ((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Application path crosses a reparse point.' }
        }
        $relative = [IO.Path]::GetRelativePath($checkout, $root).Replace('\','/')
        $bom = Join-Path $workspacePath ('bom-' + [guid]::NewGuid() + '.json')
        & $Collector collect --path $root --output $bom
        if ($LASTEXITCODE -ne 0) { throw 'Collection failed.' }
        & $Collector submit --bom $bom --repository $claim.repositoryId --application $application.name --relative-path $relative --commit $claim.commit --branch $claim.branch
        if ($LASTEXITCODE -ne 0) { throw 'Submission failed.' }
    }
    $success = $true
} finally {
    if ($claim) {
        & $Collector complete --job $claim.id --lease $claim.leaseOwner --success $success.ToString().ToLowerInvariant()
    }
    # The provisioner destroys the entire disposable environment and credentials after this job.
}
