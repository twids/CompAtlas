[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$path = [IO.Path]::GetFullPath($Destination)
if (-not (Test-Path -LiteralPath $path)) {
    & git clone --filter=blob:none -- https://github.com/ossf/malicious-packages.git $path
    if ($LASTEXITCODE -ne 0) { throw 'Dataset clone failed.' }
} else {
    $origin = & git -C $path remote get-url origin
    if ($origin -ne 'https://github.com/ossf/malicious-packages.git') { throw 'Unexpected dataset origin.' }
    & git -C $path -c core.hooksPath=NUL pull --ff-only
    if ($LASTEXITCODE -ne 0) { throw 'Dataset refresh failed; freshness is unchanged.' }
}
$commit = & git -C $path rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Dataset commit unavailable.' }
@{ fetchedAt = [DateTimeOffset]::UtcNow.ToString('O'); commit = $commit } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $path 'compatlas-source.json') -Encoding utf8
