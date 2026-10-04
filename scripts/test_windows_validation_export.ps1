#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'export_windows_validation.ps1'
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Windows exporter has PowerShell syntax errors.' }

$root = Join-Path ([IO.Path]::GetTempPath()) ('asp-export-check-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    # Use the latest existing Security record. No audit settings or event data are changed.
    $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    $start = $latest.TimeCreated.ToUniversalTime().AddSeconds(-1).ToString('o')
    $latest.Dispose()
    $end = [DateTimeOffset]::UtcNow.ToString('o')
    $destination = Join-Path $root 'export'
    $parameters = @{ StartUtc = $start; EndUtc = $end; OutputDirectory = $destination;
        CaptureId = 'ci-export'; EnvironmentLabel = 'Ephemeral Windows CI runner' }
    $result = (& $scriptPath @parameters | Out-String | ConvertFrom-Json)
    if ($result.records -lt 1 -or $result.label -ne 'unlabeled') { throw 'Unexpected export status.' }
    $metadata = Get-Content -Raw -LiteralPath (Join-Path $destination 'collection.json') | ConvertFrom-Json
    $plan = Get-Content -Raw -LiteralPath (Join-Path $destination 'plan.json') | ConvertFrom-Json
    if ($plan.captures.Count -ne 1 -or $plan.captures[0].label -ne 'unlabeled' -or
        $plan.captures[0].partition -ne 'development') { throw 'Export plan must default to unknown.' }
    if ($metadata.record_count -ne $result.records -or $metadata.channel -ne 'Security' -or
        $metadata.exporter -ne 'asp.security_export.v1') { throw 'Collection metadata mismatch.' }
    $capture = Join-Path $destination 'Security.evtx'
    if ((Get-FileHash -LiteralPath $capture -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        $metadata.capture_sha256) { throw 'Export hash mismatch.' }
    if ($metadata.query -match 'EventID') { throw 'Export must retain all Security event types.' }
    $prepared = Join-Path $root 'prepared'
    & python -m adaptive_security.capture_preparation $capture $prepared `
        --collection-info (Join-Path $destination 'collection.json') --rule auth.kerberos_password_spray | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Python preparation rejected the native export metadata.' }
    $frozen = Join-Path $prepared 'frozen-plan.json'
    & python -m adaptive_security.capture_validation freeze (Join-Path $prepared 'plan.json') $frozen | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Native export reservation failed.' }
    $evaluated = Join-Path $root 'evaluated'
    & python -m adaptive_security.capture_validation run $frozen $evaluated | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Python EVTX parser rejected native Security capture.' }
    $report = Get-Content -Raw -LiteralPath (Join-Path $evaluated 'report.json') | ConvertFrom-Json
    if ($report.inventory[0].records -ne $metadata.record_count -or $report.datasets.Count -ne 0) {
        throw 'Native/Python record counts must agree and unknown activity must stay out of metrics.'
    }
    $acl = Get-Acl -LiteralPath $destination
    if (-not $acl.AreAccessRulesProtected) { throw 'Evidence directory inherits broad permissions.' }
    $allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
    foreach ($access in $acl.Access) {
        $sid = $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed) { throw 'Unexpected evidence-directory access.' }
    }
    # Empty intervals fail without leaving a published or partial export.
    $empty = $parameters.Clone()
    $empty.StartUtc = '1900-01-01T00:00:00Z'; $empty.EndUtc = '1900-01-01T00:01:00Z'
    $empty.OutputDirectory = Join-Path $root 'empty'
    $failed = $false
    try { & $scriptPath @empty | Out-Null } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath $empty.OutputDirectory)) {
        throw 'Empty export should fail without partial results.'
    }
    $marker = Join-Path $destination 'keep.txt'
    [IO.File]::WriteAllText($marker, 'keep')
    $failed = $false
    try { & $scriptPath @parameters | Out-Null } catch { $failed = $true }
    if (-not $failed -or [IO.File]::ReadAllText($marker) -ne 'keep') {
        throw 'Existing output must not be overwritten.'
    }
    $naive = $parameters.Clone()
    $naive.StartUtc = '2020-01-01T00:00:00'; $naive.OutputDirectory = Join-Path $root 'naive'
    $failed = $false
    try { & $scriptPath @naive | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Timezone-free collection timestamps must fail.' }
    if (@(Get-ChildItem -LiteralPath $root -Filter '.asp-export-*' -Force).Count -ne 0) {
        throw 'Failed exports left temporary evidence directories.'
    }
    Write-Output 'Windows export checks passed: native Security export, bounds, metadata, ACLs and failures.'
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
