#Requires -Version 5.1
<#
.SYNOPSIS
Export a complete bounded Security log interval for offline validation.
.DESCRIPTION
Read-only event-log operation. Creates a new private export directory; does not
change auditing, clear logs, generate authentication attempts or run detection.
Use an account permitted to read the local Security channel.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StartUtc,
    [Parameter(Mandatory = $true)][string]$EndUtc,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]+$')][string]$CaptureId,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$EnvironmentLabel,
    [ValidateSet('auth.explicit_credential_fanout', 'auth.kerberos_password_spray')]
    [string]$Rule = 'auth.kerberos_password_spray'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ExplicitTime([string]$Value) {
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') {
        throw 'Timestamps require ISO 8601 format with an explicit timezone.'
    }
    return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
}

$start = Convert-ExplicitTime $StartUtc
$end = Convert-ExplicitTime $EndUtc
if ($end -le $start -or $end -gt [DateTimeOffset]::UtcNow) {
    throw 'Choose a completed interval with end after start.'
}
if ([string]::IsNullOrWhiteSpace($EnvironmentLabel)) { throw 'Describe the collection environment.' }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Output exists; choose a new directory.' }
$parent = [IO.Path]::GetDirectoryName($destination)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Create the output parent directory first.'
}
$stage = Join-Path $parent ('.asp-export-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage
$records = @()
try {
    # Restrict the directory before writing any evidence; children inherit these rules.
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($owner)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $access = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($access)
    }
    Set-Acl -LiteralPath $stage -AclObject $acl
    $from = $start.ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'")
    $until = $end.ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'")
    # Retain every Security event in the interval; do not select only 4648/4771.
    $query = "*[System[TimeCreated[@SystemTime >= '$from' and @SystemTime <= '$until']]]"
    $capture = Join-Path $stage 'Security.evtx'
    & wevtutil.exe epl Security $capture "/q:$query" '/ow:false' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $capture -PathType Leaf)) {
        throw 'Security export failed; check local event-log read permissions.'
    }
    $size = (Get-Item -LiteralPath $capture).Length
    if ($size -gt 5000000) { throw 'Export exceeds 5 MB; choose a bounded validation interval.' }
    # This limits the verification read only; the on-disk export is never truncated.
    $records = @(Get-WinEvent -Path $capture -MaxEvents 10001 -ErrorAction Stop)
    if ($records.Count -eq 0 -or $records.Count -gt 10000) {
        throw 'Export must contain 1-10000 records; no truncated results are accepted.'
    }
    foreach ($record in $records) {
        if ($null -eq $record.TimeCreated -or $record.TimeCreated.ToUniversalTime() -lt $start.UtcDateTime -or
            $record.TimeCreated.ToUniversalTime() -gt $end.UtcDateTime -or $record.LogName -ne 'Security') {
            throw 'Exported records do not match the requested collection interval/channel.'
        }
        $record.Dispose()
    }
    $metadata = [ordered]@{
        version = 1; exporter = 'asp.security_export.v1'; capture_id = $CaptureId
        capture_file = 'Security.evtx'; channel = 'Security'
        capture_sha256 = (Get-FileHash -LiteralPath $capture -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = $size; record_count = $records.Count
        collection_start = $from; collection_end = $until
        exported_at = [DateTimeOffset]::UtcNow.ToString('o')
        environment = $EnvironmentLabel.Trim(); machine = [Environment]::MachineName; query = $query
    }
    $entry = [ordered]@{
        capture_id = $CaptureId; path = 'Security.evtx'; partition = 'development'; label = 'unlabeled'
        label_reference = 'collection.json'; environment = $EnvironmentLabel.Trim()
        collection_start = $from; collection_end = $until
    }
    $plan = [ordered]@{ version = 1; rule_id = $Rule; captures = @($entry) }
    # UTF-8 without a BOM works consistently in Windows PowerShell 5.1 and Python.
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $stage 'collection.json'), ($metadata | ConvertTo-Json -Depth 5), $utf8)
    [IO.File]::WriteAllText((Join-Path $stage 'plan.json'), ($plan | ConvertTo-Json -Depth 5), $utf8)
    [IO.Directory]::Move($stage, $destination)
    [ordered]@{ output = $destination; records = $records.Count; label = 'unlabeled';
        status = 'exported; review and validation still required' } | ConvertTo-Json
}
catch {
    foreach ($record in $records) { if ($null -ne $record) { $record.Dispose() } }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    throw 'Security capture export failed; check timestamps, permissions, size and record bounds.'
}
