# Collect and prepare Windows validation inputs

The platform's macOS Wazuh agent does not produce Windows 4648/4771 Security events. Use a Windows
endpoint for explicit-credential activity and a domain controller for Kerberos preauthentication
activity, with an account permitted to read the local Security log. These tools export existing
activity only. They do not change audit policy, clear logs, generate authentication attempts, run
attacks, or upload evidence. They create unlabeled development inputs; review is still required.

## Export on Windows

In Windows PowerShell 5.1 or newer, from the repository on the Windows machine:

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\asp-validation" -Force | Out-Null
$end = [DateTimeOffset]::UtcNow
$start = $end.AddMinutes(-10)
.\scripts\export_windows_validation.ps1 `
  -StartUtc $start.ToString('o') -EndUtc $end.ToString('o') `
  -OutputDirectory "$env:USERPROFILE\asp-validation\auth-window-01" `
  -CaptureId 'auth-window-01' -EnvironmentLabel 'Describe the actual Windows lab and activity' `
  -Rule 'auth.kerberos_password_spray'
```

For a documented collection, use the actual completed UTC start/end instead of the preceding ten
minutes. Any explicit ISO 8601 timezone is accepted and normalized to UTC. Use the explicit-credential
rule on the corresponding endpoint if appropriate. Choose a new output directory each time; existing
outputs are refused. The parent directory must already exist.

The exporter calls Microsoft's
[`wevtutil epl`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
with a time-only query over the Security channel. All Security event types in the interval are retained,
including unsupported events. It verifies the exported channel and collection bounds, counts records,
and records a SHA-256 checksum. `Get-WinEvent` reads the exported file for these checks; there is no
rule execution. Empty exports, over 5 MB, over 10,000 records, failed commands and mismatched bounds
are rejected without publishing a partial directory. The verification limit never truncates the EVTX.

The new directory restricts NTFS access to the current Windows identity and SYSTEM before writing
evidence. It contains `Security.evtx`, `collection.json`, and `plan.json`. The collection sidecar records
exporter version, source machine, exact query, interval, timestamp, bytes and record count. These are
export provenance, not proof that auditing was enabled throughout the interval or that log rollover,
clock changes, missing hosts or omitted audit subcategories did not hide activity.

If an export is too large, choose an appropriate bounded lab window with its activity documented.
Do not arbitrarily split an attack or five-minute pattern across separate evaluation cases: the current
rules evaluate each capture independently and cannot combine evidence across captures. Retain original
exports and document any collection limitations. Zero selected-event records cannot validate a rule.

## Prepare on your Mac

Transfer the export directory privately to your Mac, for example as `artifacts/windows-export-01`.
Then create a private prepared copy and an unlabeled plan:

```bash
python -m adaptive_security.capture_preparation \
  artifacts/windows-export-01/Security.evtx artifacts/prepared-window-01 \
  --collection-info artifacts/windows-export-01/collection.json \
  --rule auth.kerberos_password_spray
python -m adaptive_security.capture_validation freeze \
  artifacts/prepared-window-01/plan.json artifacts/prepared-window-01/frozen-plan.json
python -m adaptive_security.capture_validation run \
  artifacts/prepared-window-01/frozen-plan.json artifacts/window-01-results
```

Preparation verifies the EVTX header, size, sidecar checksum and byte count. It does not parse records,
run detection, relabel the capture or certify the exporter's declared record count. The evaluator later
reports every parser-yielded record. Sidecar metadata cannot be silently overridden. On macOS/Linux,
prepared directories/files use owner-only permissions (700/600); on Windows use a private NTFS parent
or the exporter directory's restricted ACLs, because POSIX modes do not configure NTFS permissions.

If you already have a complete EVTX export without this sidecar, supply its actual collection bounds
and environment directly:

```bash
python -m adaptive_security.capture_preparation /path/to/Security.evtx \
  artifacts/prepared-existing-export --rule auth.explicit_credential_fanout \
  --capture-id existing-export-01 --start '2026-10-04T12:00:00Z' \
  --end '2026-10-04T12:10:00Z' --environment 'Describe the real collection'
```

Replace the example dates with the true bounds. Timezone-free dates and missing metadata are refused.
Collection bounds must contain every record, or evaluation fails rather than silently filtering.
The source export is never modified. Existing prepared directories are refused.

`review-notes.md` provides space for actual activity, supporting transcripts and audit/retention gaps.
Follow [local capture validation](LOCAL_CAPTURE_VALIDATION.md) for reviewed labels and held-out history.
Keep the initial reservation and any later review declarations as separate durable artifacts; a new
reservation after inspection does not establish unseen data. Unlabeled evaluation can support evidence
review, but calculates no accuracy metrics. Representative benign and fresh attack validation remain
unfinished; these tools do not enable live detection or establish production false-alert performance.

## Verification

CI checks the exporter on a native Windows runner, including a real existing Security-log export,
collection metadata, record bounds, restricted ACLs, empty-window failures and overwrite protection.
It then prepares/freezes/replays that export in Python and compares native and parser-yielded record
counts. The runner's activity stays unlabeled and no log artifacts are uploaded. This verifies the
collection pipeline, not representative benign detection performance.
