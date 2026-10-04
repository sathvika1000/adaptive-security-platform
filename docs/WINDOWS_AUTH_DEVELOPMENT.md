# Offline Windows authentication coverage

The frozen password-spray baseline remains reproducible with the existing command in
[Captured validation](CAPTURED_VALIDATION.md). Its original two missed cases remain unchanged.
This extension adds two separately named rules, opt-in mappings and evidence findings to offline
EVTX evaluation. Live Wazuh ingestion and the API do not run these rules.

| Rule | Evidence and grouping | Interpretation |
| --- | --- | --- |
| `auth.explicit_credential_fanout` v1 | Security 4648, five distinct nonmachine target accounts within five minutes; same source host, caller, logon session, process ID, process name when available and target server | Suspicious credential-use fan-out; no claim that credentials succeeded, failed or were compromised |
| `auth.kerberos_password_spray` v1 | Security 4771 with Status `0x18`, five distinct nonmachine target accounts within five minutes; same client IP and domain controller | Possible password spraying; not proof of compromise |

Both rules require the Security audit provider and explicit origin fields, deduplicate source/event
identities, treat target account names case-insensitively and keep telemetry families separate.
Missing origin/grouping fields exclude a record from the candidate count, but preserve its evidence.
Process name is optional because a host/session/process ID identifies the process in these inputs;
when present its value separates groups. The DeepBlue sample omits process names.
Repeated attempts against one account cannot reach the distinct-account threshold. Mapped IPv6
client addresses normalize to IPv4. Other Kerberos status values and 4768 remain excluded.

Microsoft documents [4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
as an explicit credential attempt, which can also occur during normal administrative activity.
[4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
records failed preauthentication; `0x18` indicates invalid preauthentication information associated
with a wrong password. Administrative automation and stale credentials can produce similar patterns.
Neither rule has representative benign validation or an established production false-alert rate.

## Reproduce development results

From the repository, with the existing virtual environment activated:

```bash
git pull --ff-only
python -m pip install -e '.[evtx]'
python -m adaptive_security.evtx_evaluation \
  docs/EVALUATION_RESERVATIONS.json artifacts/explicit-credentials-dev-v1 \
  --development-rule auth.explicit_credential_fanout
python -m adaptive_security.evtx_evaluation \
  docs/EVALUATION_RESERVATIONS.json artifacts/kerberos-spray-dev-v1 \
  --development-rule auth.kerberos_password_spray
```

Use new output directories; existing directories are refused. Each report preserves the original
reservation as historical baseline metadata, forces every new-rule dataset into `development`,
and hashes the new mapping and detector files. It does not identify the historical reservation's
commit as the new rule's frozen commit. Captured precision and recall remain null.
Each capture's private `*.findings.json` links candidate incidents to original event IDs; the
matching `*.events.jsonl` preserves XML, timestamps and raw fields for review. Original captures,
checksums and parser-yielded record counts are retained. These outputs are not loaded into the live DB.

The previously inspected DeepBlue capture is development data for these new rules. The explicit
credential rule detects account fan-out there. The Kerberos capture has only two 4771 bad-password
failures, so remains below five accounts. This is a remaining coverage gap, not a reason to lower
the threshold to fit this sample. Cross-rule case verdicts are telemetry coverage checks only.

Synthetic tests exercise thresholds, repeated users, missing fields, wrong status/provider,
separate callers/processes/sessions/servers, separate IPs/controllers, time boundaries and
baseline/partition preservation. They do not replace fresh attack and representative benign
captures. Before enabling live detection, reserve fresh validation captures against the new rule
and mapping hashes, collect reviewed benign controls and review actual candidate evidence.
