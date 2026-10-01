# OTRF captured telemetry evaluation

This workflow imports the OTRF PurpleSharp Active Directory Playbook I **host capture**,
replays every record through production ingestion in isolation, and builds a separate
password-spray investigation. It never calls the live API or opens the live database.

## Run on the Mac

From the repository, with Python 3.12 or later:

```sh
cd ~/adaptive-security-platform
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
python -m adaptive_security.otrf_replay artifacts/otrf-playbook-1
```

The command downloads the public host ZIP and checks its pinned SHA-256 before reading
it. It refuses an existing output directory. To repeat, choose another directory name.
For an already downloaded copy:

```sh
python -m adaptive_security.otrf_replay artifacts/otrf-playbook-2 \
  --capture artifacts/otrf-playbook-1/capture.zip
```

Inspect the report and evaluate the narrow documented attack case:

```sh
python -m json.tool artifacts/otrf-playbook-1/report.json
python scripts/evaluate_signal.py artifacts/otrf-playbook-1/attack-case.jsonl \
  --rule auth.password_spray --details
```

Expected inspected capture: 25,993 records, seven documented logon failures, one
password-spray candidate, and zero incidents from the current per-user correlation
pipeline. These are development observations, not a production accuracy estimate.

## Inspect the incident in our UI

In a separate Terminal, activate the same environment. Start a second local app using
only the findings database (the Docker app remains at port 8000):

```sh
cd ~/adaptive-security-platform
source .venv/bin/activate
export ASP_API_KEY="$(docker exec adaptive-security-platform-platform-1 printenv ASP_API_KEY)"
ASP_DB_PATH=artifacts/otrf-playbook-1/findings.db \
  python -m uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001 and enter your existing platform API key. Select **Possible
password spraying** to inspect its seven evidence events. Stop this second app with
Ctrl+C. This database is an offline investigation artifact; do not point a live
forwarder at it. The fuller supporting timeline is in `timeline.jsonl`.

## Outputs

| File | Purpose |
| --- | --- |
| `capture.zip` | Unmodified source capture, retained for tracing evidence |
| `events.jsonl` | All normalized records, including the original record in attributes |
| `replay.db` | Production ingestion replay, with existing authentication rules |
| `findings.db` | Separate UI-compatible database containing batch spray findings |
| `spray-incidents.jsonl` | Candidate incidents and exact evidence IDs |
| `attack-case.jsonl` | Only the seven failures in the publisher-documented attack case |
| `timeline.jsonl` | Mapped capture telemetry from 30 seconds before to two minutes after findings |
| `report.json` | Provenance, inventory, mapping coverage, missingness, and case verdict |

Output files have owner-only permissions. References to ZIP member and physical line
are preserved in every normalized event. Event IDs are stable for this exact capture.
Blank lines are skipped; malformed records fail the run rather than silently dropping
telemetry. Unmapped Windows events remain `other` with their raw data preserved.

## Interpretation and limitations

- Source: [OTRF PurpleSharp Playbook I](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201022042947.html).
  [Repository and licensing](https://github.com/OTRF/Security-Datasets).
  This is captured telemetry from a controlled attack simulation, not invented logs
  and not a representative enterprise population. Large capture files are not vendored.
- Pinned host ZIP SHA-256:
  `2a2d80e7b8d8ee6821a1754118f3ab908b4bac84cf4ed3d018e281f631bd2870`.
  Changed upstream content fails closed; review a replacement before changing the pin.
- Sysmon `UtcTime` is event time. Other records use local `EventTime` with an explicit
  `America/New_York` interpretation: publisher 04:29:53 maps to 08:29:53 UTC, consistent
  with capture observation timestamps. `@timestamp` is kept as observation time.
  This policy belongs to this inspected capture; it is not a default for all OTRF data.
- `Hostname` identifies the endpoint; `host` in these records identifies the collector.
  Missing source IPs remain missing. IPv4-mapped IPv6 addresses normalize to IPv4.
- Password spray is a **batch replay detector**, not enabled for live ingestion. It
  requires five distinct target accounts in five minutes from the same source IP,
  or explicit source workstation when an IP is absent. Only failed logon records
  count; credential-validation records are excluded to avoid counting another audit
  of the same attempt. Workstation-based results are weaker origin attribution.
- The documented seven failures are the labeled malicious case. Background events
  remain unlabeled. No benign verdicts, precision, recall, or false-alert rate are
  inferred from this one attack capture. The case verdict is a coverage check.
  The generic evaluator prints mathematical precision/recall of 1.0 for this one
  positive-only case; those values are not a meaningful performance estimate.
  The capture report deliberately leaves those metrics null.
- Novel-IP detection requires baseline successes and valid IPs; this capture does not
  provide a labeled accuracy test for that detector. Ticket requests, shares, processes,
  network connections, and DNS are preserved; Kerberoasting and WinRM detection are
  not yet implemented. Context around a finding does not prove causal relationships. Timeline records
  distinguish `same_endpoint` from `capture_context`; domain-controller ticket/share
  activity is included as context, not automatically labeled attack evidence.
- The network ZIP is a separate capture and is not yet imported. Host and network
  correlation, held-out captures, and representative benign evaluation are next steps.
- The automated regression suite uses explicitly synthetic minimal records to check
  boundaries, duplicates, order, source separation, timestamp conversion, isolation,
  and evidence persistence. They are not presented as real capture measurements.

Reserve entire additional captures for held-out evaluation before tuning further.
Do not split adjacent events from this development simulation into train/test sets.
