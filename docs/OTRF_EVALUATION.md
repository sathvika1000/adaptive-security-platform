# OTRF captured telemetry evaluation

This workflow imports the OTRF PurpleSharp Active Directory Playbook I **host capture**,
replays every record through production ingestion in isolation, and builds a separate
password-spray and RC4 service-ticket investigations. It never calls the live API or opens
the live database.

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
password-spray candidate, one five-event RC4 ticket candidate, and zero incidents from
the current per-user correlation
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

Open http://127.0.0.1:8001/ui and enter your existing platform API key. Select **Possible
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
| `evaluation-suite.json` | Checksum-pinned development case and capture provenance |
| `rc4-ticket-incidents.jsonl` | Offline RC4 ticket-burst candidates and evidence IDs |
| `rc4-ticket-case.jsonl` | Five ticket records tied to the documented T1558.003 simulation |
| `rc4-ticket-suite.json` | Separate checksum-pinned ticket development evaluation |
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
  network connections, and DNS are preserved. An offline RC4 ticket-burst candidate now
  covers a narrow Kerberoasting pattern; WinRM detection remains unimplemented.
  Context around a finding does not prove causal relationships. Timeline records
  distinguish `same_endpoint` from `capture_context`; domain-controller ticket/share
  activity is included as context, not automatically labeled attack evidence.
- The network ZIP is a separate, optional capture with conservative metadata links
  described below. Held-out captures and representative benign evaluation remain next steps.
- The automated regression suite uses explicitly synthetic minimal records to check
  boundaries, duplicates, order, source separation, timestamp conversion, isolation,
  and evidence persistence. They are not presented as real capture measurements.

Reserve entire additional captures for held-out evaluation before tuning further.
Do not split adjacent events from this development simulation into train/test sets.

## Paired host and network investigation

To create a **new** isolated replay with the paired network capture:

```sh
cd ~/adaptive-security-platform
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
python -m adaptive_security.otrf_replay artifacts/otrf-playbook-network \
  --capture artifacts/otrf-playbook-1/capture.zip --with-network
```

Stop the old port-8001 server with Ctrl+C in its Terminal, then start the new view:

```sh
export ASP_API_KEY="$(docker exec adaptive-security-platform-platform-1 printenv ASP_API_KEY)"
ASP_DB_PATH=artifacts/otrf-playbook-network/findings.db \
  python -m uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001/ui. The seven failed-logon evidence events are distinct from
**Supporting network context**. Accounts, endpoints, origins, and explanations are
visible; long references and raw records expand on demand. Unassigned OTRF event severity
is labeled unassigned. The signal explanation states that this is an offline finding.

Network processing preserves `network-capture.zip` and writes `network-events.jsonl`.
The inspected network ZIP SHA-256 is
`c7dd67e1f2b914d4f553b3ef98d29b8858ed86b03ffa7dd7c0a55af30eacf03b`.
To use a local network ZIP instead of downloading it, pass `--network-capture PATH`.

The original capture contains 1,121 packets. This version supports classic microsecond
PCAP with Ethernet (including single VLAN), complete nonfragmented IPv4, TCP, and UDP.
It extracts metadata from 1,048 packets into 159 directed connection/UTC-second buckets;
61 truncated IPv4 packets and 12 other IP protocol packets are counted separately and
remain in the original capture. IPv6, reassembly, application payload decoding, PCAPNG,
and nanosecond PCAP are not implemented. The parser does not claim to detect WinRM from
its port number. PCAP packet time is UTC; collection observation time is unavailable
and its fallback is explicitly recorded.

Context linking requires a nearby Sysmon network event on the incident endpoint,
an exact directed source/destination address, source/destination port, and protocol
match, and a packet-time overlap within two seconds. Host anchors are restricted to
30 seconds before through two minutes after the finding. The spray investigation retains
45 matched buckets, and the ticket investigation has 39; their union is 52 buckets.
Shared buckets retain the host-anchor IDs and investigation IDs from both findings.
Each retains packet numbers and matching host event IDs. Shared IP
or temporal proximity alone cannot create a link. These are metadata relationships,
not proof of maliciousness, successful compromise, or packet-level user attribution.

The authenticated, paginated endpoint is `/v1/incidents/{incident_id}/context`.
Context references are preserved in incident records and protected from the unlinked
archive classification. Existing host-only artifacts display no network context;
rerun into a new directory to obtain it. Live detection remains unchanged.

## Explicit synthetic detector controls

```sh
python scripts/evaluate_signal.py examples/evaluation/password-spray.synthetic.jsonl \
  --rule auth.password_spray --details
```

Six constructed cases cover a spray, single-account retries, separate origins,
fewer-than-threshold accounts, a shared-kiosk benign lookalike, and a slow attack.
The current rule intentionally reports one true positive, three true negatives,
one false positive (shared kiosk), and one false negative (slow spray). This exposes
threshold limitations; it is not measured accuracy on representative customer traffic.
Held-out captured attacks and permissioned benign activity are still required before
live deployment or tuning claims.

## Provenance-aware evaluation suites

New replay outputs also contain `evaluation-suite.json`. Run it with:

```sh
python -m adaptive_security.evaluation_suite \
  artifacts/otrf-playbook-network/evaluation-suite.json
python -m adaptive_security.evaluation_suite \
  examples/evaluation/password-spray.suite.json
```

The first command reports the publisher-documented attack as **development** coverage;
precision and recall stay null because the capture's labeled case contains no benign
activity. The second reports the six **synthetic controls** separately. Existing
`scripts/evaluate_signal.py` behavior is unchanged. Older replay outputs must be rerun
into a new directory to obtain the suite manifest.

The manifest has `version: 1`, one `rule_id`, and a nonempty `datasets` array. Each dataset
declares `dataset_id`, relative `cases_file`, its `cases_sha256`, `kind` (`synthetic` or
`captured`), `partition` (`control`, `development`, or `held_out`), `capture_id`, and
`label_reference`. Captured datasets also require the original `capture_sha256`.
Synthetic datasets must use `control`. Case files use the existing labeled canonical
event JSONL format. Paths must remain within the manifest directory, including symlinks.
Compute case digests with `shasum -a 256 PATH` after the labeled cases are finalized.

Before running any detector, the evaluator validates every file's checksum, unique
dataset/case IDs, and partition boundaries. Reusing a capture ID, original capture
digest, case-file digest, or source/event identity in different partitions fails.
Cases from the same capture must stay in the same partition. Results are per dataset;
there is no combined score across development, held-out, and synthetic data. Reports
contain case IDs, labels, predictions, verdicts, and declared provenance, without event
bodies, user/host entities, or raw logs. Use non-sensitive IDs and label references
because those declarations appear in reports.

Partitions and label references are declarations, not independent certification. The
evaluator verifies the labeled case files; it does not reopen the original capture to
verify its declared digest or prove that a human never used it for tuning. Record the
capture reservation and labeling decision before development, retain original captures,
and freeze the rule before evaluating a reserved capture. Renaming/re-normalizing events
or changing capture declarations can defeat overlap checks; keep those identities stable.

Only deliberately labeled cases enter these reports. Unknown background must remain
excluded, rather than receiving an inferred benign label. Counts and metrics describe
the supplied cases, not attack-level localization or enterprise false-alert rates. A
dataset with both benign and malicious cases still needs representative sampling before
its metrics support a product claim. No new held-out or benign capture is supplied here.

## RC4 service-ticket candidates

New replays include **Suspicious RC4 service-ticket burst** alongside the password-spray
incident. Its five evidence records are separate from the seven spray failures.
The UI shows the service account, requester, issuing domain controller, client IP,
ticket encryption, and ticket issuance status. Status is kept separate from logon
outcome, so ticket issuance does not update production successful-login baselines.

The batch rule `auth.rc4_service_ticket_burst` v1 requires successful Security event
4769 requests with RC4-HMAC (`TicketEncryptionType` 0x17), an explicit requester and
client IP, and at least five distinct service accounts within five minutes on one
issuing domain controller. Machine service names ending in `$` and `krbtgt` are excluded.
Duplicates by source/event identity do not count again. Unknown status, encryption,
requester, client address, service, or controller cannot create a candidate.
Grouping by controller is conservative and may miss requests distributed across DCs.
The rule is offline only; it is not called by live ingestion.

Publisher provenance: the [PurpleSharp simulation transcript](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201022042947.html)
lists five service-account requests during T1558.003. Those records from the existing
development capture form the narrow attack case; surrounding records remain unlabeled.
Field semantics follow [Microsoft event 4769 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769).
Service Name denotes the service account, rather than an SPN string. RC4 can result from
legitimate legacy use; issuing a ticket does not prove extraction, password cracking,
or compromise. AES-based, slow, and single-service attacks are outside this rule.

```sh
python -m adaptive_security.evaluation_suite \
  artifacts/otrf-playbook-network/rc4-ticket-suite.json
python -m adaptive_security.evaluation_suite examples/evaluation/rc4-tickets.suite.json
python scripts/evaluate_signal.py \
  artifacts/otrf-playbook-network/rc4-ticket-case.jsonl \
  --rule auth.rc4_service_ticket_burst --details
```

Choose a new replay directory after updating to generate these artifacts. Existing
findings databases do not gain ticket candidates automatically. Use the provenance-aware
suite for captured reporting: it keeps precision and recall null for this single-label
development case. The legacy evaluator retains its mathematical single-case metrics.

### RC4 ticket candidate controls

Six explicitly constructed cases cover an attack pattern, AES tickets, repeated requests
for one service, failed requests, a benign legacy-app lookalike, and a slow attack. The
expected counts are one true positive, three true negatives, one false positive, and one
false negative. These controls illustrate behavior, not production accuracy. Additional
reserved captures and permissioned representative benign cases remain required.
