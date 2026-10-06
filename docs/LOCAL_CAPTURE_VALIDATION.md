# Reviewed local capture validation

The public captures already used for development do not establish benign false-alert performance.
The `adaptive_security.capture_validation` command supports reviewed local EVTX exports for the two
new Windows authentication rules. It does not collect from Windows, generate attacks, label unknown
background benign, or enable live detection. No representative benign validation is claimed yet.

## Plan and freeze

Place a complete EVTX export and `plan.json` together in a private directory. Capture paths are
relative to that directory; absolute paths and symlinks outside it are refused. One complete capture
is one evaluation case. Supported limits are 20 captures, 5 MB and 10,000 parser-yielded records per
capture. Export smaller complete collection intervals when necessary; do not silently truncate or
select only alerts. The interval must contain every event in the export.

Start with this plan, replacing paths, references, environment and actual collection times:

```json
{
  "version": 1,
  "rule_id": "auth.kerberos_password_spray",
  "captures": [
    {
      "capture_id": "routine-auth-window-01",
      "path": "Security.evtx",
      "partition": "development",
      "label": "unlabeled",
      "label_reference": "collection-notes/window-01",
      "environment": "Describe the isolated lab or reviewed environment",
      "collection_start": "2026-10-04T12:00:00Z",
      "collection_end": "2026-10-04T13:00:00Z"
    }
  ]
}
```

`unlabeled` is the default. To declare `benign` or `malicious`, add `reviewer`, `reviewed_at` (timezone
required), and `label_basis`. For benign captures, the basis must describe review of the **complete
collection interval**, expected activity and supporting records. An absence of detections is not a
benign label. For malicious captures, reference the attack execution transcript and relevant rule
family; publisher attack presence does not make every record malicious. Review information is stored
privately with results, so use suitable analyst identifiers and references.

Use `held_out` only when the implementation was fixed before inspecting or tuning against the
capture. The tool refuses the two known development-capture digests in that partition. It cannot
certify prior inspection history or identify all related sessions/exports; reviewers must also avoid
reusing overlapping records across partitions. The freeze step hashes bytes without parsing records
or running detection. Save the reservation before inspecting fresh records, and retain a durable
version/commit of it. Freeze time is local provenance, not an independent attestation.

```bash
python -m adaptive_security.capture_validation freeze \
  artifacts/local-validation/plan.json artifacts/local-validation/frozen-plan.json
python -m adaptive_security.capture_validation run \
  artifacts/local-validation/frozen-plan.json artifacts/local-validation-results-v1
```

The frozen plan must stay beside the input plan because it pins relative paths. Both commands refuse
existing outputs. Evaluation rejects modified capture bytes, changed normalization/detection/evaluation
implementation hashes, duplicate captures, malformed XML, empty captures, and out-of-bound event times.
Partial results are removed on failure. There is no download or live application write.

## Read the results

- `report.json`: inventories, review declarations, case verdicts and validation status. All-unlabeled
  plans produce no accuracy metrics. Single-label captured datasets retain null precision and recall.
- `*.findings.json`: candidate findings and original evidence event IDs, including findings in
  unlabeled captures. A finding in unknown activity is not counted as a false positive.
- `*.events.jsonl` and `*.evtx`: all parser-yielded records and original evidence. Unsupported event
  types remain available; no records are relabeled or filtered out.
- `frozen-plan.json`: the exact reservation that generated the result, plus its report digest.

Outputs use owner-only permissions (directories 700/files 600 on POSIX). The report includes review
metadata, and the original/exported evidence may include identities; retain outputs privately.
A capture without selected telemetry still produces a case verdict if explicitly labeled, but its
zero selected-record count makes the coverage gap visible. Selected event counts do not establish
that required origins, process fields, error codes or distinct accounts were present.

Reports keep development and held-out datasets separate. They do not pool case counts into a
production score or treat observation duration as complete audited exposure. `production_false_alert_rate`
remains null and the new rules remain disabled for live deployment. Multiple benign cases with zero
alerts alone are not proof of safety, especially if they contain no eligible telemetry.

## Capture selection still needed

Collect controlled, documented windows for normal administrative explicit-credential use (including
scheduled tasks, approved account switching and automation), isolated mistyped/stale credentials,
and routine Kerberos authentication. Include different source hosts, callers, clients and controllers,
and periods containing the selected event families. Keep uncertain/background captures unlabeled.
Representative coverage depends on actual environment and workload, not a fixed sample count.

For fresh attack validation, record an authorized isolated lab simulation independently of detector
output, preserve the transcript, and reserve the implementation/capture hashes before examination.
A five-account rule needs an appropriate multiaccount simulation; the existing two-failure Kerberos
sample remains a development miss. This tool supplies reproducibility and label discipline; obtaining
reviewed representative exports and reviewing candidate evidence are still required.

## Check usable telemetry before interpreting quiet results

Each inventory row now includes `telemetry_coverage`: input records, unique eligible
records, eligible grouping contexts, distinct target accounts, and mutually exclusive
exclusion counts. These checks share the detector's eligibility boundary, including
Security provider/mapping, nonmachine targets, the exact event family/outcome/status,
and required caller/session/process/server or host/client fields. Duplicate source/event
identities are excluded once. Exclusion reasons follow that order and describe the first
failed check, not every defect in a record. No account names or grouping values are
added to the coverage summary.

`no_eligible_telemetry` means the capture cannot exercise this rule's eligible input
boundary; a declared benign case may still have a case-level true-negative verdict,
but it is not useful benign telemetry coverage. `eligible_telemetry_present` also does
not establish representative coverage: two eligible Kerberos failures remain below the
five-account threshold. Distinct-account counts span all groups and times and must not
be interpreted as a five-minute detection window. Validation status counts captures
with and without eligible records separately; accuracy labels and metrics are unchanged.

The same coverage summary appears in development EVTX evaluation output. To reuse
existing downloaded bytes on a Mac without downloading again, choose a new output:

```bash
python -m adaptive_security.evtx_evaluation \
  docs/EVALUATION_RESERVATIONS.json artifacts/kerberos-coverage-dev-v1 \
  --capture-directory artifacts/explicit-credentials-dev-v1 \
  --development-rule auth.kerberos_password_spray
```

This is a diagnostic rerun of inspected development captures, not fresh validation.
Implementation hashes change with this update; existing local frozen plans will be
refused. Preserve old reservations/results, then freeze a new plan for a new run.
Previously inspected inputs remain development data.
