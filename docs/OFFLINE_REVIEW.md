# Review offline Windows findings on a Mac

Windows is not required to review existing captured EVTX results. The investigation UI
can open output from `evtx_evaluation --development-rule` or `capture_validation run`
for `auth.explicit_credential_fanout` and `auth.kerberos_password_spray`.

## Start a local review server

From the repository directory, in a new terminal:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install -e '.[evtx]'
export ASP_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '%s' "$ASP_API_KEY" | pbcopy
ASP_OFFLINE_REVIEW_PATH=artifacts/explicit-credentials-dev-v1 \
ASP_DB_PATH=artifacts/offline-review.db \
python -m uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8003
```

Open <http://127.0.0.1:8003/ui>, paste the copied key, click **Load incidents**,
then **Offline captures**. Select a capture and a candidate finding. **Finding evidence**
shows only that finding's records; **All capture records** includes unsupported and
background events. Both views have pagination and expandable canonical/raw records,
including preserved XML. Capture and run provenance are expandable separately.

The earlier `artifacts/explicit-credentials-dev-v1` output works directly; no new capture
or rerun is needed. If it is missing, generate it using:

```bash
python -m adaptive_security.evtx_evaluation \
  docs/EVALUATION_RESERVATIONS.json \
  artifacts/explicit-credentials-dev-v1 \
  --development-rule auth.explicit_credential_fanout
```

Stop with Control-C. To review the Kerberos run or a local validation run, restart with
`ASP_OFFLINE_REVIEW_PATH` pointing at its complete output directory. Each server caches
one validated snapshot on first access; restart after replacing output files. A missing
configuration shows an empty offline view. Invalid or incomplete output returns a generic
review error while the live API remains available. If port 8003 is occupied, use another
free port and update the URL.

## Evidence and limits

The offline view reads stored results and never imports events/findings into the incident
database or provides analyst closure actions. Analyst assessments are stored separately in the configured
SQLite database; they do not alter captured files, detector findings, labels, or metrics. It displays declared labels and partitions,
computed case verdicts, source checksums, and available review/implementation provenance.
A capture-level malicious label does not label all background records. No findings does
not establish benign activity. Unsupported event families are identified explicitly.
Unknown labels remain excluded from accuracy calculations.

4648 records show caller/session/process/server context where present. A credential attempt
has no recorded target-logon outcome and does not prove compromise. 4771 records show the
preauthentication failure status and issuing domain controller. These rules remain offline;
previously inspected development captures do not establish held-out performance or a
representative benign false-alert rate.

All three read endpoints require the platform API key:

- `GET /v1/offline-review`: configured state, run provenance, capture summaries.
- `GET /v1/offline-review/captures/{capture_id}`: capture metadata and stored findings.
- `GET /v1/offline-review/captures/{capture_id}/events`: paginated records; optional
  `finding_id` restricts the page to that finding's evidence. `limit` is 1–100 and `offset`
  is nonnegative.

The loader checks original EVTX hashes, labeled-case hashes, normalized record counts and
capture references, inventory event counts, and finding rule/evidence/time/entity consistency.
Paths and symlinks must stay within the configured directory. These are local consistency
checks, not independent verification of labels or signed proof of detector execution.
Historical implementation hashes are displayed rather than required to match current code;
the viewer does not rerun or tune a detector.

Loading is bounded to 20 captures, 10,000 normalized records per capture, 1 MB metadata
files, 5 MB original EVTX/findings files, 40 MB normalized/case files, and a 128 MB total
read budget. Bundles above those bounds must be split into smaller complete runs.

## Save analyst assessments

Select a candidate finding, choose a disposition under **Analyst assessment**, and write
a supporting note (1–2,000 characters). Click **Save assessment**. The current disposition
and paginated history update together. Every save creates another revision; there is no
edit/delete endpoint. Dispositions are `needs_review`, `suspicious`, `benign_activity`,
`confirmed_malicious`, and `inconclusive`. They express analyst judgments, not evaluation
labels or proof of compromise.

With the default shared platform key, reviews are explicitly unattributed. If named analyst
keys are configured, supply an analyst key with the new `review` permission. For example:

```json
{
  "sathvika": {"key": "YOUR_DISTINCT_AT_LEAST_32_CHARACTER_KEY", "permissions": ["review"]}
}
```

Use this JSON as `ASP_ANALYST_KEYS_JSON` before starting the server. A key may have both
`close` and `review`; existing string entries and close-only keys retain close permission
only. Server configuration determines the actor, never a user-supplied name. The UI clears
the analyst key after submission and clears draft notes/history when changing findings or
forgetting the platform key. Keys are never included in saved review entries.

Review history is bound to a SHA-256 fingerprint of the capture metadata/label, run and
rule provenance, finding, and its full stored evidence. Changed output starts a separate
review history even if capture and finding IDs match. Notes persist across server restarts
and standard SQLite backups. Keep `ASP_DB_PATH` consistent when restarting to retain them.
Capture files are still a cached read-only snapshot; restart to open changed output.

`GET /v1/offline-review/captures/{capture_id}/findings/{finding_id}/reviews` returns
`review_key`, latest `revision`, and newest-first `entries`, with `limit` (1–100) and
`offset` pagination. `POST` to the same URL appends a review using `review_key`,
`expected_revision`, `disposition`, and `note`. Both require the platform key; named mode
also requires an analyst key with review permission for POST. The server supplies actor,
UTC timestamp, revision, and request ID. A stale revision or fingerprint returns HTTP 409;
the UI reloads history and retains your note for reconsideration. A failed save does not
modify history. Reviews stay separate from live incident lifecycle and evaluation scores.
