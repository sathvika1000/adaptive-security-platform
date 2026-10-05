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
database or provides analyst closure actions. It displays declared labels and partitions,
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
