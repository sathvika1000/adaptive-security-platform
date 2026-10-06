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

## Export a finding review

Select a finding and click **Export finding review** to download a JSON file containing
its full stored evidence (including XML), capture metadata, declared labels/partitions,
rule/run provenance, and the latest 100 **saved** assessment revisions. Unsaved drafts
are omitted. Exports are available before an assessment is saved too, with empty history.
The original EVTX binary and other capture records are omitted; its checksum is retained.
If more than 100 revisions exist, `history_truncated` is true and both the file and UI
identify the omission. Full older history remains available through review pagination.

The file may contain private details from source records. Nothing is uploaded or sent
automatically; the button downloads through an authenticated same-origin request. The
export does not modify captured files, assessments, live incidents, or metrics. Named
review permission is required to save assessments, but exporting uses the platform read
key, like viewing evidence/history. No platform or analyst credentials are added to exports.

`GET /v1/offline-review/captures/{capture_id}/findings/{finding_id}/export` requires the
platform key plus query parameters `review_key` and `expected_revision`. A changed finding
or review returns HTTP 409. The UI refreshes history and asks you to export again, preserving
your draft. The optional `format` query accepts `json` (default) or `html`. Successful
responses are attachments with no-store caching. Filenames
use the validated capture ID and a fingerprint prefix rather than untrusted finding titles.

The format is `asp.offline-finding-review`, version 1. `binding` contains the exact context
used to calculate `review_key`; `assessment_history` contains newest-first revisions and
explicit inclusion counts; `scope` describes omissions and interpretation limits.
`payload_sha256` hashes every other top-level field using Python-compatible JSON
serialization (`sort_keys=True`, `separators=(",", ":")`, default ASCII escaping, UTF-8).
The same serialization of `binding` must match `review_key`. These checks detect content
changes; they are not signatures or independent proof of author identity or labels.

To check both hashes, replace the path below with the downloaded JSON filename:

```bash
python - /path/to/downloaded-review.json <<'PY'
import hashlib
import json
import sys
from pathlib import Path

artifact = json.loads(Path(sys.argv[1]).read_text())
expected = artifact.pop("payload_sha256")
def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
if digest(artifact) != expected or digest(artifact["binding"]) != artifact["review_key"]:
    raise SystemExit("Content check failed")
print("Content hashes match (author identity and labels are not verified)")
PY
```

## Readable investigation report

Click **Download readable report** beside the JSON export button. Open the downloaded
HTML file in your browser. On a Mac, press **Command-P** and choose **Save as PDF** to
keep a printable copy. No Windows system or additional software is needed.

The self-contained report shows the finding, capture labels and partition, current saved
assessment, latest 100 saved revisions, hashes, and the first 100 selected evidence records
in an overview table. Expand **Complete export** to read the complete JSON with all selected
evidence and preserved raw XML. The printable copy contains the summary, saved assessments,
overview, and scope limits; complete JSON and detailed provenance stay in the digital HTML
file. Keep the HTML or JSON export when you need complete evidence. History truncation and
excluded capture records remain explicit.

The HTML download uses the same authentication, fingerprint, and revision checks as JSON.
It contains no scripts or remote assets. Notes and raw evidence are escaped literal text.
The UI downloads the report without inserting its contents into the platform page.

## Browser regression checks

CI now includes a `browser-review` job using real Chromium and disposable synthetic
review bundles. It checks the UI against the real API: incorrect keys, evidence pagination
and XML expansion, saved assessments, literal note rendering, conflicting saves/exports,
JSON downloads and both hashes, readable HTML downloads and print rendering, reload
persistence, named analyst attribution, forgotten
key cleanup, and narrow-screen overflow. Desktop and narrow screenshots plus the HTML
report are retained in the `browser-review-report` Actions artifact for seven days. Failure
traces are retained too. These fixtures do not establish captured detection accuracy.

To run the same checks locally with an active development virtual environment and Node 22+:

```bash
python -m pip install -e '.[dev,evtx]'
npm ci
npx playwright install chromium
npm run test:browser
```

The runner creates two synthetic servers on loopback ports 8037 and 8038 and temporary
SQLite databases, then shuts them down. It never reuses an already running server; choose
free ports before running. It does not read your existing captures, review database, API
keys, or analyst configuration. Reports use fixture records and test-only keys. Node and
Playwright are developer tooling only; running the platform itself still requires no npm
installation. These Chromium checks cover the tested desktop/narrow layouts; they are
not an accessibility audit or a claim that every browser is tested.

## Assessment queue

The **Assessment queue** shows findings across the configured run. It defaults to
**Needs review**; use disposition and capture filters to narrow the list, or choose
**All dispositions**. Click a queue item to open that exact finding and its evidence.
Queue entries show the latest disposition/revision and named or shared-key attribution.
**Refresh queue** picks up assessments saved by another session. Saving a review in this
page refreshes queue counts automatically without changing the open finding or draft.

Progress always covers the entire configured run, even with filters selected. **Assessed**
means the latest saved disposition differs from `needs_review`. Unsaved findings and
findings whose latest disposition is `needs_review` are pending. **No saved assessment**
counts only findings with no journal revision for their current evidence/context fingerprint.
Changing a disposition back to Needs review restores pending status without deleting
history. Capture cards show their own progress; captures without findings show zero work,
which does not establish benign activity. These workload counts are not accuracy metrics.

`GET /v1/offline-review/queue` requires the platform API key. Optional `disposition` and
`capture_id` filter entries before `limit` (1–100) and `offset` pagination. Responses contain
global `counts`, per-capture `capture_counts`, filtered `matching` count, and brief `entries`
without notes/raw evidence. Pending findings sort first, then capture/finding ID. Counts and
latest revisions are read in one database transaction; changes between page requests can
move entries, so refresh to restart pagination. Old journals outside the current bundle's
fingerprints do not count. No run configuration returns an empty queue and zero counts.
