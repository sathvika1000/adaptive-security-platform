"""Self-contained readable rendering of a portable offline finding review."""

import json
from html import escape
from typing import Any

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
STYLE = """
:root {font-family:system-ui,sans-serif;color:#172a33;background:#f5f7f8}
body {margin:0;padding:24px} main {max-width:1050px;margin:auto}
section,header {background:white;border:1px solid #dbe5e6;border-radius:12px;padding:24px;
margin-bottom:20px} h1 {font-size:28px;margin:8px 0} h2 {font-size:21px}
.kicker {color:#116850;font-weight:700} .muted {color:#536b74}
p,li {line-height:1.5} .note,pre {white-space:pre-wrap;overflow-wrap:anywhere}
pre {font-size:12px;background:#f5f7f8;padding:14px;max-height:440px;overflow:auto}
table {border-collapse:collapse;width:100%;table-layout:fixed}
th,td {text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #dbe5e6;
overflow-wrap:anywhere;font-size:13px} .facts th {width:30%}
.assessment {border-top:1px solid #dbe5e6;padding:14px 0}
summary {cursor:pointer;font-weight:600} code {overflow-wrap:anywhere}
@media(max-width:540px) {body{padding:12px}section,header{padding:16px}h1{font-size:23px}}
@media print {body{background:white;color:black;padding:0} section,header{border:0;padding:0;
margin:0 0 20px} .digital-only{display:none} table{font-size:10px} th,td{padding:6px}
.assessment,tr{break-inside:avoid} h2{break-after:avoid} a{color:black}}
"""


def text(value: Any) -> str:
    return escape(str(value), quote=True)


def readable_report(artifact: dict[str, Any]) -> str:
    binding = artifact["binding"]
    capture = binding["capture"]
    finding = binding["finding"]
    history = artifact["assessment_history"]
    evidence = binding["evidence"]
    latest = history["entries"][0] if history["entries"] else None
    assessment = latest["disposition"].replace("_", " ") if latest else "Needs review (unsaved)"
    facts = {
        "Capture": capture["capture_id"],
        "Rule": binding["rule_id"],
        "Finding ID": finding["incident_id"],
        "Partition": capture["partition"],
        "Declared capture label": capture["label"],
        "Capture-level case verdict": capture["verdict"],
        "Selected evidence records": len(evidence),
        "Total capture records": capture["records"],
        "Current analyst assessment": assessment,
        "Latest assessment revision": history["latest_revision"],
        "Evidence window (UTC)": f"{finding['first_seen']} to {finding['last_seen']}",
        "Original EVTX SHA-256": capture["capture_sha256"],
        "Review fingerprint": artifact["review_key"],
        "Export payload SHA-256": artifact["payload_sha256"],
    }
    rows = "".join(
        f"<tr><th>{text(label)}</th><td>{text(value)}</td></tr>" for label, value in facts.items()
    )
    reviews = ""
    for entry in history["entries"]:
        reviews += (
            f'<article class="assessment"><h3>Revision {text(entry["revision"])}: '
            f"{text(entry['disposition'].replace('_', ' '))}</h3>"
            f'<p class="muted">{text(entry["occurred_at"])} · '
            f"{text(entry['actor'] or 'Shared key (unattributed)')}</p>"
            f'<p class="note">{text(entry["note"])}</p></article>'
        )
    if not reviews:
        reviews = "<p>No saved assessments. Unsaved UI drafts are not included.</p>"
    truncated = (
        "Older assessment revisions are omitted."
        if history["history_truncated"]
        else "No saved assessment revisions are omitted."
    )
    overview = ""
    for event in evidence[:100]:
        targets = ", ".join(
            entity["value"] for entity in event["entities"] if entity["type"] == "user"
        )
        overview += (
            f"<tr><td>{text(event['event_time'])}</td><td>{text(targets or 'Unrecorded')}</td>"
            f"<td>{text(event['action'] or event['category'])}</td>"
            f"<td>{text(event['source_ip'] or 'Unrecorded')}</td></tr>"
        )
    limits = "".join(f"<li>{text(limit)}</li>" for limit in artifact["scope"]["limitations"])
    complete = text(json.dumps(artifact, indent=2))
    provenance = text(
        json.dumps({"capture": binding["metadata"], "run": binding["provenance"]}, indent=2)
    )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{text(REPORT_CSP)}">
<title>Offline review: {text(capture["capture_id"])}</title><style>{STYLE}</style></head>
<body><main><header><p class="kicker">Adaptive Security Platform · Offline investigation</p>
<h1>{text(finding["title"])}</h1><p class="muted">Exported {text(artifact["exported_at"])} (UTC)</p>
<p>Analyst judgments are separate from declared capture labels and detector verdicts.
Credential attempts do not establish a successful compromise.</p></header>
<section><h2>Finding summary</h2><table class="facts">{rows}</table></section>
<section><h2>Saved assessments</h2><p>{text(history["included_revisions"])} of
{text(history["latest_revision"])} revisions included, newest first.
{text(truncated)}</p>{reviews}</section>
<section><h2>Evidence overview</h2><p>First {min(100, len(evidence))} of {len(evidence)} selected
records shown here. The complete JSON below contains all selected records and preserved raw XML.</p>
<table><thead><tr><th>Event time (UTC)</th><th>Target account</th>
<th>Activity</th><th>Client IP</th></tr></thead>
<tbody>{overview}</tbody></table></section>
<section><h2>Scope and limitations</h2><ul>{limits}</ul>
<p>Printing includes this summary, saved assessments, and evidence overview. Complete JSON
and detailed provenance remain in the digital file and are excluded from the printout.</p>
<p>Content hashes detect changes; this report is not a signed attestation.</p></section>
<section class="digital-only"><h2>Provenance</h2><details>
<summary>Capture and run declarations</summary>
<pre>{provenance}</pre></details></section>
<section class="digital-only"><h2>Complete export</h2><details>
<summary>All selected evidence and saved revisions (JSON)</summary>
<pre id="complete-export">{complete}</pre></details></section></main></body></html>'''
