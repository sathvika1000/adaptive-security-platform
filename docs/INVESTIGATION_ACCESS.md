# Read-only investigation access

Use a dedicated key for an investigation client. Keep `ASP_API_KEY` with the operator;
it retains broad platform access. No model or MCP server is connected by these steps.
This guide uses the native Python offline review server on a Mac.

## 1. Start the updated offline server

After the access change is merged, pull/install and start a review server on an unused port.
The platform key can be restored from your existing platform container without printing it:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install -e '.[evtx]'
export ASP_API_KEY="$(docker exec adaptive-security-platform-platform-1 printenv ASP_API_KEY)"
ASP_DB_PATH=artifacts/investigation-access.db \
ASP_OFFLINE_REVIEW_PATH=artifacts/explicit-credentials-dev-v1 \
  python -m uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8011
```

Use a complete existing evaluation/validation output directory with findings. Keep this server
terminal open. If 8011 is occupied, choose another unused port and update the URL below.

## 2. Discover operator scopes and select a grant

In another terminal in the repository, restore the platform key there as well. Fetch the catalog:

```bash
export ASP_API_KEY="$(docker exec adaptive-security-platform-platform-1 printenv ASP_API_KEY)"
mkdir -p artifacts
curl --fail --silent --show-error \
  -H "X-API-Key: $ASP_API_KEY" \
  'http://127.0.0.1:8011/v1/investigation-tools/scopes?limit=100' \
  > artifacts/investigation-scopes.json
```

Inspect `entries` for the finding you want the client to investigate. Each entry has capture ID,
finding ID, fingerprint and tool names. If `next_offset` is not null, fetch subsequent pages
using that offset. The following script selects an entry by index from the downloaded page,
grants evidence and related-event reads, and generates a private key file without displaying
the key. Change `selected_index` to your chosen entry before running it:

```bash
python - <<'PY'
import json
import os
import secrets
from pathlib import Path

selected_index = 0
catalog = json.loads(Path("artifacts/investigation-scopes.json").read_text())
scope = catalog["entries"][selected_index]
if scope["stale"]:
    raise SystemExit("Select a current finding")
grant = {name: scope[name] for name in ("capture_id", "finding_id", "review_key")}
grant["tools"] = ["get_finding_evidence", "get_related_events"]
config = {"research-agent": {"key": secrets.token_hex(32), "grants": [grant]}}
path = "artifacts/investigation-access.json"
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as file:
    json.dump(config, file, indent=2)
print("Created private configuration for", scope["capture_id"], scope["finding_id"])
PY
```

An existing file causes the script to stop instead of overwriting a credential. Use a new
filename for deliberate rotation. `artifacts/` is excluded by the repository's gitignore;
keep this private configuration local. Add `get_telemetry_coverage` only if the client should
also see aggregate eligibility counts for the entire capture. Related events likewise extend
beyond the selected finding's original evidence under the documented entity/time filter.

## 3. Load the grants and restart the review server

Stop the review server with Control-C in its terminal, then run:

```bash
export ASP_INVESTIGATION_KEYS_JSON="$(cat artifacts/investigation-access.json)"
ASP_DB_PATH=artifacts/investigation-access.db \
ASP_OFFLINE_REVIEW_PATH=artifacts/explicit-credentials-dev-v1 \
  python -m uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8011
```

Platform/analyst keys and investigation keys must be different. Configuration is loaded only
at startup; all API worker processes must restart for revocation, rotation or changed grants.
An updated offline snapshot also requires operator review and explicitly reissued fingerprints;
old grants never automatically follow changed evidence.

## 4. Verify permitted and denied access

In the second terminal, activate the virtual environment. This smoke check uses only the
dedicated credential for requests and never prints it:

```bash
source .venv/bin/activate
python - <<'PY'
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

config = json.loads(Path("artifacts/investigation-access.json").read_text())["research-agent"]
base = "http://127.0.0.1:8011"
headers = {"X-Investigation-Key": config["key"], "Content-Type": "application/json"}
with urlopen(Request(base + "/v1/investigation-tools/scopes", headers=headers)) as response:
    catalog = json.load(response)
assert catalog["matching"] == len(config["grants"])
grant = config["grants"][0]
body = {name: grant[name] for name in ("capture_id", "finding_id", "review_key")}
request = Request(base + "/v1/investigation-tools/get_finding_evidence",
                  headers=headers, data=json.dumps(body).encode(), method="POST")
with urlopen(request) as response:
    result = json.load(response)
print("Permitted evidence records:", result["page"]["returned_records"])
try:
    urlopen(Request(base + "/v1/incidents", headers=headers))
except HTTPError as error:
    assert error.code == 401
    print("Protected platform access denied as expected")
else:
    raise SystemExit("Unexpected platform access")
PY
```

401 means an invalid/missing credential; 400 means both credential types were supplied;
403 means scope/tool is not granted; 409 means the granted finding has changed. Discovery marks
missing/changed grants `stale` and returns their old fingerprint only. It does not provide a
replacement fingerprint to the restricted caller. Invalid bundles produce generic 503 errors.
Request metadata logs include the authenticated caller name and request ID, including denied
scope/tool calls, while omitting keys, request bodies and evidence.

These checks establish local credential separation and offline scope enforcement. They do not
establish multi-tenant isolation, model prompt-injection resistance or production readiness.
See [the architecture](INVESTIGATION_ARCHITECTURE.md) for the remaining MCP and agent gates.
