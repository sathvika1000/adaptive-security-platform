# Adaptive Security Platform

A local security operations prototype that normalizes Wazuh alerts, correlates
authentication activity into incidents, and lets analysts inspect the
supporting evidence in a browser or through an API.

## Run locally

Use Python 3.12. The API binds to loopback and requires a key.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
export ASP_API_KEY="$(openssl rand -hex 32)"
export ASP_DB_PATH="./security.db"
uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8000
```

Open the [incident workspace](http://127.0.0.1:8000/ui). For Wazuh integration
and Docker setup, follow the [Wazuh deployment guide](docs/WAZUH_DOCKER_DESKTOP.md).
Keep API keys and collected telemetry in local configuration and storage.

## Documentation

- [Platform reference](docs/PLATFORM_REFERENCE.md) for API usage, correlation, backup, and retention.
- [Investigation architecture](docs/INVESTIGATION_ARCHITECTURE.md) for evidence and investigation boundaries.
- [Offline investigation review](docs/OFFLINE_REVIEW.md) for a local evidence walkthrough.
- [Captured validation](docs/CAPTURED_VALIDATION.md) for evaluated scenarios and limitations.
