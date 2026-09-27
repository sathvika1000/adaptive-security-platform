from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app


def test_incident_view_assets_are_local_and_data_remains_authenticated(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "private-test-key"))
    page = client.get("/ui")
    assert page.status_code == 200
    assert 'src="/ui/app.js"' in page.text
    assert 'href="/ui/style.css"' in page.text
    assert "private-test-key" not in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert "connect-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"

    script = client.get("/ui/app.js")
    stylesheet = client.get("/ui/style.css")
    assert script.status_code == 200 and script.headers["cache-control"] == "no-store"
    assert script.headers["content-type"].startswith("text/javascript")
    assert '"X-API-Key": apiKey' in script.text
    assert "localStorage" not in script.text
    assert stylesheet.status_code == 200
    assert client.get("/ui/anything-else").status_code == 404
    assert client.get("/v1/incidents").status_code == 401
    assert client.get("/v1/incidents", headers={"X-API-Key": "private-test-key"}).json() == []
