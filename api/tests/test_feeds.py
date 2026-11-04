"""Threat-feed auto-refresh tests (ITEM 2).

A local HTTP server on 127.0.0.1 (python http.server in a thread) stands
in for the feed origin. NO real external feed is ever fetched. Modes:
valid feed, invalid JSON, invalid shape, HTTP 500. Fail-safe assertions:
a failed refresh must leave previously ingested indicators intact and
must append a failure row to the audit log.
"""

import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "feeds.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"
os.environ.pop("AEGIS_FEED_URL", None)
# The test feed server is local (127.0.0.1); the default SSRF guard
# refuses non-public feed hosts, so tests opt into private feeds.
os.environ["AEGIS_FEED_ALLOW_PRIVATE"] = "1"

db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

from app import app, get_conn  # noqa: E402

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-token-123"}

VALID_FEED = {
    "indicators": [
        {"type": "ip", "value": "203.0.113.7", "expires_at": 4102444800},
        {"type": "domain", "value": "bad.example.test", "expires_at": None},
    ]
}
INVALID_SHAPE_FEED = {
    "indicators": [
        {"type": "ip", "value": "not-an-ip", "expires_at": None},
    ]
}


class FeedHandler(BaseHTTPRequestHandler):
    mode = "valid"

    def log_message(self, *args):  # keep test output quiet
        pass

    def do_GET(self):
        mode = self.server.mode  # type: ignore[attr-defined]
        if mode == "valid":
            body = json.dumps(VALID_FEED).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif mode == "invalid_json":
            body = b"{this is not json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif mode == "invalid_shape":
            body = json.dumps(INVALID_SHAPE_FEED).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif mode == "http500":
            body = b"boom"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
        else:  # pragma: no cover - test bug
            body = b"unknown mode"
            self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def feed_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FeedHandler)
    server.mode = "valid"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def clear_feed():
    conn = get_conn()
    conn.execute("DELETE FROM feed_indicators")
    conn.execute("DELETE FROM feed_meta")
    conn.commit()
    conn.close()
    yield


def _ingest_valid(feed_server, monkeypatch):
    feed_server.mode = "valid"
    monkeypatch.setenv("AEGIS_FEED_URL",
                       f"http://127.0.0.1:{feed_server.server_port}/feed.json")
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "success"
    assert r.json()["count"] == 2


def test_feeds_status_never_before_refresh():
    r = client.get("/feeds/status", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["last_outcome"] == "never"
    assert body["last_refresh_at"] is None
    assert body["indicator_count"] == 0


def test_feeds_require_auth():
    assert client.get("/feeds/status").status_code == 401
    assert client.post("/feeds/refresh").status_code == 401


def test_valid_feed_ingests_and_status(feed_server, monkeypatch):
    _ingest_valid(feed_server, monkeypatch)
    r = client.get("/feeds/status", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["last_outcome"] == "success"
    assert body["last_refresh_at"] is not None
    assert body["indicator_count"] == 2
    # Success is audited.
    audit = client.get("/audit", headers=AUTH).json()
    assert any(row["action"] == "feed_refresh" and "success" in row["detail"]
               for row in audit)


def test_invalid_json_and_500_preserve_indicators(feed_server, monkeypatch):
    _ingest_valid(feed_server, monkeypatch)

    feed_server.mode = "invalid_json"
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "invalid_feed"
    assert client.get("/feeds/status", headers=AUTH).json()["indicator_count"] == 2

    feed_server.mode = "http500"
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "fetch_failed"
    status = client.get("/feeds/status", headers=AUTH).json()
    assert status["indicator_count"] == 2
    assert status["last_outcome"] == "fetch_failed"
    # Both failures are audited.
    audit = client.get("/audit", headers=AUTH).json()
    details = [row["detail"] for row in audit if row["action"] == "feed_refresh"]
    assert any("invalid_feed" in d for d in details)
    assert any("fetch_failed" in d for d in details)


def test_invalid_shape_preserves_indicators(feed_server, monkeypatch):
    _ingest_valid(feed_server, monkeypatch)
    feed_server.mode = "invalid_shape"
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "invalid_feed"
    assert client.get("/feeds/status", headers=AUTH).json()["indicator_count"] == 2


def test_refresh_without_url_configured(monkeypatch):
    monkeypatch.delenv("AEGIS_FEED_URL", raising=False)
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "not_configured"


def test_background_refresh_runs_when_url_set(feed_server, monkeypatch):
    """Lifespan task: with AEGIS_FEED_URL set, entering the TestClient
    context starts the background loop, which refreshes immediately."""
    feed_server.mode = "valid"
    monkeypatch.setenv("AEGIS_FEED_URL",
                       f"http://127.0.0.1:{feed_server.server_port}/feed.json")
    monkeypatch.setenv("AEGIS_FEED_INTERVAL_SECS", "3600")
    with TestClient(app) as ctx_client:
        deadline = time.time() + 10
        status = {}
        while time.time() < deadline:
            status = ctx_client.get("/feeds/status", headers=AUTH).json()
            if status["last_outcome"] == "success":
                break
            time.sleep(0.2)
        assert status["last_outcome"] == "success", status
        assert status["indicator_count"] == 2
    # Exiting the context cancels the loop; a plain request still works.
    assert client.get("/feeds/status", headers=AUTH).status_code == 200


def test_background_task_absent_without_url():
    """Entering the lifespan with no AEGIS_FEED_URL must not hang: the
    context opens and closes promptly with no task started."""
    start = time.time()
    with TestClient(app):
        pass
    assert time.time() - start < 5
    # sqlite3 import is used by nothing else here; keep the import honest.
    assert sqlite3.sqlite_version
