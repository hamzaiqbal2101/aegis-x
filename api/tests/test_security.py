"""API security review regressions (Nov 3, 2026 pentest-lite).

Each test pins one fixed finding. Run from api/:
.venv/bin/python -m pytest -q
Env is set BEFORE importing app; this module uses its own throwaway DB.
"""

import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "security.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"
os.environ.pop("AEGIS_FEED_URL", None)
# NOTE: do NOT pop AEGIS_FEED_ALLOW_PRIVATE here. Pytest imports all
# test modules before running any test, and test_feeds.py sets that flag
# at import for its local feed server; popping it would break its tests.
# Tests below that need the flag unset use monkeypatch.delenv instead.

db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

from app import app, get_conn  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)
AUTH = {"Authorization": "Bearer test-token-123"}

GOOD = {"version": 1, "name": "good", "default_action": "deny",
        "rules": [{"id": "w", "priority": 10, "action": "allow",
                   "protocol": "tcp", "dst_port": 443}]}


def _mk_policy(name="sec"):
    r = client.post("/policies", json={"name": name, "policy": GOOD}, headers=AUTH)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _nested(depth):
    """A list nested `depth` levels deep around a scalar."""
    value: object = 1
    for _ in range(depth):
        value = [value]
    return value


# --- ids: out-of-range must 404, never 500 (SQLite OverflowError) ---

def test_huge_policy_id_is_404_not_500():
    assert client.get("/policies/99999999999999999999", headers=AUTH).status_code == 404
    assert client.delete("/policies/99999999999999999999", headers=AUTH).status_code == 404
    r = client.put("/policies/99999999999999999999",
                   json={"name": "x", "policy": GOOD}, headers=AUTH)
    assert r.status_code == 404
    r = client.post("/policies/99999999999999999999/validate", json={},
                    headers=AUTH)
    assert r.status_code == 404


def test_bool_policy_id_is_400_not_policy_1():
    pid = _mk_policy("bool-id")
    # True must not silently become id 1 (or any id): malformed -> 400.
    r = client.post("/apply", json={"policy_id": True, "netns": "n1"}, headers=AUTH)
    assert r.status_code == 400
    client.delete(f"/policies/{pid}", headers=AUTH)


# --- strict booleans on the host-apply gate ---

def test_confirm_host_apply_string_false_is_400():
    pid = _mk_policy("gate-str")
    try:
        r = client.post("/apply",
                        json={"policy_id": pid, "confirm_host_apply": "false"},
                        headers=AUTH)
        assert r.status_code == 400
        r = client.post("/rollback", json={"confirm_host_apply": "yes"},
                        headers=AUTH)
        assert r.status_code == 400
    finally:
        client.delete(f"/policies/{pid}", headers=AUTH)


def test_no_conntrack_string_is_400():
    pid = _mk_policy("nc-str")
    try:
        r = client.post(f"/policies/{pid}/validate",
                        json={"no_conntrack": "false"}, headers=AUTH)
        assert r.status_code == 400
    finally:
        client.delete(f"/policies/{pid}", headers=AUTH)


def test_netns_non_string_is_400():
    pid = _mk_policy("netns-type")
    try:
        r = client.post("/apply", json={"policy_id": pid, "netns": ["n1"]},
                        headers=AUTH)
        assert r.status_code == 400
    finally:
        client.delete(f"/policies/{pid}", headers=AUTH)


# --- policy depth / rule-count caps ---

def test_deeply_nested_policy_is_400_not_500():
    deep = {"version": 1, "name": "deep", "default_action": "deny",
            "rules": [{"id": "d", "priority": 1, "action": "allow",
                       "extra": _nested(150)}]}
    r = client.post("/policies", json={"name": "deep", "policy": deep}, headers=AUTH)
    assert r.status_code == 400
    assert "nesting" in r.json()["detail"]


def test_moderately_nested_policy_still_accepted():
    modest = {"version": 1, "name": "modest", "default_action": "deny",
              "rules": [{"id": "m", "priority": 1, "action": "allow",
                         "extra": _nested(50)}]}
    r = client.post("/policies", json={"name": "modest", "policy": modest},
                    headers=AUTH)
    assert r.status_code == 201, r.text
    client.delete(f"/policies/{r.json()['id']}", headers=AUTH)


def test_rule_count_cap():
    big = {"version": 1, "name": "many", "default_action": "deny",
           "rules": [{"id": f"r{i}", "priority": i, "action": "allow"}
                     for i in range(1001)]}
    r = client.post("/policies", json={"name": "many", "policy": big}, headers=AUTH)
    assert r.status_code == 400


# --- body-size cap ---

def test_oversized_body_is_413():
    body = b'{"name": "x", "policy": {"version": 1, "name": "y", "default_action": "deny", "rules": [], "pad": "' + b"x" * (2 * 1024 * 1024) + b'"}}'
    r = client.post("/policies", content=body,
                    headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 413


# --- pagination bounds ---

def test_pagination_bounds_and_behavior():
    ids = [_mk_policy(f"pg{i}") for i in range(3)]
    try:
        r = client.get("/policies?limit=2", headers=AUTH)
        assert r.status_code == 200 and len(r.json()) == 2
        r = client.get("/policies?limit=2&offset=2", headers=AUTH)
        assert r.status_code == 200 and len(r.json()) >= 1
        assert client.get("/policies?limit=0", headers=AUTH).status_code == 422
        assert client.get("/policies?limit=999999", headers=AUTH).status_code == 422
        assert client.get("/policies?offset=-1", headers=AUTH).status_code == 422
        assert client.get("/audit?limit=0", headers=AUTH).status_code == 422
        assert client.get("/audit?limit=5", headers=AUTH).status_code == 200
    finally:
        for pid in ids:
            client.delete(f"/policies/{pid}", headers=AUTH)


# --- docs / info disclosure ---

def test_auto_docs_disabled_without_auth():
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_status_hides_engine_path_and_sets_security_headers():
    r = client.get("/status")
    assert r.status_code == 200
    assert "engine_path" not in r.json()
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


# --- DB file permissions ---

def test_fresh_db_is_owner_only():
    conn = get_conn()
    conn.close()
    mode = stat.S_IMODE(Path(os.environ["AEGIS_API_DB"]).stat().st_mode)
    assert mode == 0o600


# --- CLI runner robustness ---

def test_cli_oserror_is_clean_failure_not_500(tmp_path, monkeypatch):
    bad = tmp_path / "not-executable"
    bad.write_text("#!/bin/sh\nexit 0\n")
    bad.chmod(0o644)  # exists but not executable -> OSError on exec
    monkeypatch.setenv("AEGIS_API_CLI", str(bad))
    pid = _mk_policy("cli-err")
    try:
        r = client.post(f"/policies/{pid}/validate", json={}, headers=AUTH)
        assert r.status_code == 200
        assert r.json()["pass"] is False
    finally:
        client.delete(f"/policies/{pid}", headers=AUTH)


# --- feed SSRF / robustness ---

class FeedHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        mode = self.server.mode  # type: ignore[attr-defined]
        if mode == "valid":
            body = json.dumps({"indicators": [
                {"type": "ip", "value": "203.0.113.7", "expires_at": None},
            ]}).encode()
            self.send_response(200)
        elif mode == "redir":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/evil")
            body = b""
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif mode == "dup":
            body = json.dumps({"indicators": [
                {"type": "ip", "value": "203.0.113.7", "expires_at": None},
                {"type": "ip", "value": "203.0.113.7", "expires_at": None},
            ]}).encode()
            self.send_response(200)
        elif mode == "toomany":
            body = json.dumps({"indicators": [
                {"type": "ip", "value": f"203.0.113.{i % 250 + 1}",
                 "expires_at": None} for i in range(10001)]}).encode()
            self.send_response(200)
        else:  # pragma: no cover
            body = b"?"
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


def _feed_url(server):
    return f"http://127.0.0.1:{server.server_port}/feed"


def _ingest(server, monkeypatch):
    server.mode = "valid"
    monkeypatch.setenv("AEGIS_FEED_URL", _feed_url(server))
    monkeypatch.setenv("AEGIS_FEED_ALLOW_PRIVATE", "1")
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200 and r.json()["outcome"] == "success", r.text


def test_feed_private_host_refused_by_default(feed_server, monkeypatch):
    monkeypatch.setenv("AEGIS_FEED_URL", _feed_url(feed_server))
    monkeypatch.delenv("AEGIS_FEED_ALLOW_PRIVATE", raising=False)
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "fetch_failed"
    assert "non-public" in r.json()["detail"]


def test_feed_redirect_refused_and_preserves(feed_server, monkeypatch):
    _ingest(feed_server, monkeypatch)
    feed_server.mode = "redir"
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "fetch_failed"
    assert client.get("/feeds/status", headers=AUTH).json()["indicator_count"] == 1


def test_feed_url_with_credentials_refused(feed_server, monkeypatch):
    monkeypatch.setenv(
        "AEGIS_FEED_URL",
        f"http://user:secret@127.0.0.1:{feed_server.server_port}/feed")
    monkeypatch.delenv("AEGIS_FEED_ALLOW_PRIVATE", raising=False)
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.json()["outcome"] == "fetch_failed"
    assert "credentials" in r.json()["detail"]


def test_feed_duplicate_indicators_deduped_not_500(feed_server, monkeypatch):
    feed_server.mode = "dup"
    monkeypatch.setenv("AEGIS_FEED_URL", _feed_url(feed_server))
    monkeypatch.setenv("AEGIS_FEED_ALLOW_PRIVATE", "1")
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "success"
    assert r.json()["count"] == 1


def test_feed_indicator_cap_is_invalid_feed(feed_server, monkeypatch):
    _ingest(feed_server, monkeypatch)
    feed_server.mode = "toomany"
    r = client.post("/feeds/refresh", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["outcome"] == "invalid_feed"
    assert client.get("/feeds/status", headers=AUTH).json()["indicator_count"] == 1
