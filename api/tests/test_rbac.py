"""Small RBAC tests (ITEM 3).

Admin token (AEGIS_API_TOKEN): full access, as before.
Readonly token (AEGIS_API_READONLY_TOKEN, only when set): GET endpoints
work, any mutating endpoint returns 403. No token / wrong token: 401.
The readonly token is read from env per request, so monkeypatch works
even though the app module was already imported by another test file.
"""

import os
import sys
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "rbac.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"

db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402

client = TestClient(app)
ADMIN = {"Authorization": "Bearer test-token-123"}
READONLY = {"Authorization": "Bearer readonly-token-456"}

GOOD = {"version": 1, "name": "good", "default_action": "deny",
        "rules": [{"id": "w", "priority": 10, "action": "allow",
                   "protocol": "tcp", "dst_port": 443}]}


@pytest.fixture(autouse=True)
def readonly_env(monkeypatch):
    monkeypatch.setenv("AEGIS_API_READONLY_TOKEN", "readonly-token-456")
    yield


def test_admin_can_mutate():
    r = client.post("/policies", json={"name": "rbac-admin", "policy": GOOD},
                    headers=ADMIN)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    r = client.delete(f"/policies/{pid}", headers=ADMIN)
    assert r.status_code == 200


def test_readonly_can_get():
    assert client.get("/policies", headers=READONLY).status_code == 200
    assert client.get("/audit", headers=READONLY).status_code == 200
    assert client.get("/feeds/status", headers=READONLY).status_code == 200


def test_readonly_blocked_on_mutations():
    assert client.post("/policies", json={"name": "x", "policy": GOOD},
                       headers=READONLY).status_code == 403
    # PUT / DELETE / validate need an existing policy (created by admin).
    r = client.post("/policies", json={"name": "rbac-ro", "policy": GOOD},
                    headers=ADMIN)
    pid = r.json()["id"]
    try:
        assert client.put(f"/policies/{pid}",
                          json={"name": "rbac-ro", "policy": GOOD},
                          headers=READONLY).status_code == 403
        assert client.delete(f"/policies/{pid}",
                             headers=READONLY).status_code == 403
        assert client.post(f"/policies/{pid}/validate", json={},
                           headers=READONLY).status_code == 403
        assert client.post("/apply", json={"policy_id": pid},
                           headers=READONLY).status_code == 403
        assert client.post("/rollback", json={},
                           headers=READONLY).status_code == 403
        assert client.post("/feeds/refresh",
                           headers=READONLY).status_code == 403
    finally:
        client.delete(f"/policies/{pid}", headers=ADMIN)


def test_no_token_or_wrong_token_still_401():
    assert client.get("/policies").status_code == 401
    assert client.post("/policies", json={"name": "x", "policy": GOOD}).status_code == 401
    assert client.get("/policies",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/policies", json={"name": "x", "policy": GOOD},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_readonly_unset_means_admin_only(monkeypatch):
    monkeypatch.delenv("AEGIS_API_READONLY_TOKEN", raising=False)
    assert client.get("/policies", headers=READONLY).status_code == 401
    assert client.get("/policies", headers=ADMIN).status_code == 200
