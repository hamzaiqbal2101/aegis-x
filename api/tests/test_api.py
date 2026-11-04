"""M2 Management API tests. Run from api/:  .venv/bin/python -m pytest -q

Env is set BEFORE importing app so each pytest run uses a throwaway DB
and state dir. No test ever performs a real host apply: the apply tests
only exercise the 400 refusal path (no netns / no confirm flag).
Successful apply inside a netns is NOT tested here -- the sandbox cannot
create netns (ip netns add fails: CAP_NET_ADMIN dropped) and nft --check
fails with 'Operation not permitted', so a CLI pass is unattainable here.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = API_DIR.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "test.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"
os.environ["AEGIS_API_STATE_DIR"] = str(TMP / "state")
os.environ["AEGIS_API_CLI"] = str(REPO_DIR / "target" / "debug" / "aegis-linux")

# Fresh DB per test module run.
db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-token-123"}

GOOD = {"version": 1, "name": "good", "default_action": "deny",
        "rules": [{"id": "w", "priority": 10, "action": "allow",
                   "protocol": "tcp", "dst_port": 443}]}
BAD = {"version": 1, "name": "bad", "default_action": "deny",
       "rules": [{"id": "x", "priority": 10, "action": "allow",
                  "src_zone": "no-such-zone"}]}


def test_status_no_auth():
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["api_version"]
    assert body["db_ok"] is True
    assert body["engine_available"] is True


def test_auth_rejection():
    assert client.get("/policies").status_code == 401
    assert client.get("/policies",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/audit").status_code == 401


def test_crud_round_trip_and_hash():
    r = client.post("/policies", json={"name": "good", "policy": GOOD}, headers=AUTH)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    h1 = r.json()["hash"]
    assert len(h1) == 64  # sha256 hex

    r = client.get(f"/policies/{pid}", headers=AUTH)
    assert r.status_code == 200 and r.json()["policy"] == GOOD
    assert r.json()["hash"] == h1  # determinism: same policy -> same hash

    changed = dict(GOOD, default_action="allow")
    r = client.put(f"/policies/{pid}", json={"name": "good", "policy": changed},
                   headers=AUTH)
    assert r.status_code == 200
    assert r.json()["hash"] != h1  # change-sensitivity

    r = client.get("/policies", headers=AUTH)
    assert any(p["id"] == pid for p in r.json())

    r = client.delete(f"/policies/{pid}", headers=AUTH)
    assert r.status_code == 200
    assert client.get(f"/policies/{pid}", headers=AUTH).status_code == 404


def test_write_validation():
    # Not an object.
    r = client.post("/policies", json={"name": "x", "policy": [1, 2]}, headers=AUTH)
    assert r.status_code == 400
    # Missing required fields.
    r = client.post("/policies", json={"name": "x", "policy": {"name": "x"}},
                    headers=AUTH)
    assert r.status_code == 400
    assert "version" in r.json()["detail"] or "required" in r.json()["detail"]


def test_validate_standard_policy_relay():
    """Standard example: API must relay the CLI verdict verbatim.

    In THIS sandbox the CLI cannot pass any policy (kernel lacks
    nf_conntrack, and nft --check fails 'Operation not permitted'), so
    pass is expected to be False here for kernel reasons, not policy
    reasons. The test therefore compares the API verdict against a
    direct CLI run instead of asserting a pass -- fabricating a pass
    would be dishonest. On a capable host this same test would see
    pass=True from both sides.
    """
    standard = json.loads((REPO_DIR / "examples" / "standard.json").read_text())
    r = client.post("/policies", json={"name": "standard", "policy": standard},
                    headers=AUTH)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    r = client.post(f"/policies/{pid}/validate", json={}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["pass"], bool)
    assert "stdout" in body and "stderr" in body
    direct = subprocess.run(
        [os.environ["AEGIS_API_CLI"], "check", "--policy",
         str(REPO_DIR / "examples" / "standard.json")],
        capture_output=True, text=True)
    assert body["pass"] == (direct.returncode == 0)
    # Verbatim relay: CLI stderr text appears in the API response.
    assert direct.stderr.strip().splitlines()[0] in body["stderr"] \
        if direct.stderr.strip() else True


def test_validate_bad_policy_fails_with_cli_output():
    r = client.post("/policies", json={"name": "bad", "policy": BAD}, headers=AUTH)
    assert r.status_code == 201
    pid = r.json()["id"]
    r = client.post(f"/policies/{pid}/validate", json={}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["pass"] is False
    combined = body["stdout"] + body["stderr"]
    assert combined.strip() != ""  # CLI output included, not swallowed


def test_apply_refusal_without_scope():
    r = client.post("/policies", json={"name": "good2", "policy": GOOD}, headers=AUTH)
    pid = r.json()["id"]
    # Neither netns nor confirm_host_apply: 400, host untouched, CLI uncalled.
    r = client.post("/apply", json={"policy_id": pid}, headers=AUTH)
    assert r.status_code == 400
    assert "confirm_host_apply" in r.json()["detail"]
    # Rollback gating is identical.
    r = client.post("/rollback", json={}, headers=AUTH)
    assert r.status_code == 400


def test_audit_accumulation_and_no_delete():
    before = client.get("/audit", headers=AUTH).json()
    n0 = len(before)
    assert n0 > 0  # earlier tests already wrote rows
    r = client.post("/policies", json={"name": "aud", "policy": GOOD}, headers=AUTH)
    pid = r.json()["id"]
    client.post(f"/policies/{pid}/validate", json={}, headers=AUTH)
    client.delete(f"/policies/{pid}", headers=AUTH)
    after = client.get("/audit", headers=AUTH).json()
    assert len(after) >= n0 + 3  # create + validate + delete
    actions = [row["action"] for row in after]
    assert "create" in actions and "validate" in actions and "delete" in actions
    # No endpoint may update or delete audit rows: DELETE /audit is a
    # method-not-allowed on the existing GET route, and /audit/{id} has no
    # route at all (404) -- either way no audit row can be removed.
    assert client.delete("/audit", headers=AUTH).status_code == 405
    assert client.delete("/audit/1", headers=AUTH).status_code in (404, 405)
    assert client.put("/audit/1", json={}, headers=AUTH).status_code in (404, 405)
    # Rows are still all present after those attempts.
    assert len(client.get("/audit", headers=AUTH).json()) == len(after)
