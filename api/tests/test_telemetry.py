"""Telemetry endpoint tests (ITEM 5).

The nft binary is NEVER the real one here: tests supply small fake
executable scripts via AEGIS_TELEMETRY_NFT_BIN that print canned
`nft -j list ruleset` JSON, plus failure cases (nonzero exit, garbage
output, missing binary, empty ruleset). On any failure the endpoint
must still return HTTP 200 with {"available": false, "reason": ...}.
"""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "telemetry.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"

db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-token-123"}

CANNED = {
    "nftables": [
        {"table": {"family": "inet", "name": "filter"}},
        {"chain": {"family": "inet", "table": "filter", "name": "input"}},
        {"rule": {"family": "inet", "table": "filter", "chain": "input",
                  "handle": 1,
                  "expr": [{"counter": {"packets": 1234, "bytes": 567890}},
                           {"accept": None}]}},
        {"rule": {"family": "inet", "table": "filter", "chain": "input",
                  "handle": 2,
                  "expr": [{"counter": {"packets": 10, "bytes": 1000}},
                           {"drop": None}]}},
        {"counter": {"name": "named1", "table": "filter",
                     "packets": 7, "bytes": 70}},
    ]
}


def _write_fake(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


@pytest.fixture()
def good_nft(tmp_path):
    body = ("#!/usr/bin/env python3\nimport json, sys\n"
            f"json.dump({CANNED!r}, sys.stdout)\n")
    return _write_fake(tmp_path, "fake-nft", body)


@pytest.fixture()
def failing_nft(tmp_path):
    return _write_fake(tmp_path, "fake-nft-fail",
                       "#!/bin/sh\necho 'perm denied' >&2\nexit 3\n")


@pytest.fixture()
def garbage_nft(tmp_path):
    return _write_fake(tmp_path, "fake-nft-garbage",
                       "#!/bin/sh\necho 'this is not json'\n")


@pytest.fixture()
def empty_nft(tmp_path):
    body = ("#!/usr/bin/env python3\nimport json, sys\n"
            "json.dump({'nftables': []}, sys.stdout)\n")
    return _write_fake(tmp_path, "fake-nft-empty", body)


def test_telemetry_parses_canned_counters(good_nft, monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", good_nft)
    r = client.get("/telemetry/counters", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    counters = body["counters"]
    assert len(counters) == 3
    first = counters[0]
    assert first["table"] == "filter" and first["chain"] == "input"
    assert first["handle"] == 1
    assert first["packets"] == 1234 and first["bytes"] == 567890
    assert counters[1]["packets"] == 10 and counters[1]["bytes"] == 1000
    named = counters[2]
    assert named["name"] == "named1" and named["packets"] == 7


def test_telemetry_failure_exit_code_is_unavailable(failing_nft, monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", failing_nft)
    r = client.get("/telemetry/counters", headers=AUTH)
    assert r.status_code == 200  # never an error status for nft failures
    body = r.json()
    assert body["available"] is False
    assert body["reason"]  # plain reason, no invented numbers


def test_telemetry_garbage_output_is_unavailable(garbage_nft, monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", garbage_nft)
    body = client.get("/telemetry/counters", headers=AUTH).json()
    assert body["available"] is False
    assert "unparsable" in body["reason"]


def test_telemetry_empty_ruleset_is_unavailable(empty_nft, monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", empty_nft)
    body = client.get("/telemetry/counters", headers=AUTH).json()
    assert body["available"] is False
    assert "empty ruleset" in body["reason"]


def test_telemetry_missing_binary_is_unavailable(monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", "/nonexistent/nft-xyz")
    body = client.get("/telemetry/counters", headers=AUTH).json()
    assert body["available"] is False
    assert "not found" in body["reason"]


def test_telemetry_requires_auth(good_nft, monkeypatch):
    monkeypatch.setenv("AEGIS_TELEMETRY_NFT_BIN", good_nft)
    assert client.get("/telemetry/counters").status_code == 401
