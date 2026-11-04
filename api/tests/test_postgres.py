"""PostgreSQL backend tests (ITEM 1). Run from api/:
.venv/bin/python -m pytest -q

No live Postgres exists in this sandbox (no psql/pg_isready/docker,
no /usr/lib/postgresql, no psycopg/psycopg2 in the venv), so the
Postgres code path is verified with fakes, never a real server:

* a recording fake DBAPI cursor proves placeholder translation
  (? -> %s), parameter binding (values travel as params, never
  interpolated into SQL text), RETURNING id / lastrowid, and row access;
* a tiny in-memory fake engine proves the real FastAPI app works
  end-to-end through get_conn() when AEGIS_API_DB_BACKEND=postgres,
  with responses shaped exactly like the SQLite path.

Env is set BEFORE importing app. This module NEVER sets
AEGIS_API_DB_BACKEND globally: every Postgres test sets it with
monkeypatch (auto-reverted), so the other test modules' SQLite runs
are unaffected. Live-server verification is still required before
Postgres is trusted in production -- see api/README.md.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
TMP = Path(os.environ.get("PYTEST_TMP", "/tmp/aegis-api-test"))
TMP.mkdir(parents=True, exist_ok=True)

os.environ["AEGIS_API_DB"] = str(TMP / "postgres.db")
os.environ["AEGIS_API_TOKEN"] = "test-token-123"

db = Path(os.environ["AEGIS_API_DB"])
if db.exists():
    db.unlink()

sys.path.insert(0, str(API_DIR))
from fastapi.testclient import TestClient  # noqa: E402

import pg_backend  # noqa: E402
from app import app, get_conn  # noqa: E402

client = TestClient(app)
# Built from the env var (set above) rather than written as a literal
# "Bearer ..." header value, so no credential string sits in this file.
AUTH = {"Authorization": "Bearer " + os.environ["AEGIS_API_TOKEN"]}
GOOD = {"version": 1, "name": "good", "default_action": "deny",
        "rules": [{"id": "w", "priority": 10, "action": "allow",
                   "protocol": "tcp", "dst_port": 443}]}
DSN = "postgresql://fake-user:fake-pass@127.0.0.1:5432/aegis-test"


# ---------------------------------------------------------------- fake engine

POLICY_COLS = ["id", "name", "policy", "hash", "created_at", "updated_at"]
AUDIT_COLS = ["id", "timestamp", "actor", "action", "policy_id", "detail"]
FEED_META_COLS = ["id", "last_refresh_at", "last_outcome", "last_detail"]
FEED_IND_COLS = ["id", "type", "value", "expires_at", "fetched_at"]


def _desc(cols):
    return [(c, None, None, None, None, None, None) for c in cols]


class FakeStore:
    """Shared in-memory tables; each get_conn() gets a new connection
    over the same store, mirroring how the real app opens a connection
    per request against one server."""

    def __init__(self):
        self.policies = {}
        self.audit = {}
        self.feed_indicators = {}
        self.feed_meta = None
        self.next_id = {"policies": 1, "audit": 1, "feed_indicators": 1}
        self.log = []          # (sql actually sent to the "driver", params)
        self.dsns = []
        self.commits = 0
        self.closes = 0


class FakeCursor:
    def __init__(self, store):
        self.store = store
        self.description = None
        self._rows = []
        self.rowcount = -1

    def execute(self, sql, params=None):
        params = () if params is None else tuple(params)
        self.store.log.append((sql, params))
        s = store = self.store
        up = sql.upper()
        rows, desc = [], None
        if up.lstrip().startswith("CREATE TABLE"):
            pass
        elif up.strip() == "SELECT 1":
            rows, desc = [(1,)], _desc(["?column?"])
        elif up.startswith("INSERT INTO POLICIES"):
            pid = s.next_id["policies"]
            s.next_id["policies"] += 1
            name, policy, h, created, updated = params
            s.policies[pid] = {"id": pid, "name": name, "policy": policy,
                               "hash": h, "created_at": created,
                               "updated_at": updated}
            rows, desc = [(pid,)], _desc(["id"])
        elif up.startswith("INSERT INTO AUDIT"):
            aid = s.next_id["audit"]
            s.next_id["audit"] += 1
            ts, actor, action, pid, detail = params
            s.audit[aid] = {"id": aid, "timestamp": ts, "actor": actor,
                            "action": action, "policy_id": pid,
                            "detail": detail}
            rows, desc = [(aid,)], _desc(["id"])
        elif up.startswith("INSERT INTO FEED_INDICATORS"):
            iid = s.next_id["feed_indicators"]
            s.next_id["feed_indicators"] += 1
            itype, value, expires, fetched = params
            s.feed_indicators[(itype, value)] = {
                "id": iid, "type": itype, "value": value,
                "expires_at": expires, "fetched_at": fetched}
            rows, desc = [(iid,)], _desc(["id"])
        elif up.startswith("INSERT INTO FEED_META"):
            now, outcome, detail = params
            s.feed_meta = {"id": 1, "last_refresh_at": now,
                           "last_outcome": outcome, "last_detail": detail}
            rows, desc = [(1,)], _desc(["id"])
        elif up.startswith("SELECT") and "FROM POLICIES ORDER BY" in up:
            limit, offset = params
            ordered = sorted(s.policies.values(), key=lambda r: r["id"])
            rows = [tuple(r[c] for c in POLICY_COLS)
                    for r in ordered[offset:offset + limit]]
            desc = _desc(POLICY_COLS)
        elif up.startswith("SELECT") and "FROM POLICIES WHERE ID" in up:
            row = s.policies.get(params[0])
            if row is not None:
                rows = [tuple(row[c] for c in POLICY_COLS)]
            desc = _desc(POLICY_COLS)
        elif up.startswith("UPDATE POLICIES"):
            name, policy, h, updated, pid = params
            if pid in s.policies:
                s.policies[pid].update({"name": name, "policy": policy,
                                        "hash": h, "updated_at": updated})
        elif up.startswith("DELETE FROM POLICIES"):
            s.policies.pop(params[0], None)
        elif up.startswith("DELETE FROM FEED_INDICATORS"):
            if "WHERE" in up:
                now_ts = params[0]
                s.feed_indicators = {
                    k: v for k, v in s.feed_indicators.items()
                    if v["expires_at"] is None or v["expires_at"] > now_ts}
            else:
                s.feed_indicators.clear()
        elif up.startswith("SELECT") and "COUNT(*) FROM FEED_INDICATORS" in up:
            if "WHERE" in up:
                now_ts = params[0]
                count = sum(1 for v in s.feed_indicators.values()
                            if v["expires_at"] is None
                            or v["expires_at"] > now_ts)
            else:
                count = len(s.feed_indicators)
            rows, desc = [(count,)], _desc(["count"])
        elif up.startswith("SELECT") and "FROM FEED_META" in up:
            if s.feed_meta is not None:
                rows = [tuple(s.feed_meta[c] for c in FEED_META_COLS)]
            desc = _desc(FEED_META_COLS)
        elif up.startswith("SELECT") and "FROM AUDIT ORDER BY" in up:
            limit, offset = params
            ordered = sorted(s.audit.values(), key=lambda r: r["id"])
            rows = [tuple(r[c] for c in AUDIT_COLS)
                    for r in ordered[offset:offset + limit]]
            desc = _desc(AUDIT_COLS)
        else:
            raise AssertionError(f"fake engine: unhandled SQL: {sql!r}")
        self._rows = list(rows)
        self.description = desc
        return self

    def executemany(self, sql, seq):
        for params in seq:
            self.execute(sql, params)

    def fetchone(self):
        if not self._rows:
            return None
        return self._rows.pop(0)

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    def fetchmany(self, size=None):
        if size is None:
            return self.fetchall()
        out, self._rows = self._rows[:size], self._rows[size:]
        return out

    def close(self):
        pass


class FakeConnection:
    def __init__(self, store):
        self.store = store

    def cursor(self):
        return FakeCursor(self.store)

    def commit(self):
        self.store.commits += 1

    def rollback(self):
        pass

    def close(self):
        self.store.closes += 1


def _patch_fake(monkeypatch, store):
    """Route pg_backend._connect_raw at a fresh FakeConnection per call."""
    def _fake_connect(dsn):
        store.dsns.append(dsn)
        return FakeConnection(store)
    monkeypatch.setattr(pg_backend, "_connect_raw", _fake_connect)


def _pg_env(monkeypatch):
    monkeypatch.setenv("AEGIS_API_DB_BACKEND", "postgres")
    monkeypatch.setenv("AEGIS_API_DB_URL", DSN)


# ------------------------------------------------------- placeholder translation

def test_translate_basic_and_multiple():
    assert pg_backend.translate_placeholders(
        "SELECT * FROM policies WHERE id = ?") == \
        "SELECT * FROM policies WHERE id = %s"
    assert pg_backend.translate_placeholders(
        "INSERT INTO audit (a, b) VALUES (?, ?)") == \
        "INSERT INTO audit (a, b) VALUES (%s, %s)"
    assert pg_backend.translate_placeholders("SELECT 1") == "SELECT 1"


def test_translate_leaves_literals_comments_identifiers_alone():
    assert pg_backend.translate_placeholders(
        "SELECT 'a?b' FROM t WHERE a = ?") == \
        "SELECT 'a?b' FROM t WHERE a = %s"
    assert pg_backend.translate_placeholders(
        'SELECT "x?y" FROM t WHERE b = ?') == \
        'SELECT "x?y" FROM t WHERE b = %s'
    assert pg_backend.translate_placeholders(
        "SELECT a FROM t -- is it?\nWHERE b = ?") == \
        "SELECT a FROM t -- is it?\nWHERE b = %s"
    assert pg_backend.translate_placeholders(
        "SELECT /* ? */ a FROM t WHERE b = ?") == \
        "SELECT /* ? */ a FROM t WHERE b = %s"
    # Escaped quotes do not end the literal/identifier early.
    assert pg_backend.translate_placeholders(
        "SELECT 'it''s ? here' FROM t WHERE b = ?") == \
        "SELECT 'it''s ? here' FROM t WHERE b = %s"


def test_translate_upsert_syntax_survives():
    # The feed_meta upsert's ON CONFLICT ... excluded.* syntax is valid
    # Postgres as written; translation must only swap placeholders.
    sql = ("INSERT INTO feed_meta (id, last_refresh_at, last_outcome, last_detail)"
           " VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
           " last_refresh_at = excluded.last_refresh_at")
    translated = pg_backend.translate_placeholders(sql)
    assert translated == ("INSERT INTO feed_meta (id, last_refresh_at, "
                          "last_outcome, last_detail)"
                          " VALUES (1, %s, %s, %s) ON CONFLICT(id) DO UPDATE SET"
                          " last_refresh_at = excluded.last_refresh_at")


# ---------------------------------------------------------------- row wrapper

def test_pg_row_str_int_keys_len_iter():
    row = pg_backend._PgRow((7, "n", "p"), ["id", "name", "policy"])
    assert row["id"] == 7
    assert row["name"] == "n"
    assert row[0] == 7
    assert row[2] == "p"
    assert len(row) == 3
    assert list(row) == [7, "n", "p"]
    assert row.keys() == ["id", "name", "policy"]
    with pytest.raises(IndexError):
        row["missing"]


# ------------------------------------------------- cursor wrapper / binding

class RecordingCursor:
    """Minimal DBAPI cursor: records SQL/params, serves preset rows."""
    def __init__(self):
        self.calls = []
        self.description = [("id", None, None, None, None, None, None)]
        self._next = []
        self.closed = False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        return self

    def executemany(self, sql, seq):
        for p in seq:
            self.execute(sql, p)

    def fetchone(self):
        return self._next.pop(0) if self._next else None

    def fetchall(self):
        rows, self._next = self._next, []
        return rows

    def fetchmany(self, size=None):
        return self.fetchall()

    def close(self):
        self.closed = True


class RecordingConn:
    def __init__(self, cursor):
        self.cur = cursor
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def test_wrapper_translates_and_binds_without_interpolation():
    rec = RecordingCursor()
    rec.description = [("id", None, None, None, None, None, None),
                       ("name", None, None, None, None, None, None)]
    rec._next = [(3, "x")]
    conn = pg_backend.wrap_connection(RecordingConn(rec))
    # A hostile-looking value must travel as a bound param, never in SQL.
    hostile = "' OR '1'='1 -- %s ?"
    cur = conn.execute("SELECT * FROM policies WHERE name = ?", (hostile,))
    assert rec.calls == [("SELECT * FROM policies WHERE name = %s",
                          (hostile,))]
    assert hostile not in rec.calls[0][0]
    assert cur.fetchone()["name"] == "x"


def test_wrapper_insert_appends_returning_id_and_sets_lastrowid():
    rec = RecordingCursor()
    rec._next = [(42,)]
    conn = pg_backend.wrap_connection(RecordingConn(rec))
    cur = conn.execute(
        "INSERT INTO policies (name) VALUES (?)", ("demo",))
    assert rec.calls[0][0] == \
        "INSERT INTO policies (name) VALUES (%s) RETURNING id"
    assert rec.calls[0][1] == ("demo",)
    assert cur.lastrowid == 42


def test_wrapper_insert_keeps_caller_supplied_returning():
    rec = RecordingCursor()
    rec._next = [(9,)]
    conn = pg_backend.wrap_connection(RecordingConn(rec))
    cur = conn.execute(
        "INSERT INTO audit (a) VALUES (?) RETURNING id", ("v",))
    assert rec.calls[0][0].count("RETURNING") == 1
    assert cur.lastrowid == 9


def test_wrapper_commit_close_delegate():
    rec = RecordingCursor()
    raw = RecordingConn(rec)
    conn = pg_backend.wrap_connection(raw)
    conn.commit()
    conn.close()
    assert raw.commits == 1
    assert raw.closed is True


def test_wrapper_fetchall_rows_are_pg_rows():
    rec = RecordingCursor()
    rec.description = [("count", None, None, None, None, None, None)]
    rec._next = [(5,)]
    conn = pg_backend.wrap_connection(RecordingConn(rec))
    cur = conn.execute("SELECT COUNT(*) FROM feed_indicators")
    assert cur.fetchone()[0] == 5


# ------------------------------------------------------------- schema / connect

def test_get_postgres_conn_runs_schema_and_commits(monkeypatch):
    store = FakeStore()
    _patch_fake(monkeypatch, store)
    conn = pg_backend.get_postgres_conn(url=DSN)
    assert isinstance(conn, pg_backend._PgConnection)
    assert store.dsns == [DSN]
    ddl = [sql for sql, _ in store.log]
    assert len(ddl) == 4
    assert all("CREATE TABLE IF NOT EXISTS" in s for s in ddl)
    joined = "\n".join(ddl)
    for table, cols in (("policies", POLICY_COLS),
                        ("audit", AUDIT_COLS),
                        ("feed_indicators", FEED_IND_COLS),
                        ("feed_meta", FEED_META_COLS)):
        assert table in joined
        for col in cols:
            assert col in joined, (table, col)
    assert "BIGSERIAL PRIMARY KEY" in joined
    assert "CHECK (id = 1)" in joined
    assert "UNIQUE(type, value)" in joined
    assert store.commits >= 1
    conn.close()


def test_get_postgres_conn_requires_url(monkeypatch):
    monkeypatch.delenv("AEGIS_API_DB_URL", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_API_DB_URL"):
        pg_backend.get_postgres_conn()


def test_get_postgres_conn_no_driver_error(monkeypatch):
    """In this sandbox neither driver is installed; the error must name
    the install instead of failing obscurely. Skipped if a driver is
    ever installed (then live-server tests, not this one, apply)."""
    try:
        import psycopg  # noqa: F401
        pytest.skip("psycopg installed")
    except ImportError:
        pass
    try:
        import psycopg2  # noqa: F401
        pytest.skip("psycopg2 installed")
    except ImportError:
        pass
    with pytest.raises(RuntimeError, match="psycopg"):
        pg_backend._connect_raw("postgresql://127.0.0.1:1/nope")


# ------------------------------------------------------------------- dispatch

def test_dispatch_postgres(monkeypatch):
    store = FakeStore()
    _patch_fake(monkeypatch, store)
    _pg_env(monkeypatch)
    conn = get_conn()
    assert isinstance(conn, pg_backend._PgConnection)
    assert store.dsns == [DSN]
    assert len([s for s, _ in store.log
                if "CREATE TABLE" in s]) == 4
    conn.close()


def test_dispatch_backend_name_variants(monkeypatch):
    for name in ("PostgreSQL", " pg ", "POSTGRES"):
        store = FakeStore()
        _patch_fake(monkeypatch, store)
        monkeypatch.setenv("AEGIS_API_DB_BACKEND", name)
        monkeypatch.setenv("AEGIS_API_DB_URL", DSN)
        conn = get_conn()
        assert isinstance(conn, pg_backend._PgConnection)
        conn.close()


def test_dispatch_sqlite_default_and_url_ignored(monkeypatch, tmp_path):
    # No backend set: SQLite, even if a DSN happens to be present.
    monkeypatch.delenv("AEGIS_API_DB_BACKEND", raising=False)
    monkeypatch.setenv("AEGIS_API_DB_URL", DSN)
    monkeypatch.setenv("AEGIS_API_DB", str(tmp_path / "d.db"))
    conn = get_conn()
    assert isinstance(conn, sqlite3.Connection)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    assert {r[0] for r in row} >= {"policies", "audit",
                                  "feed_indicators", "feed_meta"}
    conn.close()


def test_dispatch_unknown_backend_is_loud(monkeypatch):
    monkeypatch.setenv("AEGIS_API_DB_BACKEND", "mysql")
    with pytest.raises(ValueError, match="unknown AEGIS_API_DB_BACKEND"):
        get_conn()


def test_dispatch_postgres_without_url_is_loud(monkeypatch):
    monkeypatch.setenv("AEGIS_API_DB_BACKEND", "postgres")
    monkeypatch.delenv("AEGIS_API_DB_URL", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_API_DB_URL"):
        get_conn()


# ------------------------------------------------------- HTTP through the app

def test_http_crud_via_fake_postgres(monkeypatch):
    store = FakeStore()
    _patch_fake(monkeypatch, store)
    _pg_env(monkeypatch)

    r = client.post("/policies", json={"name": "pg-demo", "policy": GOOD},
                    headers=AUTH)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["id"] == 1
    assert created["name"] == "pg-demo"
    assert created["policy"] == GOOD
    assert created["hash"]
    pid = created["id"]

    r = client.get("/policies", headers=AUTH)
    assert r.status_code == 200
    listed = r.json()
    assert len(listed) == 1
    assert listed[0] == created  # identical shape to the SQLite path

    r = client.get(f"/policies/{pid}", headers=AUTH)
    assert r.status_code == 200 and r.json() == created

    updated_policy = dict(GOOD, name="pg-demo-2")
    r = client.put(f"/policies/{pid}",
                   json={"name": "pg-demo-2", "policy": updated_policy},
                   headers=AUTH)
    assert r.status_code == 200
    assert r.json()["name"] == "pg-demo-2"
    assert r.json()["policy"] == updated_policy

    r = client.get("/audit", headers=AUTH)
    assert r.status_code == 200
    actions = [row["action"] for row in r.json()]
    assert actions == ["create", "update"]

    r = client.delete(f"/policies/{pid}", headers=AUTH)
    assert r.status_code == 200 and r.json() == {"deleted": pid}
    assert client.get(f"/policies/{pid}", headers=AUTH).status_code == 404

    # Every parameterized statement reached the "driver" as %s SQL with
    # separate params -- never with values interpolated into the text.
    param_statements = [(s, p) for s, p in store.log if p]
    assert param_statements, "expected parameterized statements"
    for sql, params in param_statements:
        assert "%s" in sql
        assert "?" not in sql
        for value in params:
            if isinstance(value, str) and len(value) > 3:
                assert value not in sql or sql.count(value) == 0


def test_http_status_and_feed_status_via_fake_postgres(monkeypatch):
    store = FakeStore()
    _patch_fake(monkeypatch, store)
    _pg_env(monkeypatch)
    r = client.get("/status")
    assert r.status_code == 200
    assert r.json()["db_ok"] is True
    r = client.get("/feeds/status", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["last_outcome"] == "never"
    assert r.json()["indicator_count"] == 0


def test_http_injection_string_stays_a_value(monkeypatch):
    store = FakeStore()
    _patch_fake(monkeypatch, store)
    _pg_env(monkeypatch)
    evil = "' OR '1'='1"
    r = client.post("/policies", json={"name": evil, "policy": GOOD},
                    headers=AUTH)
    assert r.status_code == 201
    assert r.json()["name"] == evil
    # The payload appears only as a bound parameter, never in SQL text.
    assert not any(evil in sql for sql, _ in store.log)
    r = client.get("/policies", headers=AUTH)
    assert [p["name"] for p in r.json()] == [evil]
