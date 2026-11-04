"""PostgreSQL backend for the AEGIS X Management API (ITEM 1).

SQLite remains the default. Postgres is selected ONLY when the operator
sets::

    AEGIS_API_DB_BACKEND=postgres
    AEGIS_API_DB_URL=postgresql://user:password@host:5432/aegis

``app.get_conn()`` delegates here in exactly that case; every other
value (unset, ``sqlite``) keeps the historical SQLite path with zero
behavior change, and any other backend name is a loud ``ValueError``
rather than a silent SQLite fallback.

Why a wrapper instead of rewriting app.py?
------------------------------------------
app.py issues all of its SQL with SQLite ``?`` placeholders and reads
rows as ``sqlite3.Row`` (``row["id"]``) plus ``cursor.lastrowid`` after
an INSERT. Rewriting every call site was out of scope for this item
(the task allowed only a dispatch edit in ``get_conn``), so this module
wraps a real DBAPI connection (``psycopg`` v3 preferred, ``psycopg2``
accepted) and translates at the boundary:

* ``?`` placeholders -> ``%s`` (psycopg/psycopg2 paramstyle), skipping
  ``?`` characters inside single-quoted string literals, double-quoted
  identifiers, and ``--`` / ``/* */`` comments. All user values still
  travel as bound parameters -- no SQL string is ever built from user
  input; the only SQL text here is the fixed schema DDL below.
* Result rows -> :class:`_PgRow`, which supports both ``row["col"]``
  and ``row[0]`` exactly like ``sqlite3.Row`` (``SELECT COUNT(*)`` call
  sites use ``fetchone()[0]``).
* ``cursor.lastrowid`` -> the INSERT statement is issued with
  ``RETURNING id`` appended (when the caller did not already supply
  one) and the returned id is consumed internally. This is safe for
  app.py because no call site fetches rows from an INSERT cursor: the
  policies INSERT is followed by a separate ``SELECT ... WHERE id``,
  and audit/feed INSERTs are never fetched from.

Schema
------
No schema change: the Postgres tables mirror the SQLite shapes column
for column (``INTEGER PRIMARY KEY AUTOINCREMENT`` becomes
``BIGSERIAL PRIMARY KEY``; ``INTEGER`` ids become ``BIGINT``). The
``INSERT ... ON CONFLICT(id) DO UPDATE SET ... excluded....`` upsert
used for ``feed_meta`` is valid in both SQLite and Postgres, so it is
passed through unchanged.

Driver
------
Neither driver is a hard dependency: :func:`get_postgres_conn` raises a
``RuntimeError`` naming the install (``pip install "psycopg[binary]"``)
when no driver is importable. Driver loading goes through
:func:`_connect_raw` so tests can monkeypatch it with a fake DBAPI
connection without a server.

Live-server status (Nov 3, 2026, sandbox)
------------------------------------------
No live Postgres was available here and none could be started cheaply:
no ``psql``/``pg_isready``/``postgres``/``initdb``/``docker`` on PATH,
no ``/usr/lib/postgresql`` tree, no ``psycopg``/``psycopg2`` in the API
venv, and no package lists for an install. This code path is therefore
verified here with a fake DBAPI connection (see
``tests/test_postgres.py``) exercising placeholder translation, parameter
binding, ``RETURNING id``/``lastrowid``, row access, schema DDL, and
the SQLite/Postgres dispatch -- including end-to-end HTTP calls through
the real FastAPI app against a tiny in-memory fake engine. A real-server
run is still required before Postgres is trusted in production; see
``README.md`` ("PostgreSQL backend") for the exact commands.
"""

from __future__ import annotations

import os

# Values of AEGIS_API_DB_BACKEND that select Postgres / SQLite.
POSTGRES_BACKEND_NAMES = frozenset({"postgres", "postgresql", "pg"})
SQLITE_BACKEND_NAMES = frozenset({"", "sqlite", "sqlite3"})

# Fixed schema DDL. Mirrors the SQLite CREATE TABLE statements in
# app.get_conn() column for column; no user input is interpolated.
POSTGRES_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS policies (
           id BIGSERIAL PRIMARY KEY,
           name TEXT NOT NULL,
           policy TEXT NOT NULL,
           hash TEXT NOT NULL,
           created_at TEXT NOT NULL,
           updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS audit (
           id BIGSERIAL PRIMARY KEY,
           timestamp TEXT NOT NULL,
           actor TEXT NOT NULL,
           action TEXT NOT NULL,
           policy_id BIGINT,
           detail TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS feed_indicators (
           id BIGSERIAL PRIMARY KEY,
           type TEXT NOT NULL,
           value TEXT NOT NULL,
           expires_at BIGINT,
           fetched_at TEXT NOT NULL,
           UNIQUE(type, value))""",
    """CREATE TABLE IF NOT EXISTS feed_meta (
           id BIGINT PRIMARY KEY CHECK (id = 1),
           last_refresh_at TEXT,
           last_outcome TEXT,
           last_detail TEXT)""",
)


def db_backend() -> str:
    """Normalized AEGIS_API_DB_BACKEND ("" when unset)."""
    return os.environ.get("AEGIS_API_DB_BACKEND", "").strip().lower()


def db_url() -> str | None:
    """Postgres DSN from AEGIS_API_DB_URL, or None when unset/blank."""
    url = os.environ.get("AEGIS_API_DB_URL", "").strip()
    return url or None


def is_postgres_selected() -> bool:
    return db_backend() in POSTGRES_BACKEND_NAMES


def translate_placeholders(sql: str) -> str:
    """Translate SQLite ``?`` placeholders to Postgres ``%s``.

    A ``?`` inside a single-quoted literal, a double-quoted identifier,
    or a ``--`` / ``/* */`` comment is left untouched. Escaped quotes
    (``''`` inside a literal, ``""`` inside an identifier) are handled.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            # Single-quoted literal; '' is an escaped quote.
            out.append(ch)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        out.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == '"':
            # Double-quoted identifier; "" is an escaped quote.
            out.append(ch)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == '"':
                    if i + 1 < n and sql[i + 1] == '"':
                        out.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            # Line comment through the newline (or end of string).
            while i < n and sql[i] != "\n":
                out.append(sql[i])
                i += 1
            continue
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            # Block comment through */ (or end of string).
            out.append(ch)
            out.append(sql[i + 1])
            i += 2
            while i < n:
                out.append(sql[i])
                if sql[i] == "*" and i + 1 < n and sql[i + 1] == "/":
                    out.append(sql[i + 1])
                    i += 2
                    break
                i += 1
            continue
        if ch == "?":
            out.append("%s")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


class _PgRow:
    """DBAPI row with sqlite3.Row-style access: ``row["col"]`` and ``row[0]``."""

    __slots__ = ("_values", "_index")

    def __init__(self, values, columns):
        self._values = tuple(values)
        # Later duplicate column names win, matching dict-style access.
        self._index = {name: pos for pos, name in enumerate(columns)}

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self._values[self._index[key]]
            except KeyError:
                # sqlite3.Row raises IndexError for an unknown key.
                raise IndexError(f"no such column: {key!r}") from None
        return self._values[key]

    def __len__(self):
        return len(self._values)

    def __iter__(self):
        return iter(self._values)

    def keys(self):
        return list(self._index)

    def __repr__(self):
        return f"_PgRow({dict(zip(self.keys(), self._values))!r})"


class _PgCursor:
    """Wraps a DBAPI cursor: translates placeholders, emulates lastrowid."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self.lastrowid = None

    def _columns(self):
        desc = self._cur.description
        if not desc:
            return []
        return [col[0] for col in desc]

    def execute(self, sql, params=None):
        translated = translate_placeholders(sql)
        is_insert = translated.lstrip().upper().startswith("INSERT")
        if is_insert and "RETURNING" not in translated.upper():
            translated = translated + " RETURNING id"
        if params is None:
            self._cur.execute(translated)
        else:
            self._cur.execute(translated, params)
        if is_insert:
            # Consume the RETURNING row here: app.py never fetches from
            # an INSERT cursor (see module docstring), so nothing the
            # caller expects is lost.
            row = self._cur.fetchone()
            if row is not None:
                self.lastrowid = row[0]
        return self

    def executemany(self, sql, seq_of_params):
        translated = translate_placeholders(sql)
        self._cur.executemany(translated, seq_of_params)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        return _PgRow(row, self._columns())

    def fetchall(self):
        columns = self._columns()
        return [_PgRow(row, columns) for row in self._cur.fetchall()]

    def fetchmany(self, size=None):
        columns = self._columns()
        if size is None:
            rows = self._cur.fetchmany()
        else:
            rows = self._cur.fetchmany(size)
        return [_PgRow(row, columns) for row in rows]

    @property
    def rowcount(self):
        return self._cur.rowcount

    def close(self):
        self._cur.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _PgConnection:
    """Wraps a DBAPI connection so app.py can use it like sqlite3."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql, params=None):
        cur = _PgCursor(self._conn.cursor())
        cur.execute(sql, params)
        return cur

    def cursor(self):
        return _PgCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def wrap_connection(raw_conn) -> _PgConnection:
    """Wrap an already-connected DBAPI connection (driver-agnostic)."""
    return _PgConnection(raw_conn)


def _connect_raw(dsn: str):
    """Open a raw DBAPI connection. Monkeypatched by tests with a fake.

    psycopg (v3) is tried first, then psycopg2; both accept a DSN as the
    single positional argument. Neither is a hard dependency of the API.
    """
    try:
        import psycopg  # type: ignore
    except ImportError:
        psycopg = None  # type: ignore
    if psycopg is not None:
        return psycopg.connect(dsn)
    try:
        import psycopg2  # type: ignore
    except ImportError:
        psycopg2 = None  # type: ignore
    if psycopg2 is not None:
        return psycopg2.connect(dsn)
    raise RuntimeError(
        "PostgreSQL driver not installed: install one with "
        "`api/.venv/bin/pip install \"psycopg[binary]\"` (preferred) or "
        "`pip install psycopg2-binary`, then set AEGIS_API_DB_URL."
    )


def get_postgres_conn(url: str | None = None) -> _PgConnection:
    """Connect to Postgres and ensure the (unchanged) schema exists.

    The DSN must come from AEGIS_API_DB_URL (or the explicit ``url``
    argument, used by tests); there is deliberately no default DSN, so
    selecting Postgres can never silently connect to a wrong database.
    """
    dsn = url or db_url()
    if not dsn:
        raise RuntimeError(
            "AEGIS_API_DB_BACKEND=postgres is set but AEGIS_API_DB_URL "
            "is not set; set it to a DSN such as "
            "postgresql://user:password@127.0.0.1:5432/aegis"
        )
    conn = wrap_connection(_connect_raw(dsn))
    try:
        for statement in POSTGRES_SCHEMA:
            conn.execute(statement)
        conn.commit()
    except Exception:
        conn.close()
        raise
    return conn
