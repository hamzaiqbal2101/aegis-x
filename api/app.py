"""AEGIS X Management API (Milestone M2).

FastAPI service over the aegis-linux CLI. It stores policies in SQLite,
validates/applies them by shelling out to the prebuilt Rust CLI, and keeps
an append-only audit log.

Security posture (see README.md):
  * Binds 127.0.0.1 by default; 0.0.0.0 only if AEGIS_API_BIND says so.
  * Every endpoint except GET /status requires a Bearer token: the admin
    token (AEGIS_API_TOKEN) has full access; if AEGIS_API_READONLY_TOKEN
    is set, that token may use GET endpoints only (mutating endpoints
    return 403 for it).
  * /apply and /rollback refuse (400) unless a netns or the explicit
    confirm_host_apply flag is supplied -- the API never touches the host
    firewall on an ambiguous request.
  * No endpoint updates or deletes audit rows.

Integrity hash (see README.md, "Integrity hash" section):
  The Rust engine (crates/aegis-core/src/integrity.rs) hashes the
  *normalized* policy struct serialized by serde_json (struct field order,
  defaults filled in, zones expanded, rules sorted by priority). This API
  does NOT reproduce that byte-for-byte: it hashes the stored policy JSON
  canonicalized as sorted-key, compact-separator JSON. The two hashes are
  therefore NOT claimed to be equal across languages. What is guaranteed
  and tested here: determinism (same stored policy -> same hash) and
  change-sensitivity (any change -> different hash).
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

API_VERSION = "0.2.0-m2"
APP_DIR = Path(__file__).resolve().parent

# --- security limits (see README.md "Security notes") ---
MAX_BODY_BYTES = 1 * 1024 * 1024          # request bodies larger than this -> 413
MAX_POLICY_DEPTH = 100                    # JSON nesting levels in a stored policy
MAX_POLICY_RULES = 1000                   # rules in a stored policy
MAX_FEED_INDICATORS = 10_000              # indicators in one feed body
MAX_FEED_BODY_BYTES = 1 * 1024 * 1024     # bytes read from a feed response
MAX_SQLITE_INT = 2**63 - 1                # ids outside 1..MAX_SQLITE_INT -> 404

# --- configuration (read dynamically so tests can override via env) ---

def db_path() -> Path:
    return Path(os.environ.get("AEGIS_API_DB", str(APP_DIR / "aegis.db")))


def cli_path() -> Path:
    env = os.environ.get("AEGIS_API_CLI")
    if env:
        return Path(env)
    return APP_DIR.parent / "target" / "debug" / "aegis-linux"


def state_dir() -> str | None:
    return os.environ.get("AEGIS_API_STATE_DIR")


def feed_url() -> str | None:
    return os.environ.get("AEGIS_FEED_URL") or None


def feed_interval_secs() -> int:
    try:
        value = int(os.environ.get("AEGIS_FEED_INTERVAL_SECS", "3600"))
    except ValueError:
        return 3600
    return value if value > 0 else 3600


def readonly_token() -> str | None:
    return os.environ.get("AEGIS_API_READONLY_TOKEN") or None


def telemetry_nft_bin() -> str:
    return os.environ.get("AEGIS_TELEMETRY_NFT_BIN", "nft")


# Token: env value wins; otherwise generate one random token at startup,
# print it to stderr once, and use it for the process lifetime. There is
# deliberately NO hardcoded default token.
_GENERATED_TOKEN = None


def _admin_token() -> str:
    global _GENERATED_TOKEN
    env = os.environ.get("AEGIS_API_TOKEN")
    if env:
        return env
    if _GENERATED_TOKEN is None:
        _GENERATED_TOKEN = secrets.token_urlsafe(32)
        print(f"AEGIS_API_TOKEN not set; generated admin token: {_GENERATED_TOKEN}",
              file=sys.stderr, flush=True)
    return _GENERATED_TOKEN


def policy_hash(policy: dict) -> str:
    """SHA-256 over canonical JSON: keys sorted, compact separators.

    NOTE: this is the API's own canonical form (see module docstring). It
    is NOT byte-identical to the Rust policy_hash in aegis-core, which
    hashes the normalized struct serialization. Do not compare the two.
    """
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- storage ---

def get_conn():
    # Postgres backend (ITEM 1, see api/pg_backend.py): delegate when
    # AEGIS_API_DB_BACKEND selects it; anything else unknown is a loud
    # error, never a silent SQLite fallback. The returned connection
    # (sqlite3 or the pg_backend wrapper) shares one interface: execute
    # with "?" placeholders, dict-style rows, cursor.lastrowid, commit,
    # close -- so every call site below works unchanged on either DB.
    backend = os.environ.get("AEGIS_API_DB_BACKEND", "").strip().lower()
    if backend in ("postgres", "postgresql", "pg"):
        import pg_backend
        return pg_backend.get_postgres_conn()
    if backend not in ("", "sqlite", "sqlite3"):
        raise ValueError(
            f"unknown AEGIS_API_DB_BACKEND={backend!r}; "
            "expected 'sqlite' (default) or 'postgres'")
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.exists()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS policies (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL,
               policy TEXT NOT NULL,
               hash TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp TEXT NOT NULL,
               actor TEXT NOT NULL,
               action TEXT NOT NULL,
               policy_id INTEGER,
               detail TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS feed_indicators (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               type TEXT NOT NULL,
               value TEXT NOT NULL,
               expires_at INTEGER,
               fetched_at TEXT NOT NULL,
               UNIQUE(type, value))"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS feed_meta (
               id INTEGER PRIMARY KEY CHECK (id = 1),
               last_refresh_at TEXT,
               last_outcome TEXT,
               last_detail TEXT)"""
    )
    conn.commit()
    if not existed:
        # A freshly created DB holds firewall policies: owner-only perms.
        # Existing files keep whatever the operator set.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return conn


def audit(conn: sqlite3.Connection, action: str, policy_id, detail: str,
          actor: str = "admin") -> None:
    conn.execute(
        "INSERT INTO audit (timestamp, actor, action, policy_id, detail)"
        " VALUES (?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), actor, action, policy_id, detail),
    )
    conn.commit()


def policy_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "policy": json.loads(row["policy"]),
        "hash": row["hash"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


REQUIRED_POLICY_FIELDS = ("version", "name", "default_action", "rules")


def _json_depth(value) -> int:
    """Iterative JSON nesting depth: scalars are 0, empty containers 1.

    Iterative (explicit stack) on purpose: a recursive depth function
    would itself hit RecursionError on the pathological input it is
    meant to reject.
    """
    max_depth = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            if not item:
                max_depth = max(max_depth, depth + 1)
            else:
                for child in item.values():
                    stack.append((child, depth + 1))
        elif isinstance(item, list):
            if not item:
                max_depth = max(max_depth, depth + 1)
            else:
                for child in item:
                    stack.append((child, depth + 1))
        else:
            max_depth = max(max_depth, depth)
    return max_depth


def validate_policy_shape(policy) -> str | None:
    """Shallow write-time validation only. Returns an error string or None.

    Full semantic validation (zone expansion, duplicate rules, nft render)
    happens via the CLI `check` in the validate endpoint, not on write.
    The depth and rule-count caps are DoS bounds: without them a deeply
    nested policy stored once crashes every later response serialization
    (RecursionError in the response encoder), and an unbounded rules
    list bloats storage and CLI work.
    """
    if not isinstance(policy, dict):
        return "policy must be a JSON object"
    missing = [f for f in REQUIRED_POLICY_FIELDS if f not in policy]
    if missing:
        return f"policy missing required field(s): {', '.join(missing)}"
    if not isinstance(policy["rules"], list):
        return "policy.rules must be a list"
    if len(policy["rules"]) > MAX_POLICY_RULES:
        return f"policy.rules exceeds {MAX_POLICY_RULES} entries"
    if _json_depth(policy) > MAX_POLICY_DEPTH:
        return f"policy JSON nesting exceeds {MAX_POLICY_DEPTH} levels"
    return None


def _strict_bool(body: dict, key: str, default: bool) -> bool:
    """Boolean body flags must be real JSON booleans.

    bool("false") is True in Python, so accepting any truthy value for
    confirm_host_apply / no_conntrack would let the string "false"
    silently confirm a host apply or disable stateful inspection. A
    non-boolean value is a 400, never a silent True.
    """
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise HTTPException(status_code=400,
                            detail=f"body.{key} must be a boolean")
    return value


def _policy_id_in_range(policy_id: int) -> bool:
    """SQLite ids are signed 64-bit; anything outside is 'not found'.

    Without this, an id above 2**63-1 reaches sqlite3 binding and raises
    OverflowError -> 500. A 404 keeps the not-found contract for every
    id shape, including absurd ones.
    """
    return 1 <= policy_id <= MAX_SQLITE_INT


# --- auth ---

def _token_matches(candidate: str, expected: str) -> bool:
    try:
        return secrets.compare_digest(candidate, expected)
    except (TypeError, ValueError):
        return False


async def require_auth(authorization: str | None = Header(default=None)) -> str:
    """Authenticate either token; return the caller's role.

    Admin token (AEGIS_API_TOKEN, or the generated fallback) -> "admin".
    Readonly token (AEGIS_API_READONLY_TOKEN, only when set) -> "readonly".
    Missing or unknown token -> 401, exactly as before. When the readonly
    token is unset, behavior is unchanged (admin token only). A token
    equal to both is treated as admin (admin is checked first).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    if _token_matches(token, _admin_token()):
        return "admin"
    ro = readonly_token()
    if ro and _token_matches(token, ro):
        return "readonly"
    raise HTTPException(status_code=401, detail="invalid token")


async def require_admin(role: str = Depends(require_auth)) -> str:
    """Mutating endpoints only: readonly callers get 403."""
    if role != "admin":
        raise HTTPException(
            status_code=403, detail="readonly token cannot mutate")
    return role


# --- threat-feed auto-refresh ---

async def _feed_refresh_loop() -> None:
    """Background loop: refresh once, then sleep for the interval.

    Started ONLY by the lifespan handler when AEGIS_FEED_URL is set, so
    TestClient tests that never set it (and never enter the lifespan)
    start no task and cannot hang on it. refresh_feed() audits every
    outcome itself and never raises past this loop.
    """
    while True:
        try:
            await asyncio.to_thread(refresh_feed, "system")
        except Exception:
            pass
        await asyncio.sleep(feed_interval_secs())


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = None
    if feed_url():
        task = asyncio.create_task(_feed_refresh_loop())
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


# Auto-docs are disabled: /docs, /redoc and /openapi.json would otherwise
# publish the full endpoint/schema surface to any unauthenticated caller.
app = FastAPI(title="AEGIS X Management API", version=API_VERSION,
              lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)


# CORS for the local dashboard only: the dashboard runs in a browser on
# localhost/127.0.0.1 (any dev port -- Vite picks a new one when the
# default is busy), so its origin differs from the API's. Without these
# headers the browser blocks every dashboard fetch even though curl
# works. Only loopback origins are allowed; any other website's origin
# is still refused, and the API token is still required for all
# endpoints except GET /status.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,
    max_age=600,
)


@app.middleware("http")
async def _security_middleware(request, call_next):
    """Body-size cap + security response headers, for every route.

    The size check reads only the Content-Length header (chunked bodies
    without one are not capped here -- uvicorn + normal clients always
    send Content-Length; this is defense-in-depth, not a guarantee).
    """
    length = request.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError:
            return JSONResponse(status_code=400,
                                content={"detail": "invalid Content-Length"})
        if size > MAX_BODY_BYTES:
            return JSONResponse(status_code=413,
                                content={"detail": "request body too large"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


def run_cli(args: list[str]) -> dict:
    cli = cli_path()
    if not cli.exists():
        return {"pass": False, "returncode": None,
                "stdout": "",
                "stderr": f"engine CLI not found at {cli}"}
    try:
        proc = subprocess.run([str(cli)] + args, capture_output=True, text=True,
                              timeout=120)
    except subprocess.TimeoutExpired:
        return {"pass": False, "returncode": None, "stdout": "",
                "stderr": "engine CLI timed out"}
    except OSError as exc:
        # Non-executable path, bad interpreter, etc.: report a clean
        # failure like the missing-CLI case instead of a 500.
        return {"pass": False, "returncode": None, "stdout": "",
                "stderr": f"engine CLI could not run: {exc}"}
    return {"pass": proc.returncode == 0, "returncode": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr}


# --- endpoints ---

@app.get("/status")
def status():
    cli = cli_path()
    try:
        conn = get_conn()
        conn.execute("SELECT 1")
        db_ok = True
        conn.close()
    except Exception:
        db_ok = False
    # engine_path deliberately omitted: /status is unauthenticated and
    # the absolute install path is filesystem layout information.
    return {"api_version": API_VERSION,
            "engine_available": cli.exists(),
            "db_ok": db_ok}


@app.get("/policies", dependencies=[Depends(require_auth)])
def list_policies(limit: int = Query(default=1000, ge=1, le=10000),
                  offset: int = Query(default=0, ge=0)):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM policies ORDER BY id LIMIT ? OFFSET ?",
        (limit, offset)).fetchall()
    conn.close()
    return [policy_row(r) for r in rows]


@app.post("/policies", dependencies=[Depends(require_admin)], status_code=201)
def create_policy(body: dict):
    name = body.get("name")
    policy = body.get("policy")
    if not isinstance(name, str) or not name:
        raise HTTPException(status_code=400, detail="body.name (string) is required")
    err = validate_policy_shape(policy)
    if err:
        raise HTTPException(status_code=400, detail=err)
    now = datetime.now(timezone.utc).isoformat()
    h = policy_hash(policy)
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO policies (name, policy, hash, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (name, json.dumps(policy), h, now, now))
    pid = cur.lastrowid
    audit(conn, "create", pid, f"created policy '{name}' hash={h}")
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (pid,)).fetchone()
    conn.close()
    return policy_row(row)


@app.get("/policies/{policy_id}", dependencies=[Depends(require_auth)])
def get_policy(policy_id: int):
    if not _policy_id_in_range(policy_id):
        raise HTTPException(status_code=404, detail="policy not found")
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="policy not found")
    return policy_row(row)


@app.put("/policies/{policy_id}", dependencies=[Depends(require_admin)])
def update_policy(policy_id: int, body: dict):
    if not _policy_id_in_range(policy_id):
        raise HTTPException(status_code=404, detail="policy not found")
    name = body.get("name")
    policy = body.get("policy")
    if policy is None:
        raise HTTPException(status_code=400, detail="body.policy is required")
    err = validate_policy_shape(policy)
    if err:
        raise HTTPException(status_code=400, detail=err)
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="policy not found")
    new_name = name if isinstance(name, str) and name else row["name"]
    now = datetime.now(timezone.utc).isoformat()
    h = policy_hash(policy)
    conn.execute(
        "UPDATE policies SET name = ?, policy = ?, hash = ?, updated_at = ?"
        " WHERE id = ?",
        (new_name, json.dumps(policy), h, now, policy_id))
    audit(conn, "update", policy_id, f"updated policy '{new_name}' hash={h}")
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    conn.close()
    return policy_row(row)


@app.delete("/policies/{policy_id}", dependencies=[Depends(require_admin)])
def delete_policy(policy_id: int):
    if not _policy_id_in_range(policy_id):
        raise HTTPException(status_code=404, detail="policy not found")
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="policy not found")
    conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    audit(conn, "delete", policy_id, f"deleted policy '{row['name']}'")
    conn.close()
    return {"deleted": policy_id}


@app.post("/policies/{policy_id}/validate", dependencies=[Depends(require_admin)])
def validate_policy(policy_id: int, body: dict | None = None):
    body = body or {}
    if not _policy_id_in_range(policy_id):
        raise HTTPException(status_code=404, detail="policy not found")
    no_conntrack = _strict_bool(body, "no_conntrack", False)
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="policy not found")
    policy = json.loads(row["policy"])
    conn.close()
    # Write the stored policy to a temp file and shell out to the CLI.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        tmp = f.name
    try:
        args = ["check", "--policy", tmp]
        if no_conntrack:
            args.append("--no-conntrack")
        result = run_cli(args)
    finally:
        os.unlink(tmp)
    conn = get_conn()
    audit(conn, "validate", policy_id,
          f"validate pass={result['pass']} no_conntrack={no_conntrack}")
    conn.close()
    return {"policy_id": policy_id, "pass": result["pass"],
            "returncode": result["returncode"],
            "stdout": result["stdout"], "stderr": result["stderr"]}


def _gate_scope(body: dict) -> list[str]:
    """Return CLI scope flags, or raise 400 if neither scope is given."""
    netns = body.get("netns")
    if netns is not None and not isinstance(netns, str):
        raise HTTPException(status_code=400,
                            detail="body.netns must be a string")
    confirm = _strict_bool(body, "confirm_host_apply", False)
    if not netns and not confirm:
        raise HTTPException(
            status_code=400,
            detail="refusing to touch the host firewall: supply netns or "
                   "confirm_host_apply=true")
    if netns:
        return ["--netns", netns]
    return ["--confirm-host-apply"]


@app.post("/apply", dependencies=[Depends(require_admin)])
def apply_policy(body: dict):
    policy_id = body.get("policy_id")
    # bool is a subclass of int: True must not silently become id 1.
    if isinstance(policy_id, bool) or not isinstance(policy_id, int):
        raise HTTPException(status_code=400, detail="body.policy_id (int) is required")
    if not _policy_id_in_range(policy_id):
        raise HTTPException(status_code=404, detail="policy not found")
    scope = _gate_scope(body)
    no_conntrack = _strict_bool(body, "no_conntrack", False)
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="policy not found")
    policy = json.loads(row["policy"])
    conn.close()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        tmp = f.name
    try:
        args = ["apply", "--policy", tmp] + scope
        if no_conntrack:
            args.append("--no-conntrack")
        sd = state_dir()
        if sd:
            args += ["--state-dir", sd]
        result = run_cli(args)
    finally:
        os.unlink(tmp)
    conn = get_conn()
    audit(conn, "apply", policy_id,
          f"apply pass={result['pass']} netns={body.get('netns')} "
          f"confirm_host_apply={_strict_bool(body, 'confirm_host_apply', False)}")
    conn.close()
    return {"policy_id": policy_id, "pass": result["pass"],
            "returncode": result["returncode"],
            "stdout": result["stdout"], "stderr": result["stderr"]}


@app.post("/rollback", dependencies=[Depends(require_admin)])
def rollback(body: dict | None = None):
    body = body or {}
    scope = _gate_scope(body)
    args = ["rollback"] + scope
    sd = state_dir()
    if sd:
        args += ["--state-dir", sd]
    result = run_cli(args)
    conn = get_conn()
    audit(conn, "rollback", None,
          f"rollback pass={result['pass']} netns={body.get('netns')} "
          f"confirm_host_apply={_strict_bool(body, 'confirm_host_apply', False)}")
    conn.close()
    return {"pass": result["pass"], "returncode": result["returncode"],
            "stdout": result["stdout"], "stderr": result["stderr"]}


# --- threat feed (ITEM 2) ---
#
# Strict feed shape (documented in api/README.md):
#   {"indicators": [{"type": "ip"|"domain", "value": str,
#                    "expires_at": <unix timestamp int>|null}, ...]}
# Anything else is rejected as "invalid_feed". FAIL SAFE: a fetch failure
# or an invalid shape NEVER touches feed_indicators -- the previous
# indicators stay until their own expiry. Only a fully validated feed
# replaces the stored set, in one transaction.

FEED_INDICATOR_KEYS = {"type", "value", "expires_at"}


def validate_feed_shape(data) -> tuple[list[dict] | None, str | None]:
    """Validate a decoded feed body. Returns (indicators, error).

    Duplicates (same type+value) are collapsed to the first occurrence:
    without this, a feed repeating one indicator hit the UNIQUE(type,
    value) constraint mid-transaction and turned a routine refresh into
    a 500 with no recorded outcome. A feed over the indicator cap is
    invalid (old indicators preserved) rather than a multi-hundred-
    thousand-row insert.
    """
    if not isinstance(data, dict):
        return None, "feed top level must be a JSON object"
    indicators = data.get("indicators")
    if not isinstance(indicators, list):
        return None, "feed.indicators must be a list"
    if len(indicators) > MAX_FEED_INDICATORS:
        return None, (f"feed has more than {MAX_FEED_INDICATORS} indicators")
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(indicators):
        if not isinstance(item, dict):
            return None, f"indicator {i} must be an object"
        if set(item.keys()) != FEED_INDICATOR_KEYS:
            return None, (f"indicator {i} must have exactly the keys "
                           "type, value, expires_at")
        itype, value, expires_at = item["type"], item["value"], item["expires_at"]
        if itype not in ("ip", "domain"):
            return None, f"indicator {i} has unsupported type {itype!r}"
        if not isinstance(value, str) or not value:
            return None, f"indicator {i} value must be a non-empty string"
        if itype == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return None, f"indicator {i} value is not a valid IP address"
        elif any(ch.isspace() for ch in value) or "/" in value or ":" in value:
            return None, f"indicator {i} value is not a valid domain"
        if expires_at is not None and (
                isinstance(expires_at, bool) or not isinstance(expires_at, int)):
            return None, f"indicator {i} expires_at must be a unix timestamp or null"
        key = (itype, value)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": itype, "value": value, "expires_at": expires_at})
    return out, None


def _record_feed_outcome(conn: sqlite3.Connection, outcome: str, detail: str,
                         actor: str) -> None:
    """Persist last-refresh state and append one audit row (never touches
    feed_indicators -- callers use this for failures AND successes)."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO feed_meta (id, last_refresh_at, last_outcome, last_detail)"
        " VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
        " last_refresh_at = excluded.last_refresh_at,"
        " last_outcome = excluded.last_outcome,"
        " last_detail = excluded.last_detail",
        (now, outcome, detail))
    audit(conn, "feed_refresh", None, f"feed_refresh {outcome}: {detail}",
          actor=actor)


def _feed_fail(outcome: str, detail: str, actor: str) -> dict:
    """Record a non-success refresh outcome and return its payload.

    Details are truncated: fetch exceptions can embed the URL, and a
    URL could one day carry credentials -- those must never land in
    feed_meta/audit verbatim at unbounded length.
    """
    detail = detail[:300]
    conn = get_conn()
    try:
        _record_feed_outcome(conn, outcome, detail, actor)
    finally:
        conn.close()
    return {"outcome": outcome, "count": None, "detail": detail}


def _feed_allow_private() -> bool:
    """Opt-in for internal feeds (lab / air-gapped origins).

    Default is deny: a feed host resolving to a private, loopback,
    link-local, multicast, reserved, or unspecified address is refused
    before any request is sent. Tests set this flag because their feed
    server is local; production feeds are public hosts.
    """
    return os.environ.get("AEGIS_FEED_ALLOW_PRIVATE", "") == "1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib follows redirects by default: a feed origin (or a
    compromised one) could 302 the fetcher at an internal address --
    cloud metadata (169.254.169.254) or a localhost admin port. Any
    redirect is a fetch failure; the old indicators stay."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     "feed redirect refused", headers, fp)


def _feed_host_is_public(parsed) -> tuple[bool, str]:
    """Resolve the feed host and require every address to be public.

    Checked BEFORE fetching (fail closed on DNS failure). This closes
    the trivial SSRF cases (localhost, RFC1918, 169.254/16 metadata).
    It does not close DNS-rebinding TOCTOU (address changing between
    this check and connect) -- see README.md.
    """
    if parsed.username or parsed.password:
        return False, "feed URL must not contain credentials"
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return False, "feed URL has an invalid port"
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, "feed host could not be resolved"
    except Exception:
        return False, "feed host lookup failed"
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, "feed host resolves to a non-public address"
    return True, ""


def refresh_feed(actor: str = "system") -> dict:
    """Fetch, validate, and (on success only) store the threat feed.

    Never raises past its own failure handling: every outcome is
    recorded in feed_meta + the audit log and returned as a dict.
    """
    url = feed_url()
    if not url:
        return _feed_fail("not_configured", "AEGIS_FEED_URL is not set", actor)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return _feed_fail(
            "fetch_failed",
            f"unsupported feed URL scheme: {parsed.scheme or '(none)'}", actor)
    if not _feed_allow_private():
        ok, detail = _feed_host_is_public(parsed)
        if not ok:
            return _feed_fail("fetch_failed", detail, actor)
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "aegis-x-feed/1.0"})
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=15) as resp:
            if resp.status != 200:
                raise urllib.error.HTTPError(url, resp.status, resp.reason,
                                             resp.headers, None)
            raw = resp.read(MAX_FEED_BODY_BYTES + 1)
    except Exception as exc:  # fetch failure: old indicators untouched
        return _feed_fail("fetch_failed", f"fetch failed: {exc}", actor)
    if len(raw) > MAX_FEED_BODY_BYTES:
        return _feed_fail("invalid_feed",
                          f"feed body exceeds {MAX_FEED_BODY_BYTES} bytes",
                          actor)
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _feed_fail("invalid_feed",
                          f"invalid feed: not valid JSON ({exc})", actor)
    indicators, err = validate_feed_shape(data)
    if err is not None:
        return _feed_fail("invalid_feed", f"invalid feed: {err}", actor)
    # Success only: replace the stored set in one transaction. Rows
    # already past expiry are dropped; the rest are kept verbatim.
    now_ts = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute("DELETE FROM feed_indicators")
        for ind in indicators:
            conn.execute(
                "INSERT INTO feed_indicators (type, value, expires_at, fetched_at)"
                " VALUES (?, ?, ?, ?)",
                (ind["type"], ind["value"], ind["expires_at"], now_iso))
        conn.execute(
            "DELETE FROM feed_indicators"
            " WHERE expires_at IS NOT NULL AND expires_at <= ?", (now_ts,))
        count = conn.execute(
            "SELECT COUNT(*) FROM feed_indicators").fetchone()[0]
        _record_feed_outcome(conn, "success",
                             f"ingested {count} indicator(s) from feed", actor)
        conn.commit()
    finally:
        conn.close()
    return {"outcome": "success", "count": count,
            "detail": f"ingested {count} indicator(s) from feed"}


def feed_status_payload() -> dict:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM feed_meta WHERE id = 1").fetchone()
        now_ts = int(time.time())
        count = conn.execute(
            "SELECT COUNT(*) FROM feed_indicators"
            " WHERE expires_at IS NULL OR expires_at > ?", (now_ts,)).fetchone()[0]
    finally:
        conn.close()
    return {"last_refresh_at": row["last_refresh_at"] if row else None,
            "last_outcome": row["last_outcome"] if row else "never",
            "last_detail": row["last_detail"] if row else None,
            "indicator_count": count,
            "feed_url_configured": bool(feed_url())}


@app.get("/feeds/status", dependencies=[Depends(require_auth)])
def feeds_status():
    return feed_status_payload()


@app.post("/feeds/refresh", dependencies=[Depends(require_admin)])
def feeds_refresh():
    return refresh_feed(actor="admin")


# --- telemetry (ITEM 5) ---
#
# Read-only `nft -j list ruleset` parse. On ANY failure this returns
# {"available": false, "reason": ...} with HTTP 200 -- numbers are never
# invented, and no firewall state is ever changed here.

def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_nft_counters(data: dict) -> list[dict] | None:
    """Extract counter rows from `nft -j list ruleset` output.

    Returns None when the shape is not recognizable at all. A ruleset
    that parses but contains no counters yields [] (honest: no counter
    data reported, not invented zeros).
    """
    entries = data.get("nftables")
    if not isinstance(entries, list):
        return None
    rows: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "rule" in entry:
            rule = entry["rule"]
            if not isinstance(rule, dict):
                continue
            counters: list[dict] = []
            expr = rule.get("expr")
            if isinstance(expr, list):
                for elem in expr:
                    if isinstance(elem, dict) and isinstance(elem.get("counter"), dict):
                        counters.append(elem["counter"])
            if isinstance(rule.get("counter"), dict):
                counters.append(rule["counter"])
            for counter in counters:
                if _is_int(counter.get("packets")) and _is_int(counter.get("bytes")):
                    rows.append({"table": rule.get("table"),
                                 "chain": rule.get("chain"),
                                 "handle": rule.get("handle"),
                                 "name": None,
                                 "packets": counter["packets"],
                                 "bytes": counter["bytes"]})
        elif "counter" in entry:
            counter = entry["counter"]
            if isinstance(counter, dict) and _is_int(counter.get("packets")) \
                    and _is_int(counter.get("bytes")):
                rows.append({"table": counter.get("table"),
                             "chain": None,
                             "handle": None,
                             "name": counter.get("name"),
                             "packets": counter["packets"],
                             "bytes": counter["bytes"]})
    return rows


def telemetry_counters() -> dict:
    binary = telemetry_nft_bin()
    try:
        proc = subprocess.run([binary, "-j", "list", "ruleset"],
                              capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return {"available": False, "reason": f"nft binary not found: {binary}"}
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "nft list timed out"}
    except OSError as exc:
        return {"available": False,
                "reason": f"cannot run nft binary: {exc.strerror or exc}"}
    if proc.returncode != 0:
        lines = (proc.stderr or "").strip().splitlines()
        detail = lines[0] if lines else f"exit code {proc.returncode}"
        return {"available": False,
                "reason": f"nft exited with code {proc.returncode}: {detail}"[:300]}
    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"available": False, "reason": "unparsable nft output"}
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        return {"available": False, "reason": "unparsable nft output"}
    if len(data["nftables"]) == 0:
        return {"available": False, "reason": "empty ruleset"}
    rows = parse_nft_counters(data)
    if rows is None:
        return {"available": False, "reason": "unparsable nft output"}
    return {"available": True, "counters": rows}


@app.get("/telemetry/counters", dependencies=[Depends(require_auth)])
def get_telemetry_counters():
    return telemetry_counters()


@app.get("/audit", dependencies=[Depends(require_auth)])
def list_audit(limit: int = Query(default=1000, ge=1, le=10000),
               offset: int = Query(default=0, ge=0)):
    # Deliberately no PUT/DELETE/PATCH route for /audit exists anywhere
    # in this app: audit rows are append-only via the API.
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM audit ORDER BY id LIMIT ? OFFSET ?",
        (limit, offset)).fetchall()
    conn.close()
    return [{"id": r["id"], "timestamp": r["timestamp"], "actor": r["actor"],
             "action": r["action"], "policy_id": r["policy_id"],
             "detail": r["detail"]} for r in rows]


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("AEGIS_API_BIND", "127.0.0.1")
    if host == "0.0.0.0":
        print("WARNING: AEGIS_API_BIND=0.0.0.0 -- API is exposed beyond localhost",
              file=sys.stderr, flush=True)
    port = int(os.environ.get("AEGIS_API_PORT", "8000"))
    # Touch the token so a generated token is printed at startup.
    _admin_token()
    uvicorn.run(app, host=host, port=port)
