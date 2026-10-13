from flask import (Flask, request, g, render_template, jsonify, abort, Response,
                   session, redirect, url_for)
import sqlite3, json, os, math, re, time, hmac, secrets
from datetime import datetime, timedelta, timezone

import detail as detail_builder

# Read data directory from env (default to /app/data)
DB_DIR = os.environ.get("DB_DIR", "/app/data")
DB_PATH = os.path.join(DB_DIR, "logs.db")

PAGE_SIZES = [25, 50, 100, 200]
DEFAULT_PAGE_SIZE = 50

# Insertion order drives the dropdown order.
TIME_RANGES = {
    "5m": ("Last 5 minutes", timedelta(minutes=5)),
    "15m": ("Last 15 minutes", timedelta(minutes=15)),
    "1h": ("Last hour", timedelta(hours=1)),
    "24h": ("Last 24 hours", timedelta(hours=24)),
    "7d": ("Last 7 days", timedelta(days=7)),
    "30d": ("Last 30 days", timedelta(days=30)),
    "all": ("All time", None),
}
DEFAULT_RANGE = "7d"

TYPES = ["llm", "mcp", "a2a", "api"]

# Which log types each secondary filter is meaningful for. A filter outside its
# scope is ignored rather than applied, so switching Type cannot leave a stale
# value silently returning nothing -- including via a shared or bookmarked URL.
FILTER_SCOPE = {
    "provider": ("llm",),
    "model": ("llm",),
    "method": ("mcp", "a2a"),
    "tool": ("mcp",),
}

FEATURE_SCOPE = {
    "sanitizer": ("llm",),
    "compressor": ("llm",),
    "judge": ("llm",),
    "cache_hit": ("llm",),
    "cache_miss": ("llm",),
    "tool_call": ("mcp",),
    "rpc_error": ("mcp", "a2a"),
}


def in_scope(name, log_type, scope=None):
    """True when a filter applies to the selected log type."""
    if log_type == "all":
        return True
    allowed = (scope or FILTER_SCOPE).get(name)
    return allowed is None or log_type in allowed

# Exports are meant for sharing a handful of representative payloads, not for
# bulk extraction -- a few hundred AI logs is already several megabytes.
MAX_EXPORT = 500

# Header values replaced when redaction is on. Kong already redacts
# `authorization` in some configurations, but not all, and not the rest.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "api-key", "x-api-key", "apikey", "x-auth-token", "x-api-token",
}

app = Flask(__name__)

# ---------------------------------------------------------------- auth
# Credentials come from the environment (docker run -e ...). The app refuses
# to start without them, so it can never come up unauthenticated.
AUTH_USER = os.environ.get("VIEWER_USERNAME", "")
AUTH_PASS = os.environ.get("VIEWER_PASSWORD", "")
if not AUTH_USER or not AUTH_PASS:
    raise SystemExit("VIEWER_USERNAME and VIEWER_PASSWORD must be set")

# Sessions are signed with SECRET_KEY. If unset, a random key is generated per
# start, which simply signs everyone out when the container restarts.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "12"))),
)

# Endpoints reachable without a session. /logs is the Kong http-log ingest
# target (a plugin can't do an interactive login) and only ever writes.
PUBLIC_ENDPOINTS = {"login", "healthz", "ingest", "static"}


def _creds_ok(user, pw):
    # Evaluate both comparisons so timing doesn't reveal which field was wrong.
    u = hmac.compare_digest(user.encode(), AUTH_USER.encode())
    p = hmac.compare_digest(pw.encode(), AUTH_PASS.encode())
    return u and p


def _safe_next(target):
    # Only allow same-site relative paths, never //host or scheme:// targets.
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("index")


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or session.get("auth") is True:
        return None
    if request.path.startswith("/api/"):
        return jsonify(error="authentication required"), 401
    nxt = request.full_path.rstrip("?") if request.method == "GET" else "/"
    return redirect(url_for("login", next=nxt))


@app.after_request
def no_store(resp):
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth") is True:
        return redirect(_safe_next(request.args.get("next")))
    error = None
    if request.method == "POST":
        if _creds_ok(request.form.get("username", ""), request.form.get("password", "")):
            session.clear()
            session["auth"] = True
            session.permanent = True
            return redirect(_safe_next(request.form.get("next")))
        time.sleep(1)  # blunt brute-force speed bump
        error = "Incorrect username or password."
    return render_template("login.html", error=error, next=request.args.get("next", request.form.get("next", ""))), (401 if error else 200)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.template_filter("fmtts")
def fmtts(value):
    """Render a stored ISO timestamp as UTC. The browser replaces this with
    local time, so this is the no-JavaScript fallback."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return value
    return dt.strftime("%b %d, %Y %I:%M:%S.") + f"{dt.microsecond // 1000:03d}" + dt.strftime(" %p")


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""

# Columns extracted from the payload at ingest time so that the list view never
# has to parse JSON, and so type/status filtering can happen in SQL.
DERIVED_COLUMNS = [
    ("log_type", "TEXT"),
    ("consumer", "TEXT"),
    ("status", "INTEGER"),
    ("method", "TEXT"),
    ("uri", "TEXT"),
    ("latency", "INTEGER"),
    ("client_ip", "TEXT"),
    ("provider", "TEXT"),
    ("model", "TEXT"),
    ("prompt_tokens", "INTEGER"),
    ("completion_tokens", "INTEGER"),
    ("total_tokens", "INTEGER"),
    ("cost", "REAL"),
    ("cache_status", "TEXT"),
    ("sanitized_count", "INTEGER"),
    ("tokens_saved", "INTEGER"),
    ("judge_score", "REAL"),
    ("user_agent", "TEXT"),
    ("client", "TEXT"),
    ("client_version", "TEXT"),
    ("rpc_method", "TEXT"),
    ("tool_name", "TEXT"),
    ("mcp_session", "TEXT"),
    ("task_state", "TEXT"),
    ("rpc_error", "TEXT"),
]

# Bump whenever extract_fields() changes what it pulls out, so existing rows
# are re-derived on the next start instead of silently keeping stale columns.
DERIVED_VERSION = 5

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_type_id ON logs (log_type, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_status_id ON logs (status, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_provider_id ON logs (provider, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_model_id ON logs (model, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_cache_id ON logs (cache_status, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_client_id ON logs (client, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_method_id ON logs (rpc_method, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_tool_id ON logs (tool_name, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs (mcp_session, id DESC)",
]


def connect():
    os.makedirs(DB_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    """Create the table, add any missing derived columns, backfill and index."""
    con = connect()
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.executescript(BASE_SCHEMA)

        existing = {r["name"] for r in con.execute("PRAGMA table_info(logs)")}
        added = []
        for name, coltype in DERIVED_COLUMNS:
            if name not in existing:
                con.execute(f"ALTER TABLE logs ADD COLUMN {name} {coltype}")
                added.append(name)
        con.commit()

        backfill(con)

        for stmt in INDEXES:
            con.execute(stmt)
        con.commit()

        if added:
            app.logger.info("Added derived columns: %s", ", ".join(added))
    finally:
        con.close()


COLUMN_ORDER = [name for name, _ in DERIVED_COLUMNS]

UPDATE_SQL = ("UPDATE logs SET " + ", ".join(c + "=?" for c in COLUMN_ORDER)
              + " WHERE id=?")

INSERT_SQL = ("INSERT INTO logs (timestamp, payload, " + ", ".join(COLUMN_ORDER)
              + ") VALUES (?, ?, " + ", ".join("?" * len(COLUMN_ORDER)) + ")")


def row_values(fields, log_id):
    return tuple(fields[c] for c in COLUMN_ORDER) + (log_id,)


def stored_version(con):
    con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    row = con.execute("SELECT value FROM meta WHERE key='derived_version'").fetchone()
    try:
        return int(row["value"]) if row else 0
    except (ValueError, TypeError):
        return 0


def backfill(con, batch=500):
    """Derive columns for rows that predate them, or re-derive everything when
    the extraction logic has changed since the database was last written."""
    version = stored_version(con)
    if version < DERIVED_VERSION:
        where, args = "", ()
        reason = "extraction logic changed (v%d -> v%d)" % (version, DERIVED_VERSION)
    else:
        where, args = " WHERE log_type IS NULL", ()
        reason = "new rows"

    total = con.execute("SELECT COUNT(*) FROM logs" + where, args).fetchone()[0]
    if total:
        app.logger.info("Deriving columns for %d rows (%s)...", total, reason)
        done = 0
        last_id = 0
        while True:
            rows = con.execute(
                "SELECT id, payload FROM logs" + (where or " WHERE 1=1")
                + " AND id > ? ORDER BY id LIMIT ?", args + (last_id, batch)
            ).fetchall()
            if not rows:
                break
            updates = []
            for row in rows:
                try:
                    payload = json.loads(row["payload"])
                except (ValueError, TypeError):
                    payload = {}
                updates.append(row_values(extract_fields(payload), row["id"]))
            con.executemany(UPDATE_SQL, updates)
            con.commit()
            last_id = rows[-1]["id"]
            done += len(rows)
            app.logger.info("  derived %d/%d", done, total)

    con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('derived_version', ?)",
                (str(DERIVED_VERSION),))
    con.commit()


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = connect()
    return db


@app.teardown_appcontext
def close_conn(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()


# --------------------------------------------------------------------------
# Payload extraction
# --------------------------------------------------------------------------

def _headers_get(headers, name):
    """Case-insensitive header lookup."""
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            if isinstance(value, list):
                return value[0] if value else None
            return value
    return None


# The `ai` block is keyed by plugin. Newer Kong writes ai.proxy / ai.mcp /
# ai.a2a; the original GA format used the full plugin name (ai["ai-proxy"]).
AI_KIND_KEYS = {
    "llm": ("proxy", "ai-proxy", "ai-proxy-advanced"),
    "mcp": ("mcp", "ai-mcp", "ai-mcp-proxy"),
    "a2a": ("a2a", "ai-a2a", "ai-a2a-proxy"),
}


# Feature plugins sit alongside ai.proxy. Naming is inconsistent between
# versions -- "sanitizer" and "compressor" are short, "ai-llm-as-judge" is the
# full plugin name -- so each is matched against a set of aliases.
FEATURE_KEYS = {
    "sanitizer": ("sanitizer", "ai-sanitizer", "ai-pii-sanitizer"),
    "compressor": ("compressor", "ai-compressor", "ai-prompt-compressor"),
    "judge": ("judge", "llm-as-judge", "ai-llm-as-judge"),
}


# --------------------------------------------------------------------------
# Client identification
# --------------------------------------------------------------------------

# Deliberately generic: the label falls out of the User-Agent itself rather
# than a lookup table, so an unrecognised client still names itself correctly
# ("claude-cli/1.2.3" -> "claude-cli"). PRETTY_CLIENTS is only a display
# override for names worth capitalising properly.
PRETTY_CLIENTS = {
    "insomnia": "Insomnia",
    "postmanruntime": "Postman",
    "curl": "curl",
    "wget": "Wget",
    "httpie": "HTTPie",
    "python-requests": "Python requests",
    "python-httpx": "Python httpx",
    "aiohttp": "aiohttp",
    "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK",
    "anthropic-sdk-python": "Anthropic SDK",
    "langchain": "LangChain",
    "llamaindex": "LlamaIndex",
    "node-fetch": "node-fetch",
    "axios": "axios",
    "undici": "undici",
    "go-http-client": "Go http",
    "okhttp": "OkHttp",
    "java": "Java",
    "grpc-go": "gRPC (Go)",
    "kong": "Kong",
    "claude-user": "Claude",
    "claude-cli": "Claude Code",
    "node": "Node.js",
    "volcano-sdk": "Volcano SDK",
}

BROWSER_ENGINES = (("edg", "Edge"), ("chrome", "Chrome"), ("firefox", "Firefox"),
                   ("safari", "Safari"))

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def classify_client(user_agent):
    """Return (label, version) for a User-Agent string."""
    if not isinstance(user_agent, str) or not user_agent.strip():
        return None, None
    ua = user_agent.strip()
    low = ua.lower()

    # Browsers pack several product tokens into one string, so the leading
    # token ("Mozilla") is meaningless -- look for the engine instead.
    if low.startswith("mozilla/"):
        for token, label in BROWSER_ENGINES:
            if token in low:
                match = re.search(token + r"/(\d+(?:\.\d+)*)", low)
                return label, match.group(1) if match else None
        return "Browser", None

    head = re.split(r"[/\s]", ua, 1)[0]
    rest = ua[len(head):]
    version_match = _VERSION_RE.search(rest)
    label = PRETTY_CLIENTS.get(head.lower(), head)
    return (label or None), (version_match.group(0) if version_match else None)


def feature_block(ai, feature):
    for key in FEATURE_KEYS[feature]:
        block = ai.get(key)
        if isinstance(block, dict):
            return block
    return None


def _num(value):
    """Coerce to int/float, treating '' and None as absent (not zero)."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _str_or_none(value):
    return value if isinstance(value, str) and value else None


def _int(value):
    n = _num(value)
    return int(n) if n is not None else None


def ai_block(ai):
    """Return (kind, block) for the AI plugin section, or ("api", {})."""
    for kind, keys in AI_KIND_KEYS.items():
        for key in keys:
            if key in ai and isinstance(ai.get(key), dict):
                return kind, ai[key]
            if key in ai:
                return kind, {}
    # Unrecognised plugin key: still AI traffic if anything carries a meta block.
    for key, block in ai.items():
        if isinstance(block, dict) and isinstance(block.get("meta"), dict):
            return "llm", block
    return "api", {}


def extract_fields(payload):
    """Pull the list-view columns out of a Kong http-log payload.

    Every lookup is defensive: log shapes vary between the http-log plugin, the
    AI proxy plugin and hand-rolled test posts.
    """
    if not isinstance(payload, dict):
        payload = {}

    req = payload.get("request") if isinstance(payload.get("request"), dict) else {}
    res = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    lat = payload.get("latencies") if isinstance(payload.get("latencies"), dict) else {}
    ai = payload.get("ai") if isinstance(payload.get("ai"), dict) else {}

    # Type
    # Key presence, not truthiness: an empty ai.mcp object still means MCP.
    log_type, block = ai_block(ai)

    # Provider and model live in the plugin's meta block. request_model is what
    # the caller asked for; response_model is what actually served it and can
    # be more specific (gpt-4o -> gpt-4o-2024-08-06), so prefer the request.
    meta = block.get("meta") if isinstance(block.get("meta"), dict) else {}
    provider = meta.get("provider_name")
    model = meta.get("request_model") or meta.get("response_model")

    # Fallback: AI Gateway echoes "provider/model" in this response header.
    if not (provider and model):
        hdr = _headers_get(res.get("headers"), "x-kong-llm-model")
        if isinstance(hdr, str) and hdr:
            head, _, tail = hdr.partition("/")
            provider = provider or (head if tail else None)
            model = model or (tail or head)

    # Consumer
    consumer = None
    cons = payload.get("consumer")
    if isinstance(cons, dict):
        consumer = cons.get("username") or cons.get("custom_id")
    if not consumer:
        consumer = payload.get("x-consumer-username")
    if not consumer:
        consumer = _headers_get(req.get("headers"), "x-consumer-username")
    if not consumer:
        consumer = _headers_get(payload.get("headers"), "x-consumer-username")
    if not consumer:
        ent = payload.get("authenticated_entity")
        if isinstance(ent, dict):
            consumer = ent.get("username")

    # Status
    status = res.get("status")
    if not isinstance(status, int):
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None

    # Latency (ms)
    latency = lat.get("request")
    if latency is None:
        latency = lat.get("total")
    if not isinstance(latency, int):
        try:
            latency = int(latency)
        except (TypeError, ValueError):
            latency = None

    uri = req.get("uri") or req.get("url")
    if isinstance(uri, str) and uri.startswith("http"):
        # Trim scheme+host so the column stays readable
        parts = uri.split("/", 3)
        uri = "/" + parts[3] if len(parts) > 3 else "/"

    # Usage. A semantic-cache hit reports zeros here and puts the real number
    # in cache.cost_savings, so zero is kept as a genuine value rather than
    # collapsed to null.
    usage = block.get("usage") if isinstance(block.get("usage"), dict) else {}
    cache = block.get("cache") if isinstance(block.get("cache"), dict) else {}

    sanitizer = feature_block(ai, "sanitizer") or {}
    compressor = feature_block(ai, "compressor") or {}
    judge = feature_block(ai, "judge") or {}

    tokens_saved = None
    items = compressor.get("compress_items")
    if isinstance(items, list) and items:
        saved = [_int(i.get("save_token_count")) for i in items if isinstance(i, dict)]
        saved = [v for v in saved if v is not None]
        tokens_saved = sum(saved) if saved else None

    sanitized_count = _int(sanitizer.get("sanitized"))
    if sanitized_count is None:
        sanitized_count = _int(sanitizer.get("identified"))

    judge_score = _num(usage.get("llm_accuracy"))
    if judge_score is None and judge:
        judge_score = _num(_headers_get(res.get("headers"), "x-kong-llm-accuracy-score"))

    user_agent = _headers_get(req.get("headers"), "user-agent")
    if not isinstance(user_agent, str) or not user_agent.strip():
        user_agent = None
    client, client_version = classify_client(user_agent)

    # MCP / A2A both log an rpc array. A single HTTP request usually carries
    # one JSON-RPC call, so the first entry drives the columns; the drawer
    # shows them all.
    rpc_method = tool_name = task_state = rpc_error = None
    mcp_session = _str_or_none(block.get("mcp_session_id"))
    rpc_entries = block.get("rpc")
    if isinstance(rpc_entries, list):
        for entry in rpc_entries:
            if not isinstance(entry, dict):
                continue
            rpc_method = rpc_method or _str_or_none(entry.get("method"))
            tool_name = tool_name or _str_or_none(entry.get("tool_name"))
            task_state = task_state or _str_or_none(entry.get("task_state"))
            if rpc_error is None:
                rpc_error = _str_or_none(entry.get("error"))

    cache_status = cache.get("cache_status")
    if not isinstance(cache_status, str) or not cache_status:
        hdr = _headers_get(res.get("headers"), "x-cache-status")
        cache_status = hdr if isinstance(hdr, str) and hdr else None
    if cache_status:
        cache_status = cache_status.lower()

    return {
        "log_type": log_type,
        "consumer": consumer if isinstance(consumer, str) else None,
        "status": status,
        "method": req.get("method") if isinstance(req.get("method"), str) else None,
        "uri": uri if isinstance(uri, str) else None,
        "latency": latency,
        "client_ip": payload.get("client_ip") if isinstance(payload.get("client_ip"), str) else None,
        "provider": provider if isinstance(provider, str) and provider else None,
        "model": model if isinstance(model, str) and model else None,
        "prompt_tokens": _int(usage.get("prompt_tokens")),
        "completion_tokens": _int(usage.get("completion_tokens")),
        "total_tokens": _int(usage.get("total_tokens")),
        "cost": _num(usage.get("cost")),
        "cache_status": cache_status,
        "sanitized_count": sanitized_count or None,
        "tokens_saved": tokens_saved,
        "judge_score": judge_score,
        "user_agent": user_agent,
        "client": client,
        "client_version": client_version,
        "rpc_method": rpc_method,
        "tool_name": tool_name,
        "mcp_session": mcp_session,
        "task_state": task_state,
        "rpc_error": rpc_error,
    }


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------

@app.route("/logs", methods=["POST"])
def ingest():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify(error="Body is not valid JSON"), 400

    # The http-log plugin sends a single object, or an array when queue
    # batching is enabled.
    records = data if isinstance(data, list) else [data]
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    rows = []
    for record in records:
        f = extract_fields(record)
        rows.append((ts, json.dumps(record)) + tuple(f[c] for c in COLUMN_ORDER))

    db = get_db()
    db.executemany(INSERT_SQL, rows)
    db.commit()

    # New rows must not sit behind a stale summary.
    global _ingest_version
    _ingest_version += 1
    return ("", 204)


# --------------------------------------------------------------------------
# List view
# --------------------------------------------------------------------------

def build_filters(args):
    """Turn query args into a WHERE clause plus the normalised filter state."""
    where, params = [], []

    range_key = args.get("range", DEFAULT_RANGE)
    if range_key not in TIME_RANGES:
        range_key = DEFAULT_RANGE
    delta = TIME_RANGES[range_key][1]
    if delta is not None:
        cutoff = datetime.now(timezone.utc) - delta
        # Timestamps are stored as ISO-8601 UTC, so string comparison is a
        # valid range comparison and can use the index.
        where.append("timestamp >= ?")
        params.append(cutoff.isoformat().replace("+00:00", "Z"))

    log_type = args.get("type", "all")
    if log_type not in TYPES:
        log_type = "all"
    if log_type != "all":
        where.append("log_type = ?")
        params.append(log_type)

    status_group = args.get("status", "all")
    if status_group == "2xx":
        where.append("status BETWEEN 200 AND 299")
    elif status_group == "4xx":
        where.append("status BETWEEN 400 AND 499")
    elif status_group == "5xx":
        where.append("status BETWEEN 500 AND 599")
    elif status_group == "error":
        where.append("status >= 400")
    else:
        status_group = "all"

    provider = (args.get("provider") or "all").strip()
    if not in_scope("provider", log_type):
        provider = "all"
    if provider != "all":
        where.append("provider = ?")
        params.append(provider)

    model = (args.get("model") or "all").strip()
    if not in_scope("model", log_type):
        model = "all"
    if model != "all":
        where.append("model = ?")
        params.append(model)

    method = (args.get("method") or "all").strip()
    if not in_scope("method", log_type):
        method = "all"
    if method != "all":
        where.append("rpc_method = ?")
        params.append(method)

    tool = (args.get("tool") or "all").strip()
    if not in_scope("tool", log_type):
        tool = "all"
    if tool != "all":
        where.append("tool_name = ?")
        params.append(tool)

    feature = (args.get("feature") or "all").strip()
    if not in_scope(feature, log_type, FEATURE_SCOPE):
        feature = "all"
    if feature == "sanitizer":
        where.append("sanitized_count IS NOT NULL")
    elif feature == "compressor":
        where.append("tokens_saved IS NOT NULL")
    elif feature == "judge":
        where.append("judge_score IS NOT NULL")
    elif feature == "cache_hit":
        where.append("cache_status = 'hit'")
    elif feature == "cache_miss":
        where.append("cache_status IS NOT NULL AND cache_status != 'hit'")
    elif feature == "rpc_error":
        where.append("rpc_error IS NOT NULL")
    elif feature == "tool_call":
        where.append("tool_name IS NOT NULL")
    else:
        feature = "all"

    q = (args.get("q") or "").strip()
    if q:
        # Substring scan over payloads. Fine for the volumes this sink handles;
        # if it ever needs to scale, move to an FTS5 virtual table.
        where.append("payload LIKE ?")
        params.append(f"%{q}%")

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    state = {"range": range_key, "type": log_type, "status": status_group,
             "provider": provider, "model": model, "feature": feature,
             "method": method, "tool": tool, "q": q}
    return clause, params, state


@app.route("/")
def index():
    db = get_db()
    args = request.args

    clause, params, state = build_filters(args)

    try:
        per_page = int(args.get("per_page", DEFAULT_PAGE_SIZE))
    except ValueError:
        per_page = DEFAULT_PAGE_SIZE
    if per_page not in PAGE_SIZES:
        per_page = DEFAULT_PAGE_SIZE

    try:
        page = max(1, int(args.get("page", 1)))
    except ValueError:
        page = 1

    # Exact totals need a full scan when a text search is active, so skip them
    # and probe for one extra row instead.
    if state["q"]:
        total = None
    else:
        total = db.execute(f"SELECT COUNT(*) FROM logs{clause}", params).fetchone()[0]
        last_page = max(1, math.ceil(total / per_page))
        page = min(page, last_page)

    offset = (page - 1) * per_page
    rows = db.execute(
        f"""SELECT id, timestamp, log_type, consumer, status, method, uri,
                   latency, client_ip, provider, model, total_tokens, cost,
                   cache_status, sanitized_count, tokens_saved, judge_score,
                   user_agent, client, client_version, rpc_method, tool_name,
                   mcp_session, task_state, rpc_error
            FROM logs{clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?""",
        params + [per_page + 1, offset],
    ).fetchall()

    has_next = len(rows) > per_page
    rows = rows[:per_page]
    entries = [dict(r) for r in rows]

    if total is None:
        total_pages = None
        range_end = offset + len(entries)
    else:
        total_pages = max(1, math.ceil(total / per_page))
        range_end = min(offset + per_page, total)

    grand_total = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    # Low-cardinality in practice (a handful of providers, tens of models) and
    # both columns are indexed, so this is cheap enough to run per request.
    providers = [r[0] for r in db.execute(
        "SELECT DISTINCT provider FROM logs WHERE provider IS NOT NULL ORDER BY provider")]
    models = [r[0] for r in db.execute(
        "SELECT DISTINCT model FROM logs WHERE model IS NOT NULL ORDER BY model")]
    methods = [r[0] for r in db.execute(
        "SELECT DISTINCT rpc_method FROM logs WHERE rpc_method IS NOT NULL ORDER BY rpc_method")]
    tools = [r[0] for r in db.execute(
        "SELECT DISTINCT tool_name FROM logs WHERE tool_name IS NOT NULL ORDER BY tool_name")]

    return render_template(
        "index.html",
        entries=entries,
        state=state,
        page=page,
        per_page=per_page,
        page_sizes=PAGE_SIZES,
        total=total,
        total_pages=total_pages,
        has_next=has_next,
        range_start=offset + 1 if entries else 0,
        range_end=range_end,
        grand_total=grand_total,
        providers=providers,
        models=models,
        methods=methods,
        tools=tools,
        filter_scope=FILTER_SCOPE,
        feature_scope=FEATURE_SCOPE,
        time_ranges=[(k, v[0]) for k, v in TIME_RANGES.items()],
    )


@app.route("/api/logs/<int:log_id>")
def log_detail(log_id):
    """Full payload for one entry, fetched on demand when a row is opened."""
    row = get_db().execute(
        "SELECT id, timestamp, payload FROM logs WHERE id = ?", (log_id,)
    ).fetchone()
    if row is None:
        abort(404)
    try:
        payload = json.loads(row["payload"])
    except (ValueError, TypeError):
        return jsonify(id=row["id"], timestamp=row["timestamp"],
                       payload={"_error": "Stored payload is not valid JSON",
                                "_raw": row["payload"]},
                       detail={"sections": [], "overview": {}, "chips": []})

    return jsonify(
        id=row["id"],
        timestamp=row["timestamp"],
        payload=payload,
        detail=detail_builder.build_detail(payload, ai_block, feature_block),
    )


# --------------------------------------------------------------------------
# Sidebar summary
# --------------------------------------------------------------------------
#
# Aggregates are cheap at demo scale (0.5 ms over 500 rows) but cost hundreds of
# milliseconds over a few hundred thousand, so they are served from a separate
# endpoint the sidebar fetches after the page renders, behind a short cache.
# The page itself never waits on them.

SUMMARY_TTL = 30.0
SUMMARY_TTL_SHORT = 5.0        # for windows measured in minutes
SHORT_RANGES = ("5m", "15m")
SUMMARY_CACHE_MAX = 32
_summary_cache = {}
_ingest_version = 0


def _compact(value):
    """1_234 -> 1.2k, keeping small numbers exact."""
    if value is None:
        return None
    value = float(value)
    for limit, suffix in ((1e9, "b"), (1e6, "m"), (1e3, "k")):
        if abs(value) >= limit:
            scaled = value / limit
            return ("%.1f" % scaled).rstrip("0").rstrip(".") + suffix
    return "{:,}".format(int(round(value)))


def _money(value):
    if value is None:
        return None
    if value == 0:
        return "$0"
    if value < 0.01:
        return "$" + ("%.4f" % value).rstrip("0")
    return "$" + "{:,.2f}".format(value)


def _bars(rows, key, formatter=_compact):
    """[(label, value)] -> bar items scaled against the largest."""
    rows = [(label, value) for label, value in rows if label and value]
    if not rows:
        return []
    top = max(value for _, value in rows) or 1
    return [{
        "label": label,
        "value": formatter(value),
        "pct": max(6, int(round(value / top * 100))),
        "key": key,
        "filter": label,
    } for label, value in rows]


def build_summary(db, args):
    clause, params, state = build_filters(args)
    log_type = state["type"]

    row = db.execute(f"""SELECT COUNT(*),
            SUM(total_tokens), SUM(cost),
            SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END),
            SUM(CASE WHEN cache_status = 'hit' THEN 1 ELSE 0 END),
            SUM(CASE WHEN cache_status IS NOT NULL THEN 1 ELSE 0 END),
            AVG(latency),
            COUNT(DISTINCT mcp_session),
            SUM(CASE WHEN tool_name IS NOT NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN rpc_error IS NOT NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN task_state = 'completed' THEN 1 ELSE 0 END),
            SUM(CASE WHEN task_state IS NOT NULL AND task_state != 'completed' THEN 1 ELSE 0 END)
        FROM logs{clause}""", params).fetchone()

    (total, tokens, cost, errors, cache_hits, cache_total, avg_latency,
     sessions, tool_calls, rpc_errors, tasks_done, tasks_other) = row

    if not total:
        return {"empty": True, "scope": "0 matching", "stats": [], "panels": []}

    def pct(part):
        return "%.1f%%" % (part / total * 100) if part else "0%"

    def scope_label(kind):
        return "%s %s request%s" % ("{:,}".format(total), kind, "" if total == 1 else "s")

    stats, panels = [], []

    if log_type == "llm":
        scope = scope_label("LLM")
        stats = [
            {"label": "Requests", "value": "{:,}".format(total)},
            {"label": "Tokens", "value": _compact(tokens) or "—"},
            {"label": "Cost", "value": _money(cost) or "—"},
            {"label": "Errors", "value": pct(errors), "tone": "err" if errors else ""},
        ]
        # The cache rate is out of requests that actually went through the
        # semantic-cache plugin, not out of all LLM traffic -- so it gets its
        # own full-width cell that states the denominator, rather than sitting
        # in the grid where it reads as a share of the request count.
        if cache_total:
            stats.append({
                "label": "Cache hit rate",
                "value": "%d%%" % round(cache_hits / cache_total * 100),
                "sub": "%s of %s cacheable request%s" % (
                    "{:,}".format(cache_hits), "{:,}".format(cache_total),
                    "" if cache_total == 1 else "s"),
                "tone": "ok" if cache_hits else "",
                "wide": True,
            })
    elif log_type == "mcp":
        scope = scope_label("MCP")
        stats = [
            {"label": "Requests", "value": "{:,}".format(total)},
            {"label": "Sessions", "value": "{:,}".format(sessions or 0)},
            {"label": "Tool calls", "value": "{:,}".format(tool_calls or 0)},
            {"label": "RPC errors", "value": "{:,}".format(rpc_errors or 0),
             "tone": "err" if rpc_errors else ""},
        ]
    elif log_type == "a2a":
        scope = scope_label("A2A")
        stats = [
            {"label": "Requests", "value": "{:,}".format(total)},
            {"label": "Tasks", "value": "{:,}".format((tasks_done or 0) + (tasks_other or 0))},
            {"label": "Completed", "value": "{:,}".format(tasks_done or 0), "tone": "ok"},
            {"label": "Unfinished", "value": "{:,}".format(tasks_other or 0),
             "tone": "err" if tasks_other else ""},
        ]
    else:
        scope = TIME_RANGES[state["range"]][0].lower()
        stats = [
            {"label": "Requests", "value": "{:,}".format(total)},
            {"label": "Tokens", "value": _compact(tokens) or "—"},
            {"label": "Cost", "value": _money(cost) or "—"},
            {"label": "Errors", "value": pct(errors), "tone": "err" if errors else ""},
        ]

    # Traffic mix, only meaningful when types are not already filtered.
    if log_type == "all":
        mix = db.execute(
            f"SELECT log_type, COUNT(*) FROM logs{clause} GROUP BY log_type", params).fetchall()
        order = {"llm": 0, "mcp": 1, "a2a": 2, "api": 3}
        items = sorted(((r[0] or "api", r[1]) for r in mix), key=lambda x: order.get(x[0], 9))
        if len(items) > 1:
            panels.append({"kind": "mix", "title": "Traffic", "items": [{
                "label": name.upper(), "value": "{:,}".format(count),
                "pct": round(count / total * 100, 2),
                "key": "type", "filter": name, "color": name,
            } for name, count in items]})

    def group(column, extra=""):
        return db.execute(
            f"SELECT {column}, {extra or 'COUNT(*)'} FROM logs{clause}"
            f"{' AND' if clause else ' WHERE'} {column} IS NOT NULL"
            f" GROUP BY 1 ORDER BY 2 DESC LIMIT 5", params).fetchall()

    if log_type in ("all", "llm"):
        rows = group("provider", "SUM(total_tokens)")
        bars = _bars([(r[0], r[1]) for r in rows], "provider")
        if bars:
            panels.append({"kind": "bars", "title": "Tokens by provider", "items": bars})

    if log_type == "llm":
        rows = group("model", "SUM(total_tokens)")
        bars = _bars([(r[0], r[1]) for r in rows], "model")
        if bars:
            panels.append({"kind": "bars", "title": "Top models", "items": bars})

    if log_type == "mcp":
        bars = _bars([(r[0], r[1]) for r in group("tool_name")], "tool", "{:,}".format)
        if bars:
            panels.append({"kind": "bars", "title": "Top tools", "items": bars, "accent": "alt"})

    if log_type in ("mcp", "a2a"):
        bars = _bars([(r[0], r[1]) for r in group("rpc_method")], "method", "{:,}".format)
        if bars:
            panels.append({"kind": "bars", "title": "Methods", "items": bars, "accent": "alt"})

    if log_type == "a2a":
        rows = group("task_state")
        items = [{"label": r[0], "value": "{:,}".format(r[1]),
                  "pct": round(r[1] / total * 100, 2), "key": "", "filter": "",
                  "color": "ok" if r[0] == "completed" else "err"} for r in rows]
        if items:
            panels.insert(0, {"kind": "mix", "title": "Task states", "items": items})

    return {"empty": False, "scope": scope, "stats": stats, "panels": panels}


@app.route("/api/summary")
def summary():
    key = (request.query_string, _ingest_version)
    now = time.time()
    ttl = (SUMMARY_TTL_SHORT if request.args.get("range") in SHORT_RANGES
           else SUMMARY_TTL)
    cached = _summary_cache.get(key)
    if cached and now - cached[0] < ttl:
        return jsonify(cached[1])

    data = build_summary(get_db(), request.args)

    if len(_summary_cache) >= SUMMARY_CACHE_MAX:
        _summary_cache.clear()
    _summary_cache[key] = (now, data)
    return jsonify(data)


def redact_payload(payload):
    """Blank credential headers and the sanitizer's captured original values.

    Returns (payload, list_of_paths_redacted) so the caller can report what
    changed rather than silently altering the data.
    """
    removed = []

    def scrub_headers(container, label):
        headers = container.get("headers")
        if not isinstance(headers, dict):
            return
        for key in list(headers):
            if isinstance(key, str) and key.lower() in SENSITIVE_HEADERS:
                headers[key] = "[REDACTED BY EXPORT]"
                removed.append(label + ".headers." + key)

    if isinstance(payload, dict):
        for label in ("request", "response"):
            if isinstance(payload.get(label), dict):
                scrub_headers(payload[label], label)

        ai = payload.get("ai")
        if isinstance(ai, dict):
            for name, block in ai.items():
                if not isinstance(block, dict):
                    continue
                for item in block.get("sanitized_items") or []:
                    if isinstance(item, dict) and item.get("original_text"):
                        item["original_text"] = "[REDACTED BY EXPORT]"
                        removed.append("ai." + name + ".sanitized_items[].original_text")

    return payload, sorted(set(removed))


@app.route("/api/export")
def export_logs():
    """Download selected logs, or everything matching the current filters.

    Emits a bare JSON array of raw payloads so the file can be posted straight
    back to /logs, or handed to someone else, without unwrapping.
    """
    db = get_db()
    args = request.args
    redact = args.get("redact", "1") != "0"

    raw_ids = (args.get("ids") or "").strip()
    if raw_ids:
        ids = []
        for part in raw_ids.split(","):
            part = part.strip()
            if part.isdigit():
                ids.append(int(part))
        ids = ids[:MAX_EXPORT]
        if not ids:
            return jsonify(error="No valid log ids supplied"), 400
        placeholders = ",".join("?" * len(ids))
        rows = db.execute(
            f"SELECT id, payload FROM logs WHERE id IN ({placeholders}) ORDER BY id DESC",
            ids,
        ).fetchall()
        scope = "selected"
    else:
        clause, params, _ = build_filters(args)
        rows = db.execute(
            f"SELECT id, payload FROM logs{clause} ORDER BY id DESC LIMIT ?",
            params + [MAX_EXPORT],
        ).fetchall()
        scope = "filtered"

    payloads, removed = [], []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            continue
        if redact:
            payload, paths = redact_payload(payload)
            removed.extend(paths)
        payloads.append(payload)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = "kong-logs-%s-%s-%d%s.json" % (
        stamp, scope, len(payloads), "-redacted" if redact else "")

    body = json.dumps(payloads, indent=2, ensure_ascii=False)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="%s"' % name,
            "X-Export-Count": str(len(payloads)),
            "X-Export-Truncated": "1" if len(rows) >= MAX_EXPORT else "0",
            "X-Export-Redacted": ",".join(sorted(set(removed))) if removed else "none",
        },
    )


@app.route("/healthz")
def healthz():
    return jsonify(status="ok", logs=get_db().execute("SELECT COUNT(*) FROM logs").fetchone()[0])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5015)