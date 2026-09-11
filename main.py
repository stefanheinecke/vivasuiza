import json
import os
import datetime
import uuid
import secrets
import re
from typing import Optional, List
from urllib.parse import urlencode
import smtplib
from email.message import EmailMessage

from fastapi import FastAPI, Form, Cookie, Response, Request
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
import psycopg2
from passlib.context import CryptContext
import hashlib
import requests

# helper to get connection using DATABASE_URL env variable
DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL=", DATABASE_URL)

# Google OAuth2 / OpenID Connect configuration (set these in your env)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# This must exactly match the redirect URI configured in Google Cloud console
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

def get_conn():
    # Expect DATABASE_URL to be set in production; raise otherwise
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    conn = psycopg2.connect(DATABASE_URL)
    print("established connection dsn", conn.dsn)
    return conn

# ensure subscriber table exists
def init_db():
    if not DATABASE_URL:
        return
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subscriber (
                email VARCHAR(255) PRIMARY KEY,
                subscription_date TIMESTAMP NOT NULL
            )
        """)
        # Keep compatibility with existing deployments while supporting subscription periods.
        cur.execute("ALTER TABLE subscriber ADD COLUMN IF NOT EXISTS start_date TIMESTAMP")
        cur.execute("ALTER TABLE subscriber ADD COLUMN IF NOT EXISTS end_date TIMESTAMP")
        cur.execute("""
            UPDATE subscriber
            SET start_date = COALESCE(start_date, subscription_date, NOW())
            WHERE start_date IS NULL
        """)
        cur.execute("ALTER TABLE subscriber ALTER COLUMN start_date SET NOT NULL")
        # users table for simple auth
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(150) PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS start_date TIMESTAMP")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS end_date TIMESTAMP")
        cur.execute("""
            UPDATE users
            SET start_date = COALESCE(start_date, created_at, NOW())
            WHERE start_date IS NULL
        """)
        cur.execute("ALTER TABLE users ALTER COLUMN start_date SET NOT NULL")
        # sessions table for server-side session IDs
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(100) PRIMARY KEY,
                username VARCHAR(150) REFERENCES users(username) ON DELETE CASCADE,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        # permissions table: which user can access which file
        cur.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                username VARCHAR(150) REFERENCES users(username) ON DELETE CASCADE,
                filename VARCHAR(255) NOT NULL,
                PRIMARY KEY (username, filename)
            )
        """)
        # Q&A questions table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150) NOT NULL,
                text TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            )
        """)
        # Q&A replies table (threaded)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS replies (
                id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                username VARCHAR(150) NOT NULL,
                text TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            )
        """)
        # OAuth state tokens (replaces cookie-based state to avoid cross-domain issues)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state VARCHAR(100) PRIMARY KEY,
                next_url TEXT NOT NULL DEFAULT '/',
                created_at TIMESTAMP NOT NULL
            )
        """)
        # One-time auth tokens for cross-domain session establishment
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token VARCHAR(100) PRIMARY KEY,
                username VARCHAR(150) NOT NULL,
                created_at TIMESTAMP NOT NULL
            )
        """)
        # Votes on checklist cards and questions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS votes (
                id SERIAL PRIMARY KEY,
                target_type VARCHAR(20) NOT NULL,
                target_id VARCHAR(100) NOT NULL,
                username VARCHAR(150) NOT NULL,
                vote SMALLINT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                UNIQUE(target_type, target_id, username)
            )
        """)
        # Module permissions: which user can access which content module
        cur.execute("""
            CREATE TABLE IF NOT EXISTS module_permissions (
                username VARCHAR(150) REFERENCES users(username) ON DELETE CASCADE,
                module VARCHAR(50) NOT NULL,
                PRIMARY KEY (username, module)
            )
        """)
        # Analytics events (clicks + section time tracking)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                event_type VARCHAR(20) NOT NULL,
                section_id VARCHAR(120) NOT NULL,
                element VARCHAR(120),
                page_path VARCHAR(255),
                seconds INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("init_db error:", e)

init_db()


app = FastAPI()


def is_valid_email(value: str) -> bool:
    """Very simple email format check for usernames.

    This is intentionally minimal; it just enforces the general shape
    local-part@domain.tld without spaces.
    """
    if not value:
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))


def send_help_request_email(step: str, message: str, from_email: Optional[str]) -> bool:
    """Send a help request email to the site owner using an HTTP API.

    This implementation is designed for providers like Resend that expose
    a simple JSON HTTP endpoint. Returns True if the provider accepted
    the email, False otherwise.
    """
    to_address = os.getenv("HELP_REQUEST_EMAIL", "stefan.heinecke1@gmail.com")
    subject = f"VivaSuiza help request: {step[:80] if step else 'Checklist'}"

    lines = [
        f"Step/Section: {step}",
        f"From: {from_email or 'unknown'}",
        "",
        message,
        "",
        f"Received at: {datetime.datetime.utcnow().isoformat()} UTC",
    ]
    body = "\n".join(lines)

    api_key = os.getenv("RESEND_API_KEY")
    from_address = os.getenv("RESEND_FROM_EMAIL", to_address)

    if not api_key or not from_address:
        print("[HELP-REQUEST] Email HTTP API not configured; logging only.")
        print("[HELP-REQUEST] To:", to_address)
        print("[HELP-REQUEST] Subject:", subject)
        print("[HELP-REQUEST] Body:\n" + body)
        return False

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_address,
                "to": [to_address],
                "subject": subject,
                "text": body,
            },
            timeout=10,
        )
        if 200 <= resp.status_code < 300:
            return True
        print("Error sending help request via HTTP API:", resp.status_code, resp.text)
        return False
    except Exception as e:
        print("Error sending help request via HTTP API:", e)
        return False


# List all users and their permissions (for admin UI)
@app.get("/admin/list_users")
def admin_list_users(session_id: str = Cookie(None)):
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, is_admin FROM users")
        users = cur.fetchall()
        cur.execute("SELECT username, filename FROM permissions")
        perms = cur.fetchall()
        cur.execute("SELECT username, module FROM module_permissions")
        mod_perms = cur.fetchall()
        cur.close()
        conn.close()
        # Build user-permissions map. Include default/free module access for all users.
        user_map = [
            {"username": u[0], "is_admin": u[1], "files": [], "modules": list(FREE_MODULES)}
            for u in users
        ]
        user_dict = {u["username"]: u for u in user_map}
        for username, filename in perms:
            if username in user_dict:
                user_dict[username]["files"].append(filename)
        for username, module in mod_perms:
            if username in user_dict:
                if module not in user_dict[username]["modules"]:
                    user_dict[username]["modules"].append(module)
        return {"users": user_map}
    except Exception as e:
        return {"error": str(e)}


@app.post("/analytics/track")
async def analytics_track(request: Request, session_id: str = Cookie(None)):
    """Collect click/time analytics events from the frontend."""
    username = get_username_from_session(session_id) if session_id else None
    try:
        payload = await request.json()
    except Exception:
        return {"error": "invalid_payload"}

    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict):
        events = payload.get("events", [])
    else:
        return {"error": "invalid_payload"}

    if not isinstance(events, list):
        return {"error": "invalid_payload"}

    inserted = 0
    try:
        conn = get_conn()
        cur = conn.cursor()
        now = datetime.datetime.utcnow()
        for event in events[:200]:
            if not isinstance(event, dict):
                continue
            event_type = str(event.get("type", "")).strip().lower()
            if event_type not in {"click", "time"}:
                continue

            section_id = str(event.get("section_id", "unknown")).strip()[:120] or "unknown"
            element = str(event.get("element", "")).strip()[:120] or None
            page_path = str(event.get("page_path", "")).strip()[:255] or None

            seconds = 0
            if event_type == "time":
                try:
                    seconds = int(float(event.get("seconds", 0)))
                except Exception:
                    seconds = 0
                if seconds < 1:
                    continue
                seconds = min(seconds, 3600)

            cur.execute(
                """
                INSERT INTO analytics_events (username, event_type, section_id, element, page_path, seconds, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (username, event_type, section_id, element, page_path, seconds, now),
            )
            inserted += 1

        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok", "inserted": inserted}
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/analytics/overview")
def admin_analytics_overview(session_id: str = Cookie(None)):
    """Admin analytics dashboard data: top clicks/time by section and by user."""
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT section_id, COUNT(*) AS clicks
            FROM analytics_events
            WHERE event_type = 'click'
            GROUP BY section_id
            ORDER BY clicks DESC
            LIMIT 20
            """
        )
        clicks_by_section = [{"section_id": r[0], "clicks": int(r[1])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT section_id, COALESCE(SUM(seconds), 0) AS total_seconds
            FROM analytics_events
            WHERE event_type = 'time'
            GROUP BY section_id
            ORDER BY total_seconds DESC
            LIMIT 20
            """
        )
        time_by_section = [{"section_id": r[0], "seconds": int(r[1])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT COALESCE(username, 'anonymous') AS actor, COUNT(*) AS clicks
            FROM analytics_events
            WHERE event_type = 'click'
            GROUP BY actor
            ORDER BY clicks DESC
            LIMIT 20
            """
        )
        clicks_by_user = [{"username": r[0], "clicks": int(r[1])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT COALESCE(username, 'anonymous') AS actor, COALESCE(SUM(seconds), 0) AS total_seconds
            FROM analytics_events
            WHERE event_type = 'time'
            GROUP BY actor
            ORDER BY total_seconds DESC
            LIMIT 20
            """
        )
        time_by_user = [{"username": r[0], "seconds": int(r[1])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT DISTINCT COALESCE(username, 'anonymous') AS actor
            FROM analytics_events
            ORDER BY actor ASC
            """
        )
        users = [r[0] for r in cur.fetchall()]

        cur.close()
        conn.close()
        return {
            "clicks_by_section": clicks_by_section,
            "time_by_section": time_by_section,
            "clicks_by_user": clicks_by_user,
            "time_by_user": time_by_user,
            "users": users,
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/analytics/user")
def admin_analytics_user(username: str, session_id: str = Cookie(None)):
    """Admin drill-down: selected user's clicks/time by section."""
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()

        if username == "anonymous":
            cur.execute(
                """
                SELECT section_id, COUNT(*) AS clicks
                FROM analytics_events
                WHERE event_type = 'click' AND username IS NULL
                GROUP BY section_id
                ORDER BY clicks DESC
                LIMIT 20
                """
            )
            clicks_by_section = [{"section_id": r[0], "clicks": int(r[1])} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT section_id, COALESCE(SUM(seconds), 0) AS total_seconds
                FROM analytics_events
                WHERE event_type = 'time' AND username IS NULL
                GROUP BY section_id
                ORDER BY total_seconds DESC
                LIMIT 20
                """
            )
            time_by_section = [{"section_id": r[0], "seconds": int(r[1])} for r in cur.fetchall()]
        else:
            cur.execute(
                """
                SELECT section_id, COUNT(*) AS clicks
                FROM analytics_events
                WHERE event_type = 'click' AND username = %s
                GROUP BY section_id
                ORDER BY clicks DESC
                LIMIT 20
                """,
                (username,),
            )
            clicks_by_section = [{"section_id": r[0], "clicks": int(r[1])} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT section_id, COALESCE(SUM(seconds), 0) AS total_seconds
                FROM analytics_events
                WHERE event_type = 'time' AND username = %s
                GROUP BY section_id
                ORDER BY total_seconds DESC
                LIMIT 20
                """,
                (username,),
            )
            time_by_section = [{"section_id": r[0], "seconds": int(r[1])} for r in cur.fetchall()]

        cur.close()
        conn.close()
        return {
            "username": username,
            "clicks_by_section": clicks_by_section,
            "time_by_section": time_by_section,
        }
    except Exception as e:
        return {"error": str(e)}

# Helper to check if session user is admin
def is_admin_user(session_id: str):
    user = get_username_from_session(session_id)
    if not user:
        return False
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (user,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row and row[0]
    except Exception:
        return False


def get_username_from_session(session_id: str):
    try:
        conn = get_conn()
        cur = conn.cursor()
        # cleanup expired sessions first
        cur.execute("DELETE FROM sessions WHERE expires_at < %s", (datetime.datetime.utcnow(),))
        cur.execute(
            """
            SELECT s.username
            FROM sessions s
            JOIN users u ON u.username = s.username
            WHERE s.session_id = %s
              AND (u.end_date IS NULL OR u.end_date > NOW())
            """,
            (session_id,),
        )
        row = cur.fetchone()
        cur.close()
        conn.commit()
        conn.close()
        if row:
            return row[0]
    except Exception as e:
        print("session lookup error", e)
    return None


def create_session_record(username: str) -> str:
    """Create a new session row for the given user and return session_id."""
    session_id = secrets.token_urlsafe(32)
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    conn2 = get_conn()
    cur2 = conn2.cursor()
    cur2.execute(
        "INSERT INTO sessions (session_id, username, created_at, expires_at) VALUES (%s, %s, %s, %s)",
        (session_id, username, datetime.datetime.utcnow(), expires),
    )
    conn2.commit()
    cur2.close()
    conn2.close()
    return session_id


def set_session_cookie(response: Response, session_id: str) -> None:
    # SameSite=None so the cookie also works when frontend is served from another domain
    response.set_cookie(
        "session_id",
        session_id,
        max_age=86400,
        path="/",
        httponly=True,
        secure=True,
        samesite="none",
    )

# password hashing context: use bcrypt_sha256 to avoid bcrypt's 72-byte password limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
print(pwd_context.schemes())

# Valid module identifiers for the freemium gating system
VALID_MODULES = {"basic", "housing", "pillars", "insurance", "taxes"}
# Modules that are free (no permission required)
FREE_MODULES = set(VALID_MODULES)
ALLOWED_DOC_FILES = ["doc1.pdf", "doc2.pdf"]

# check whether a given username has permission for a filename
def user_has_permission(username: str, filename: str) -> bool:
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM permissions WHERE username = %s AND filename = %s", (username, filename))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return bool(row)
    except Exception as e:
        print("permission check error", e)
        return False

# CORS erlauben, damit dein HTML/JS im Browser zugreifen darf
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # für Entwicklung ok
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/me")
def get_me(session_id: str = Cookie(None)):
    """Return current user info including admin status and module permissions."""
    username = get_username_from_session(session_id) if session_id else None
    normalized_username = username.strip().lower() if username else None
    if not username:
        return {
            "user": None,
            "is_admin": False,
            "modules": list(FREE_MODULES),
            "is_subscriber": False,
            "doc_files": [],
        }
    admin = False
    modules = list(FREE_MODULES)
    is_subscriber = False
    doc_files: list[str] = []
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        admin = bool(row and row[0])
        if admin:
            modules = list(VALID_MODULES)
            doc_files = list(ALLOWED_DOC_FILES)
        else:
            cur.execute("SELECT module FROM module_permissions WHERE username = %s", (username,))
            granted = {r[0] for r in cur.fetchall()}
            modules = list(FREE_MODULES | granted)
            cur.execute("SELECT filename FROM permissions WHERE username = %s", (username,))
            doc_files = [r[0] for r in cur.fetchall() if r and r[0] in ALLOWED_DOC_FILES]
        cur.execute(
            """
            SELECT 1
            FROM subscriber
            WHERE LOWER(email) = %s
              AND (end_date IS NULL OR end_date > NOW())
            """,
            (normalized_username,),
        )
        is_subscriber = bool(cur.fetchone())
        cur.close()
        conn.close()
    except Exception:
        pass
    return {
        "user": username,
        "is_admin": admin,
        "modules": modules,
        "is_subscriber": is_subscriber,
        "doc_files": doc_files,
    }

@app.get("/")
def get_root():
    return FileResponse("index.html")


@app.get("/topics/{topic}")
def get_topic_page(topic: str):
    allowed_topics = {"moving", "arrival", "housing", "pillars", "insurance", "taxes"}
    if topic not in allowed_topics:
        return RedirectResponse(url="/")
    return FileResponse("topic.html")


@app.get("/admin")
def get_admin_html(session_id: str = Cookie(None)):
    # optionally restrict the admin UI itself to admin users
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    return FileResponse("admin.html")

@app.post("/subscriber")
def post_subscriber(request: Request):
    session_id = request.cookies.get("session_id")
    username = get_username_from_session(session_id) if session_id else None
    if not username:
        return {"error": "not_logged_in"}
    normalized_username = username.strip().lower()
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Check if already actively subscribed (end_date is null or in the future).
        cur.execute(
            """
            SELECT 1
            FROM subscriber
            WHERE LOWER(email) = %s
              AND (end_date IS NULL OR end_date > NOW())
            """,
            (normalized_username,),
        )
        if cur.fetchone():
            cur.close()
            conn.close()
            return {"status": "ok", "already": True}
        cur.execute(
            """
            INSERT INTO subscriber (email, subscription_date, start_date, end_date)
            VALUES (%s, %s, %s, NULL)
            ON CONFLICT (email) DO UPDATE
            SET subscription_date = EXCLUDED.subscription_date,
                start_date = EXCLUDED.start_date,
                end_date = NULL
            """,
            (normalized_username, datetime.datetime.utcnow(), datetime.datetime.utcnow())
        )
        conn.commit()
        # verify insertion and get active subscriber count
        cur.execute(
            "SELECT count(*) FROM subscriber WHERE end_date IS NULL OR end_date > NOW()"
        )
        count = cur.fetchone()[0]
        cur.close()
        conn.close()

        # Notify admin about new subscriber
        try:
            to_address = os.getenv("HELP_REQUEST_EMAIL", "stefan.heinecke1@gmail.com")
            api_key = os.getenv("RESEND_API_KEY")
            from_address = os.getenv("RESEND_FROM_EMAIL", to_address)
            print(f"[SUBSCRIBER-NOTIFY] api_key set: {bool(api_key)}, from: {from_address}, to: {to_address}")
            if api_key and from_address:
                resp = requests.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": from_address,
                        "to": [to_address],
                        "subject": "VivaSuiza: New community subscriber",
                        "text": f"New subscriber: {username}\nTotal subscribers: {count}\nTime: {datetime.datetime.utcnow().isoformat()} UTC",
                    },
                    timeout=10,
                )
                print(f"[SUBSCRIBER-NOTIFY] Resend response: {resp.status_code} {resp.text}")
            else:
                print("[SUBSCRIBER-NOTIFY] Email not configured, skipping notification")
        except Exception as mail_err:
            print("Error notifying admin about new subscriber:", mail_err)

        return {"status": "ok", "count": count}
    except Exception as e:
        return {"error": str(e)}


@app.post("/subscriber/end")
def end_subscriber(request: Request):
    session_id = request.cookies.get("session_id")
    username = get_username_from_session(session_id) if session_id else None
    if not username:
        return {"error": "not_logged_in"}
    normalized_username = username.strip().lower()
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE subscriber
            SET end_date = NOW()
            WHERE LOWER(email) = %s
              AND (end_date IS NULL OR end_date > NOW())
            """,
            (normalized_username,),
        )
        ended = cur.rowcount > 0
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok", "ended": ended}
    except Exception as e:
        return {"error": str(e)}


@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    try:
        print("Start register")
        # enforce that username is an email address
        if not is_valid_email(username):
            return {"error": "invalid_email"}
        normalized_username = username.strip().lower()
        conn = get_conn()
        cur = conn.cursor()
        # check whether user exists; allow reactivation for ended users
        cur.execute(
            "SELECT username, end_date FROM users WHERE LOWER(username) = %s",
            (normalized_username,),
        )
        existing = cur.fetchone()
        if existing and (existing[1] is None or existing[1] > datetime.datetime.utcnow()):
            cur.close()
            conn.close()
            return {"error": "user_exists"}

        # avoid bcrypt length limit by pre-hashing long passwords
        pw_bytes = password.encode('utf-8')
        if len(pw_bytes) > 72:
            to_hash = hashlib.sha256(pw_bytes).hexdigest()
        else:
            to_hash = password
        pwd_hash = pwd_context.hash(to_hash)
        if existing:
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s,
                    start_date = %s,
                    end_date = NULL
                WHERE LOWER(username) = %s
                """,
                (pwd_hash, datetime.datetime.utcnow(), normalized_username),
            )
        else:
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at, start_date, end_date) VALUES (%s, %s, %s, %s, NULL)",
                (normalized_username, pwd_hash, datetime.datetime.utcnow(), datetime.datetime.utcnow())
            )
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), response: Response = None):
    try:
        normalized_username = username.strip().lower()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, end_date FROM users WHERE LOWER(username) = %s",
            (normalized_username,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return {"error": "invalid_credentials"}
        pwd_hash = row[0]
        end_date = row[1]
        if end_date is not None and end_date <= datetime.datetime.utcnow():
            return {"error": "account_inactive"}
        # apply same pre-hash rule when verifying
        pw_try = password
        if len(password.encode('utf-8')) > 72:
            pw_try = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if not pwd_context.verify(pw_try, pwd_hash):
            return {"error": "invalid_credentials"}
        # create server-side session record
        session_id = create_session_record(normalized_username)
        if response is not None:
            set_session_cookie(response, session_id)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/user/end")
def end_user_account(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    username = get_username_from_session(session_id) if session_id else None
    if not username:
        return {"error": "not_logged_in"}
    normalized_username = username.strip().lower()
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT is_admin FROM users WHERE LOWER(username) = %s",
            (normalized_username,),
        )
        row = cur.fetchone()
        if row and bool(row[0]):
            cur.close()
            conn.close()
            return {"error": "admin_cannot_deactivate"}
        cur.execute(
            """
            UPDATE users
            SET end_date = NOW()
            WHERE LOWER(username) = %s
              AND (end_date IS NULL OR end_date > NOW())
            """,
            (normalized_username,),
        )
        ended = cur.rowcount > 0
        cur.execute(
            "DELETE FROM sessions WHERE username = %s",
            (normalized_username,),
        )
        conn.commit()
        cur.close()
        conn.close()
        response.delete_cookie("session_id", path="/")
        return {"status": "ok", "ended": ended}
    except Exception as e:
        return {"error": str(e)}

@app.get("/download/{filename}")
def download_doc(filename: str, session_id: str = Cookie(None)):
    try:
        # lookup user by session id
        user = get_username_from_session(session_id) if session_id else None
        if not user:
            return {"error": "unauthorized"}
        # Only allow specific filenames (whitelist)
        allowed_files = ["doc1.pdf", "doc2.pdf"]
        if filename not in allowed_files:
            return {"error": "not_found"}
        # check user permission for this file
        if not user_has_permission(user, filename):
            return {"error": "forbidden"}
        file_path = os.path.join("download", filename)
        if not os.path.exists(file_path):
            return {"error": "file_not_found"}
        return FileResponse(file_path, media_type="application/pdf", filename=filename)
    except Exception as e:
        return {"error": str(e)}

@app.post("/logout")
def logout(response: Response, session_id: str = Cookie(None)):
    try:
        if session_id:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("DELETE FROM sessions WHERE session_id = %s", (session_id,))
            conn.commit()
            cur.close()
            conn.close()
        # clear cookie
        response.delete_cookie("session_id", path="/")
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/help-request")
def help_request(
    step: str = Form(...),
    message: str = Form(...),
    from_email: Optional[str] = Form(None),
    session_id: Optional[str] = Cookie(None),
):
    """Receive a help request from the checklist and forward it via email."""
    try:
        # derive email from session if not explicitly provided
        user_email: Optional[str] = None
        if from_email and is_valid_email(from_email):
            user_email = from_email
        elif session_id:
            username = get_username_from_session(session_id)
            if username and is_valid_email(username):
                user_email = username

        clean_step = (step or "").strip() or "checklist"
        clean_message = (message or "").strip()
        if not clean_message:
            return {"error": "empty_message"}

        sent = send_help_request_email(clean_step, clean_message, user_email)
        if not sent:
            # surface an explicit error so the frontend can show a proper message
            return {"error": "email_send_failed"}
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/auth/google")
def google_login(next: str = "/"):
    """Start Google OAuth2 login flow by redirecting to Google's consent screen."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        return {"error": "google_oauth_not_configured"}

    state = secrets.token_urlsafe(16)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": "openid email profile",
        "access_type": "offline",
        "include_granted_scopes": "true",
        "state": state,
    }
    # Store state + next URL in DB (avoids cross-domain cookie issues)
    try:
        conn = get_conn()
        cur = conn.cursor()
        # clean up expired states older than 10 minutes
        cur.execute("DELETE FROM oauth_states WHERE created_at < %s",
                     (datetime.datetime.utcnow() - datetime.timedelta(minutes=10),))
        cur.execute(
            "INSERT INTO oauth_states (state, next_url, created_at) VALUES (%s, %s, %s)",
            (state, next, datetime.datetime.utcnow()),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return {"error": f"state_store_failed: {e}"}

    return RedirectResponse(url=f"{GOOGLE_AUTH_URL}?{urlencode(params)}")


@app.get("/auth/google/callback")
def google_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
):
    """Handle Google's callback, create a local user+session, and redirect back."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        return {"error": "google_oauth_not_configured"}

    if not code or not state:
        return {"error": "invalid_oauth_state"}

    # Look up and consume state from DB
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT next_url FROM oauth_states WHERE state = %s", (state,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return {"error": "invalid_oauth_state"}
        oauth_next = row[0] or "/"
        cur.execute("DELETE FROM oauth_states WHERE state = %s", (state,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return {"error": f"state_lookup_failed: {e}"}

    # Exchange authorization code for tokens
    try:
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_resp = requests.post(GOOGLE_TOKEN_URL, data=token_data, timeout=10)
        token_resp.raise_for_status()
        token_json = token_resp.json()
    except Exception as e:
        return {"error": f"token_exchange_failed: {e}"}

    access_token = token_json.get("access_token")
    if not access_token:
        return {"error": "no_access_token"}

    # Fetch user info (email, etc.)
    try:
        userinfo_resp = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        info = userinfo_resp.json()
    except Exception as e:
        return {"error": f"userinfo_failed: {e}"}

    email = info.get("email")
    if not email:
        return {"error": "email_not_provided"}

    username = email  # map Google account to local username by email

    # Ensure local user exists (create one if missing, with a random password hash)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if not row:
            # create a user that can only log in via Google (random unknown password)
            random_pw = secrets.token_urlsafe(16)
            pwd_hash = pwd_context.hash(random_pw)
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (%s, %s, %s)",
                (username, pwd_hash, datetime.datetime.utcnow()),
            )
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return {"error": f"user_upsert_failed: {e}"}

    # Create a normal server-side session and set cookie
    session_id = create_session_record(username)
    redirect_target = oauth_next or "/"

    # Generate a one-time auth token so the frontend can establish a session
    # cookie on whatever domain it's served from (cross-domain fix)
    auth_token = secrets.token_urlsafe(32)
    try:
        conn2 = get_conn()
        cur2 = conn2.cursor()
        # clean up expired tokens older than 5 minutes
        cur2.execute("DELETE FROM auth_tokens WHERE created_at < %s",
                     (datetime.datetime.utcnow() - datetime.timedelta(minutes=5),))
        cur2.execute(
            "INSERT INTO auth_tokens (token, username, created_at) VALUES (%s, %s, %s)",
            (auth_token, username, datetime.datetime.utcnow()),
        )
        conn2.commit()
        cur2.close()
        conn2.close()
    except Exception as e:
        print("auth_token store error:", e)

    # pass username and auth_token back so frontend can establish session on its domain
    if "?" in redirect_target:
        sep = "&"
    else:
        sep = "?"
    redirect_url = f"{redirect_target}{sep}user={username}&auth_token={auth_token}"
    response = RedirectResponse(url=redirect_url)
    set_session_cookie(response, session_id)
    return response


@app.post("/auth/token-login")
def token_login(token: str = Form(...)):
    """Exchange a one-time auth token for a session cookie on the current domain."""
    if not token:
        return {"error": "missing_token"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, created_at FROM auth_tokens WHERE token = %s", (token,)
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return {"error": "invalid_token"}
        username, created_at = row
        # Token must be less than 5 minutes old
        if (datetime.datetime.utcnow() - created_at).total_seconds() > 300:
            cur.execute("DELETE FROM auth_tokens WHERE token = %s", (token,))
            conn.commit()
            cur.close()
            conn.close()
            return {"error": "expired_token"}
        # Consume the token
        cur.execute("DELETE FROM auth_tokens WHERE token = %s", (token,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return {"error": f"token_login_failed: {e}"}

    # Create a session and set the cookie on the response (current domain)
    session_id = create_session_record(username)
    response = Response(
        content=json.dumps({"status": "ok", "user": username}),
        media_type="application/json",
    )
    set_session_cookie(response, session_id)
    return response


# Admin endpoints: grant/revoke permission
@app.post("/admin/grant_permission")
def admin_grant_permission(username: str = Form(...), filename: str = Form(...), session_id: str = Cookie(None)):
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO permissions (username, filename) VALUES (%s, %s) ON CONFLICT DO NOTHING", (username, filename))
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/admin/revoke_permission")
def admin_revoke_permission(username: str = Form(...), filename: str = Form(...), session_id: str = Cookie(None)):
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM permissions WHERE username = %s AND filename = %s", (username, filename))
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


# ── Module permission endpoints ────────────────────────────────

@app.post("/admin/grant_module")
def admin_grant_module(username: str = Form(...), module: str = Form(...), session_id: str = Cookie(None)):
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    if module not in VALID_MODULES:
        return {"error": "invalid_module"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO module_permissions (username, module) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (username, module),
        )
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/admin/revoke_module")
def admin_revoke_module(username: str = Form(...), module: str = Form(...), session_id: str = Cookie(None)):
    if not is_admin_user(session_id):
        return {"error": "unauthorized"}
    if module not in VALID_MODULES:
        return {"error": "invalid_module"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM module_permissions WHERE username = %s AND module = %s", (username, module))
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/request-module")
def request_module_access(
    module: str = Form(...),
    session_id: str = Cookie(None),
):
    """User requests access to a premium module. Sends email to admin."""
    username = get_username_from_session(session_id) if session_id else None
    if not username:
        return {"error": "not_logged_in"}
    if module not in VALID_MODULES:
        return {"error": "invalid_module"}
    if module in FREE_MODULES:
        return {"error": "already_free"}

    module_labels = {
        "housing": "Vivienda y trabajo (Housing & Jobs)",
        "pillars": "3-Pillar System (Vorsorge)",
        "insurance": "Insurance (Versicherung)",
        "taxes": "Taxes (Steuern)",
    }
    label = module_labels.get(module, module)
    subject = f"VivaSuiza module access request: {label}"
    body = "\n".join([
        f"User: {username}",
        f"Requested module: {label} ({module})",
        "",
        f"Please grant access in the admin panel.",
        "",
        f"Received at: {datetime.datetime.utcnow().isoformat()} UTC",
    ])

    to_address = os.getenv("HELP_REQUEST_EMAIL", "stefan.heinecke1@gmail.com")
    api_key = os.getenv("RESEND_API_KEY")
    from_address = os.getenv("RESEND_FROM_EMAIL", to_address)

    if not api_key or not from_address:
        print("[MODULE-REQUEST] Email not configured; logging only.")
        print("[MODULE-REQUEST]", body)
        return {"status": "ok"}

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_address,
                "to": [to_address],
                "subject": subject,
                "text": body,
            },
            timeout=10,
        )
        if 200 <= resp.status_code < 300:
            return {"status": "ok"}
        print("Error sending module request:", resp.status_code, resp.text)
        return {"error": "email_send_failed"}
    except Exception as e:
        print("Error sending module request:", e)
        return {"error": "email_send_failed"}


# ── Feedback form ──────────────────────────────────────────────

@app.post("/feedback")
def submit_feedback(
    email: str = Form(...),
    message: str = Form(...),
    name: Optional[str] = Form(None),
):
    """Receive feedback from a visitor and forward it to the site owner via email."""
    clean_email = (email or "").strip()
    if not is_valid_email(clean_email):
        return {"error": "invalid_email"}
    clean_message = (message or "").strip()
    if not clean_message or len(clean_message) > 2000:
        return {"error": "invalid_message"}
    clean_name = (name or "").strip()

    step = f"Feedback from {clean_name}" if clean_name else "Feedback"
    sent = send_help_request_email(step, clean_message, clean_email)
    if not sent:
        return {"error": "email_send_failed"}
    return {"status": "ok"}


# ── Voting endpoints ─────────────────────────────────────

@app.get("/votes/{target_type}/{target_id}")
def get_votes(target_type: str, target_id: str):
    """Return vote totals for a target."""
    if target_type not in ("card", "question"):
        return {"error": "invalid_type"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COALESCE(SUM(CASE WHEN vote=1 THEN 1 ELSE 0 END),0), "
            "COALESCE(SUM(CASE WHEN vote=-1 THEN 1 ELSE 0 END),0) "
            "FROM votes WHERE target_type=%s AND target_id=%s",
            (target_type, target_id),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        return {"up": row[0], "down": row[1]}
    except Exception as e:
        return {"error": str(e)}


@app.post("/votes/{target_type}/{target_id}")
def cast_vote(target_type: str, target_id: str, vote: int = Form(...), session_id: str = Cookie(None)):
    """Cast or change a vote (1=up, -1=down). Logged-in users only."""
    if target_type not in ("card", "question"):
        return {"error": "invalid_type"}
    if vote not in (1, -1):
        return {"error": "invalid_vote"}
    username = get_username_from_session(session_id) if session_id else None
    if not username:
        return {"error": "unauthorized"}
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Check existing vote
        cur.execute(
            "SELECT id, vote FROM votes WHERE target_type=%s AND target_id=%s AND username=%s",
            (target_type, target_id, username),
        )
        existing = cur.fetchone()
        if existing:
            if existing[1] == vote:
                # Same vote again = remove it
                cur.execute("DELETE FROM votes WHERE id=%s", (existing[0],))
            else:
                # Change vote
                cur.execute("UPDATE votes SET vote=%s WHERE id=%s", (vote, existing[0]))
        else:
            cur.execute(
                "INSERT INTO votes (target_type, target_id, username, vote, created_at) VALUES (%s,%s,%s,%s,%s)",
                (target_type, target_id, username, vote, datetime.datetime.utcnow()),
            )
        conn.commit()
        # Return updated totals
        cur.execute(
            "SELECT COALESCE(SUM(CASE WHEN vote=1 THEN 1 ELSE 0 END),0), "
            "COALESCE(SUM(CASE WHEN vote=-1 THEN 1 ELSE 0 END),0) "
            "FROM votes WHERE target_type=%s AND target_id=%s",
            (target_type, target_id),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "ok", "up": row[0], "down": row[1]}
    except Exception as e:
        return {"error": str(e)}


# ── PDF-based legal knowledge loader ─────────────────────────────────────────
# Reads OR_law.pdf (and any other PDFs listed) once at startup.
# Replace OR_law.pdf with the actual Swiss Obligationenrecht PDF from fedlex.
_PDF_LEGAL_FILES = ["OR_law.pdf"]
_pdf_legal_cache: str = ""


def _load_pdf_legal_knowledge() -> str:
    """Extract text from all configured legal PDF files and return combined text."""
    import pypdf
    parts: list = []
    for path in _PDF_LEGAL_FILES:
        if not os.path.exists(path):
            print(f"[LEGAL-PDF] File not found: {path}")
            continue
        try:
            reader = pypdf.PdfReader(path)
            text = "".join(page.extract_text() or "" for page in reader.pages)
            text = re.sub(r"\n{3,}", "\n\n", text).strip()
            parts.append(f"[Quelle: {path}]\n{text}")
            print(f"[LEGAL-PDF] Loaded {path}: {len(text)} chars, {len(reader.pages)} pages")
        except Exception as exc:
            print(f"[LEGAL-PDF] Failed to read {path}: {exc}")
    return "\n\n".join(parts)


# Load once at startup
_pdf_legal_cache = _load_pdf_legal_knowledge()
# Split into article-level chunks for retrieval (OR PDF uses \nArt. N boundaries)
_pdf_legal_paragraphs: list = []
if _pdf_legal_cache:
    # Split on article boundaries: "Art. NNN" at start of a token
    raw_chunks = re.split(r"(?=\bArt\.\s*\d+)", _pdf_legal_cache)
    _pdf_legal_paragraphs = [c.strip() for c in raw_chunks if len(c.strip()) > 40]
    print(f"[LEGAL-PDF] Indexed {len(_pdf_legal_paragraphs)} article chunks for retrieval")


def _get_relevant_legal_context(question: str, max_chars: int = 4000) -> str:
    """Return the most relevant paragraphs from the PDF for the given question.

    Uses simple keyword overlap scoring — no external ML dependencies.
    """
    if not _pdf_legal_paragraphs:
        return ""
    # Tokenise question into lowercase words (≥3 chars)
    q_words = set(w.lower() for w in re.findall(r"[a-zA-ZäöüÄÖÜß]{3,}", question))
    if not q_words:
        return ""

    scored: list = []
    for para in _pdf_legal_paragraphs:
        para_lower = para.lower()
        hits = sum(1 for w in q_words if w in para_lower)
        if hits > 0:
            scored.append((hits, para))

    # Sort by score descending, then take top paragraphs up to max_chars
    scored.sort(key=lambda x: x[0], reverse=True)
    selected: list = []
    total = 0
    for _, para in scored:
        if total + len(para) > max_chars:
            break
        selected.append(para)
        total += len(para)
    return "\n\n".join(selected)


class ChatRequest(BaseModel):
    question: str
    language: str = "es"
    history: list = []


@app.post("/chat")
def chat_endpoint(body: ChatRequest):
    question = body.question.strip()
    language = body.language
    history = body.history

    if not question:
        return {"error": "empty_question"}

    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        return {"error": "ai_not_configured"}

    # Build page context from translations
    try:
        with open("translations.json", "r", encoding="utf-8") as f:
            all_translations = json.load(f)
    except Exception:
        return {"error": "context_unavailable"}

    lang_data = all_translations.get(language, all_translations.get("es", {}))

    # Build context string from page content (skip UI-only keys)
    skip_prefixes = ("chat_", "search_", "auth_", "nav_", "footer_", "logo_")
    context_lines = []
    for key, value in lang_data.items():
        if any(key.startswith(p) for p in skip_prefixes):
            continue
        context_lines.append(f"- {value}")

    page_content = "\n".join(context_lines)

    # Retrieve relevant paragraphs from the legal PDF based on the question
    fedlex_text = _get_relevant_legal_context(question)
    legal_section = (
        "\n\nHere is relevant Swiss legal content fetched from fedlex.admin.ch:\n---\n"
        f"{fedlex_text}\n"
        "---"
    ) if fedlex_text else ""

    lang_names = {"es": "Spanish", "de": "German", "en": "English"}
    resp_lang = lang_names.get(language, "the user's language")

    system_prompt = (
        "You are VivaSuiza's friendly assistant. VivaSuiza helps people relocate from Spain to Switzerland.\n\n"
        "Here is the complete content of the VivaSuiza website:\n---\n"
        f"{page_content}\n"
        "---"
        f"{legal_section}\n\n"
        "Rules:\n"
        "1. Answer based on the website content and the Swiss legal content provided above. Do not invent information.\n"
        "2. If the answer is NOT found in the content above, respond with exactly and only: NO_ANSWER\n"
        "3. Be concise, helpful, and friendly. Use 2-4 sentences maximum.\n"
        f"4. Respond in {resp_lang}.\n"
        "5. You may use **bold** for emphasis on key terms.\n"
        "6. When citing Swiss law, reference the specific article and law name (e.g., 'Art. 3 AHVG')."
    )

    messages = [{"role": "system", "content": system_prompt}]

    # Add conversation history (limit to last 10 exchanges)
    for msg in history[-10:]:
        role = msg.get("role", "user") if isinstance(msg, dict) else "user"
        content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": content[:500]})

    messages.append({"role": "user", "content": question[:500]})

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": messages,
                "max_tokens": 300,
                "temperature": 0.3,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"[CHAT] OpenAI error: {resp.status_code} {resp.text}")
            return {"error": "ai_error"}

        data = resp.json()
        answer = data["choices"][0]["message"]["content"].strip()

        if answer == "NO_ANSWER" or answer.startswith("NO_ANSWER"):
            return {"answer": None, "no_answer": True}

        return {"answer": answer}
    except Exception as e:
        print(f"[CHAT] Error: {e}")
        return {"error": "ai_error"}


@app.get("/translations")
def get_translations():
    try:
        with open("translations.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        return {"error": "translations.json not found"}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {str(e)}"}
    except Exception as e:
        return {"error": str(e)} 
