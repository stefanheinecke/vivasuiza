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
        cur.close()
        conn.close()
        # Build user-permissions map
        user_map = [
            {"username": u[0], "is_admin": u[1], "files": []}
            for u in users
        ]
        user_dict = {u["username"]: u for u in user_map}
        for username, filename in perms:
            if username in user_dict:
                user_dict[username]["files"].append(filename)
        return {"users": user_map}
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
import json
import os
import datetime
import uuid
import secrets
from fastapi import FastAPI, Form, Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import psycopg2
from passlib.context import CryptContext
import hashlib

# helper to get connection using DATABASE_URL env variable
DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL=", DATABASE_URL)

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
        # users table for simple auth
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(150) PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)
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
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("init_db error:", e)

init_db()


app = FastAPI()


def get_username_from_session(session_id: str):
    try:
        conn = get_conn()
        cur = conn.cursor()
        # cleanup expired sessions first
        cur.execute("DELETE FROM sessions WHERE expires_at < %s", (datetime.datetime.utcnow(),))
        cur.execute("SELECT username FROM sessions WHERE session_id = %s", (session_id,))
        row = cur.fetchone()
        cur.close()
        conn.commit()
        conn.close()
        if row:
            return row[0]
    except Exception as e:
        print("session lookup error", e)
    return None

# password hashing context: use bcrypt_sha256 to avoid bcrypt's 72-byte password limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
print(pwd_context.schemes())

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

@app.get("/")
def get_root():
    return FileResponse("index.html")

@app.post("/subscriber")
def post_subscriber(email: str = Form(...)):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO subscriber (email, subscription_date) VALUES (%s, %s)",
            (email, datetime.datetime.utcnow())
        )
        conn.commit()
        # verify insertion
        cur.execute("SELECT count(*) FROM subscriber")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {"status": "ok", "count": count}
    except Exception as e:
        return {"error": str(e)}


@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    try:
        print("Start register")
        conn = get_conn()
        cur = conn.cursor()
        # check exists
        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cur.fetchone():
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
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (%s, %s, %s)",
            (username, pwd_hash, datetime.datetime.utcnow())
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
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return {"error": "invalid_credentials"}
        pwd_hash = row[0]
        # apply same pre-hash rule when verifying
        pw_try = password
        if len(password.encode('utf-8')) > 72:
            pw_try = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if not pwd_context.verify(pw_try, pwd_hash):
            return {"error": "invalid_credentials"}
        # create server-side session record
        session_id = secrets.token_urlsafe(32)
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        conn2 = get_conn()
        cur2 = conn2.cursor()
        cur2.execute("INSERT INTO sessions (session_id, username, created_at, expires_at) VALUES (%s, %s, %s, %s)",
                     (session_id, username, datetime.datetime.utcnow(), expires))
        conn2.commit()
        cur2.close()
        conn2.close()
        if response is not None:
            response.set_cookie("session_id", session_id, max_age=86400, path="/", httponly=True, secure=True, samesite="Lax")
        return {"status": "ok"}
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
        file_path = os.path.join("docs", filename)
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
