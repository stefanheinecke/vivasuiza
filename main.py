import json
import os
import datetime
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


# password hashing context: use bcrypt_sha256 to avoid bcrypt's 72-byte password limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
print(pwd_context.schemes())

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
        # set a cookie so browser will send it on future requests
        if response is not None:
            response.set_cookie("loggedInUser", username, max_age=86400, path="/")
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/download/{filename}")
def download_doc(filename: str, loggedInUser: str = Cookie(None)):
    try:
        # Check if user is authenticated via cookie
        if not loggedInUser:
            return {"error": "unauthorized"}
        
        # Only allow specific filenames (whitelist)
        allowed_files = ["doc1.pdf", "doc2.pdf"]
        if filename not in allowed_files:
            return {"error": "not_found"}
        
        file_path = os.path.join("download", filename)
        if not os.path.exists(file_path):
            return {"error": "file_not_found"}
        
        return FileResponse(file_path, media_type="application/pdf", filename=filename)
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
