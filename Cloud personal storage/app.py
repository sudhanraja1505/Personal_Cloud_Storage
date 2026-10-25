"""Personal Cloud File Storage - Flask + SQLite backend.
Run:  python -m pip install -r requirements.txt  then  python app.py
Cloud: replace the three storage helpers with S3 (boto3) and SQLite with PostgreSQL."""
import os, sqlite3, uuid, secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
import jwt
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
SECRET = os.environ.get("SECRET_KEY", "change-me-in-production")
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "storage.db"))
STORE = os.environ.get("STORE_DIR", os.path.join(BASE, "storage"))
QUOTA = 100 * 1024 * 1024          # per user
MAX_UPLOAD = 50 * 1024 * 1024      # per request
BLOCKED = {"exe", "bat", "cmd", "scr", "msi", "js", "vbs", "sh"}
os.makedirs(STORE, exist_ok=True)

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
  name TEXT NOT NULL, stored TEXT NOT NULL, size INTEGER NOT NULL, uploaded_at TEXT NOT NULL,
  share_token TEXT UNIQUE, share_expires TEXT);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

with sqlite3.connect(DB_PATH) as c:
    c.executescript(SCHEMA)

def utcnow(): return datetime.now(timezone.utc)

def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        try:
            p = jwt.decode(request.headers.get("Authorization", "").removeprefix("Bearer "), SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify(error="Please sign in again."), 401
        g.user = {"id": int(p["sub"]), "name": p["name"]}
        return fn(*a, **kw)
    return wrapper

def token_for(uid, name):
    return jwt.encode({"sub": str(uid), "name": name, "exp": utcnow() + timedelta(hours=12)}, SECRET, algorithm="HS256")

# ---- storage helpers (swap for S3: upload_fileobj / get_object / delete_object)
def user_dir(uid):
    p = os.path.join(STORE, str(uid)); os.makedirs(p, exist_ok=True); return p

def store_file(uid, f):
    stored = uuid.uuid4().hex
    path = os.path.join(user_dir(uid), stored); f.save(path)
    return stored, os.path.getsize(path)

def remove_file(uid, stored):
    try: os.remove(os.path.join(user_dir(uid), stored))
    except FileNotFoundError: pass

def send(uid, stored, name):
    return send_from_directory(user_dir(uid), stored, as_attachment=True, download_name=name)

def used(uid):
    return db().execute("SELECT COALESCE(SUM(size),0) FROM files WHERE user_id=?", (uid,)).fetchone()[0]

# ---- accounts
@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    if not all(d.get(k) for k in ("name", "email", "password")):
        return jsonify(error="Fill in name, email and password."), 400
    if len(d["password"]) < 6:
        return jsonify(error="Password must be at least 6 characters."), 400
    try:
        cur = db().execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                           (d["name"].strip(), d["email"].lower().strip(), generate_password_hash(d["password"])))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That email is already registered."), 409
    return jsonify(token=token_for(cur.lastrowid, d["name"].strip()), name=d["name"].strip())

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE email=?", (d.get("email", "").lower().strip(),)).fetchone()
    if not u or not check_password_hash(u["password"], d.get("password", "")):
        return jsonify(error="Email or password is incorrect."), 401
    return jsonify(token=token_for(u["id"], u["name"]), name=u["name"])

# ---- files
@app.get("/api/files")
@auth
def list_files():
    q = f"%{request.args.get('q', '').strip()}%"
    rows = db().execute("""SELECT id,name,size,uploaded_at,share_token,share_expires FROM files
                           WHERE user_id=? AND name LIKE ? ORDER BY uploaded_at DESC""", (g.user["id"], q))
    return jsonify(files=[dict(r) for r in rows], used=used(g.user["id"]), quota=QUOTA)

@app.post("/api/files")
@auth
def upload():
    files = [f for f in request.files.getlist("files") if f.filename]
    if not files: return jsonify(error="Choose at least one file."), 400
    uid, saved, skipped = g.user["id"], 0, []
    for f in files:
        name = secure_filename(f.filename) or "file"
        if name.rsplit(".", 1)[-1].lower() in BLOCKED:
            skipped.append(f"{name} (file type not allowed)"); continue
        stored, size = store_file(uid, f)
        if used(uid) + size > QUOTA:
            remove_file(uid, stored); skipped.append(f"{name} (storage full)"); continue
        db().execute("INSERT INTO files(user_id,name,stored,size,uploaded_at) VALUES(?,?,?,?,?)",
                     (uid, name, stored, size, utcnow().isoformat()))
        db().commit(); saved += 1
    return jsonify(saved=saved, skipped=skipped)

def own(fid):
    return db().execute("SELECT * FROM files WHERE id=? AND user_id=?", (fid, g.user["id"])).fetchone()

@app.get("/api/files/<int:fid>/download")
@auth
def download(fid):
    f = own(fid)
    if not f: return jsonify(error="File not found."), 404
    return send(g.user["id"], f["stored"], f["name"])

@app.patch("/api/files/<int:fid>")
@auth
def rename(fid):
    name = secure_filename((request.get_json(force=True).get("name") or "").strip())
    if not own(fid): return jsonify(error="File not found."), 404
    if not name: return jsonify(error="Enter a file name."), 400
    db().execute("UPDATE files SET name=? WHERE id=?", (name, fid)); db().commit()
    return jsonify(ok=True)

@app.delete("/api/files/<int:fid>")
@auth
def delete(fid):
    f = own(fid)
    if not f: return jsonify(error="File not found."), 404
    remove_file(g.user["id"], f["stored"])
    db().execute("DELETE FROM files WHERE id=?", (fid,)); db().commit()
    return jsonify(ok=True)

@app.post("/api/files/<int:fid>/share")
@auth
def share(fid):
    if not own(fid): return jsonify(error="File not found."), 404
    days = request.get_json(force=True).get("days")
    expires = (utcnow() + timedelta(days=int(days))).isoformat() if days else None
    tok = secrets.token_urlsafe(16)
    db().execute("UPDATE files SET share_token=?, share_expires=? WHERE id=?", (tok, expires, fid)); db().commit()
    return jsonify(token=tok, expires=expires)

@app.delete("/api/files/<int:fid>/share")
@auth
def unshare(fid):
    if not own(fid): return jsonify(error="File not found."), 404
    db().execute("UPDATE files SET share_token=NULL, share_expires=NULL WHERE id=?", (fid,)); db().commit()
    return jsonify(ok=True)

@app.get("/s/<token>")
def public_download(token):
    f = db().execute("SELECT * FROM files WHERE share_token=?", (token,)).fetchone()
    if not f or (f["share_expires"] and utcnow() > datetime.fromisoformat(f["share_expires"])):
        return "This link is invalid or has expired.", 404
    return send(f["user_id"], f["stored"], f["name"])

@app.errorhandler(413)
def too_big(_): return jsonify(error=f"Upload is larger than {MAX_UPLOAD // 1024 // 1024} MB."), 413

@app.get("/")
def index(): return app.send_static_file("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
