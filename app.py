#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sqlite3
import hashlib
import uuid
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import bcrypt
import httpx
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "guides.db")
FILES_DIR = os.path.join(DATA_DIR, "files")
_secret_file = os.path.join(DATA_DIR, ".secret_key")

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
BASE_URL             = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")

CATEGORIES = [
    ("tools",    "🛠 כלים ותוכנות"),
    ("guides",   "📚 מדריכים מעשיים"),
    ("tips",     "💡 טיפים וטריקים"),
    ("news",     "📰 חדשות ועדכונים"),
    ("strategy", "🎯 אסטרטגיה"),
    ("ethics",   "⚖️ אתיקה ובטיחות"),
]
CATEGORY_MAP = {k: v for k, v in CATEGORIES}

def _load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY", "")
    if env_key:
        return env_key
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(_secret_file):
        return open(_secret_file).read().strip()
    key = secrets.token_hex(32)
    with open(_secret_file, "w") as f:
        f.write(key)
    return key

SECRET_KEY         = _load_secret_key()
ALGORITHM          = "HS256"
TOKEN_EXPIRE_DAYS  = 7
USER_TOKEN_DAYS    = 30
MAX_FILE_MB        = 500

ALLOWED_EMOJIS = ["👍", "❤️", "🔥", "💡", "🎯", "🤯", "👏"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("ai-guides")

app = FastAPI()
os.makedirs(FILES_DIR, exist_ok=True)

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_super INTEGER DEFAULT 0,
            avatar TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT DEFAULT '',
            picture TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS allowed_editors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT '',
            added_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS guides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            cover_image TEXT DEFAULT '',
            category TEXT DEFAULT '',
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            is_published INTEGER DEFAULT 0,
            view_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS guide_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guide_id INTEGER NOT NULL,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime_type TEXT DEFAULT '',
            file_size INTEGER DEFAULT 0,
            display_order INTEGER DEFAULT 0,
            FOREIGN KEY (guide_id) REFERENCES guides(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guide_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            ip_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(guide_id, emoji, ip_hash)
        );
        """)
    _migrate()


def _migrate():
    """Add new columns to existing tables if they don't exist."""
    conn = get_db()
    try:
        for ddl in [
            "ALTER TABLE guides ADD COLUMN view_count INTEGER DEFAULT 0",
            "ALTER TABLE admins ADD COLUMN avatar TEXT DEFAULT ''",
            "ALTER TABLE guides ADD COLUMN category TEXT DEFAULT ''",
            """CREATE TABLE IF NOT EXISTS allowed_editors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                label TEXT DEFAULT '',
                added_at TEXT DEFAULT (datetime('now'))
            )""",
        ]:
            try:
                conn.execute(ddl)
                conn.commit()
            except Exception:
                pass
    finally:
        conn.close()


init_db()


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def create_admin_token(admin_id: int, username: str, is_super: bool) -> str:
    expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(admin_id), "username": username, "is_super": is_super,
         "type": "admin", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM
    )

def create_user_token(user_id: int, name: str, email: str, picture: str, is_editor: bool = False) -> str:
    expire = datetime.utcnow() + timedelta(days=USER_TOKEN_DAYS)
    return jwt.encode(
        {"sub": str(user_id), "name": name, "email": email,
         "picture": picture, "is_editor": is_editor, "type": "user", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM
    )

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def get_current_admin(request: Request) -> Optional[dict]:
    token = request.cookies.get("admin_token")
    if not token:
        return None
    d = decode_token(token)
    if d and d.get("type") == "admin":
        return d
    return None

def get_current_user(request: Request) -> Optional[dict]:
    """Returns user dict if logged in — either admin or Google user."""
    admin = get_current_admin(request)
    if admin:
        return {"id": admin["sub"], "name": admin["username"],
                "picture": "", "is_admin": True, "is_editor": True}
    token = request.cookies.get("user_token")
    if not token:
        return None
    d = decode_token(token)
    if d and d.get("type") == "user":
        return {"id": d["sub"], "name": d["name"],
                "picture": d.get("picture", ""),
                "is_admin": False, "is_editor": d.get("is_editor", False)}
    return None

def require_admin(request: Request) -> dict:
    """Requires username/password admin login."""
    admin = get_current_admin(request)
    if not admin:
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return admin

def require_editor(request: Request) -> dict:
    """Allows both admins and permitted Google editors."""
    admin = get_current_admin(request)
    if admin:
        return {"sub": admin["sub"], "username": admin["username"],
                "is_super": admin.get("is_super", False), "is_editor": False, "is_admin": True}
    token = request.cookies.get("user_token")
    if token:
        d = decode_token(token)
        if d and d.get("type") == "user" and d.get("is_editor"):
            return {"sub": d["sub"], "username": d["name"],
                    "is_super": False, "is_editor": True, "is_admin": False,
                    "picture": d.get("picture", "")}
    raise HTTPException(status_code=302, headers={"Location": "/admin/login"})

def google_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

def reaction_key(request: Request, user: Optional[dict]) -> str:
    if user:
        return hashlib.sha256(f"uid_{user['id']}".encode()).hexdigest()
    ip = request.headers.get("X-Forwarded-For", request.client.host or "unknown").split(",")[0].strip()
    return hashlib.sha256(ip.encode()).hexdigest()


# ─── Template helpers ─────────────────────────────────────────────────────────

def fmt_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"

def get_file_icon(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    icons = {
        ".pdf": "📄", ".doc": "📝", ".docx": "📝", ".txt": "📃",
        ".xls": "📊", ".xlsx": "📊", ".csv": "📊",
        ".ppt": "📊", ".pptx": "📊",
        ".jpg": "🖼", ".jpeg": "🖼", ".png": "🖼", ".gif": "🖼", ".webp": "🖼",
        ".mp4": "🎬", ".mov": "🎬", ".avi": "🎬", ".mkv": "🎬",
        ".mp3": "🎵", ".wav": "🎵", ".m4a": "🎵",
        ".zip": "🗜", ".rar": "🗜", ".7z": "🗜",
        ".py": "🐍", ".js": "⚡", ".html": "🌐", ".css": "🎨",
        ".json": "📋", ".xml": "📋",
    }
    return icons.get(ext, "📎")

import json as _json
templates.env.filters["fmt_size"]  = fmt_size
templates.env.filters["tojson"]    = lambda v: _json.dumps(v, ensure_ascii=False)
templates.env.globals["get_file_icon"] = get_file_icon
templates.env.globals["CATEGORIES"] = CATEGORIES
templates.env.globals["CATEGORY_MAP"] = CATEGORY_MAP


# ─── Landing / Auth ───────────────────────────────────────────────────────────

@app.get("/landing", response_class=HTMLResponse)
async def landing(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse("/")
    with get_db() as conn:
        member_count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "google_configured": google_configured(),
        "member_count": member_count,
        "error": request.query_params.get("error"),
    })

@app.get("/auth/google")
async def google_login():
    if not google_configured():
        return RedirectResponse("/")
    state = secrets.token_hex(16)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie("oauth_state", state, httponly=True, max_age=600, samesite="lax")
    return resp

@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    if error or not code:
        return RedirectResponse("/landing?error=1")
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        return RedirectResponse("/landing?error=1")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            token_resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": f"{BASE_URL}/auth/google/callback",
                    "grant_type": "authorization_code",
                }
            )
            tokens = token_resp.json()
            if "access_token" not in tokens:
                return RedirectResponse("/landing?error=1")
            user_resp = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
            guser = user_resp.json()
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        return RedirectResponse("/landing?error=1")

    google_id = guser.get("sub", "")
    name      = guser.get("name", guser.get("email", "משתמש"))
    email     = guser.get("email", "")
    picture   = guser.get("picture", "")

    # Check if this email is a permitted editor
    with get_db() as conn:
        is_editor = bool(
            conn.execute("SELECT id FROM allowed_editors WHERE lower(email)=lower(?)", (email,)).fetchone()
        )
        existing = conn.execute("SELECT id FROM users WHERE google_id=?", (google_id,)).fetchone()
        if existing:
            user_id = existing["id"]
            conn.execute("UPDATE users SET name=?, email=?, picture=? WHERE id=?",
                         (name, email, picture, user_id))
        else:
            cur = conn.execute(
                "INSERT INTO users (google_id, name, email, picture) VALUES (?,?,?,?)",
                (google_id, name, email, picture)
            )
            user_id = cur.lastrowid

    token = create_user_token(user_id, name, email, picture, is_editor=is_editor)
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie("user_token", token, httponly=True,
                    max_age=USER_TOKEN_DAYS * 86400, samesite="lax")
    resp.delete_cookie("oauth_state")
    return resp

@app.get("/auth/logout")
async def user_logout():
    resp = RedirectResponse("/landing", status_code=302)
    resp.delete_cookie("user_token")
    return resp


# ─── Public Routes ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = get_current_user(request)
    if not user and google_configured():
        return RedirectResponse("/landing")
    cat = request.query_params.get("cat", "")
    with get_db() as conn:
        if cat:
            guides = conn.execute("""
                SELECT g.*,
                    (SELECT COUNT(*) FROM guide_files WHERE guide_id = g.id) as file_count,
                    a.username as author_name, a.avatar as author_avatar
                FROM guides g
                LEFT JOIN admins a ON g.created_by = a.id
                WHERE g.is_published = 1 AND g.category = ?
                ORDER BY g.created_at DESC
            """, (cat,)).fetchall()
        else:
            guides = conn.execute("""
                SELECT g.*,
                    (SELECT COUNT(*) FROM guide_files WHERE guide_id = g.id) as file_count,
                    a.username as author_name, a.avatar as author_avatar
                FROM guides g
                LEFT JOIN admins a ON g.created_by = a.id
                WHERE g.is_published = 1
                ORDER BY g.created_at DESC
            """).fetchall()
        all_reactions = {}
        for g in guides:
            rows = conn.execute(
                "SELECT emoji, COUNT(*) as cnt FROM reactions WHERE guide_id=? GROUP BY emoji",
                (g["id"],)
            ).fetchall()
            all_reactions[g["id"]] = {r["emoji"]: r["cnt"] for r in rows}
        member_count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
        # Count per category for sidebar badges
        cat_counts = {row["category"]: row["cnt"] for row in conn.execute(
            "SELECT category, COUNT(*) as cnt FROM guides WHERE is_published=1 GROUP BY category"
        ).fetchall()}
    return templates.TemplateResponse("index.html", {
        "request": request,
        "guides": guides,
        "reactions": all_reactions,
        "allowed_emojis": ALLOWED_EMOJIS,
        "current_user": user,
        "member_count": member_count,
        "active_cat": cat,
        "cat_counts": cat_counts,
    })


@app.get("/guide/{guide_id}", response_class=HTMLResponse)
async def view_guide(request: Request, guide_id: int):
    user = get_current_user(request)
    if not user and google_configured():
        return RedirectResponse("/landing")
    with get_db() as conn:
        guide = conn.execute("""
            SELECT g.*, a.username as author_name, a.avatar as author_avatar
            FROM guides g
            LEFT JOIN admins a ON g.created_by = a.id
            WHERE g.id=? AND g.is_published=1
        """, (guide_id,)).fetchone()
        if not guide:
            raise HTTPException(status_code=404, detail="מדריך לא נמצא")
        conn.execute("UPDATE guides SET view_count = view_count + 1 WHERE id=?", (guide_id,))

        files = conn.execute(
            "SELECT * FROM guide_files WHERE guide_id=? ORDER BY display_order",
            (guide_id,)
        ).fetchall()
        rows = conn.execute(
            "SELECT emoji, COUNT(*) as cnt FROM reactions WHERE guide_id=? GROUP BY emoji",
            (guide_id,)
        ).fetchall()
        reactions = {r["emoji"]: r["cnt"] for r in rows}
        related = conn.execute("""
            SELECT id, title, cover_image FROM guides
            WHERE is_published=1 AND id != ?
            ORDER BY RANDOM() LIMIT 3
        """, (guide_id,)).fetchall()

    return templates.TemplateResponse("guide.html", {
        "request": request,
        "guide": guide,
        "files": files,
        "reactions": reactions,
        "allowed_emojis": ALLOWED_EMOJIS,
        "related": related,
        "current_user": user,
        "base_url": BASE_URL,
    })


@app.post("/guide/{guide_id}/react")
async def react(guide_id: int, request: Request):
    user = get_current_user(request)
    data = await request.json()
    emoji = data.get("emoji", "")
    if emoji not in ALLOWED_EMOJIS:
        raise HTTPException(status_code=400)
    rkey = reaction_key(request, user)
    with get_db() as conn:
        guide = conn.execute("SELECT id FROM guides WHERE id=? AND is_published=1", (guide_id,)).fetchone()
        if not guide:
            raise HTTPException(status_code=404)
        # Find existing reaction by this user on this guide (any emoji)
        existing = conn.execute(
            "SELECT emoji FROM reactions WHERE guide_id=? AND ip_hash=?",
            (guide_id, rkey)
        ).fetchone()
        old_emoji = existing["emoji"] if existing else None
        removed_emoji = None
        removed_count = 0
        if old_emoji == emoji:
            # Toggle off — same emoji clicked again
            conn.execute("DELETE FROM reactions WHERE guide_id=? AND ip_hash=?", (guide_id, rkey))
            action = "removed"
        else:
            # Remove previous reaction if any
            if old_emoji:
                conn.execute("DELETE FROM reactions WHERE guide_id=? AND ip_hash=?", (guide_id, rkey))
                removed_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM reactions WHERE guide_id=? AND emoji=?",
                    (guide_id, old_emoji)
                ).fetchone()["cnt"]
                removed_emoji = old_emoji
            conn.execute(
                "INSERT OR IGNORE INTO reactions (guide_id, emoji, ip_hash) VALUES (?,?,?)",
                (guide_id, emoji, rkey)
            )
            action = "added"
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM reactions WHERE guide_id=? AND emoji=?",
            (guide_id, emoji)
        ).fetchone()["cnt"]
    result = {"action": action, "count": count, "emoji": emoji}
    if removed_emoji is not None:
        result["removed_emoji"] = removed_emoji
        result["removed_count"] = removed_count
    return JSONResponse(result)


@app.get("/files/{filename}")
async def serve_file(filename: str):
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400)
    path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404)

    import mimetypes
    with get_db() as conn:
        f        = conn.execute("SELECT original_name, mime_type FROM guide_files WHERE stored_name=?", (filename,)).fetchone()
        is_cover = conn.execute("SELECT id FROM guides WHERE cover_image=?", (filename,)).fetchone()
        is_avatar= conn.execute("SELECT id FROM admins WHERE avatar=?", (filename,)).fetchone()

    if f:
        return FileResponse(path, media_type=f["mime_type"] or "application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{f["original_name"]}"'})
    if is_cover or is_avatar:
        mime = mimetypes.guess_type(filename)[0] or "image/jpeg"
        return FileResponse(path, media_type=mime)
    raise HTTPException(status_code=404)


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if get_current_admin(request):
        return RedirectResponse("/admin/")
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": None})

@app.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_db() as conn:
        admin = conn.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
    if not admin or not bcrypt.checkpw(password.encode(), admin["password_hash"].encode()):
        return templates.TemplateResponse("admin/login.html",
                                          {"request": request, "error": "שם משתמש או סיסמה שגויים"})
    token = create_admin_token(admin["id"], admin["username"], bool(admin["is_super"]))
    resp = RedirectResponse("/admin/", status_code=302)
    resp.set_cookie("admin_token", token, httponly=True, max_age=TOKEN_EXPIRE_DAYS * 86400, samesite="lax")
    return resp

@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie("admin_token")
    return resp

@app.get("/admin/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    try:
        actor = require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        guides = conn.execute("""
            SELECT g.*, a.username as author,
                (SELECT COUNT(*) FROM guide_files WHERE guide_id=g.id) as file_count
            FROM guides g LEFT JOIN admins a ON g.created_by=a.id
            ORDER BY g.created_at DESC
        """).fetchall()
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request, "admin": actor, "guides": guides
    })

@app.get("/admin/new", response_class=HTMLResponse)
async def admin_new_guide(request: Request):
    try:
        actor = require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    return templates.TemplateResponse("admin/new_guide.html", {"request": request, "admin": actor})

@app.post("/admin/new")
async def admin_create_guide(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    is_published: str = Form("0"),
    cover: UploadFile = File(None),
    files: list[UploadFile] = File([]),
):
    try:
        actor = require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    cover_path = ""
    if cover and cover.filename:
        cover_path = await save_upload(cover)

    # For Google editors, created_by is None (not in admins table)
    created_by = int(actor["sub"]) if actor.get("is_admin", True) else None

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO guides (title, description, cover_image, category, created_by, is_published) VALUES (?,?,?,?,?,?)",
            (title.strip(), description, cover_path, category,
             created_by, 1 if is_published == "1" else 0)
        )
        guide_id = cur.lastrowid
        for i, f in enumerate(files):
            if f and f.filename:
                stored = await save_upload(f)
                size = os.path.getsize(os.path.join(FILES_DIR, stored))
                conn.execute(
                    "INSERT INTO guide_files (guide_id, stored_name, original_name, mime_type, file_size, display_order) VALUES (?,?,?,?,?,?)",
                    (guide_id, stored, f.filename, f.content_type or "", size, i)
                )
    return RedirectResponse(f"/admin/edit/{guide_id}?saved=1", status_code=302)

@app.get("/admin/edit/{guide_id}", response_class=HTMLResponse)
async def admin_edit_guide(request: Request, guide_id: int):
    try:
        actor = require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        guide = conn.execute("SELECT * FROM guides WHERE id=?", (guide_id,)).fetchone()
        if not guide:
            raise HTTPException(status_code=404)
        files = conn.execute(
            "SELECT * FROM guide_files WHERE guide_id=? ORDER BY display_order", (guide_id,)
        ).fetchall()
    saved = request.query_params.get("saved") == "1"
    return templates.TemplateResponse("admin/edit_guide.html", {
        "request": request, "admin": actor, "guide": guide, "files": files, "saved": saved
    })

@app.post("/admin/edit/{guide_id}")
async def admin_update_guide(
    request: Request,
    guide_id: int,
    title: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    is_published: str = Form("0"),
    cover: UploadFile = File(None),
    files: list[UploadFile] = File([]),
):
    try:
        require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        guide = conn.execute("SELECT * FROM guides WHERE id=?", (guide_id,)).fetchone()
        if not guide:
            raise HTTPException(status_code=404)
        cover_path = guide["cover_image"]
        if cover and cover.filename:
            cover_path = await save_upload(cover)
        conn.execute(
            "UPDATE guides SET title=?, description=?, cover_image=?, category=?, is_published=?, updated_at=datetime('now') WHERE id=?",
            (title.strip(), description, cover_path, category, 1 if is_published == "1" else 0, guide_id)
        )
        existing_count = conn.execute("SELECT COUNT(*) as cnt FROM guide_files WHERE guide_id=?", (guide_id,)).fetchone()["cnt"]
        for i, f in enumerate(files):
            if f and f.filename:
                stored = await save_upload(f)
                size = os.path.getsize(os.path.join(FILES_DIR, stored))
                conn.execute(
                    "INSERT INTO guide_files (guide_id, stored_name, original_name, mime_type, file_size, display_order) VALUES (?,?,?,?,?,?)",
                    (guide_id, stored, f.filename, f.content_type or "", size, existing_count + i)
                )
    return RedirectResponse(f"/admin/edit/{guide_id}?saved=1", status_code=302)

@app.post("/admin/delete/{guide_id}")
async def admin_delete_guide(request: Request, guide_id: int):
    try:
        require_editor(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        files = conn.execute("SELECT stored_name FROM guide_files WHERE guide_id=?", (guide_id,)).fetchall()
        for f in files:
            p = os.path.join(FILES_DIR, f["stored_name"])
            if os.path.exists(p):
                os.remove(p)
        conn.execute("DELETE FROM guide_files WHERE guide_id=?", (guide_id,))
        conn.execute("DELETE FROM reactions WHERE guide_id=?", (guide_id,))
        conn.execute("DELETE FROM guides WHERE id=?", (guide_id,))
    return RedirectResponse("/admin/", status_code=302)

@app.post("/admin/files/delete/{file_id}")
async def admin_delete_file(request: Request, file_id: int):
    try:
        require_editor(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        f = conn.execute("SELECT * FROM guide_files WHERE id=?", (file_id,)).fetchone()
        if not f:
            raise HTTPException(status_code=404)
        p = os.path.join(FILES_DIR, f["stored_name"])
        if os.path.exists(p):
            os.remove(p)
        conn.execute("DELETE FROM guide_files WHERE id=?", (file_id,))
    return JSONResponse({"ok": True})

@app.get("/admin/admins", response_class=HTMLResponse)
async def admin_admins_page(request: Request):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403)
    with get_db() as conn:
        admins = conn.execute("SELECT id, username, is_super, created_at FROM admins ORDER BY id").fetchall()
        editors = conn.execute("SELECT * FROM allowed_editors ORDER BY added_at DESC").fetchall()
    return templates.TemplateResponse("admin/admins.html", {
        "request": request, "admin": admin, "admins": admins, "editors": editors,
        "error": None,
    })

@app.post("/admin/admins/add")
async def admin_add_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_super: str = Form("0"),
):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with get_db() as conn:
        try:
            conn.execute("INSERT INTO admins (username, password_hash, is_super) VALUES (?,?,?)",
                         (username.strip(), hashed, 1 if is_super == "1" else 0))
        except sqlite3.IntegrityError:
            admins = conn.execute("SELECT id, username, is_super, created_at FROM admins ORDER BY id").fetchall()
            editors = conn.execute("SELECT * FROM allowed_editors ORDER BY added_at DESC").fetchall()
            return templates.TemplateResponse("admin/admins.html", {
                "request": request, "admin": admin, "admins": admins, "editors": editors,
                "error": "שם משתמש כבר קיים"
            })
    return RedirectResponse("/admin/admins?added=1", status_code=302)

@app.post("/admin/admins/remove/{admin_id}")
async def admin_remove_admin(request: Request, admin_id: int):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403)
    if str(admin_id) == admin["sub"]:
        raise HTTPException(status_code=400, detail="לא ניתן למחוק את עצמך")
    with get_db() as conn:
        conn.execute("DELETE FROM admins WHERE id=?", (admin_id,))
    return RedirectResponse("/admin/admins", status_code=302)

@app.post("/admin/editors/add")
async def admin_add_editor(
    request: Request,
    email: str = Form(...),
    label: str = Form(""),
):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403)
    with get_db() as conn:
        try:
            conn.execute("INSERT INTO allowed_editors (email, label) VALUES (?,?)",
                         (email.strip().lower(), label.strip()))
        except sqlite3.IntegrityError:
            pass  # already exists
    return RedirectResponse("/admin/admins?editor_added=1", status_code=302)

@app.post("/admin/editors/remove/{editor_id}")
async def admin_remove_editor(request: Request, editor_id: int):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403)
    with get_db() as conn:
        conn.execute("DELETE FROM allowed_editors WHERE id=?", (editor_id,))
    return RedirectResponse("/admin/admins", status_code=302)

@app.get("/admin/profile", response_class=HTMLResponse)
async def admin_profile_page(request: Request):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        admin_row = conn.execute("SELECT * FROM admins WHERE id=?", (int(admin["sub"]),)).fetchone()
    saved = request.query_params.get("saved") == "1"
    return templates.TemplateResponse("admin/profile.html", {
        "request": request, "admin": admin, "admin_row": admin_row, "saved": saved
    })

@app.post("/admin/profile")
async def admin_profile_update(
    request: Request,
    avatar: UploadFile = File(None),
):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if avatar and avatar.filename:
        stored = await save_upload(avatar)
        with get_db() as conn:
            conn.execute("UPDATE admins SET avatar=? WHERE id=?", (stored, int(admin["sub"])))
    return RedirectResponse("/admin/profile?saved=1", status_code=302)


# ─── Init Super Admin ─────────────────────────────────────────────────────────

@app.post("/admin/init")
async def init_super_admin(request: Request):
    import traceback
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            return JSONResponse({"error": "חסרים פרטים"}, status_code=400)
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) as cnt FROM admins").fetchone()["cnt"]
        if count > 0:
            conn.close()
            return JSONResponse({"error": "כבר קיים אדמין במערכת"}, status_code=403)
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn.execute("INSERT INTO admins (username, password_hash, is_super) VALUES (?,?,1)",
                     (username, hashed))
        conn.commit()
        conn.close()
        return JSONResponse({"ok": True, "message": f"אדמין ראשי '{username}' נוצר בהצלחה"})
    except Exception:
        return JSONResponse({"error": traceback.format_exc()}, status_code=500)


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def save_upload(upload: UploadFile) -> str:
    ext = Path(upload.filename).suffix.lower()
    stored_name = uuid.uuid4().hex + ext
    dest = os.path.join(FILES_DIR, stored_name)
    content = await upload.read()
    if len(content) > MAX_FILE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"קובץ גדול מדי (מקסימום {MAX_FILE_MB}MB)")
    with open(dest, "wb") as f:
        f.write(content)
    return stored_name


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
