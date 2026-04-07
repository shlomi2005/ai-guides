#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sqlite3
import hashlib
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "guides.db")
FILES_DIR = os.path.join(DATA_DIR, "files")
_secret_file = os.path.join(DATA_DIR, ".secret_key")

def _load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY", "")
    if env_key:
        return env_key
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(_secret_file):
        return open(_secret_file).read().strip()
    import secrets
    key = secrets.token_hex(32)
    with open(_secret_file, "w") as f:
        f.write(key)
    return key

SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 7
MAX_FILE_MB = 500

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
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_super INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS guides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            cover_image TEXT DEFAULT '',
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            is_published INTEGER DEFAULT 0
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


init_db()


# ─── Auth ─────────────────────────────────────────────────────────────────────

def create_token(admin_id: int, username: str, is_super: bool) -> str:
    expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(admin_id), "username": username, "is_super": is_super, "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_current_admin(token: Optional[str] = None) -> Optional[dict]:
    if not token:
        return None
    return decode_token(token)


def require_admin(request: Request) -> dict:
    token = request.cookies.get("admin_token")
    admin = get_current_admin(token)
    if not admin:
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return admin


def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()


def fmt_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


templates.env.filters["fmt_size"] = fmt_size


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


templates.env.globals["get_file_icon"] = get_file_icon

import json as _json
templates.env.filters["tojson"] = lambda v: _json.dumps(v, ensure_ascii=False)


# ─── Public Routes ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    with get_db() as conn:
        guides = conn.execute("""
            SELECT g.*,
                (SELECT COUNT(*) FROM guide_files WHERE guide_id = g.id) as file_count
            FROM guides g WHERE g.is_published = 1
            ORDER BY g.created_at DESC
        """).fetchall()
        all_reactions = {}
        for g in guides:
            rows = conn.execute(
                "SELECT emoji, COUNT(*) as cnt FROM reactions WHERE guide_id=? GROUP BY emoji",
                (g["id"],)
            ).fetchall()
            all_reactions[g["id"]] = {r["emoji"]: r["cnt"] for r in rows}
    return templates.TemplateResponse("index.html", {
        "request": request,
        "guides": guides,
        "reactions": all_reactions,
        "allowed_emojis": ALLOWED_EMOJIS,
    })


@app.get("/guide/{guide_id}", response_class=HTMLResponse)
async def view_guide(request: Request, guide_id: int):
    with get_db() as conn:
        guide = conn.execute(
            "SELECT * FROM guides WHERE id=? AND is_published=1", (guide_id,)
        ).fetchone()
        if not guide:
            raise HTTPException(status_code=404, detail="מדריך לא נמצא")
        files = conn.execute(
            "SELECT * FROM guide_files WHERE guide_id=? ORDER BY display_order",
            (guide_id,)
        ).fetchall()
        rows = conn.execute(
            "SELECT emoji, COUNT(*) as cnt FROM reactions WHERE guide_id=? GROUP BY emoji",
            (guide_id,)
        ).fetchall()
        reactions = {r["emoji"]: r["cnt"] for r in rows}
    return templates.TemplateResponse("guide.html", {
        "request": request,
        "guide": guide,
        "files": files,
        "reactions": reactions,
        "allowed_emojis": ALLOWED_EMOJIS,
    })


@app.post("/guide/{guide_id}/react")
async def react(guide_id: int, request: Request):
    data = await request.json()
    emoji = data.get("emoji", "")
    if emoji not in ALLOWED_EMOJIS:
        raise HTTPException(status_code=400, detail="אימוגי לא חוקי")
    ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()
    ip_hash = hash_ip(ip)
    with get_db() as conn:
        guide = conn.execute("SELECT id FROM guides WHERE id=? AND is_published=1", (guide_id,)).fetchone()
        if not guide:
            raise HTTPException(status_code=404)
        try:
            conn.execute(
                "INSERT INTO reactions (guide_id, emoji, ip_hash) VALUES (?,?,?)",
                (guide_id, emoji, ip_hash)
            )
            action = "added"
        except sqlite3.IntegrityError:
            conn.execute(
                "DELETE FROM reactions WHERE guide_id=? AND emoji=? AND ip_hash=?",
                (guide_id, emoji, ip_hash)
            )
            action = "removed"
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM reactions WHERE guide_id=? AND emoji=?",
            (guide_id, emoji)
        ).fetchone()["cnt"]
    return JSONResponse({"action": action, "count": count, "emoji": emoji})


@app.get("/files/{filename}")
async def serve_file(filename: str, request: Request):
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400)
    path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    with get_db() as conn:
        f = conn.execute("SELECT original_name, mime_type FROM guide_files WHERE stored_name=?", (filename,)).fetchone()
        is_cover = conn.execute("SELECT id FROM guides WHERE cover_image=?", (filename,)).fetchone()
    if not f and not is_cover:
        raise HTTPException(status_code=404)
    if f:
        return FileResponse(path, media_type=f["mime_type"] or "application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{f["original_name"]}"'})
    # cover image — serve inline
    import mimetypes
    mime = mimetypes.guess_type(filename)[0] or "image/jpeg"
    return FileResponse(path, media_type=mime)


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    token = request.cookies.get("admin_token")
    if get_current_admin(token):
        return RedirectResponse("/admin/")
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": None})


@app.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_db() as conn:
        admin = conn.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
    if not admin or not bcrypt.checkpw(password.encode(), admin["password_hash"].encode()):
        return templates.TemplateResponse("admin/login.html",
                                          {"request": request, "error": "שם משתמש או סיסמה שגויים"})
    token = create_token(admin["id"], admin["username"], bool(admin["is_super"]))
    resp = RedirectResponse("/admin/", status_code=302)
    resp.set_cookie("admin_token", token, httponly=True, max_age=TOKEN_EXPIRE_DAYS * 86400)
    return resp


@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie("admin_token")
    return resp


@app.get("/admin/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    try:
        admin = require_admin(request)
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
        "request": request, "admin": admin, "guides": guides
    })


@app.get("/admin/new", response_class=HTMLResponse)
async def admin_new_guide(request: Request):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    return templates.TemplateResponse("admin/new_guide.html", {"request": request, "admin": admin})


@app.post("/admin/new")
async def admin_create_guide(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    is_published: str = Form("0"),
    cover: UploadFile = File(None),
    files: list[UploadFile] = File([]),
):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")

    cover_path = ""
    if cover and cover.filename:
        cover_path = await save_upload(cover)

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO guides (title, description, cover_image, created_by, is_published) VALUES (?,?,?,?,?)",
            (title.strip(), description, cover_path, int(admin["sub"]), 1 if is_published == "1" else 0)
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
        admin = require_admin(request)
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
        "request": request, "admin": admin, "guide": guide, "files": files, "saved": saved
    })


@app.post("/admin/edit/{guide_id}")
async def admin_update_guide(
    request: Request,
    guide_id: int,
    title: str = Form(...),
    description: str = Form(""),
    is_published: str = Form("0"),
    cover: UploadFile = File(None),
    files: list[UploadFile] = File([]),
):
    try:
        admin = require_admin(request)
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
            "UPDATE guides SET title=?, description=?, cover_image=?, is_published=?, updated_at=datetime('now') WHERE id=?",
            (title.strip(), description, cover_path, 1 if is_published == "1" else 0, guide_id)
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
        require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    with get_db() as conn:
        files = conn.execute("SELECT stored_name FROM guide_files WHERE guide_id=?", (guide_id,)).fetchall()
        for f in files:
            path = os.path.join(FILES_DIR, f["stored_name"])
            if os.path.exists(path):
                os.remove(path)
        conn.execute("DELETE FROM guide_files WHERE guide_id=?", (guide_id,))
        conn.execute("DELETE FROM reactions WHERE guide_id=?", (guide_id,))
        conn.execute("DELETE FROM guides WHERE id=?", (guide_id,))
    return RedirectResponse("/admin/", status_code=302)


@app.post("/admin/files/delete/{file_id}")
async def admin_delete_file(request: Request, file_id: int):
    try:
        require_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        f = conn.execute("SELECT * FROM guide_files WHERE id=?", (file_id,)).fetchone()
        if not f:
            raise HTTPException(status_code=404)
        path = os.path.join(FILES_DIR, f["stored_name"])
        if os.path.exists(path):
            os.remove(path)
        conn.execute("DELETE FROM guide_files WHERE id=?", (file_id,))
    return JSONResponse({"ok": True})


@app.get("/admin/admins", response_class=HTMLResponse)
async def admin_admins_page(request: Request):
    try:
        admin = require_admin(request)
    except HTTPException:
        return RedirectResponse("/admin/login")
    if not admin.get("is_super"):
        raise HTTPException(status_code=403, detail="גישה מותרת לאדמין ראשי בלבד")
    with get_db() as conn:
        admins = conn.execute("SELECT id, username, is_super, created_at FROM admins ORDER BY id").fetchall()
    return templates.TemplateResponse("admin/admins.html", {
        "request": request, "admin": admin, "admins": admins
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
            return templates.TemplateResponse("admin/admins.html", {
                "request": request, "admin": admin, "admins": admins,
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
