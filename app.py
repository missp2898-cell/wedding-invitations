import os, io, csv, secrets, sqlite3, base64
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-this-secret")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1")
DB = os.getenv("DATABASE_PATH", "wedding_qr.sqlite3")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "ayoub")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "ayoubayoub")

def db():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS event(id INTEGER PRIMARY KEY CHECK(id=1), title TEXT DEFAULT 'دعوة زفاف',
        hosts TEXT DEFAULT '', couple TEXT DEFAULT '', event_date TEXT DEFAULT '', hall TEXT DEFAULT '',
        reception TEXT DEFAULT '', zaffa TEXT DEFAULT '', message TEXT DEFAULT 'بكل الحب نتشرف بدعوتكم لحضور حفل زفافنا',
        theme TEXT DEFAULT 'blush');
        INSERT OR IGNORE INTO event(id) VALUES(1);
        CREATE TABLE IF NOT EXISTS guests(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        password_hash TEXT NOT NULL, invite_code TEXT UNIQUE NOT NULL, qr_token TEXT UNIQUE NOT NULL,
        used INTEGER DEFAULT 0, used_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        """)
init()

def csrf():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]

@app.context_processor
def globals_for_templates(): return {"csrf_token": csrf}

@app.before_request
def check_csrf():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        sent = request.form.get("_csrf") or data.get("_csrf")
        expected = session.get("_csrf")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            if request.path.startswith("/api/"): return jsonify(ok=False, message="حدّث الصفحة وحاول مجدداً."), 400
            abort(400)

def admin(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not session.get("admin"): return redirect(url_for("login"))
        return fn(*a, **kw)
    return inner

def event_data():
    with db() as c: return c.execute("SELECT * FROM event WHERE id=1").fetchone()

def qr_uri(token):
    img = qrcode.make(token); b = io.BytesIO(); img.save(b, format="PNG")
    return "data:image/png;base64," + base64.b64encode(b.getvalue()).decode()

@app.route("/")
def home(): return redirect(url_for("login"))

@app.route("/admin/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username",""), request.form.get("password","")
        if secrets.compare_digest(u, ADMIN_USER) and secrets.compare_digest(p, ADMIN_PASS):
            session.clear(); session["admin"] = True; csrf()
            return redirect(url_for("dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "error")
    return render_template("login.html")

@app.route("/admin/logout", methods=["POST"])
@admin
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin
def dashboard():
    q = request.args.get("q","").strip()
    with db() as c:
        guests = c.execute("SELECT * FROM guests WHERE name LIKE ? ORDER BY id DESC", (f"%{q}%",)).fetchall()
        total = c.execute("SELECT COUNT(*) n FROM guests").fetchone()["n"]
        used = c.execute("SELECT COUNT(*) n FROM guests WHERE used=1").fetchone()["n"]
    return render_template("dashboard.html", event=event_data(), guests=guests, total=total, used=used, q=q)

@app.route("/admin/event", methods=["POST"])
@admin
def save_event():
    keys = ["title","hosts","couple","event_date","hall","reception","zaffa","message","theme"]
    vals = [request.form.get(k,"").strip() for k in keys]
    if vals[-1] not in ("blush","cream","burgundy"): vals[-1] = "blush"
    with db() as c:
        c.execute("""UPDATE event SET title=?,hosts=?,couple=?,event_date=?,hall=?,reception=?,zaffa=?,message=?,theme=? WHERE id=1""", vals)
    flash("تم حفظ تفاصيل الحفل.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/guest", methods=["POST"])
@admin
def add_guest():
    name, password = request.form.get("name","").strip(), request.form.get("password","")
    if len(name)<2 or len(password)<4:
        flash("اكتب الاسم وكلمة مرور من 4 أحرف على الأقل.", "error")
        return redirect(url_for("dashboard"))
    with db() as c:
        c.execute("INSERT INTO guests(name,password_hash,invite_code,qr_token) VALUES(?,?,?,?)",
          (name, generate_password_hash(password), secrets.token_urlsafe(20), secrets.token_urlsafe(32)))
    flash("تم إنشاء الدعوة. انسخ الرابط من القائمة.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/guest/<int:gid>/delete", methods=["POST"])
@admin
def delete_guest(gid):
    with db() as c: c.execute("DELETE FROM guests WHERE id=?", (gid,))
    flash("تم حذف الدعوة.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/guest/<int:gid>/reset", methods=["POST"])
@admin
def reset_guest(gid):
    with db() as c:
        c.execute("UPDATE guests SET used=0, used_at=NULL, qr_token=? WHERE id=?", (secrets.token_urlsafe(32), gid))
    flash("أعيد تفعيل الدعوة وتم إنشاء QR جديد.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/export.csv")
@admin
def export_csv():
    with db() as c: rows = c.execute("SELECT id,name,used,used_at,created_at FROM guests ORDER BY id").fetchall()
    out = io.StringIO(); w = csv.writer(out); w.writerow(["ID","Name","Used","Used at","Created at"])
    for r in rows: w.writerow([r["id"],r["name"],r["used"],r["used_at"] or "",r["created_at"]])
    res = make_response("\\ufeff" + out.getvalue()); res.headers["Content-Type"]="text/csv; charset=utf-8"
    res.headers["Content-Disposition"]="attachment; filename=guest-list.csv"; return res

@app.route("/admin/scanner")
@admin
def scanner(): return render_template("scanner.html")

@app.route("/api/scan", methods=["POST"])
@admin
def scan():
    token = (request.get_json(silent=True) or {}).get("token","").strip()
    if not token: return jsonify(ok=False,status="invalid",message="لم يتم قراءة QR صالح.")
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        g = c.execute("SELECT id,name,used FROM guests WHERE qr_token=?", (token,)).fetchone()
        if not g:
            c.rollback(); return jsonify(ok=False,status="invalid",message="هذا الباركود غير معروف.")
        if g["used"]:
            c.rollback(); return jsonify(ok=False,status="used",name=g["name"],message="مرفوض — تم استعماله من قبل.")
        c.execute("UPDATE guests SET used=1,used_at=? WHERE id=?",
          (datetime.now(timezone.utc).isoformat(timespec="seconds"),g["id"]))
        c.commit()
        return jsonify(ok=True,status="accepted",name=g["name"],message="دخول مسموح — تم تسجيل الدخول.")
    finally: c.close()

@app.route("/invite/<code>", methods=["GET","POST"])
def guest_login(code):
    with db() as c: g = c.execute("SELECT id,name,password_hash FROM guests WHERE invite_code=?", (code,)).fetchone()
    if not g: abort(404)
    if request.method == "POST":
        n,p = request.form.get("name","").strip(),request.form.get("password","")
        if secrets.compare_digest(n,g["name"]) and check_password_hash(g["password_hash"],p):
            session["guest_id"],session["guest_code"] = g["id"],code
            return redirect(url_for("ticket",code=code))
        flash("الاسم أو كلمة المرور غير صحيحة.", "error")
    return render_template("guest_login.html",code=code)

@app.route("/invite/<code>/ticket")
def ticket(code):
    if session.get("guest_code") != code or not session.get("guest_id"):
        return redirect(url_for("guest_login",code=code))
    with db() as c: g = c.execute("SELECT * FROM guests WHERE invite_code=?", (code,)).fetchone()
    if not g: abort(404)
    return render_template("ticket.html",guest=g,event=event_data(),qr=qr_uri(g["qr_token"]))

@app.route("/guest/logout",methods=["POST"])
def guest_logout():
    session.pop("guest_id",None);session.pop("guest_code",None)
    return redirect(url_for("home"))

@app.errorhandler(404)
def missing(_): return render_template("error.html",message="الرابط غير موجود أو تم حذف الدعوة."),404
@app.errorhandler(400)
def bad(_): return render_template("error.html",message="انتهت صلاحية الطلب. حدّث الصفحة وحاول مجدداً."),400

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")),debug=False)
