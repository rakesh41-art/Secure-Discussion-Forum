"""Secure Discussion Forum - Flask + SQLite.

Security model summary
- Passwords: scrypt hashes (werkzeug). Login throttling per IP+username.
- Sessions: signed, HttpOnly, SameSite=Lax cookies. Only user_id is stored;
  role and ban status are re-read from the DB on EVERY request, so a demoted
  or banned moderator loses privileges immediately.
- CSRF: per-session token required on every POST.
- XSS: Jinja autoescape everywhere, no |safe, strict CSP.
- SQLi: parameterized queries only.
- Validation: length limits, control-char stripping, Unicode normalization,
  link limits.
- Anti-spam: sliding-window rate limits, duplicate detection, new-account
  link restrictions, honeypot field, minimum fill time.
- Moderation: roles (user < moderator < admin), hierarchy enforcement,
  append-only audit log, user reports queue.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

ROLE_RANK = {"user": 0, "moderator": 1, "admin": 2}

# ---- limits / anti-spam config -------------------------------------------
TITLE_MIN, TITLE_MAX = 5, 150
BODY_MIN, BODY_MAX = 2, 10000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")
URL_RE = re.compile(r"(https?://|www\.)", re.I)
MAX_LINKS = 3
NEW_ACCOUNT_SECONDS = 24 * 3600     # accounts younger than this: no links
MIN_FILL_SECONDS = 2                # forms submitted faster are bots
RATE_LIMITS = {                     # action: (max events, window seconds)
    "thread": (3, 600),
    "reply": (8, 120),
    "report": (10, 600),
    "register": (5, 3600),
    "login": (8, 600),
}
DUPLICATE_WINDOW = 3600


def create_app(db_path=None, testing=False):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FORUM_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=db_path or os.environ.get("FORUM_DB", "forum.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not testing and os.environ.get("FORUM_INSECURE") != "1",
        MAX_CONTENT_LENGTH=64 * 1024,
        PERMANENT_SESSION_LIFETIME=8 * 3600,
        TESTING=testing,
    )
    if testing:
        app.config["MIN_FILL_SECONDS"] = 0
    else:
        app.config["MIN_FILL_SECONDS"] = MIN_FILL_SECONDS

    # ---------------- database ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user'
        CHECK(role IN ('user','moderator','admin')),
      banned INTEGER NOT NULL DEFAULT 0, ban_reason TEXT,
      created_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS threads(
      id INTEGER PRIMARY KEY, author_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL, body TEXT NOT NULL, created_at REAL NOT NULL,
      locked INTEGER NOT NULL DEFAULT 0, pinned INTEGER NOT NULL DEFAULT 0,
      removed INTEGER NOT NULL DEFAULT 0, last_activity REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS replies(
      id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL REFERENCES threads(id),
      author_id INTEGER NOT NULL REFERENCES users(id),
      body TEXT NOT NULL, created_at REAL NOT NULL,
      removed INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id),
      target_type TEXT NOT NULL CHECK(target_type IN ('thread','reply')),
      target_id INTEGER NOT NULL, reason TEXT NOT NULL, created_at REAL NOT NULL,
      resolved INTEGER NOT NULL DEFAULT 0, resolved_by INTEGER,
      UNIQUE(reporter_id, target_type, target_id));
    CREATE TABLE IF NOT EXISTS mod_log(
      id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL, action TEXT NOT NULL,
      target TEXT NOT NULL, detail TEXT, created_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,
      created_at REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS ev_idx ON events(kind, key, created_at);
    CREATE TABLE IF NOT EXISTS content_hashes(
      id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, h TEXT NOT NULL,
      created_at REAL NOT NULL);
    """

    with app.app_context():
        get_db().executescript(SCHEMA)
        get_db().commit()

    # ---------------- helpers ----------------
    def client_ip():
        return request.remote_addr or "unknown"

    def rate_limited(kind, key, record=True):
        limit, window = RATE_LIMITS[kind]
        now = time.time()
        db = get_db()
        n = db.execute(
            "SELECT COUNT(*) FROM events WHERE kind=? AND key=? AND created_at>?",
            (kind, key, now - window)).fetchone()[0]
        if n >= limit:
            return True
        if record:
            db.execute("INSERT INTO events(kind,key,created_at) VALUES(?,?,?)",
                       (kind, key, now))
            db.commit()
        return False

    def clean_text(s, multiline):
        s = unicodedata.normalize("NFC", s or "")
        allowed = "\n\t" if multiline else ""
        s = "".join(c for c in s
                    if c in allowed or unicodedata.category(c)[0] != "C")
        s = s.replace("\r", "")
        return s.strip()

    def validate_content(text, kind):
        """Returns (cleaned, error). kind: 'title' or 'body'."""
        multiline = kind == "body"
        text = clean_text(text, multiline)
        lo, hi = (TITLE_MIN, TITLE_MAX) if kind == "title" else (BODY_MIN, BODY_MAX)
        if not (lo <= len(text) <= hi):
            return None, f"{kind.title()} must be {lo}-{hi} characters."
        if len(set(text.lower())) <= 2 and len(text) > 20:
            return None, f"{kind.title()} looks like repeated characters."
        if re.search(r"(.)\1{14,}", text):
            return None, f"{kind.title()} has excessive repeated characters."
        letters = [c for c in text if c.isalpha()]
        if len(letters) > 30 and sum(c.isupper() for c in letters) / len(letters) > 0.8:
            return None, f"{kind.title()} is mostly capital letters."
        return text, None

    def spam_check(user, *texts):
        """Anti-spam rules that apply to posted content. Returns error or None."""
        joined = "\n".join(texts)
        links = len(URL_RE.findall(joined))
        if links > MAX_LINKS:
            return f"Too many links (max {MAX_LINKS})."
        if links and user["role"] == "user" and \
                time.time() - user["created_at"] < NEW_ACCOUNT_SECONDS:
            return "New accounts cannot post links during their first 24 hours."
        digest = hashlib.sha256(re.sub(r"\s+", " ", joined.lower()).encode()).hexdigest()
        db = get_db()
        dup = db.execute(
            "SELECT 1 FROM content_hashes WHERE user_id=? AND h=? AND created_at>?",
            (user["id"], digest, time.time() - DUPLICATE_WINDOW)).fetchone()
        if dup:
            return "Duplicate content detected."
        g.pending_hash = digest
        return None

    def record_hash(user):
        h = getattr(g, "pending_hash", None)
        if h:
            get_db().execute(
                "INSERT INTO content_hashes(user_id,h,created_at) VALUES(?,?,?)",
                (user["id"], h, time.time()))

    def bot_check():
        """Honeypot + minimum fill time. Returns error or None."""
        if request.form.get("website"):  # honeypot, hidden from humans
            return "Submission rejected."
        try:
            ts = float(request.form.get("_ts", "0"))
        except ValueError:
            return "Submission rejected."
        sig = request.form.get("_ts_sig", "")
        expect = hmac.new(app.config["SECRET_KEY"].encode(),
                          f"{ts}".encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expect):
            return "Form expired, please reload the page and try again."
        age = time.time() - ts
        if age < app.config["MIN_FILL_SECONDS"]:
            return "You submitted too quickly. Please slow down."
        if age > 6 * 3600:
            return "Form expired, please reload the page and try again."
        return None

    def audit(action, target, detail=""):
        get_db().execute(
            "INSERT INTO mod_log(actor_id,action,target,detail,created_at) VALUES(?,?,?,?,?)",
            (g.user["id"], action, target, detail[:500], time.time()))

    # ---------------- request lifecycle ----------------
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid is not None:
            row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if row is None or row["banned"]:
                session.clear()
            else:
                g.user = row  # role is always fresh from the DB

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("csrf")
            sent = request.form.get("csrf_token", "")
            if not token or not hmac.compare_digest(token, sent):
                abort(400, "Invalid CSRF token.")

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def form_stamp():
        ts = f"{time.time()}"
        sig = hmac.new(app.config["SECRET_KEY"].encode(),
                       ts.encode(), hashlib.sha256).hexdigest()[:32]
        return ts, sig

    app.jinja_env.globals.update(csrf_token=csrf_token, form_stamp=form_stamp,
                                 ROLE_RANK=ROLE_RANK)

    @app.template_filter("dt")
    def fmt_dt(ts):
        return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + " UTC"

    @app.template_filter("ago")
    def fmt_ago(ts):
        d = max(0, time.time() - ts)
        if d < 60:
            return "just now"
        if d < 3600:
            return f"{int(d // 60)}m ago"
        if d < 86400:
            return f"{int(d // 3600)}h ago"
        if d < 86400 * 30:
            return f"{int(d // 86400)}d ago"
        return time.strftime("%b %d, %Y", time.gmtime(ts))

    @app.template_filter("avc")
    def avatar_color(name):
        return sum(ord(c) for c in (name or "")) % 8

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        if request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "public, max-age=300"
        else:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------- access control ----------------
    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            return f(*a, **kw)
        return wrapper

    def role_required(min_role):
        """Server-side privilege enforcement; role comes from DB, never client."""
        def deco(f):
            @wraps(f)
            def wrapper(*a, **kw):
                if g.user is None:
                    return redirect(url_for("login"))
                if ROLE_RANK[g.user["role"]] < ROLE_RANK[min_role]:
                    abort(403)
                return f(*a, **kw)
            return wrapper
        return deco

    def is_mod():
        return g.user is not None and ROLE_RANK[g.user["role"]] >= ROLE_RANK["moderator"]

    def can_moderate_user(target):
        """Moderators may act only on strictly lower-ranked users."""
        return ROLE_RANK[g.user["role"]] > ROLE_RANK[target["role"]]

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def err(e):
        return render_template("error.html", e=e), e.code

    # ---------------- auth ----------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            if (e := bot_check()):
                flash(e); return render_template("register.html"), 400
            if rate_limited("register", client_ip()):
                flash("Too many registrations from your network."); return render_template("register.html"), 429
            username = request.form.get("username", "")
            pw = request.form.get("password", "")
            if not USERNAME_RE.match(username):
                flash("Username must be 3-24 letters, digits or underscores.")
            elif not (10 <= len(pw) <= 200):
                flash("Password must be 10-200 characters.")
            elif pw.lower() == username.lower():
                flash("Password must differ from username.")
            else:
                db = get_db()
                first = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                try:
                    db.execute(
                        "INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
                        (username, generate_password_hash(pw),
                         "admin" if first else "user", time.time()))
                    db.commit()
                except sqlite3.IntegrityError:
                    flash("That username is taken.")
                    return render_template("register.html"), 400
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            return render_template("register.html"), 400
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")[:24]
            key = f"{client_ip()}|{username.lower()}"
            if rate_limited("login", key, record=False):
                flash("Too many login attempts. Try again later.")
                return render_template("login.html"), 429
            row = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            ok = row is not None and check_password_hash(row["pw_hash"], request.form.get("password", ""))
            if not ok:
                rate_limited("login", key)
                flash("Invalid username or password.")
                return render_template("login.html"), 401
            if row["banned"]:
                flash("This account has been banned.")
                return render_template("login.html"), 403
            session.clear()  # prevent session fixation
            session["uid"] = row["id"]
            session.permanent = True
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # ---------------- forum ----------------
    @app.route("/")
    def index():
        page = max(1, request.args.get("page", 1, type=int))
        db = get_db()
        where = "" if is_mod() else "WHERE t.removed=0"
        rows = db.execute(f"""
          SELECT t.*, u.username, u.role,
            (SELECT COUNT(*) FROM replies r WHERE r.thread_id=t.id AND r.removed=0) AS n_replies
          FROM threads t JOIN users u ON u.id=t.author_id {where}
          ORDER BY t.pinned DESC, t.last_activity DESC LIMIT 25 OFFSET ?""",
          ((page - 1) * 25,)).fetchall()
        return render_template("index.html", threads=rows, page=page)

    @app.route("/thread/new", methods=["GET", "POST"])
    @login_required
    def new_thread():
        if request.method == "POST":
            err_msg = bot_check()
            title, e1 = validate_content(request.form.get("title"), "title")
            body, e2 = validate_content(request.form.get("body"), "body")
            err_msg = err_msg or e1 or e2
            if not err_msg:
                err_msg = spam_check(g.user, title, body)
            if not err_msg and rate_limited("thread", str(g.user["id"])):
                err_msg = "You are creating threads too quickly."
            if err_msg:
                flash(err_msg)
                return render_template("new_thread.html"), 429 if "quickly" in err_msg else 400
            db = get_db()
            now = time.time()
            cur = db.execute(
                "INSERT INTO threads(author_id,title,body,created_at,last_activity) VALUES(?,?,?,?,?)",
                (g.user["id"], title, body, now, now))
            record_hash(g.user)
            db.commit()
            return redirect(url_for("view_thread", tid=cur.lastrowid))
        return render_template("new_thread.html")

    def get_thread_or_404(tid):
        t = get_db().execute(
            "SELECT t.*, u.username, u.role AS author_role FROM threads t JOIN users u ON u.id=t.author_id WHERE t.id=?",
            (tid,)).fetchone()
        if t is None or (t["removed"] and not is_mod()):
            abort(404)
        return t

    @app.route("/thread/<int:tid>")
    def view_thread(tid):
        t = get_thread_or_404(tid)
        replies = get_db().execute("""
          SELECT r.*, u.username, u.role FROM replies r JOIN users u ON u.id=r.author_id
          WHERE r.thread_id=? {} ORDER BY r.created_at""".format(
              "" if is_mod() else "AND r.removed=0"), (tid,)).fetchall()
        return render_template("thread.html", t=t, replies=replies)

    @app.route("/thread/<int:tid>/reply", methods=["POST"])
    @login_required
    def reply(tid):
        t = get_thread_or_404(tid)
        if t["locked"] or t["removed"]:
            abort(403)
        err_msg = bot_check()
        body, e = validate_content(request.form.get("body"), "body")
        err_msg = err_msg or e
        if not err_msg:
            err_msg = spam_check(g.user, body)
        if not err_msg and rate_limited("reply", str(g.user["id"])):
            err_msg = "You are replying too quickly."
        if err_msg:
            flash(err_msg)
            return redirect(url_for("view_thread", tid=tid))
        db = get_db()
        now = time.time()
        db.execute("INSERT INTO replies(thread_id,author_id,body,created_at) VALUES(?,?,?,?)",
                   (tid, g.user["id"], body, now))
        db.execute("UPDATE threads SET last_activity=? WHERE id=?", (now, tid))
        record_hash(g.user)
        db.commit()
        return redirect(url_for("view_thread", tid=tid))

    @app.route("/report/<kind>/<int:target_id>", methods=["POST"])
    @login_required
    def report(kind, target_id):
        if kind not in ("thread", "reply"):
            abort(404)
        table = "threads" if kind == "thread" else "replies"
        if not get_db().execute(f"SELECT 1 FROM {table} WHERE id=? AND removed=0", (target_id,)).fetchone():
            abort(404)
        reason, e = validate_content(request.form.get("reason"), "body")
        if e or rate_limited("report", str(g.user["id"])):
            flash(e or "Too many reports."); return redirect(request.referrer or url_for("index"))
        try:
            get_db().execute(
                "INSERT INTO reports(reporter_id,target_type,target_id,reason,created_at) VALUES(?,?,?,?,?)",
                (g.user["id"], kind, target_id, reason[:500], time.time()))
            get_db().commit()
            flash("Report submitted. A moderator will review it.", "success")
        except sqlite3.IntegrityError:
            flash("You already reported this.")
        return redirect(request.referrer or url_for("index"))

    # ---------------- moderation ----------------
    def author_of(kind, target_id):
        table = "threads" if kind == "thread" else "replies"
        return get_db().execute(
            f"SELECT u.* FROM {table} x JOIN users u ON u.id=x.author_id WHERE x.id=?",
            (target_id,)).fetchone()

    @app.route("/mod/thread/<int:tid>/<action>", methods=["POST"])
    @role_required("moderator")
    def mod_thread(tid, action):
        if action not in ("lock", "unlock", "pin", "unpin", "remove", "restore"):
            abort(404)
        author = author_of("thread", tid)
        if author is None:
            abort(404)
        # removing/restoring content by an equal-or-higher rank is not allowed
        if action in ("remove", "restore") and not can_moderate_user(author) \
                and author["id"] != g.user["id"]:
            abort(403)
        col, val = {"lock": ("locked", 1), "unlock": ("locked", 0), "pin": ("pinned", 1),
                    "unpin": ("pinned", 0), "remove": ("removed", 1), "restore": ("removed", 0)}[action]
        get_db().execute(f"UPDATE threads SET {col}=? WHERE id=?", (val, tid))
        audit(action, f"thread:{tid}", request.form.get("reason", ""))
        get_db().commit()
        return redirect(url_for("view_thread", tid=tid))

    @app.route("/mod/reply/<int:rid>/<action>", methods=["POST"])
    @role_required("moderator")
    def mod_reply(rid, action):
        if action not in ("remove", "restore"):
            abort(404)
        author = author_of("reply", rid)
        if author is None:
            abort(404)
        if not can_moderate_user(author) and author["id"] != g.user["id"]:
            abort(403)
        row = get_db().execute("SELECT thread_id FROM replies WHERE id=?", (rid,)).fetchone()
        get_db().execute("UPDATE replies SET removed=? WHERE id=?", (1 if action == "remove" else 0, rid))
        audit(action, f"reply:{rid}", request.form.get("reason", ""))
        get_db().commit()
        return redirect(url_for("view_thread", tid=row["thread_id"]))

    @app.route("/mod/user/<int:uid>/<action>", methods=["POST"])
    @role_required("moderator")
    def mod_user(uid, action):
        if action not in ("ban", "unban"):
            abort(404)
        target = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if target is None:
            abort(404)
        if target["id"] == g.user["id"] or not can_moderate_user(target):
            abort(403)  # cannot ban yourself, peers or superiors
        reason = clean_text(request.form.get("reason", ""), False)[:200]
        get_db().execute("UPDATE users SET banned=?, ban_reason=? WHERE id=?",
                         (1 if action == "ban" else 0, reason if action == "ban" else None, uid))
        audit(action, f"user:{uid}", reason)
        get_db().commit()
        flash(f"User {target['username']} {'banned' if action == 'ban' else 'unbanned'}.", "success")
        return redirect(request.referrer or url_for("mod_queue"))

    @app.route("/mod/queue")
    @role_required("moderator")
    def mod_queue():
        db = get_db()
        reports = db.execute("""
          SELECT r.*, u.username AS reporter,
            CASE WHEN r.target_type='thread' THEN r.target_id
                 ELSE (SELECT thread_id FROM replies WHERE id=r.target_id) END AS thread_id
          FROM reports r
          JOIN users u ON u.id=r.reporter_id WHERE r.resolved=0 ORDER BY r.created_at""").fetchall()
        log = db.execute("""
          SELECT m.*, u.username FROM mod_log m JOIN users u ON u.id=m.actor_id
          ORDER BY m.id DESC LIMIT 50""").fetchall()
        users = db.execute("SELECT id,username,role,banned,created_at FROM users ORDER BY id").fetchall()
        stats = {
            "reports": len(reports),
            "users": len(users),
            "banned": sum(1 for u in users if u["banned"]),
            "threads": db.execute("SELECT COUNT(*) FROM threads WHERE removed=0").fetchone()[0],
        }
        return render_template("mod_queue.html", reports=reports, log=log, users=users, stats=stats)

    @app.route("/mod/report/<int:rid>/resolve", methods=["POST"])
    @role_required("moderator")
    def resolve_report(rid):
        get_db().execute("UPDATE reports SET resolved=1, resolved_by=? WHERE id=?", (g.user["id"], rid))
        audit("resolve_report", f"report:{rid}")
        get_db().commit()
        return redirect(url_for("mod_queue"))

    @app.route("/admin/user/<int:uid>/role", methods=["POST"])
    @role_required("admin")
    def set_role(uid):
        role = request.form.get("role")
        if role not in ("user", "moderator"):
            abort(400)
        target = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if target is None:
            abort(404)
        if target["role"] == "admin":
            abort(403)  # admins cannot be changed through the web UI
        get_db().execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        audit("set_role", f"user:{uid}", role)
        get_db().commit()
        return redirect(url_for("mod_queue"))

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
