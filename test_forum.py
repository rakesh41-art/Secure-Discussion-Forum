import re
import time

import pytest

from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(str(tmp_path / "t.db"), testing=True)


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1)


def stamp(client, path):
    html = client.get(path).get_data(as_text=True)
    ts = re.search(r'name="_ts" value="([^"]+)"', html).group(1)
    sig = re.search(r'name="_ts_sig" value="([^"]+)"', html).group(1)
    return {"_ts": ts, "_ts_sig": sig}


def register(client, name, pw="correct-horse-1"):
    d = {"csrf_token": token(client, "/register"), "username": name, "password": pw,
         **stamp(client, "/register")}
    return client.post("/register", data=d)


def login(client, name, pw="correct-horse-1"):
    return client.post("/login", data={"csrf_token": token(client), "username": name, "password": pw})


def make_user(app, name):
    c = app.test_client()
    assert register(c, name).status_code == 302
    assert login(c, name).status_code == 302
    return c


def post_thread(c, title="Hello world thread", body="Some body text here", **extra):
    d = {"csrf_token": token(c, "/thread/new"), "title": title, "body": body,
         **stamp(c, "/thread/new"), **extra}
    return c.post("/thread/new", data=d)


def post_reply(c, tid, body):
    p = f"/thread/{tid}"
    # a locked thread renders no reply form, so take the form stamp from another page;
    # the server must still reject the POST on its own
    d = {"csrf_token": token(c, "/thread/new"), "body": body, **stamp(c, "/thread/new")}
    return c.post(f"{p}/reply", data=d)


def role_of(app, name):
    import sqlite3
    return sqlite3.connect(app.config["DATABASE"]).execute(
        "SELECT role FROM users WHERE username=?", (name,)).fetchone()[0]


def set_role_db(app, name, role):
    import sqlite3
    db = sqlite3.connect(app.config["DATABASE"])
    db.execute("UPDATE users SET role=? WHERE username=?", (role, name)); db.commit()


def age_account(app, name):
    import sqlite3
    db = sqlite3.connect(app.config["DATABASE"])
    db.execute("UPDATE users SET created_at=? WHERE username=?", (time.time() - 99999, name)); db.commit()


def test_first_user_is_admin_others_not(app):
    make_user(app, "alice"); make_user(app, "bob")
    assert role_of(app, "alice") == "admin" and role_of(app, "bob") == "user"


def test_csrf_required(app):
    c = make_user(app, "alice")
    assert c.post("/thread/new", data={"title": "abcdef", "body": "xx"}).status_code == 400


def test_xss_escaped(app):
    c = make_user(app, "alice")
    r = post_thread(c, title="<script>alert(1)</script>", body="<img src=x onerror=alert(1)>")
    page = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert "default-src 'none'" in c.get("/").headers["Content-Security-Policy"]


def test_validation(app):
    c = make_user(app, "alice")
    assert post_thread(c, title="abc").status_code == 400
    assert post_thread(c, body="x").status_code == 400
    assert post_thread(c, body="a" * 10001).status_code == 400
    assert post_thread(c, body="aaaaaaaaaaaaaaaaaaaa" * 3).status_code == 400
    r = post_thread(c, title="Valid title\x00\x07ok", body="fine\x00 body")
    assert r.status_code == 302


def test_honeypot_and_forged_timestamp(app):
    c = make_user(app, "alice")
    assert post_thread(c, website="http://spam").status_code == 400
    d = {"csrf_token": token(c, "/thread/new"), "title": "Valid title", "body": "body ok",
         "_ts": str(time.time() - 100), "_ts_sig": "forged"}
    assert c.post("/thread/new", data=d).status_code == 400


def test_link_rules(app):
    c = make_user(app, "bob"); make_user(app, "alice")  # alice is not first; bob? first is bob (admin)
    c2 = make_user(app, "carol")
    assert post_thread(c2, body="see http://x.com").status_code == 400  # new account
    age_account(app, "carol")
    assert post_thread(c2, body="see http://x.com").status_code == 302
    assert post_thread(c2, title="Another valid", body="http://a.com http://b.com http://c.com http://d.com").status_code == 400


def test_duplicate_and_rate_limit(app):
    c = make_user(app, "alice")
    assert post_thread(c).status_code == 302
    assert post_thread(c).status_code == 400  # duplicate
    assert post_thread(c, title="Second title", body="body two").status_code == 302
    assert post_thread(c, title="Third title", body="body three").status_code == 302
    assert post_thread(c, title="Fourth title", body="body four").status_code == 429


def test_login_throttle(app):
    make_user(app, "alice")
    c = app.test_client()
    codes = [login(c, "alice", "wrong").status_code for _ in range(10)]
    assert 429 in codes
    assert login(c, "alice").status_code == 429


def test_user_cannot_moderate(app):
    make_user(app, "admin1")
    u = make_user(app, "mallory")
    tid = int(post_thread(u).headers["Location"].rsplit("/", 1)[1])
    for path in (f"/mod/thread/{tid}/remove", f"/mod/thread/{tid}/lock", "/mod/user/1/ban"):
        assert u.post(path, data={"csrf_token": token(u, "/")}).status_code == 403
    assert u.get("/mod/queue").status_code == 403
    assert u.post("/admin/user/2/role", data={"csrf_token": token(u, "/"), "role": "moderator"}).status_code == 403
    anon = app.test_client()
    assert anon.get("/mod/queue").status_code == 302


def test_cannot_forge_role_via_form(app):
    make_user(app, "admin1")
    u = make_user(app, "mallory")
    post_thread(u, role="admin")
    assert role_of(app, "mallory") == "user"


def test_moderator_powers_and_hierarchy(app):
    a = make_user(app, "admin1")
    m = make_user(app, "mod1"); m2 = make_user(app, "mod2"); u = make_user(app, "user1")
    t = a.post("/admin/user/2/role", data={"csrf_token": token(a, "/mod/queue"), "role": "moderator"})
    assert t.status_code == 302 and role_of(app, "mod1") == "moderator"
    a.post("/admin/user/3/role", data={"csrf_token": token(a, "/mod/queue"), "role": "moderator"})
    tid = int(post_thread(u).headers["Location"].rsplit("/", 1)[1])
    tm = lambda c: token(c, "/mod/queue")
    # mod can lock, pin, remove, ban a regular user
    assert m.post(f"/mod/thread/{tid}/lock", data={"csrf_token": tm(m)}).status_code == 302
    assert post_reply(u, tid, "reply text").status_code == 403
    assert m.post(f"/mod/thread/{tid}/remove", data={"csrf_token": tm(m)}).status_code == 302
    assert "Hello world thread" not in u.get("/").get_data(as_text=True)
    assert u.get(f"/thread/{tid}").status_code == 404
    assert "Hello world thread" in m.get("/").get_data(as_text=True)
    # mod cannot ban peer mod or admin, nor self
    for uid in (1, 3, 2):
        assert m.post(f"/mod/user/{uid}/ban", data={"csrf_token": tm(m)}).status_code == 403
    # mod cannot remove content of an admin
    atid = int(post_thread(a, title="Admin thread", body="admin body").headers["Location"].rsplit("/", 1)[1])
    assert m.post(f"/mod/thread/{atid}/remove", data={"csrf_token": tm(m)}).status_code == 403
    # mod cannot promote anyone
    assert m.post("/admin/user/4/role", data={"csrf_token": tm(m), "role": "moderator"}).status_code == 403
    # ban takes effect immediately, including active session
    assert m.post("/mod/user/4/ban", data={"csrf_token": tm(m), "reason": "spam"}).status_code == 302
    assert u.get("/thread/new").status_code == 302
    assert login(app.test_client(), "user1").status_code == 403
    # audit log written
    page = a.get("/mod/queue").get_data(as_text=True)
    assert "lock" in page and "ban" in page


def test_demoted_moderator_loses_access_immediately(app):
    a = make_user(app, "admin1"); m = make_user(app, "mod1")
    a.post("/admin/user/2/role", data={"csrf_token": token(a, "/mod/queue"), "role": "moderator"})
    assert m.get("/mod/queue").status_code == 200
    a.post("/admin/user/2/role", data={"csrf_token": token(a, "/mod/queue"), "role": "user"})
    assert m.get("/mod/queue").status_code == 403


def test_reports(app):
    make_user(app, "admin1")
    u = make_user(app, "user1")
    tid = int(post_thread(u).headers["Location"].rsplit("/", 1)[1])
    v = make_user(app, "user2")
    r = v.post(f"/report/thread/{tid}", data={"csrf_token": token(v, "/"), "reason": "this is spam"})
    assert r.status_code == 302
    admin = app.test_client(); login(admin, "admin1")
    assert "this is spam" in admin.get("/mod/queue").get_data(as_text=True)
