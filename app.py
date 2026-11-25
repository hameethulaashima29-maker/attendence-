import os, csv, io, json, sqlite3, datetime as dt
import urllib.request, urllib.error
from zoneinfo import ZoneInfo
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, Response)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
SUBJECT, ROOM = "Open Elective", ""
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Asia/Kolkata"))

# ---------- database: Postgres online (DATABASE_URL), SQLite on your own PC ----------
DATABASE_URL = os.environ.get("DATABASE_URL")
PG = bool(DATABASE_URL)
SQLITE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attendance.db")
if PG:
    import psycopg2, psycopg2.extras
    IntegrityError = psycopg2.IntegrityError
else:
    IntegrityError = sqlite3.IntegrityError

class Conn:
    def __init__(self):
        if PG:
            self.c = psycopg2.connect(DATABASE_URL, connect_timeout=10,
                                      cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            self.c = sqlite3.connect(SQLITE_FILE); self.c.row_factory = sqlite3.Row
    def execute(self, sql, p=()):
        if PG:
            cur = self.c.cursor(); cur.execute(sql.replace("?", "%s"), p); return cur
        return self.c.execute(sql, p)
    def commit(self): self.c.commit()
    def rollback(self): self.c.rollback()
    def close(self): self.c.close()

PK = "SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY"
SCHEMA = [
 f"CREATE TABLE IF NOT EXISTS users(id {PK}, name TEXT, email TEXT UNIQUE, pw TEXT, role TEXT CHECK(role IN ('admin','staff','counsellor')))",
 f"CREATE TABLE IF NOT EXISTS students(id {PK}, reg TEXT UNIQUE, name TEXT, dept TEXT, counsellor_id INTEGER REFERENCES users(id))",
 "CREATE TABLE IF NOT EXISTS attendance(student_id INTEGER, date TEXT, status TEXT, marked_by INTEGER, UNIQUE(student_id, date))",
 "CREATE TABLE IF NOT EXISTS submissions(date TEXT PRIMARY KEY, staff_id INTEGER, created_at TEXT)",
 f"CREATE TABLE IF NOT EXISTS email_log(id {PK}, counsellor_id INTEGER, date TEXT, status TEXT, error TEXT, sent_at TEXT, UNIQUE(counsellor_id, date))",
]

def db():
    if "db" not in g: g.db = Conn()
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = Conn()
    for s in SCHEMA: c.execute(s)
    c.commit()
    if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users(name,email,pw,role) VALUES(?,?,?,'admin')",
                  ("Admin", "admin@college.edu",
                   generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123"))))
        c.commit()
    c.close()

def need(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login"))
            if session["role"] not in roles: return "Access denied", 403
            return f(*a, **k)
        return w
    return deco

def now(): return dt.datetime.now(TZ)
def today(): return now().date().isoformat()

# ---------- email (Brevo HTTPS API: works on free hosting, SMTP does not) ----------
def brevo(to_email, to_name, subject, text):
    key, sender = os.environ.get("BREVO_API_KEY"), os.environ.get("SENDER_EMAIL")
    if not (key and sender): return "not_configured", "BREVO_API_KEY / SENDER_EMAIL not set"
    req = urllib.request.Request("https://api.brevo.com/v3/smtp/email",
        data=json.dumps({"sender": {"name": "Attendance System", "email": sender},
                         "to": [{"email": to_email, "name": to_name}],
                         "subject": subject, "textContent": text}).encode(),
        headers={"api-key": key, "content-type": "application/json", "accept": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20); return "sent", ""
    except urllib.error.HTTPError as e:
        return "failed", f"{e.code} {e.read()[:150].decode('utf-8', 'ignore')}"
    except Exception as e:
        return "failed", str(e)[:200]

def send_report(cid, date):
    """One email per counsellor per date; never sent twice once status is 'sent'."""
    d = db()
    row = d.execute("SELECT status FROM email_log WHERE counsellor_id=? AND date=?", (cid, date)).fetchone()
    if row and row["status"] == "sent": return "sent"
    c = d.execute("SELECT name,email FROM users WHERE id=?", (cid,)).fetchone()
    rows = d.execute("""SELECT s.reg,s.name,s.dept,COALESCE(a.status,'Pending') st FROM students s
        LEFT JOIN attendance a ON a.student_id=s.id AND a.date=? WHERE s.counsellor_id=? ORDER BY s.reg""",
        (date, cid)).fetchall()
    if not rows: return "no_students"
    pres = sum(r["st"] == "Present" for r in rows)
    body = f"Dear {c['name']},\n\n{SUBJECT} attendance for {date}:\n\n"
    body += "\n".join(f"{r['reg']}  {r['name']} ({r['dept']})  -  {r['st']}" for r in rows)
    body += f"\n\nPresent: {pres}   Absent: {len(rows)-pres}\n\n- Smart Attendance System"
    status, err = brevo(c["email"], c["name"], f"{SUBJECT} attendance {date}", body)
    d.execute("""INSERT INTO email_log(counsellor_id,date,status,error,sent_at) VALUES(?,?,?,?,?)
        ON CONFLICT(counsellor_id,date) DO UPDATE SET status=excluded.status,error=excluded.error,sent_at=excluded.sent_at""",
        (cid, date, status, err, now().strftime("%Y-%m-%d %H:%M")))
    d.commit()
    return status

# ---------- auth ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["pw"], request.form["password"]):
            session.clear()
            session.update(uid=u["id"], role=u["role"], name=u["name"])
            return redirect(url_for(u["role"]))
        flash("Wrong email or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

# ---------- staff ----------
@app.route("/staff", methods=["GET", "POST"])
@need("staff", "admin")
def staff():
    date = request.values.get("date", today())
    d = db()
    done = d.execute("SELECT 1 FROM submissions WHERE date=?", (date,)).fetchone()
    studs = d.execute("""SELECT s.*,u.name cname,a.status FROM students s
        LEFT JOIN users u ON u.id=s.counsellor_id
        LEFT JOIN attendance a ON a.student_id=s.id AND a.date=? ORDER BY s.reg""", (date,)).fetchall()
    if request.method == "POST":
        if done:
            flash("Attendance for this date is already submitted. Ask admin to reopen it for a correction.")
            return redirect(url_for("staff", date=date))
        missing = [s["reg"] for s in studs if request.form.get(f"s{s['id']}") not in ("Present", "Absent")]
        if missing:
            flash("Mark every student first. Not marked: " + ", ".join(missing))
            return redirect(url_for("staff", date=date))
        for s in studs:
            d.execute("""INSERT INTO attendance(student_id,date,status,marked_by) VALUES(?,?,?,?)
                ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status,marked_by=excluded.marked_by""",
                (s["id"], date, request.form[f"s{s['id']}"], session["uid"]))
        d.execute("INSERT INTO submissions(date,staff_id,created_at) VALUES(?,?,?)", (date, session["uid"], now().isoformat()))
        d.commit()
        cids = {s["counsellor_id"] for s in studs if s["counsellor_id"]}
        res = [send_report(c, date) for c in cids]
        flash(f"Attendance saved. Emails sent: {res.count('sent')} of {len(cids)}."
              + ("" if res.count('sent') == len(cids) else " Check the Admin email log for problems."))
        return redirect(url_for("staff", date=date))
    return render_template("staff.html", studs=studs, date=date, done=done, room=ROOM, subject=SUBJECT)

# ---------- counsellor ----------
def my_rows(date):
    return db().execute("""SELECT s.reg,s.name,s.dept,COALESCE(a.status,'Pending') st FROM students s
        LEFT JOIN attendance a ON a.student_id=s.id AND a.date=? WHERE s.counsellor_id=? ORDER BY s.reg""",
        (date, session["uid"])).fetchall()

@app.route("/counsellor")
@need("counsellor")
def counsellor():
    date = request.args.get("date", today())
    rows = my_rows(date)
    n = {k: sum(r["st"] == k for r in rows) for k in ("Present", "Absent", "Pending")}
    return render_template("counsellor.html", rows=rows, date=date, n=n)

@app.route("/counsellor/csv")
@need("counsellor")
def counsellor_csv():
    date = request.args.get("date", today())
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Register No", "Name", "Department", "Date", "Status"])
    for r in my_rows(date): w.writerow([r["reg"], r["name"], r["dept"], date, r["st"]])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=attendance_{date}.csv"})

# ---------- admin ----------
@app.route("/admin")
@need("admin")
def admin():
    d = db()
    return render_template("admin.html",
        users=d.execute("SELECT * FROM users WHERE role!='admin' ORDER BY role,name").fetchall(),
        counsellors=d.execute("SELECT * FROM users WHERE role='counsellor' ORDER BY name").fetchall(),
        studs=d.execute("SELECT s.*,u.name cname FROM students s LEFT JOIN users u ON u.id=s.counsellor_id ORDER BY s.reg").fetchall(),
        mails=d.execute("SELECT e.*,u.name,u.email FROM email_log e JOIN users u ON u.id=e.counsellor_id ORDER BY e.id DESC LIMIT 30").fetchall(),
        subs=d.execute("SELECT * FROM submissions ORDER BY date DESC LIMIT 10").fetchall())

@app.post("/admin/user")
@need("admin")
def add_user():
    f = request.form
    try:
        db().execute("INSERT INTO users(name,email,pw,role) VALUES(?,?,?,?)",
            (f["name"].strip(), f["email"].strip().lower(), generate_password_hash(f["password"]), f["role"]))
        db().commit(); flash("User added.")
    except IntegrityError:
        db().rollback(); flash("That email already exists.")
    return redirect(url_for("admin"))

@app.post("/admin/student")
@need("admin")
def add_student():
    f = request.form
    try:
        db().execute("INSERT INTO students(reg,name,dept,counsellor_id) VALUES(?,?,?,?)",
            (f["reg"].strip(), f["name"].strip(), f["dept"].strip(), int(f["counsellor_id"])))
        db().commit(); flash("Student added.")
    except (IntegrityError, KeyError, ValueError):
        db().rollback(); flash("Could not add: duplicate register number or no counsellor selected.")
    return redirect(url_for("admin"))

@app.post("/admin/import")
@need("admin")
def import_students():
    """CSV columns: reg,name,dept,counsellor_email"""
    f = request.files.get("file"); added = skipped = 0
    if f:
        for r in csv.DictReader(io.StringIO(f.read().decode("utf-8-sig"))):
            try:
                c = db().execute("SELECT id FROM users WHERE email=? AND role='counsellor'",
                                 ((r.get("counsellor_email") or "").strip().lower(),)).fetchone()
                if not c: raise IntegrityError
                db().execute("INSERT INTO students(reg,name,dept,counsellor_id) VALUES(?,?,?,?)",
                    (r["reg"].strip(), r["name"].strip(), r["dept"].strip(), c["id"]))
                db().commit(); added += 1
            except (IntegrityError, KeyError, AttributeError):
                db().rollback(); skipped += 1
    flash(f"Imported {added} students, skipped {skipped}.")
    return redirect(url_for("admin"))

@app.post("/admin/reopen")
@need("admin")
def reopen():
    db().execute("DELETE FROM submissions WHERE date=?", (request.form["date"],)); db().commit()
    flash("Date reopened. Staff can correct and submit again (emails already sent will not repeat).")
    return redirect(url_for("admin"))

@app.post("/admin/resend")
@need("admin")
def resend():
    r = send_report(int(request.form["cid"]), request.form["date"])
    flash(f"Email status: {r}"); return redirect(url_for("admin"))

TEMPLATES = {'staff.html': '{% extends "base.html" %}{% block body %}\n<h2>{{ subject }} attendance</h2>\n<form method="get" class="row card"><div><label>Date</label><input type="date" name="date" value="{{ date }}"></div><button>Open</button></form>\n{% if done %}<div class="msg">Submitted for {{ date }}. Locked unless admin reopens it.</div>{% endif %}\n<form method="post" class="card"><input type="hidden" name="date" value="{{ date }}">\n<table><tr><th>Reg. no.</th><th>Student</th><th>Counsellor</th><th>Attendance</th></tr>\n{% for s in studs %}<tr><td>{{ s.reg }}</td><td>{{ s.name }}</td><td>{{ s.cname }}</td><td>\n{% for v in ["Present","Absent"] %}<label class="o"><input type="radio" name="s{{ s.id }}" value="{{ v }}" required {{ \'checked\' if s.status==v }} {{ \'disabled\' if done }}> {{ v }}</label>{% endfor %}</td></tr>\n{% else %}<tr><td colspan="4">No students yet. Ask admin to add them.</td></tr>{% endfor %}</table>\n<p><button {{ \'disabled\' if done }}>Submit attendance</button></p></form>{% endblock %}\n', 'admin.html': '{% extends "base.html" %}{% block body %}\n<h2>Admin</h2>\n<form method="post" action="{{ url_for(\'add_user\') }}" class="card row"><h3 style="width:100%">Add staff / counsellor</h3>\n<div><label>Name</label><input name="name" required></div><div><label>Email</label><input name="email" type="email" required></div>\n<div><label>Password</label><input name="password" required></div>\n<div><label>Role</label><select name="role"><option>staff</option><option>counsellor</option></select></div><button>Add</button></form>\n<form method="post" action="{{ url_for(\'add_student\') }}" class="card row"><h3 style="width:100%">Add student</h3>\n<div><label>Register no.</label><input name="reg" required></div><div><label>Name</label><input name="name" required></div>\n<div><label>Dept.</label><input name="dept" required></div>\n<div><label>Counsellor</label><select name="counsellor_id">{% for c in counsellors %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}</select></div><button>Add</button></form>\n<form method="post" action="{{ url_for(\'import_students\') }}" enctype="multipart/form-data" class="card row"><h3 style="width:100%">Import students (CSV: reg,name,dept,counsellor_email)</h3>\n<input type="file" name="file" accept=".csv" required><button>Import</button></form>\n<div class="card"><h3>Students ({{ studs|length }})</h3><table><tr><th>Reg.</th><th>Name</th><th>Dept.</th><th>Counsellor</th></tr>\n{% for s in studs %}<tr><td>{{ s.reg }}</td><td>{{ s.name }}</td><td>{{ s.dept }}</td><td>{{ s.cname }}</td></tr>{% endfor %}</table></div>\n<div class="card"><h3>Email log</h3><table><tr><th>Date</th><th>Counsellor</th><th>Status</th><th>Detail</th><th></th></tr>\n{% for m in mails %}<tr><td>{{ m.date }}</td><td>{{ m.name }}<br><small>{{ m.email }}</small></td><td class="{{ m.status }}">{{ m.status }}</td><td>{{ m.error }}</td>\n<td>{% if m.status!=\'sent\' %}<form method="post" action="{{ url_for(\'resend\') }}"><input type="hidden" name="cid" value="{{ m.counsellor_id }}"><input type="hidden" name="date" value="{{ m.date }}"><button>Resend</button></form>{% endif %}</td></tr>\n{% else %}<tr><td colspan="5">No emails yet.</td></tr>{% endfor %}</table></div>\n<div class="card"><h3>Submitted dates</h3>{% for s in subs %}<form method="post" action="{{ url_for(\'reopen\') }}" class="row"><span>{{ s.date }}</span><input type="hidden" name="date" value="{{ s.date }}"><button>Reopen for correction</button></form>{% else %}<p>None yet.</p>{% endfor %}</div>\n{% endblock %}\n', 'login.html': '{% extends "base.html" %}{% block body %}\n<form method="post" class="card" style="max-width:380px;margin:40px auto"><h2>Log in</h2>\n<p><label>Email<br><input name="email" type="email" required style="width:100%"></label></p>\n<p><label>Password<br><input name="password" type="password" required style="width:100%"></label></p>\n<button>Log in</button></form>{% endblock %}\n', 'counsellor.html': '{% extends "base.html" %}{% block body %}\n<h2>My students</h2>\n<form method="get" class="row card"><div><label>Date</label><input type="date" name="date" value="{{ date }}"></div><button>View</button>\n<a href="{{ url_for(\'counsellor_csv\', date=date) }}">Download CSV</a></form>\n<div class="stats"><div><b class="Present">{{ n.Present }}</b>Present</div><div><b class="Absent">{{ n.Absent }}</b>Absent</div><div><b class="Pending">{{ n.Pending }}</b>Pending</div></div><br>\n<div class="card"><table><tr><th>Reg. no.</th><th>Name</th><th>Dept.</th><th>Status</th></tr>\n{% for r in rows %}<tr><td>{{ r.reg }}</td><td>{{ r.name }}</td><td>{{ r.dept }}</td><td class="{{ r.st }}">{{ r.st }}</td></tr>\n{% else %}<tr><td colspan="4">No students assigned to you.</td></tr>{% endfor %}</table></div>{% endblock %}\n', 'base.html': '<!doctype html><html lang="en"><head><meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1"><title>Open Elective Attendance</title>\n<style>:root{--g:#0f4c45;--l:#d3dde0}*{box-sizing:border-box}\nbody{margin:0;font:16px/1.5 system-ui,sans-serif;background:#eef2f4;color:#12262b}\nheader{background:var(--g);color:#fff;padding:12px 20px;display:flex;gap:14px;align-items:center}\nheader b{flex:1}header a{color:#fff}\nmain{max-width:960px;margin:auto;padding:20px}\n.card{background:#fff;border:1px solid var(--l);border-radius:10px;padding:16px;margin-bottom:16px;overflow-x:auto}\ntable{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--l)}\ninput,select,button{font:inherit;padding:8px 10px;border:1px solid #9ab;border-radius:6px}\nbutton{background:var(--g);color:#fff;border-color:var(--g);cursor:pointer}\n.msg{background:#fff7e0;border-left:4px solid #e8a317;padding:10px 14px;margin-bottom:12px}\n.Present,.sent{color:#1b7a43;font-weight:600}.Absent,.failed{color:#b3261e;font-weight:600}.Pending,.not_configured{color:#8a6d00;font-weight:600}\n.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}.row div{display:flex;flex-direction:column}\n.stats{display:flex;gap:10px}.stats div{flex:1;background:#fff;border:1px solid var(--l);border-radius:8px;padding:10px}.stats b{font-size:1.6rem;display:block}\nlabel.o{margin-right:14px}\n</style></head><body>\n<header><b>Open Elective Attendance</b>{% if session.uid %}<span>{{ session.name }} ({{ session.role }})</span><a href="{{ url_for(\'logout\') }}">Log out</a>{% endif %}</header>\n<main>{% for m in get_flashed_messages() %}<div class="msg">{{ m }}</div>{% endfor %}{% block body %}{% endblock %}</main></body></html>\n'}
app.jinja_loader = DictLoader(TEMPLATES)

init_db()
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
