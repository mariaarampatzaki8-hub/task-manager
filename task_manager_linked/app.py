# app.py
import os
import secrets
from datetime import datetime, date, time

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

# -------- App Factory & DB config (Render Postgres via pg8000, fallback SQLite) --------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # ensure instance folder exists (for sqlite fallback file)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    uri = os.environ.get("DATABASE_URL")  # e.g. postgresql://... from Render

    if uri:
        # 1) Heroku-style -> official scheme
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) force pg8000 driver
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

        # IMPORTANT: Do NOT add ?ssl= / connect_args for pg8000 on Render.
        # Render's DATABASE_URL ήδη περιέχει τα σωστά SSL params όταν χρειάζεται.
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
        # fallback σε local SQLite
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app

app = create_app()
db = SQLAlchemy(app)

# ---------------- Models ----------------
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=True, unique=False)
    phone = db.Column(db.String(40), nullable=True)
    id_number = db.Column(db.String(40), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)

    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(16), default="#3273dc")  # Bulma primary (blue)

    token = db.Column(db.String(64), nullable=True)  # optional one-time login link

    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

    # relations
    tasks = relationship("Task", backref="assignee", lazy="dynamic")
    notes = relationship("Note", backref="user", lazy="dynamic")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(20), default="open")  # open/done
    progress = db.Column(db.Integer, default=0)       # 0..100

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ---------------- Helpers ----------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

# -------------- Initial DB & seed admin (runs at import) --------------
with app.app_context():
    db.create_all()

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email=None,
            is_admin=True,
            color="#3273dc",
        )
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Δημιουργήθηκε Admin username=admin password=admin123")

    # write ephemeral login link to logs each boot (for ευκολία)
    magic = secrets.token_urlsafe(8)
    session_key = f"adm:{magic}"
    app.config["ADM_LINK"] = f"/login/{magic}"
    app.logger.info("== Admin login links ==")
    app.logger.info("Admin: %s", app.config["ADM_LINK"])
    app.logger.info("== End admin links ==")

# ---------------- Routes: Auth ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    if u.is_admin:
        return redirect(url_for("admin"))
    return redirect(url_for("dashboard"))

# one-time admin boot link
@app.route("/login/<token>")
def one_time_login(token):
    # token is the magic printed at logs — not persistent user token
    if token and app.config.get("ADM_LINK") == f"/login/{token}":
        # login as admin quickly
        admin = User.query.filter_by(username="admin").first()
        if admin:
            session["uid"] = admin.id
            flash("Συνδέθηκες ως admin.", "success")
            return redirect(url_for("admin"))
    flash("Άκυρο link.", "danger")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------------- Routes: Dashboard / Tasks / Notes (User) ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()
    return render_template("dashboard.html",
                           open_tasks=open_tasks,
                           done_tasks=done_tasks,
                           notes=notes)

@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    if t.status == "open":
        t.status = "done"
        t.progress = 100 if t.progress < 100 else t.progress
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.completed_at = None
        if t.progress == 100:
            t.progress = 90  # μικρό “uncomplete”
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/tasks/<int:task_id>/progress", methods=["POST"])
@login_required
def set_task_progress(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    try:
        val = int(request.form.get("progress", 0))
    except Exception:
        val = 0
    val = max(0, min(100, val))
    t.progress = val
    if val == 100:
        t.status = "done"
        if not t.completed_at:
            t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.completed_at = None
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

# Notes (user)
@app.route("/me/add_note", methods=["POST"])
@login_required
def me_add_note():
    u = current_user()
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Το σημείωμα είναι κενό.", "warning")
        return redirect(url_for("dashboard"))
    db.session.add(Note(content=content, user_id=u.id))
    db.session.commit()
    flash("Η σημείωση αποθηκεύτηκε.", "success")
    return redirect(url_for("dashboard"))

@app.route("/me/notes/<int:note_id>/edit", methods=["POST"])
@login_required
def me_edit_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("dashboard"))
    n.content = new_content
    db.session.commit()
    flash("Η σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("dashboard"))

@app.route("/me/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def me_delete_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    db.session.delete(n)
    db.session.commit()
    flash("Η σημείωση διαγράφηκε.", "info")
    return redirect(url_for("dashboard"))

# ---------------- Progress (visible to all logged users) ----------------
@app.route("/progress")
@login_required
def progress():
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        avg_prog = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0
        rows.append({
            "user": u,
            "total": total, "done": done, "open": open_cnt,
            "avg": int(round(avg_prog))
        })
    return render_template("progress.html", rows=rows)

# ---------------- Settings (change password/color) ----------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()
    if request.method == "POST":
        new_color = request.form.get("color") or u.color
        u.color = new_color
        if request.form.get("new_password"):
            u.set_password(request.form.get("new_password"))
            u.must_change_password = False
        db.session.commit()
        flash("Αποθηκεύτηκαν οι αλλαγές.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", user=u)

# ---------------- Admin: Dashboard (users / notes overview / quick stats) ----------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    stats = {}
    for u in users:
        last_done = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).first()
        stats[u.id] = {
            "open": Task.query.filter_by(assignee_id=u.id, status="open").count(),
            "done": Task.query.filter_by(assignee_id=u.id, status="done").count(),
            "avg": int(round(db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0)),
            "last_done": last_done.completed_at if last_done else None
        }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

# Admin: create user
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    phone = (request.form.get("phone") or "").strip() or None
    idn = (request.form.get("id_number") or "").strip() or None
    color = request.form.get("color") or "#3273dc"
    raw_pw = (request.form.get("password") or "").strip()
    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger"); return redirect(url_for("admin"))
    u = User(name=name, username=username, email=email, phone=phone, id_number=idn, color=color)
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u); db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin"))

# Admin: delete user
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash("Δεν γίνεται να διαγράψεις τον τελευταίο admin.", "danger")
        return redirect(url_for("admin"))
    # delete related data
    Task.query.filter_by(assignee_id=u.id).delete()
    Note.query.filter_by(user_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# Admin: reset password -> must_change on next login
@app.route("/admin/users/<int:user_id>/reset_pw", methods=["POST"])
@admin_required
def admin_reset_pw(user_id):
    u = User.query.get_or_404(user_id)
    tmp = "pass-" + secrets.token_hex(2)
    u.set_password(tmp)
    u.must_change_password = True
    db.session.commit()
    flash(f"Προσωρινός κωδικός: {tmp}", "info")
    return redirect(url_for("admin"))

# Admin: set/unset admin role
@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = request.form.get("is_admin") in ("1", "on", "true", "True")
    if make_admin:
        u.is_admin = True
        db.session.commit()
        flash(f"Ο/Η {u.name} έγινε Διαχειριστής.", "success")
    else:
        admins_left = User.query.filter_by(is_admin=True).count()
        if u.is_admin and admins_left <= 1:
            flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        else:
            u.is_admin = False
            db.session.commit()
            flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))

# Admin: edit user's color
@app.route("/admin/users/<int:user_id>/color", methods=["POST"])
@admin_required
def admin_set_color(user_id):
    u = User.query.get_or_404(user_id)
    color = request.form.get("color") or "#3273dc"
    u.color = color
    db.session.commit()
    flash("Χρώμα ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

# Admin: Notes edit/delete (για να “διορθώνει” σημειώσεις)
@app.route("/admin/notes/<int:note_id>/edit", methods=["POST"])
@admin_required
def admin_edit_note(note_id):
    n = Note.query.get_or_404(note_id)
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("admin"))
    n.content = new_content
    db.session.commit()
    flash("Σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    n = Note.query.get_or_404(note_id)
    db.session.delete(n)
    db.session.commit()
    flash("Σημείωση διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# ---------------- Admin: Tasks CRUD & assign ----------------
@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    assignee_id = request.form.get("assignee_id") or None
    if not title:
        flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
        return redirect(url_for("admin_tasks"))
    t = Task(title=title, description=description)
    if assignee_id:
        t.assignee_id = int(assignee_id)
    db.session.add(t); db.session.commit()
    flash("Εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin_tasks"))

@app.route("/admin/tasks")
@admin_required
def admin_tasks():
    tasks = Task.query.order_by(Task.id.desc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_tasks.html", tasks=tasks, users=users)

@app.route("/admin/tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or "") or None
    t.assignee_id = int(request.form.get("assignee_id")) if request.form.get("assignee_id") else None
    try:
        t.progress = max(0, min(100, int(request.form.get("progress", t.progress))))
    except Exception:
        pass
    status = request.form.get("status")
    if status in ("open","done"):
        t.status = status
        if status == "done":
            t.progress = max(t.progress, 100)
            t.completed_at = t.completed_at or datetime.utcnow()
        else:
            t.completed_at = None
    db.session.commit()
    flash("Η εργασία ενημερώθηκε.", "success")
    return redirect(url_for("admin_tasks"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t); db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin_tasks"))

# ---------------- Teams ----------------
# Δημόσια (για όλους τους συνδεδεμένους): λίστα ομάδων (read-only)
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# Admin: διαχείριση ομάδων + ανάθεση μελών/leader
@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))
        db.session.add(Team(name=name)); db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/assign_team", methods=["POST"])
@admin_required
def admin_assign_team():
    user_id = int(request.form.get("user_id"))
    team_id = int(request.form.get("team_id")) if request.form.get("team_id") else None
    u = User.query.get_or_404(user_id)
    if team_id:
        team = Team.query.get_or_404(team_id)
        u.team_id = team.id
    else:
        u.team_id = None
    db.session.commit()
    flash("Ανάθεση ομάδας ενημερώθηκε.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/set_leader", methods=["POST"])
@admin_required
def admin_set_leader():
    team_id = int(request.form.get("team_id"))
    user_id = int(request.form.get("user_id")) if request.form.get("user_id") else None
    team = Team.query.get_or_404(team_id)
    if user_id:
        u = User.query.get_or_404(user_id)
        if u.team_id != team.id:
            u.team_id = team.id
        team.leader_id = u.id
    else:
        team.leader_id = None
    db.session.commit()
    flash("Leader ενημερώθηκε.", "success")
    return redirect(url_for("admin_teams"))
# ============== Progress (όλοι βλέπουν) ==============
@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress():
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        avg_prog = db.session.query(db.func.avg(Task.progress)) \
                    .filter(Task.assignee_id == u.id).scalar() or 0
        rows.append({
            "user": u,
            "total": total,
            "done": done,
            "open": open_cnt,
            "avg": int(round(avg_prog)),
        })
    return render_template("progress.html", rows=rows)
# ---------------- Directory (admin & leaders) ----------------
@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # leaders βλέπουν τον κατάλογο, εκτός από τους admin φυσικά
    if not (u.is_admin or (u.team_id and u.id == (u.team.leader_id if u.team else None))):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# ---------------- Help / Οδηγίες ----------------
@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------------- Gunicorn entry ----------------
# (Render uses: gunicorn app:app)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
