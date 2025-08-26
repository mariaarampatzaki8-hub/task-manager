# app.py
import os
import secrets
from datetime import datetime, date, time

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App factory & DB config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # Instance folder & sqlite fallback file
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    # DATABASE_URL from Render (Postgres) else fallback SQLite
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # 1) Heroku-style -> official
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) Use pg8000 driver, not psycopg
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        # 3) SSL for Render Postgres via query param (no connect_args)
        if "sslmode=" not in uri:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}sslmode=require"

        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
        # Fallback to SQLite for local/dev
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app

app = create_app()
db = SQLAlchemy(app)

# ---------- Models ----------
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
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(50), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

    # relationships
    notes = relationship("Note", backref="user", lazy="dynamic")
    tasks = relationship("Task", backref="assignee", lazy="dynamic", foreign_keys="Task.assignee_id")

    # helpers
    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

    @property
    def is_leader(self) -> bool:
        return Team.query.filter_by(leader_id=self.id).first() is not None

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="open")  # open|done
    progress = db.Column(db.Integer, default=0)        # 0..100

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.String(20), nullable=True) # simple strings for templates
    due_time = db.Column(db.String(20), nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

# ---------- Session helpers / guards ----------
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
            flash("Σύνδεση απαιτείται.", "warning")
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

# ---------- Init DB & seed admin (Flask 3 safe) ----------
_startup_done = False

@app.before_request
def _init_db_and_seed_once():
    global _startup_done
    if _startup_done:
        return
    _startup_done = True
    try:
        db.create_all()
    except Exception as e:
        app.logger.error("DB init/seed failed: %s", e)
        return
    # seed default admin
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
        app.logger.info("Δημιουργήθηκε Admin (admin/admin123)")

# ---------- Routes: Auth ----------
@app.route("/")
def index():
    # απλό login form
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "GET":
        return redirect(url_for("index"))
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

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------- User: Dashboard / Tasks / Notes ----------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()
    return render_template(
        "dashboard.html",
        open_tasks=open_tasks,
        done_tasks=done_tasks,
        notes=notes
    )

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
            t.progress = 99
    db.session.commit()
    return redirect(url_for("dashboard"))

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
    if n.user_id != u.id:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("dashboard"))
    n.content = new_content
    db.session.commit()
    flash("Σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("dashboard"))

@app.route("/me/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def me_delete_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    db.session.delete(n)
    db.session.commit()
    flash("Σημείωση διαγράφηκε.", "info")
    return redirect(url_for("dashboard"))

# ---------- Progress (όλοι οι χρήστες το βλέπουν) ----------
@app.route("/progress", methods=["GET"])
@login_required
def progress():
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done_cnt = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        avg_prog = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0
        rows.append({
            "user": u,
            "total": total,
            "done": done_cnt,
            "open": open_cnt,
            "avg": int(round(avg_prog)),
        })
    return render_template("progress.html", rows=rows)

# ---------- Admin: Panel / Users / Tasks / Notes ----------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    stats = {
        "users": len(users),
        "tasks": Task.query.count(),
        "done": Task.query.filter_by(status="done").count(),
        "open": Task.query.filter_by(status="open").count(),
    }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    phone = (request.form.get("phone") or "").strip() or None
    id_number = (request.form.get("id_number") or "").strip() or None
    color = request.form.get("color") or "#3273dc"
    raw_pw = (request.form.get("password") or "").strip()

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))
    if email and User.query.filter_by(email=email).first():
        flash("Το email υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, phone=phone, id_number=id_number, color=color)
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u)
    db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user().id:
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "danger")
        return redirect(url_for("admin"))
    u = User.query.get_or_404(user_id)
    # καθάρισε child rows (απλά: cascade χειροκίνητα)
    for n in u.notes.all():
        db.session.delete(n)
    for t in u.tasks.all():
        db.session.delete(t)
    # αν είναι leader κάπου, άδειασε leader_id
    team_led = Team.query.filter_by(leader_id=u.id).first()
    if team_led:
        team_led.leader_id = None
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = request.form.get("is_admin") in ("1", "on", "true", "True")
    if make_admin:
        u.is_admin = True
        db.session.commit()
        flash(f"Ο/Η {u.name} έγινε Διαχειριστής.", "success")
        return redirect(url_for("admin"))
    # προστασία: να μη μείνει σύστημα χωρίς admin
    admins_left = User.query.filter_by(is_admin=True).count()
    if u.is_admin and admins_left <= 1:
        flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        return redirect(url_for("admin"))
    u.is_admin = False
    db.session.commit()
    flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/reset_token/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_token(user_id):
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Ανανέωση link/ token ολοκληρώθηκε.", "info")
    return redirect(url_for("admin"))

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

# Admin: task management (create/edit/delete)
@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    due_date_s = request.form.get("due_date") or ""
    due_time_s = request.form.get("due_time") or ""
    assignee_id = request.form.get("assignee_id") or None
    if not title:
        flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
        return redirect(url_for("admin"))
    t = Task(
        title=title,
        description=description,
        due_date=due_date_s,
        due_time=due_time_s,
        assignee_id=int(assignee_id) if assignee_id else None,
    )
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or t.description).strip()
    t.due_date = request.form.get("due_date") or t.due_date
    t.due_time = request.form.get("due_time") or t.due_time
    status = request.form.get("status")
    if status in ("open", "done"):
        t.status = status
        t.completed_at = datetime.utcnow() if status == "done" else None
    prog = request.form.get("progress")
    if prog is not None and str(prog).isdigit():
        t.progress = max(0, min(100, int(prog)))
    assignee_id = request.form.get("assignee_id")
    if assignee_id:
        t.assignee_id = int(assignee_id)
    db.session.commit()
    flash("Η εργασία ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# ---------- Teams ----------
# Δημόσια (για όλους τους συνδεδεμένους): λίστα ομάδων (read-only)
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# Admin: διαχείριση ομάδων (create, set leader, add/remove member)
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
        db.session.add(Team(name=name))
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))
    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/teams/<int:team_id>/set_leader", methods=["POST"])
@admin_required
def admin_set_leader(team_id):
    team = Team.query.get_or_404(team_id)
    leader_id = request.form.get("leader_id")
    team.leader_id = int(leader_id) if leader_id else None
    db.session.commit()
    flash("Leader ενημερώθηκε.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/add_member", methods=["POST"])
@admin_required
def admin_add_member():
    user_id = int(request.form.get("user_id"))
    team_id = int(request.form.get("team_id"))
    u = User.query.get_or_404(user_id)
    u.team_id = team_id
    db.session.commit()
    flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/remove_member", methods=["POST"])
@admin_required
def admin_remove_member():
    user_id = int(request.form.get("user_id"))
    u = User.query.get_or_404(user_id)
    u.team_id = None
    db.session.commit()
    flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
    return redirect(url_for("admin_teams"))

# ---------- Directory (Admin & Leaders) ----------
@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # leaders βλέπουν τον κατάλογο (και φυσικά admin)
    is_leader = Team.query.filter_by(leader_id=u.id).first() is not None
    if not (u.is_admin or is_leader):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# ---------- Help ----------
@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

# ---------- Error handlers ----------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# (Δεν κάνουμε app.run εδώ. Στο Render εκκινεί με gunicorn app:app)
