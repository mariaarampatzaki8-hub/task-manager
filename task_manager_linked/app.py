# app.py
import os, secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# App
# -------------------------------------------------
app = Flask(
    __name__,
    instance_relative_config=True,
    template_folder="templates",
    static_folder="static",
)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# -------------------------------------------------
# DB CONFIG (Render Postgres via pg8000 ή SQLite fallback)
# -------------------------------------------------
def build_db_uri() -> str:
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
    elif uri.startswith("postgresql://") and "+pg8000" not in uri:
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    return uri

app.config["SQLALCHEMY_DATABASE_URI"] = build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------------------------------------------------
# Models  (prefix tm_*)
# -------------------------------------------------
class Team(db.Model):
    __tablename__ = "tm_teams"
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"), nullable=True)

class User(db.Model):
    __tablename__ = "tm_users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(120), unique=True, nullable=False)
    email         = db.Column(db.String(200))
    phone         = db.Column(db.String(50))
    id_card       = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin      = db.Column(db.Boolean, default=False, nullable=False)
    color         = db.Column(db.String(20), default="#3273dc")
    team_id       = db.Column(db.Integer, db.ForeignKey("tm_teams.id"), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    __tablename__ = "tm_tasks"
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    status      = db.Column(db.String(20), default="open")  # open|done
    progress    = db.Column(db.Integer, default=0)          # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# -------------------------------------------------
# Bootstrap / Seed
# -------------------------------------------------
def bootstrap_db():
    db.create_all()

    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#ff4444",
            team_id=team.id,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    bootstrap_db()

# -------------------------------------------------
# Helpers / decorators
# -------------------------------------------------
def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*a, **k)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}

# -------------------------------------------------
# Health / Diag
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/__diag")
def __diag():
    insp = inspect(db.engine)
    data = {
        "tables": insp.get_table_names(),
        "users": db.session.query(User).count(),
        "tasks": db.session.query(Task).count(),
    }
    return (str(data), 200, {"Content-Type": "text/plain"})

# -------------------------------------------------
# Auth
# -------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not username or not password:
        flash("Συμπλήρωσε username & κωδικό.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -------------------------------------------------
# Pages
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/progress-view")
@login_required
def progress_view():
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

@app.route("/progress", endpoint="progress")
@login_required
def progress_alias():
    return redirect(url_for("progress_view"))

@app.route("/catalog")
@login_required
def catalog():
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template("catalog.html", tasks=tasks)

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")

# 🔧 ΣΗΜΑΝΤΙΚΟ: το όνομα endpoint είναι "tasks" (ταιριάζει με base.html)
@app.route("/tasks", methods=["GET"])
@login_required
def tasks():
    u = current_user()
    if u and u.is_admin:
        items = Task.query.order_by(Task.created_at.desc()).all()
    else:
        items = Task.query.filter_by(assignee_id=u.id).order_by(Task.created_at.desc()).all()
    users = User.query.all()
    user_map = {usr.id: usr.username for usr in users}
    return render_template("tasks.html", tasks=items, user_map=user_map)

@app.route("/teams")
@login_required
def teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    users = (
        User.query.order_by(User.username.asc()).all()
        if (u and u.is_admin)
        else User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
        if u and u.team_id else []
    )
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

@app.route("/notes")
@login_required
def notes():
    return render_template("notes.html")

# -------------------------------------------------
# Settings
# -------------------------------------------------
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/settings/profile", methods=["POST"])
@login_required
def update_profile():
    u = current_user()
    u.email   = (request.form.get("email") or "").strip() or None
    u.phone   = (request.form.get("phone") or "").strip() or None
    u.id_card = (request.form.get("id_card") or "").strip() or None
    u.color   = (request.form.get("color") or "").strip() or "#3273dc"
    db.session.commit()
    flash("Το προφίλ ενημερώθηκε.", "success")
    return redirect(url_for("settings"))

@app.route("/settings/password", methods=["POST"])
@login_required
def update_password():
    u = current_user()
    current_pw = (request.form.get("current_password") or "").strip()
    new_pw     = (request.form.get("new_password") or "").strip()
    confirm_pw = (request.form.get("confirm_password") or "").strip()

    if not current_pw or not new_pw or not confirm_pw:
        flash("Συμπλήρωσε όλα τα πεδία.", "warning")
        return redirect(url_for("settings"))
    if not u.check_password(current_pw):
        flash("Λάθος τρέχων κωδικός.", "danger")
        return redirect(url_for("settings"))
    if new_pw != confirm_pw:
        flash("Η επιβεβαίωση δεν ταιριάζει.", "warning")
        return redirect(url_for("settings"))
    if len(new_pw) < 6:
        flash("Ο νέος κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες.", "warning")
        return redirect(url_for("settings"))

    u.set_password(new_pw)
    db.session.commit()
    flash("Ο κωδικός άλλαξε επιτυχώς.", "success")
    return redirect(url_for("settings"))

# -------------------------------------------------
# Admin
# -------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    user_map = {u.id: u.username for u in users}
    return render_template("admin.html", users=users, teams=teams, tasks=tasks, user_map=user_map)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    email    = (request.form.get("email") or "").strip() or None
    phone    = (request.form.get("phone") or "").strip() or None
    id_card  = (request.form.get("id_card") or "").strip() or None
    color    = (request.form.get("color") or "").strip() or "#3273dc"
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_id  = request.form.get("team_id") or None

    if not username or not password:
        flash("Username & κωδικός υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη αυτό το username.", "danger")
        return redirect(url_for("admin"))

    team = Team.query.get(team_id) if team_id else None
    u = User(
        username=username, email=email, phone=phone, id_card=id_card,
        is_admin=is_admin, color=color, team_id=(team.id if team else None)
    )
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        leader_username = (request.form.get("leader_username") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))

        team = Team(name=name)
        if leader_username:
            leader = User.query.filter_by(username=leader_username).first()
            if leader:
                team.leader_id = leader.id
        db.session.add(team)
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/teams/<int:team_id>/members", methods=["GET", "POST"])
@admin_required
def admin_team_members(team_id):
    team = Team.query.get_or_404(team_id)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if not username:
            flash("Διάλεξε χρήστη.", "warning")
            return redirect(url_for("admin_team_members", team_id=team_id))
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Ο χρήστης δεν βρέθηκε.", "danger")
            return redirect(url_for("admin_team_members", team_id=team_id))
        user.team_id = team.id
        db.session.commit()
        flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
        return redirect(url_for("admin_team_members", team_id=team_id))

    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    users   = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, users=users)

@app.route("/admin/teams/<int:team_id>/members/<int:user_id>/remove", methods=["POST"])
@admin_required
def admin_team_member_remove(team_id, user_id):
    user = User.query.get_or_404(user_id)
    if user.team_id == team_id:
        user.team_id = None
        db.session.commit()
        flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
    return redirect(url_for("admin_team_members", team_id=team_id))

# Tasks από admin
@app.route("/admin/tasks", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    assignee_username = (request.form.get("assignee_username") or "").strip()
    progress_raw = (request.form.get("progress") or "").strip()

    if not title or not assignee_username:
        flash("Τίτλος και Username αναλαμβάνοντος είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    user = User.query.filter_by(username=assignee_username).first()
    if not user:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
        return redirect(url_for("admin"))

    try:
        progress = max(0, min(100, int(progress_raw))) if progress_raw else 0
    except ValueError:
        progress = 0

    t = Task(title=title, assignee_id=user.id, status="open", progress=progress)
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε και ανατέθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/create-task", methods=["GET"])
@admin_required
def create_task_form():
    users = User.query.order_by(User.username.asc()).all()
    return render_template("create_task.html", users=users)

@app.route("/admin/tasks/<int:task_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.status = "done" if t.status != "done" else "open"
    if t.status == "done":
        t.progress = 100
    db.session.commit()
    flash("Η κατάσταση της εργασίας ενημερώθηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    try:
        return render_template("error.html", code=500, message="Σφάλμα server."), 500
    except Exception:
        return "500 Internal Server Error", 500

# -------------------------------------------------
# Entry
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
