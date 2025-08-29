import os, secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect

# ---------------- App ----------------
app = Flask(
    __name__,
    instance_relative_config=True,
    template_folder="templates",
    static_folder="static",
)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# ---------------- DB CONFIG ----------------
def build_db_uri():
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

# ---------------- MODELS ----------------
class Team(db.Model):
    __tablename__ = "tm_teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"), nullable=True)

class User(db.Model):
    __tablename__ = "tm_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    id_card = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    color = db.Column(db.String(20), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("tm_teams.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, raw: str): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw: str) -> bool: return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    __tablename__ = "tm_tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")   # open|done
    progress = db.Column(db.Integer, default=0)         # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# ---------------- BOOTSTRAP ----------------
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
            phone="0000000000",
            id_card="AA000000",
            is_admin=True,
            color="#ff4444",
            team_id=team.id,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    bootstrap_db()

# ---------------- HELPERS ----------------
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

# ---------------- HEALTH / DIAG ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/__diag")
def __diag():
    insp = inspect(db.engine)
    return {
        "tables": insp.get_table_names(),
        "users": db.session.query(User).count(),
        "tasks": db.session.query(Task).count()
    }

# ---------------- AUTH ----------------
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"): return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
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

# ---------------- PAGES ----------------
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
def progress_alias(): return redirect(url_for("progress_view"))

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html", teams=Team.query.order_by(Team.name.asc()).all())

@app.route("/catalog")
@login_required
def catalog():
    return render_template("catalog.html", tasks=Task.query.order_by(Task.id.desc()).all())

@app.route("/tasks")
@login_required
def tasks_list():
    u = current_user()
    tasks = Task.query.order_by(Task.created_at.desc()).all() if u.is_admin else \
            Task.query.filter_by(assignee_id=u.id).order_by(Task.created_at.desc()).all()
    user_map = {usr.id: usr.username for usr in User.query.all()}
    return render_template("tasks.html", tasks=tasks, user_map=user_map)

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    users = User.query.order_by(User.username.asc()).all() if u.is_admin else \
            User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page(): return render_template("help.html")

@app.route("/settings")
@login_required
def settings(): return render_template("settings.html")

@app.route("/settings/profile", methods=["POST"])
@login_required
def update_profile():
    u = current_user()
    u.email = request.form.get("email") or None
    u.phone = request.form.get("phone") or None
    u.id_card = request.form.get("id_card") or None
    u.color = request.form.get("color") or "#3273dc"
    db.session.commit()
    flash("Το προφίλ ενημερώθηκε.", "success")
    return redirect(url_for("settings"))

@app.route("/settings/password", methods=["POST"])
@login_required
def update_password():
    u = current_user()
    current_pw = request.form.get("current_password") or ""
    new_pw = request.form.get("new_password") or ""
    confirm_pw = request.form.get("confirm_password") or ""
    if not u.check_password(current_pw):
        flash("Λάθος τρέχων κωδικός.", "danger")
    elif new_pw != confirm_pw:
        flash("Η επιβεβαίωση δεν ταιριάζει.", "warning")
    else:
        u.set_password(new_pw)
        db.session.commit()
        flash("Ο κωδικός άλλαξε.", "success")
    return redirect(url_for("settings"))

# ---------------- ADMIN ----------------
@app.route("/admin")
@admin_required
def admin():
    return render_template(
        "admin.html",
        users=User.query.order_by(User.username.asc()).all(),
        teams=Team.query.order_by(Team.name.asc()).all(),
        tasks=Task.query.order_by(Task.created_at.desc()).all(),
        user_map={u.id: u.username for u in User.query.all()}
    )

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username") or ""
    password = request.form.get("password") or ""
    if not username or not password:
        flash("Username & κωδικός υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))
    u = User(
        username=username,
        email=request.form.get("email") or None,
        phone=request.form.get("phone") or None,
        id_card=request.form.get("id_card") or None,
        is_admin=True if request.form.get("is_admin")=="on" else False,
        color=request.form.get("color") or "#3273dc",
        team_id=(Team.query.get(request.form.get("team_id")) or None).id if request.form.get("team_id") else None
    )
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/teams", methods=["POST"])
@admin_required
def admin_create_team():
    name = request.form.get("name") or ""
    if not name:
        flash("Όνομα ομάδας υποχρεωτικό.", "warning")
    elif Team.query.filter_by(name=name).first():
        flash("Υπάρχει ήδη ομάδα.", "danger")
    else:
        team = Team(name=name)
        db.session.add(team)
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks", methods=["POST"])
@admin_required
def admin_create_task():
    title = request.form.get("title") or ""
    assignee_username = request.form.get("assignee_username") or ""
    user = User.query.filter_by(username=assignee_username).first()
    if not user:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
    else:
        t = Task(title=title, assignee_id=user.id)
        db.session.add(t)
        db.session.commit()
        flash("Η εργασία ανατέθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.status = "done" if t.status!="done" else "open"
    t.progress = 100 if t.status=="done" else 0
    db.session.commit()
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    return redirect(url_for("admin"))

# ---------------- ERRORS ----------------
@app.errorhandler(404)
def not_found(e): return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e): return render_template("error.html", code=500, message="Σφάλμα server."), 500

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
