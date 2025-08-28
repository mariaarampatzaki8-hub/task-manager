import os, secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- App ----------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# ---------------- DB CONFIG (Postgres pg8000 ή SQLite fallback) ----------------
def build_db_uri():
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        # τοπικό fallback
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")
    # Μετατροπή για SQLAlchemy + pg8000
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
    elif uri.startswith("postgresql://") and "+pg8000" not in uri:
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    # Σκόπιμα ΔΕΝ προσθέτουμε sslmode/connect_args εδώ (να αποφύγουμε conflicts).
    return uri

app.config["SQLALCHEMY_DATABASE_URI"] = build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------- MODELS (tm_* για να μην συγκρούονται με παλιά) ----------------
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

# ---------------- BOOTSTRAP / SEED ----------------
def bootstrap_db():
    db.create_all()
    # default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # admin user
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", email="admin@example.com", is_admin=True, color="#ff4444", team_id=team.id)
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

# ---------------- HEALTH ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- AUTH ----------------
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"): return redirect(url_for("dashboard"))
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

# alias για τυχόν παλιά menu links
@app.route("/progress", endpoint="progress")
@login_required
def progress_alias():
    return redirect(url_for("progress_view"))

@app.route("/teams")
@login_required
def teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

@app.route("/catalog")
@login_required
def catalog():
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template("catalog.html", tasks=tasks)

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Admin βλέπει όλους — αλλιώς (προαιρετικά) φιλτράρεις ανά ομάδα
    users = User.query.order_by(User.username.asc()).all() if (u and u.is_admin) else \
            User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all() if u and u.team_id else []
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# ---------------- ADMIN ----------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False
    email = (request.form.get("email") or "").strip() or None
    color = (request.form.get("color") or "").strip() or "#3273dc"
    team_id = request.form.get("team_id") or None

    if not username or not password:
        flash("Username & κωδικός υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη αυτό το username.", "danger")
        return redirect(url_for("admin"))

    team = Team.query.get(team_id) if team_id else None
    u = User(username=username, email=email, is_admin=is_admin, color=color, team_id=team.id if team else None)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    # POST: δημιουργία ομάδας
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

    # GET: φέρε λίστες για το template
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin_teams.html", users=users, teams=teams)
# ---------------- TASKS ----------------
def is_admin_or_leader(u: User) -> bool:
    return u.is_admin or (u.team and u.team.leader_id == u.id)

@app.route("/tasks")
@login_required
def list_tasks():
    u = current_user()
    if u.is_admin:
        tasks = Task.query.all()
    elif u.team:
        tasks = Task.query.filter_by(team_id=u.team_id).all()
    else:
        tasks = []
    return render_template("tasks.html", tasks=tasks)

@app.route("/tasks/create", methods=["GET", "POST"])
@login_required
def create_task():
    u = current_user()
    if not is_admin_or_leader(u):
        flash("Μόνο οι admin ή οι leaders μπορούν να δημιουργούν εργασίες.", "danger")
        return redirect(url_for("list_tasks"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        team_id = request.form.get("team_id")

        if not title:
            flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
            return redirect(url_for("create_task"))

        task = Task(title=title, description=description, team_id=team_id)
        db.session.add(task)
        db.session.commit()
        flash("Η εργασία δημιουργήθηκε!", "success")
        return redirect(url_for("list_tasks"))

    teams = Team.query.all()
    return render_template("create_task.html", teams=teams)

@app.route("/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_task(task_id):
    u = current_user()
    task = Task.query.get_or_404(task_id)

    if not (u.is_admin or (u.team_id == task.team_id)):
        flash("Δεν έχετε δικαίωμα να ολοκληρώσετε αυτήν την εργασία.", "danger")
        return redirect(url_for("list_tasks"))

    task.status = "done"
    db.session.commit()
    flash("Η εργασία ολοκληρώθηκε!", "success")
    return redirect(url_for("list_tasks"))
    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Σφάλμα server."), 500

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    # Το Render τρέχει με gunicorn app:app — εδώ είναι μόνο για τοπικό debug
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
