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

# ---------------- DB CONFIG (Postgres via pg8000 ή SQLite fallback) ----------------
def build_db_uri():
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")
    # κάνε το συμβατό με SQLAlchemy + pg8000 (ΧΩΡΙΣ sslmode/extra args)
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
    name = db.Column(db.String(200))
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

# ---------------- BOOTSTRAP / SEED ----------------
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
            name="Admin",
            email="admin@example.com",
            is_admin=True,
            color="#ff4444",
            team_id=team.id
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

# ---------------- HEALTH ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- AUTH ----------------
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

# alias για παλιά menu links
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
    # ο πίνακας δείχνει το ίδιο template με τον catalog
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    users = (User.query.order_by(User.username.asc()).all()
             if (u and u.is_admin)
             else User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
             if u and u.team_id else [])
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

# -------- Settings (προφίλ + αλλαγή κωδικού) --------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()
    if request.method == "POST":
        # ενημέρωση στοιχείων
        u.name = (request.form.get("name") or "").strip() or None
        u.email = (request.form.get("email") or "").strip() or None
        u.phone = (request.form.get("phone") or "").strip() or None
        u.id_card = (request.form.get("id_card") or "").strip() or None
        u.color = (request.form.get("color") or "#3273dc").strip() or "#3273dc"

        new_pw = (request.form.get("new_password") or "").strip()
        confirm = (request.form.get("confirm_password") or "").strip()
        if new_pw or confirm:
            if new_pw != confirm:
                flash("Οι δύο κωδικοί δεν ταιριάζουν.", "danger")
                return redirect(url_for("settings"))
            if len(new_pw) < 4:
                flash("Ο κωδικός πρέπει να έχει τουλάχιστον 4 χαρακτήρες.", "warning")
                return redirect(url_for("settings"))
            u.set_password(new_pw)
            flash("Ο κωδικός άλλαξε.", "success")

        db.session.commit()
        flash("Το προφίλ ενημερώθηκε.", "success")
        return redirect(url_for("settings"))

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
    name = (request.form.get("name") or "").strip() or None
    email = (request.form.get("email") or "").strip() or None
    phone = (request.form.get("phone") or "").strip() or None
    id_card = (request.form.get("id_card") or "").strip() or None
    color = (request.form.get("color") or "").strip() or "#3273dc"
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_id = request.form.get("team_id") or None

    if not username:
        flash("Username είναι υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη αυτό το username.", "danger")
        return redirect(url_for("admin"))

    # προσωρινός κωδικός
    temp_pw = request.form.get("password") or "change-me"

    team = Team.query.get(team_id) if team_id else None
    u = User(
        username=username,
        name=name,
        email=email,
        phone=phone,
        id_card=id_card,
        is_admin=is_admin,
        color=color,
        team_id=team.id if team else None
    )
    u.set_password(temp_pw)
    db.session.add(u)
    db.session.commit()
    flash(f"Ο χρήστης δημιουργήθηκε (προσωρινός κωδ.: {temp_pw}).", "success")
    return redirect(url_for("admin"))

# -- Διαχείριση ομάδων --
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

    users = User.query.order_by(User.username.asc()).all()
    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, users=users, members=members)

@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_team_delete(team_id):
    team = Team.query.get_or_404(team_id)
    # βγάλε τα μέλη από την ομάδα
    User.query.filter_by(team_id=team.id).update({"team_id": None})
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

# ---------------- TASKS (προαιρετικά για τα templates tasks/create_task) ----------------
@app.route("/tasks")
@login_required
def tasks_view():
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("tasks.html", tasks=tasks, users=users)

@app.route("/tasks/create", methods=["GET", "POST"])
@login_required
def create_task():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        assignee_id = request.form.get("assignee_id") or None
        if not title:
            flash("Τίτλος υποχρεωτικός.", "warning")
            return redirect(url_for("create_task"))
        t = Task(title=title, assignee_id=assignee_id or None)
        db.session.add(t)
        db.session.commit()
        flash("Η εργασία δημιουργήθηκε.", "success")
        return redirect(url_for("tasks_view"))

    users = User.query.order_by(User.username.asc()).all()
    return render_template("create_task.html", users=users)

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Σφάλμα server."), 500

# ---------------- ENTRY (local only) ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
