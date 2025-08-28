import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# -----------------------------------------------------------------------------
# App / Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Secret
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Instance folder ( SQLite fallback file lives here )
os.makedirs(app.instance_path, exist_ok=True)
sqlite_path = os.path.join(app.instance_path, "app.db")

# DATABASE_URL from Render (Postgres) ή fallback σε SQLite
raw_uri = os.environ.get("DATABASE_URL")

def normalize_db_url(uri: str) -> str:
    """
    - render/heroku δίνουν 'postgres://...' -> SQLAlchemy θέλει 'postgresql://'
    - αλλά εμείς θέλουμε driver pg8000 -> 'postgresql+pg8000://'
    - βάζουμε 'sslmode=require' στο query string (απαραίτητο στο Render)
    """
    # 1) postgres:// -> postgresql://
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)

    # 2) postgresql:// -> postgresql+pg8000://
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

    # 3) add sslmode=require αν λείπει
    if "sslmode=" not in uri:
        sep = "&" if "?" in uri else "?"
        uri = f"{uri}{sep}sslmode=require"

    return uri

if raw_uri:
    app.config["SQLALCHEMY_DATABASE_URI"] = normalize_db_url(raw_uri)
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + sqlite_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(16), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    token = db.Column(db.String(32), nullable=True)  # optional magic login
    must_change_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open/done
    progress = db.Column(db.Integer, default=0)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# -----------------------------------------------------------------------------
# Seed (run at startup; no before_first_request in Flask 3)
# -----------------------------------------------------------------------------
def init_db_and_seed():
    db.create_all()

    # Default team
    default_team = Team.query.filter_by(name="Default Team").first()
    if not default_team:
        default_team = Team(name="Default Team")
        db.session.add(default_team)
        db.session.commit()

    # Admin user
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            team_id=default_team.id
        )
        admin.set_password("admin123")
        admin.token = secrets.token_hex(8)
        db.session.add(admin)
        db.session.commit()

    # Make admin leader of default team if none
    if default_team.leader_id is None:
        default_team.leader_id = admin.id
        db.session.commit()

with app.app_context():
    init_db_and_seed()


# -----------------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
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


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


# -----------------------------------------------------------------------------
# Home / Auth
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, πήγαινε στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()

    # Demo: αν βάλεις μόνο username χωρίς κωδικό, κάνουμε soft-login
    if user and (not password or user.check_password(password)):
        session["uid"] = user.id
        session["username"] = user.username
        session["is_admin"] = bool(user.is_admin)
        flash("Συνδέθηκες επιτυχώς.", "success")
        return redirect(url_for("dashboard"))

    flash("Λάθος στοιχεία.", "danger")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# -----------------------------------------------------------------------------
# Dashboard / Board / Directory / Help / Settings
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return render_template("dashboard.html", user=u)

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Admin βλέπει όλους — αλλιώς φιλτράρουμε ανά ομάδα
    if u.is_admin or not u.team_id:
        users = User.query.order_by(User.username.asc()).all()
    else:
        users = User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


# -----------------------------------------------------------------------------
# Progress (χωρίς σύγκρουση endpoint)
# -----------------------------------------------------------------------------
@app.route("/progress", endpoint="progress_view", methods=["GET"])
@login_required
def progress_view():
    u = current_user()

    # για παράδειγμα: υπολογισμός προόδου ανά χρήστη
    users = User.query.order_by(User.username.asc()).all()
    rows = []
    for usr in users:
        total = Task.query.filter_by(assignee_id=usr.id).count()
        done = Task.query.filter_by(assignee_id=usr.id, status="done").count()
        avg_prog = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == usr.id).scalar() or 0
        rows.append({
            "user": usr,
            "total": total,
            "done": done,
            "open": total - done,
            "avg": int(round(avg_prog))
        })

    return render_template("progress.html", rows=rows)


# -----------------------------------------------------------------------------
# ADMIN
# -----------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

# Δημιουργία χρήστη (απλό)
@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    is_admin = True if request.form.get("is_admin") == "1" else False
    color = (request.form.get("color") or "#3273dc").strip()

    if not username:
        flash("Username υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    user = User(
        username=username,
        name=name,
        email=email,
        is_admin=is_admin,
        color=color
    )
    # default password
    user.set_password("pass123")
    db.session.add(user)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

# Ομάδες: λίστα + δημιουργία
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

    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin_teams.html", users=users, teams=teams)

# Διαχείριση μελών ομάδας (ΠΡΟΣΟΧΗ: μόνο μία φορά αυτό το endpoint!)
@app.route("/admin/teams/<int:team_id>/members", methods=["GET", "POST"])
@admin_required
def admin_team_members(team_id):
    team = Team.query.get_or_404(team_id)

    if request.method == "POST":
        action = request.form.get("action")
        username = (request.form.get("username") or "").strip()

        if not username:
            flash("Διάλεξε χρήστη.", "warning")
            return redirect(url_for("admin_team_members", team_id=team_id))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Ο χρήστης δεν βρέθηκε.", "danger")
            return redirect(url_for("admin_team_members", team_id=team_id))

        if action == "add":
            user.team_id = team.id
            db.session.commit()
            flash(f"Ο χρήστης {username} προστέθηκε στην ομάδα.", "success")

        elif action == "remove":
            user.team_id = None
            db.session.commit()
            flash(f"Ο χρήστης {username} αφαιρέθηκε από την ομάδα.", "success")

        return redirect(url_for("admin_team_members", team_id=team_id))

    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    all_users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, all_users=all_users)

# Διαγραφή ομάδας
@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)

    # Αποσυνδέουμε τυχόν μέλη από την ομάδα πριν τη διαγραφή
    User.query.filter_by(team_id=team.id).update({User.team_id: None})
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))


# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Στα logs να βλέπουμε το σφάλμα
    app.logger.exception("Unhandled 500")
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# -----------------------------------------------------------------------------
# Gunicorn entry (Render τρέχει 'gunicorn app:app')
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Τοπικά μόνο
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
