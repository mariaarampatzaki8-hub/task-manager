# app.py
# Task Manager - Render/Flask 3 compatible app
# DB: PostgreSQL (Render) via SQLAlchemy + pg8000

from __future__ import annotations
import os
import secrets
from functools import wraps
from typing import Optional, List

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

# -----------------------------------------------------------------------------
# App & DB config
# -----------------------------------------------------------------------------

app = Flask(__name__, instance_relative_config=True)

# Secret key από env ή προσωρινό default
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Φάκελος instance (αν χρειαστεί SQLite fallback file)
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app_final.db")

# DATABASE_URL από Render
uri = os.environ.get("DATABASE_URL")

if uri:
    # 1) 'postgres://' -> 'postgresql://'
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    # 2) Χρήση driver pg8000
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    # ΣΗΜ.: Δεν περνάμε connect_args με 'ssl' γιατί ο pg8000 πριν σου πέταγε:
    # connect() got an unexpected keyword argument 'ssl'
    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    # Fallback σε SQLite για τοπικό dev
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models (μόνο πεδία που πράγματι έχουμε στον πίνακα)
# -----------------------------------------------------------------------------

class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # σχέσεις (lazy='select' ώστε να μην βαραίνει)
    leader = relationship("User", foreign_keys=[leader_id], uselist=False, backref="leading_team")

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    # Τα παρακάτω πεδία είναι “ελαφρά” και ταιριάζουν με τα SQL που τρέξαμε
    username = db.Column(db.String(200), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(200), nullable=True)
    color = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = relationship("Team", foreign_keys=[team_id], backref="members")

# Προαιρετικοί πίνακες – αν δεν υπάρχουν, απλώς δεν τους χρησιμοποιούμε
class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")
    progress = db.Column(db.Integer, nullable=False, default=0)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def current_user() -> Optional[User]:
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Αρχικοποίηση DB χωρίς before_first_request (δεν υπάρχει σε Flask 3)
# -----------------------------------------------------------------------------

_db_initialized = False

def init_db_and_seed_once():
    """Τρέχει στο πρώτο request: φτιάχνει πίνακες και σπέρνει admin/ομάδα αν λείπουν."""
    global _db_initialized
    if _db_initialized:
        return
    _db_initialized = True

    db.create_all()

    # Default ομάδα
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # Admin user (αν δεν υπάρχει)
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            name="Admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            team_id=team.id
        )
        db.session.add(admin)
        db.session.commit()
    else:
        # βεβαιώσου ότι είναι admin & έχει team
        changed = False
        if not admin.is_admin:
            admin.is_admin = True
            changed = True
        if not admin.team_id:
            admin.team_id = team.id
            changed = True
        if changed:
            db.session.commit()

    # Κάνε τον admin leader αν δεν υπάρχει leader
    if not team.leader_id:
        team.leader_id = admin.id
        db.session.commit()

# Θα τρέχει πριν από κάθε request (ελαφρύ, προστατευμένο με flag)
@app.before_request
def _ensure_inited():
    init_db_and_seed_once()

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
    # Αν είναι ήδη συνδεδεμένος, πάει στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """
    Login απλό: μόνο username από τη βάση.
    - Αν υπάρχει χρήστης, συνδέεται.
    - Αν δεν υπάρχει, μήνυμα λάθους (δεν δημιουργούμε αυθαίρετα user).
    """
    username = (request.form.get("username") or "").strip()
    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    role = "Διαχειριστής" if (u and u.is_admin) else "Χρήστης"
    # δείχνω και ένα mini health check κάτω όπως είχαμε
    return render_template("dashboard.html", user=u, role=role, status="/healthz -> ok")

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings_view():
    return render_template("settings.html")

@app.route("/catalog")
@login_required
def catalog_view():
    return render_template("catalog.html")

# Όλοι να βλέπουν καρτέλα Ομάδες (read-only)
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# Κατάλογος: admin και leaders (read-only λίστα χρηστών)
@app.route("/directory")
@login_required
def directory():
    u = current_user()
    is_leader = bool(u and u.team and u.team.leader_id == u.id)
    if not (u and (u.is_admin or is_leader)):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# Πρόοδος (demo): αν υπάρχει πίνακας tasks, δίνει metrics, αλλιώς κενό
@app.route("/progress")
@login_required
def progress_view():
    rows = []
    try:
        all_users: List[User] = User.query.order_by(User.username.asc()).all()
        for u in all_users:
            total = db.session.query(Task).filter_by(assignee_id=u.id).count()
            done = db.session.query(Task).filter_by(assignee_id=u.id, status="done").count()
            open_cnt = db.session.query(Task).filter_by(assignee_id=u.id, status="open").count()
            # μέσος όρος progress
            avg_val = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0
            rows.append({
                "user": u,
                "total": total,
                "done": done,
                "open": open_cnt,
                "avg": int(round(avg_val)),
            })
    except Exception:
        # Αν δεν υπάρχει πίνακας tasks, απλώς δείξε κενό
        rows = []
    return render_template("progress.html", rows=rows)

# -----------------------------------------------------------------------------
# Admin περιοχές
# -----------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.order_by(User.username.asc()).all()
    notes = Note.query.order_by(Note.id.desc()).all() if db.inspect(db.engine).has_table("notes") else []
    return render_template("admin.html", users=users, notes=notes)

# CRUD ομάδων (πολύ βασικό: δημιουργία μόνο με όνομα)
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
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

# Προσθήκη/αφαίρεση μέλους σε ομάδα
@app.route("/admin/teams/<int:team_id>/assign", methods=["POST"])
@admin_required
def admin_assign_team(team_id):
    user_id = int(request.form.get("user_id", "0"))
    user = User.query.get_or_404(user_id)
    team = Team.query.get_or_404(team_id)
    user.team_id = team.id
    db.session.commit()
    flash(f"Ο χρήστης {user.username} μπήκε στην ομάδα {team.name}.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/set_leader", methods=["POST"])
@admin_required
def admin_set_leader(team_id):
    user_id = int(request.form.get("user_id", "0"))
    user = User.query.get_or_404(user_id)
    team = Team.query.get_or_404(team_id)
    team.leader_id = user.id
    db.session.commit()
    flash(f"Leader της {team.name} ορίστηκε ο {user.username}.", "success")
    return redirect(url_for("admin_teams"))

# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Προσπάθησε να μην “καρφώνεις” trace στην οθόνη
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Gunicorn entry (Render τρέχει gunicorn app:app)
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
