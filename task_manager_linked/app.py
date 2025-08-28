# app.py
import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from types import SimpleNamespace

# -----------------------------------------------------------------------------
# Δημιουργία app + DB config (Render Postgres με pg8000, αλλιώς SQLite)
# -----------------------------------------------------------------------------
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or ("dev-" + secrets.token_hex(16))

# Instance folder για SQLite
os.makedirs(app.instance_path, exist_ok=True)
sqlite_path = os.path.join(app.instance_path, "app.db")

db_url = os.environ.get("DATABASE_URL")  # π.χ. postgresql://user:pass@host/db
if db_url:
    # Heroku-style -> official
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    # Χρησιμοποιούμε pg8000 (όχι psycopg2)
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + sqlite_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Μοντέλα
# -----------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    leader = db.relationship("User", foreign_keys=[leader_id], backref="leading_team", uselist=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    # βασικά
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)

    # επιπλέον στοιχεία
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    id_card = db.Column(db.String(40), nullable=True)

    # ρόλος/ρυθμίσεις
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    color = db.Column(db.String(16), default="#3273dc", nullable=False)

    # auth
    password_hash = db.Column(db.String(255), nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)

    # σχέσεις
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = db.relationship("Team", backref="members")

    # timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # helpers
    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

# -----------------------------------------------------------------------------
# Αρχικοποίηση DB & seed admin/default team
# -----------------------------------------------------------------------------
def init_db_and_seed():
    db.create_all()

    # Default Team
    default_team = Team.query.filter_by(name="Default Team").first()
    if not default_team:
        default_team = Team(name="Default Team")
        db.session.add(default_team)
        db.session.commit()

    # Admin user
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            name="Admin",
            email="admin@example.com",
            phone=None,
            id_card=None,
            is_admin=True,
            color="#3273dc",
            team=default_team,
            must_change_password=False,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

    # Ορίσμος leader για default team (admin)
    if default_team.leader_id is None:
        default_team.leader_id = admin.id
        db.session.commit()

with app.app_context():
    init_db_and_seed()

# -----------------------------------------------------------------------------
# Helpers: current_user / decorators
# -----------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
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

# Διαθέσιμος ο `user` σε ΟΛΑ τα templates (για να μη ρίχνει 500 πριν το login)
@app.context_processor
def inject_user():
    u = current_user()
    if not u:
        u = SimpleNamespace(
            id=None, username=None, name=None,
            is_admin=False, color="#3273dc"
        )
    return {"user": u}

# -----------------------------------------------------------------------------
# Healthcheck
# -----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# -----------------------------------------------------------------------------
# Home / Auth
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
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

# -----------------------------------------------------------------------------
# Dashboard & βασικές σελίδες
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Μικρό status ping να φαίνεται στο UI
    try:
        status = "ok"
    except Exception:
        status = "error"
    return render_template("dashboard.html", status=status)

@app.route("/board")
@login_required
def board():
    # «Πίνακας» – απλά δίνουμε το template catalog.html
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    if u.is_admin:
        users = User.query.order_by(User.username.asc()).all()
    else:
        # Αν έχει team, βλέπει μόνο την ομάδα του
        if u.team_id:
            users = User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
        else:
            users = [u]
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()
    if request.method == "POST":
        new_pass = (request.form.get("new_password") or "").strip()
        new_color = (request.form.get("color") or "").strip()
        if new_pass:
            u.set_password(new_pass)
            u.must_change_password = False
            flash("Ο κωδικός άλλαξε.", "success")
        if new_color:
            u.color = new_color
            flash("Το χρώμα ενημερώθηκε.", "info")
        db.session.commit()
        return redirect(url_for("settings"))
    return render_template("settings.html")

# Προαιρετικό «progress» για να μη σκάει το navbar αν το καλεί
@app.route("/progress")
@login_required
def progress_view():
    return render_template("progress.html", rows=[], total=0, done=0, avg=0)

# -----------------------------------------------------------------------------
# ADMIN
# -----------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

# Δημιουργία χρήστη (admin)
@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    id_card = (request.form.get("id_card") or "").strip()
    color = (request.form.get("color") or "#3273dc").strip()
    is_admin = True if request.form.get("is_admin") in ("1", "true", "on") else False

    if not username:
        flash("Username υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    # Προσωρινός κωδικός – θα τον αλλάξει από Settings
    temp_password = request.form.get("temp_password") or "changeme123"

    user = User(
        username=username,
        name=name or username,
        email=email or None,
        phone=phone or None,
        id_card=id_card or None,
        is_admin=is_admin,
        color=color or "#3273dc",
        must_change_password=True,
    )
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

# Reset password (admin)
@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_pass = (request.form.get("new_password") or "changeme123").strip()
    user.set_password(new_pass)
    user.must_change_password = True
    db.session.commit()
    flash("Ο κωδικός επαναφέρθηκε.", "info")
    return redirect(url_for("admin"))

# Διαγραφή χρήστη (admin)
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν γίνεται να σβήσεις τον admin.", "warning")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# Ομάδες: λίστα + δημιουργία + ορισμός leader
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

# Διαχείριση μελών ομάδας
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
    others = User.query.filter((User.team_id.is_(None)) | (User.team_id != team.id)).order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, others=others)

# Αφαίρεση μέλους από ομάδα
@app.route("/admin/teams/<int:team_id>/members/<int:user_id>/remove", methods=["POST"])
@admin_required
def admin_remove_member(team_id, user_id):
    team = Team.query.get_or_404(team_id)
    user = User.query.get_or_404(user_id)
    if user.team_id == team.id:
        user.team_id = None
        db.session.commit()
        flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
    return redirect(url_for("admin_team_members", team_id=team.id))

# Διαγραφή ομάδας
@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    # Απο-σύνδεση μελών πριν τη διαγραφή
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
    # Στα logs το ακριβές σφάλμα, στον χρήστη φιλικό μήνυμα
    app.logger.exception("500 error: %s", e)
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Gunicorn entrypoint (Render: app:app)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
