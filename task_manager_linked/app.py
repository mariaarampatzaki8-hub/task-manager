# app.py
import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# App factory-ish single file
# -------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# ---------- DB config (Render Postgres με pg8000) ----------
db_url = (os.environ.get("DATABASE_URL") or "").strip()

if db_url:
    # 1) postgres:// -> postgresql://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    # 2) Βάλε explicit driver pg8000
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)

    # 3) SSL για Render: βάλ' το στο URL, ΟΧΙ σε connect_args
    #    (pg8000 δεν δέχεται 'ssl'/'sslmode' ως kwarg μέσω SQLAlchemy)
    if "ssl=" not in db_url and "sslmode=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}ssl=true"

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    # Fallback σε SQLite για local dev
    os.makedirs("instance", exist_ok=True)
    sqlite_path = os.path.join("instance", "app.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{sqlite_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------------------------------
# Models
# -------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    members = db.relationship("User", backref="team", lazy="select")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    id_card = db.Column(db.String(40), nullable=True)
    color = db.Column(db.String(12), nullable=True, default="#3273dc")
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    password_hash = db.Column(db.String(255), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")  # open|done
    progress = db.Column(db.Integer, default=0, nullable=False)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


# -------------------------------------------------
# DB init & seed (Flask 3+ – κάνουμε seed στο startup)
# -------------------------------------------------
with app.app_context():
    db.create_all()

    # admin seed
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            must_change_password=True,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        # default team
        t = Team(name="Default Team", leader_id=None)
        db.session.add(t)
        db.session.flush()  # για να πάρει id
        # κάνε τον admin leader & μέλος
        t.leader_id = admin.id
        admin.team_id = t.id
        db.session.commit()


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def logged_in_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = logged_in_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)

    return wrapper


# -------------------------------------------------
# Basic routes
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    if not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    session["name"] = user.name
    session["is_admin"] = bool(user.is_admin)

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    u = logged_in_user()
    # μικρό health ping να φαίνεται στο UI όπως πριν
    return render_template("dashboard.html", user=u, health="ok")


# -------------------------------------------------
# Admin: χρήστες
# -------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)


@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    id_card = (request.form.get("id_card") or "").strip()
    color = (request.form.get("color") or "#3273dc").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False
    temp_password = request.form.get("temp_password") or "temp1234"

    if not name or not username:
        flash("Όνομα και username είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    u = User(
        name=name,
        username=username,
        email=email or None,
        phone=phone or None,
        id_card=id_card or None,
        color=color or "#3273dc",
        is_admin=is_admin,
        must_change_password=True,
    )
    u.set_password(temp_password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = logged_in_user()
    if request.method == "POST":
        new_pass = (request.form.get("new_password") or "").strip()
        color = (request.form.get("color") or "").strip()
        if new_pass:
            u.set_password(new_pass)
            u.must_change_password = False
        if color:
            u.color = color
        db.session.commit()
        flash("Οι ρυθμίσεις αποθηκεύτηκαν.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", user=u)


# -------------------------------------------------
# Admin: ομάδες
# -------------------------------------------------
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
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, users=users)


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


# -------------------------------------------------
# Error handlers (απλά – χρησιμοποιούν templates/error.html)
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # Προσοχή: για debug μπορείς να βάλεις print/log
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# -------------------------------------------------
# Gunicorn entry (Render)
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
