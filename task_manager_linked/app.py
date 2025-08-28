# app.py
import os
import secrets
from functools import wraps
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine.url import make_url
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------------------------------------------------------------------
# App
# ------------------------------------------------------------------------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# DB: Render Postgres (DATABASE_URL) ή fallback σε SQLite
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app_final.db")

DB_URL = os.environ.get("DATABASE_URL")

def _strip_sslmode(qs: str) -> str:
    """Αφαίρεσε τυχόν sslmode από query string για pg8000."""
    if not qs:
        return ""
    pairs = dict(parse_qsl(qs, keep_blank_values=True))
    pairs.pop("sslmode", None)
    return urlencode(pairs)

if DB_URL:
    # 1) Heroku/Render format postgres:// -> postgresql://
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    # 2) Χρήση driver pg8000
    if DB_URL.startswith("postgresql://"):
        DB_URL = DB_URL.replace("postgresql://", "postgresql+pg8000://", 1)
    # 3) Αφαίρεση sslmode από query (pg8000 δεν το δέχεται ως kwarg)
    parsed = urlparse(DB_URL)
    new_qs = _strip_sslmode(parsed.query)
    parsed = parsed._replace(query=new_qs)
    DB_URL = urlunparse(parsed)

    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # σχέση προς τα μέλη (users.team_id -> teams.id)
    members = db.relationship(
        "User",
        back_populates="team",
        foreign_keys="User.team_id"
    )

    def __repr__(self):
        return f"<Team {self.name}>"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    id_card = db.Column(db.String(40), nullable=True)  # ΑΔΤ
    color = db.Column(db.String(16), default="#3273dc")

    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = db.relationship(
        "Team",
        back_populates="members",
        foreign_keys=[team_id]
    )

    # reverse προς Team.leader_id (προαιρετικά)
    leads_team = db.relationship(
        "Team",
        backref="leader",
        foreign_keys=[Team.leader_id],
        uselist=False
    )

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)

    def __repr__(self):
        return f"<User {self.username}>"


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open | done
    progress = db.Column(db.Integer, default=0)        # 0..100

    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assignee = db.relationship("User", foreign_keys=[assignee_id])


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


# ------------------------------------------------------------------------------
# Helpers / decorators
# ------------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Πρόσβαση μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

# ------------------------------------------------------------------------------
# Health
# ------------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ------------------------------------------------------------------------------
# Home / Auth
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    # redirect στη φόρμα σύνδεσης
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username or not password:
        flash("Συμπλήρωσε username & κωδικό.", "warning")
        return redirect(url_for("home"))

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("home"))

    session["uid"] = user.id
    session["name"] = user.name
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("home"))

# ------------------------------------------------------------------------------
# Pages
# ------------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    # απλό health ping για το template
    return render_template("dashboard.html", user=u, health_status="ok")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Admin βλέπει όλους — αλλιώς (προαιρετικά) φιλτράρεις ανά ομάδα
    users = User.query.order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/progress", methods=["GET"], endpoint="progress_view")
@login_required
def progress():
    # Απλό σύνολο για το template
    tasks = Task.query.all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

# Alias ώστε τυχ. templates που έχουν url_for('progress') να μη σπάνε
@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress_alias():
    return redirect(url_for("progress_view"))

# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

# ---- Users (CRUD + reset password) ----
@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    id_card = (request.form.get("id_card") or "").strip()
    color = (request.form.get("color") or "#3273dc").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False

    if not username or not name:
        flash("Username & Όνομα είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    u = User(
        username=username, name=name, email=email, phone=phone,
        id_card=id_card, color=color, is_admin=is_admin,
        must_change_password=True,
    )
    # προσωρινός κωδικός
    u.set_password("change-me")
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε (προσωρινός κωδικός: change-me).", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    u.set_password("change-me")
    u.must_change_password = True
    db.session.commit()
    flash("Έγινε επαναφορά κωδικού (change-me).", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν μπορείς να διαγράψεις τον default admin.", "danger")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# ---- Teams (CRUD + ανάθεση μελών/leader) ----
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

    # GET: λίστες
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

    users = User.query.order_by(User.username.asc()).all()
    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, users=users, members=members)

@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    # απο-συσχέτιση μελών
    for u in User.query.filter_by(team_id=team.id).all():
        u.team_id = None
    if team.leader_id:
        team.leader_id = None
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

# ------------------------------------------------------------------------------
# Error handlers
# ------------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ------------------------------------------------------------------------------
# DB bootstrap (create tables + default admin)
# ------------------------------------------------------------------------------
with app.app_context():
    db.create_all()
    # default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # default admin
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            name="Admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            must_change_password=True,
            team_id=team.id,
        )
        admin_user.set_password("admin123")
        db.session.add(admin_user)
        # ορίσμος leader στην default
        team.leader_id = admin_user.id
        db.session.commit()

# ------------------------------------------------------------------------------
# Dev run (το Render τρέχει gunicorn app:app)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
