import os
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Secret
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Database URL (Render)
raw_db_url = os.environ.get("DATABASE_URL", "").strip()
if raw_db_url.startswith("postgres://"):
    # SQLAlchemy + pg8000
    fixed_db_url = raw_db_url.replace("postgres://", "postgresql+pg8000://", 1)
elif raw_db_url.startswith("postgresql://"):
    fixed_db_url = raw_db_url.replace("postgresql://", "postgresql+pg8000://", 1)
elif raw_db_url.startswith("postgresql+pg8000://"):
    fixed_db_url = raw_db_url
else:
    # fallback για local sqlite αν λείπει το DATABASE_URL
    fixed_db_url = "sqlite:///local.db"

app.config["SQLALCHEMY_DATABASE_URI"] = fixed_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True
}

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # relationships
    members = db.relationship(
        "User",
        back_populates="team",
        foreign_keys="User.team_id"
    )

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    name     = db.Column(db.String(120), nullable=False)
    email    = db.Column(db.String(200))
    phone    = db.Column(db.String(50))
    id_card  = db.Column(db.String(50))
    color    = db.Column(db.String(20), default="#3273dc")

    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = db.relationship("Team", back_populates="members", foreign_keys=[team_id])

    def set_password(self, plain: str):
        self.password_hash = generate_password_hash(plain)

    def check_password(self, plain: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, plain)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open | done
    progress = db.Column(db.Integer, default=0)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------------------------------------------------------------
# Helpers
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
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
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

@app.before_request
def load_user_to_g():
    g.user = current_user()

# -----------------------------------------------------------------------------
# Health / Home / Auth
# -----------------------------------------------------------------------------
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

    if not username or not password:
        flash("Συμπλήρωσε username και κωδικό.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")

    if user.must_change_password:
        flash("Αλλάξε τον προσωρινό κωδικό στις Ρυθμίσεις.", "info")
        return redirect(url_for("settings"))

    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -----------------------------------------------------------------------------
# Core pages
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    role = "Διαχειριστής" if u.is_admin else "Χρήστης"
    return render_template("dashboard.html", user=u, role=role)

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")

@app.route("/progress", methods=["GET"], endpoint="progress_view")
@login_required
def progress():
    tasks = Task.query.all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # απλός κατάλογος (μπορείς να τον φιλτράρεις ανά ομάδα)
    users = User.query.order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

# -----------------------------------------------------------------------------
# Settings (προφίλ & αλλαγή κωδικού)
# -----------------------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "profile":
            email = (request.form.get("email") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            color = (request.form.get("color") or "").strip() or "#3273dc"

            u.email = email
            u.phone = phone
            u.color = color
            db.session.commit()
            flash("Το προφίλ ενημερώθηκε.", "success")
            return redirect(url_for("settings"))

        if action == "password":
            curr = (request.form.get("current_password") or "").strip()
            new1 = (request.form.get("new_password") or "").strip()
            new2 = (request.form.get("new_password2") or "").strip()

            if not u.check_password(curr):
                flash("Λάθος τρέχων κωδικός.", "danger")
                return redirect(url_for("settings"))
            if not new1 or new1 != new2:
                flash("Οι νέοι κωδικοί δεν ταιριάζουν.", "warning")
                return redirect(url_for("settings"))

            u.set_password(new1)
            u.must_change_password = False
            db.session.commit()
            flash("Ο κωδικός άλλαξε.", "success")
            return redirect(url_for("settings"))

        flash("Άκυρη ενέργεια.", "warning")
        return redirect(url_for("settings"))

    return render_template("settings.html", user=u)

# -----------------------------------------------------------------------------
# ADMIN
# -----------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

# -- users (create/delete/reset) --
@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    name     = (request.form.get("name") or "").strip()
    email    = (request.form.get("email") or "").strip()
    phone    = (request.form.get("phone") or "").strip()
    id_card  = (request.form.get("id_card") or "").strip()
    color    = (request.form.get("color") or "#3273dc").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False

    if not username or not name:
        flash("Username & Όνομα είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    u = User(
        username=username,
        name=name,
        email=email,
        phone=phone,
        id_card=id_card,
        color=color,
        is_admin=is_admin,
        must_change_password=True,
    )
    # προσωρινός κωδικός
    temp_pwd = "change-me"
    u.set_password(temp_pwd)

    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε (προσωρινός κωδ.: change-me).", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == session.get("uid"):
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "warning")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# -- teams (create/list) --
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

# -- team members manage + delete team --
@app.route("/admin/teams/<int:team_id>/members", methods=["GET", "POST"])
@admin_required
def admin_team_members(team_id):
    team = Team.query.get_or_404(team_id)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "assign":
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

        if action == "remove":
            uid = request.form.get("user_id")
            if uid:
                member = User.query.get(int(uid))
                if member and member.team_id == team.id:
                    member.team_id = None
                    db.session.commit()
                    flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
            return redirect(url_for("admin_team_members", team_id=team_id))

        if action == "delete_team":
            # Καθάρισε τα μέλη πριν διαγράψεις την ομάδα
            for m in team.members:
                m.team_id = None
            db.session.delete(team)
            db.session.commit()
            flash("Η ομάδα διαγράφηκε.", "info")
            return redirect(url_for("admin_teams"))

        flash("Άκυρη ενέργεια.", "warning")
        return redirect(url_for("admin_team_members", team_id=team_id))

    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, users=users)

# -----------------------------------------------------------------------------
# Error pages
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Bootstrap DB (προαιρετικό local run)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # default team & admin (αν δεν υπάρχουν)
        if not Team.query.filter_by(name="Default Team").first():
            db.session.add(Team(name="Default Team"))
            db.session.commit()
        if not User.query.filter_by(username="admin").first():
            admin_user = User(
                username="admin",
                name="Admin",
                email="admin@example.com",
                is_admin=True,
                must_change_password=True,
                color="#3273dc",
            )
            admin_user.set_password("change-me")
            # σύνδεση με default team
            dt = Team.query.filter_by(name="Default Team").first()
            if dt:
                admin_user.team_id = dt.id
                dt.leader_id = admin_user.id
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
