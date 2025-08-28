import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


# ------------------------------------------------------------------------------
# App / Config
# ------------------------------------------------------------------------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# DB URL from Render (or fallback to sqlite for local runs)
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app_final.db")

uri = os.environ.get("DATABASE_URL")  # e.g. postgresql://... from Render

if uri:
    # Heroku/Render style -> ensure driver pg8000
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}

db = SQLAlchemy(app)


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    # αρχηγός ομάδας (optional)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # μέλη (users.team_id -> teams.id)
    members = relationship("User", back_populates="team", foreign_keys="User.team_id")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)

    email = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    id_card = db.Column(db.String(50))

    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    color = db.Column(db.String(20), default="#3273dc")

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = relationship("Team", back_populates="members", foreign_keys=[team_id])

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # helper methods
    def set_password(self, plain: str) -> None:
        self.password_hash = generate_password_hash(plain)

    def check_password(self, plain: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, plain)


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    assignee = relationship("User", foreign_keys=[assignee_id])

    status = db.Column(db.String(20), default="open")  # open | done
    progress = db.Column(db.Integer, default=0)        # 0..100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------------------------------------------------------------
# Bootstrap DB on import (works on Render)
# ------------------------------------------------------------------------------
def bootstrap_db():
    with app.app_context():
        db.create_all()

        # φτιάξε default team αν δεν υπάρχει
        default_team = Team.query.filter_by(name="Default Team").first()
        if not default_team:
            default_team = Team(name="Default Team")
            db.session.add(default_team)
            db.session.commit()

        # φτιάξε admin αν λείπει
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                name="Admin",
                email="admin@example.com",
                is_admin=True,
                must_change_password=True,
                color="#3273dc",
                team_id=default_team.id,
            )
            admin.set_password("change-me")
            db.session.add(admin)
            db.session.commit()

        # όρισε αρχηγό ομάδας αν δεν υπάρχει
        if default_team.leader_id is None:
            default_team.leader_id = admin.id
            db.session.commit()


bootstrap_db()


# ------------------------------------------------------------------------------
# Helpers & decorators
# ------------------------------------------------------------------------------
@app.before_request
def load_current_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = User.query.get(uid)


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user or not g.user.is_admin:
            flash("Πρόσβαση μόνο σε διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapper


# ------------------------------------------------------------------------------
# Health
# ------------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


# ------------------------------------------------------------------------------
# Auth / Home
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη logged in -> dashboard
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
    session["name"] = user.name

    if user.must_change_password:
        flash("Αλλάξε τον προσωρινό κωδικό σου.", "info")
        return redirect(url_for("settings"))

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# ------------------------------------------------------------------------------
# Pages
# ------------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    # απλό dashboard — templates/ dashboard.html
    return render_template("dashboard.html")


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


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        new_password = (request.form.get("new_password") or "").strip()
        if not new_password:
            flash("Βάλε νέο κωδικό.", "warning")
            return redirect(url_for("settings"))
        g.user.set_password(new_password)
        g.user.must_change_password = False
        db.session.commit()
        flash("Ο κωδικός άλλαξε.", "success")
        return redirect(url_for("dashboard"))

    return render_template("settings.html")


# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)


# -- Users (CRUD + reset password) --------------------------------------------
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
        return redirect(url_for("admin_home"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin_home"))

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
    u.set_password("change-me")  # προσωρινός
    db.session.add(u)
    db.session.commit()

    flash("Ο χρήστης δημιουργήθηκε (προσωρινός κωδ.: change-me).", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    u.set_password("change-me")
    u.must_change_password = True
    db.session.commit()
    flash("Ο κωδικός επανήλθε σε 'change-me'.", "info")
    return redirect(url_for("admin_home"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν μπορείς να διαγράψεις τον admin.", "danger")
        return redirect(url_for("admin_home"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin_home"))


# -- Teams (CRUD + assign members/leader) -------------------------------------
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
        # Ανάθεση χρήστη στην ομάδα
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

    # GET
    users = User.query.order_by(User.username.asc()).all()
    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    return render_template(
        "admin_team_members.html", team=team, users=users, members=members
    )


@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    # βγάλε τα μέλη από την ομάδα πριν διαγραφή
    for u in User.query.filter_by(team_id=team.id).all():
        u.team_id = None
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
    # Απόκρυψη stacktrace από τον χρήστη
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# ------------------------------------------------------------------------------
# Local run (προαιρετικό)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
