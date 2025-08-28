import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# --------------------------------------
# App factory
# --------------------------------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# --- DB config (Render Postgres με pg8000, αλλιώς SQLite fallback) ---
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app_final.db")

uri = os.environ.get("DATABASE_URL")  # π.χ. postgresql://... από Render
if uri:
    # 1) postgres:// -> postgresql://
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    # 2) Χρήση driver pg8000
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    # 3) SSL σε Render: ΔΕΝ βάζουμε connect_args sslmode (pg8000 δεν το δέχεται)
    if "ssl=" not in uri and "sslmode=" not in uri:
        sep = "&" if "?" in uri else "?"
        uri = f"{uri}{sep}ssl=true"

    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Connection pool tip για serverless περιβάλλοντα
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)


# --------------------------------------
# Models
# --------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Σημαντικό για να μην είναι ambiguous (δηλώνουμε ποιο FK χρησιμοποιείται)
    members = db.relationship(
        "User",
        back_populates="team",
        foreign_keys="User.team_id",
        lazy="dynamic"
    )

    leader = db.relationship(
        "User",
        foreign_keys=[leader_id],
        uselist=False
    )

    def __repr__(self):
        return f"<Team {self.name}>"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)

    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    id_card = db.Column(db.String(40), nullable=True)

    color = db.Column(db.String(16), default="#3273dc")

    password_hash = db.Column(db.String(255), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)

    is_admin = db.Column(db.Boolean, default=False)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = db.relationship(
        "Team",
        back_populates="members",
        foreign_keys=[team_id]
    )

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # helpers
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
    status = db.Column(db.String(20), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)       # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------------------
# Utilities / decorators
# --------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapper


# --------------------------------------
# Health / Home / Auth
# --------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


# Αρχική (endpoint = index ώστε να ταιριάζει με τα templates)
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

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    session["name"] = user.name
    session["is_admin"] = bool(user.is_admin)

    # Αν πρέπει να αλλάξει προσωρινό κωδικό, στείλ’ τον στις ρυθμίσεις
    if user.must_change_password:
        flash("Άλλαξε τον προσωρινό κωδικό σου.", "info")
        return redirect(url_for("settings"))

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# --------------------------------------
# Pages
# --------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    # Απλό status για το footer των σελίδων
    health = "ok"
    return render_template("dashboard.html", user=u, health=health)


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()

    if request.method == "POST":
        # αλλαγή κωδικού
        new_pass = (request.form.get("new_password") or "").strip()
        if new_pass:
            if len(new_pass) < 6:
                flash("Ο κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες.", "warning")
                return redirect(url_for("settings"))
            u.set_password(new_pass)
            u.must_change_password = False
            db.session.commit()
            flash("Ο κωδικός άλλαξε.", "success")
            return redirect(url_for("dashboard"))

    return render_template("settings.html", user=u)


@app.route("/progress", methods=["GET"], endpoint="progress_view")
@login_required
def progress():
    # μια απλή σύνοψη για το template
    tasks = Task.query.all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)


# --------------------------------------
# ADMIN
# --------------------------------------
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
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get("uid"):
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "warning")
        return redirect(url_for("admin"))
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    u.set_password("change-me")
    u.must_change_password = True
    db.session.commit()
    flash("Ο κωδικός επανήλθε σε 'change-me'.", "success")
    return redirect(url_for("admin"))


# ---- Teams (CRUD + assign members/leader) ----
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

    # GET: φέρε λίστες
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
        flash("Ο χρήστης ανατέθηκε στην ομάδα.", "success")
        return redirect(url_for("admin_team_members", team_id=team_id))

    # GET: λίστα μελών και διαθέσιμων χρηστών
    members = team.members.order_by(User.username.asc()).all()
    available = User.query.filter(
        (User.team_id.is_(None)) | (User.team_id != team.id)
    ).order_by(User.username.asc()).all()

    return render_template(
        "admin_team_members.html",
        team=team,
        members=members,
        available=available
    )


@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)

    # βγάλε τα μέλη από την ομάδα πριν τη διαγραφή
    for m in team.members.all():
        m.team_id = None
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))


# --------------------------------------
# Error handlers
# --------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # Μην εμφανίζεις stacktrace στον χρήστη
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# --------------------------------------
# Local run (προαιρετικό)
# --------------------------------------
if __name__ == "__main__":
    # Δημιούργησε πίνακες αν δεν υπάρχουν (στο Render τρέχει gunicorn)
    with app.app_context():
        db.create_all()
        # seed admin αν λείπει
        if not User.query.filter_by(username="admin").first():
            admin_user = User(
                username="admin",
                name="Admin",
                email="admin@example.com",
                is_admin=True,
                must_change_password=True,
                color="#3273dc"
            )
            admin_user.set_password("change-me")
            db.session.add(admin_user)
            # default team
            default_team = Team(name="Default Team")
            db.session.add(default_team)
            db.session.commit()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
