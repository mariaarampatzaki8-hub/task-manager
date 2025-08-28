import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# --------------------------------------------------------------------------------------
# App & DB
# --------------------------------------------------------------------------------------

app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Instance folder (SQLite fallback file)
os.makedirs(app.instance_path, exist_ok=True)
_sqlite_path = os.path.join(app.instance_path, "app_final.db")

# DATABASE_URL (Render Postgres) ή fallback SQLite
uri = os.environ.get("DATABASE_URL", "").strip()
if uri:
    # Heroku-style -> επίσημο
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    # Χρήση driver pg8000 (ΟΧΙ psycopg2)
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + _sqlite_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Optional, κάνει ping πριν το borrow από το pool (καλό σε Render)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)


# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------

class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Σχέσεις
    leader = db.relationship("User", foreign_keys=[leader_id], backref="leading_teams")
    # Προσοχή: δηλώνουμε το foreign key που «μετράει» για να μην είναι ambiguous
    members = db.relationship(
        "User",
        back_populates="team",
        primaryjoin="Team.id==User.team_id"
    )

    def __repr__(self):
        return f"<Team {self.name}>"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)

    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_card = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(16), default="#3273dc")

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    team = db.relationship("Team", back_populates="members", foreign_keys=[team_id])

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # helpers
    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)

    def __repr__(self):
        return f"<User {self.username}>"


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(32), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user = db.relationship("User", foreign_keys=[user_id])
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------------------------------------------------------------------
# Helpers: τρέχουν στην εκκίνηση (seed admin + φτιάχνουν password σε κενά accounts)
# --------------------------------------------------------------------------------------

def ensure_admin_and_fix_passwords():
    """
    - Αν δεν υπάρχει admin -> δημιουργείται με password 'change-me'
    - Όλοι οι χρήστες που δεν έχουν password_hash -> τους μπαίνει 'change-me'
    """
    created_admin = False

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
        )
        admin.set_password("change-me")
        admin.must_change_password = True
        db.session.add(admin)
        created_admin = True

    # φτιάξε κλειστούς/κενούς κωδικούς
    changed = 0
    for u in User.query.filter(
        db.or_(User.password_hash.is_(None), User.password_hash == "")
    ):
        u.set_password("change-me")
        u.must_change_password = True
        changed += 1

    if created_admin or changed:
        db.session.commit()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Σύνδεση απαιτείται.", "warning")
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


# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    return "ok", 200


# --------------------------------------------------------------------------------------
# Home / Auth
# --------------------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος -> dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username or not password:
        flash("Συμπλήρωσε username & password.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    # ασφαλές: ελέγχουμε κανονικά το hash
    if not user.check_password(password):
        flash("Λάθος κωδικός.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------------------
# UI pages (dashboard, board->catalog, directory, help, settings, progress)
# --------------------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    # δείχνουμε υγεία σαν demo
    health = "ok"
    role = "Διαχειριστής" if u.is_admin else "Χρήστης"
    return render_template("dashboard.html", user=u, role=role, health=health)


@app.route("/board")
@login_required
def board():
    # Render του πίνακα (στο δικό σου project τον έλεγες catalog)
    return render_template("catalog.html")


@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Admin βλέπει όλους, αλλιώς (προαιρετικά) φίλτραρε ανά ομάδα
    users = User.query.order_by(User.username.asc()).all() if (u and u.is_admin) \
        else User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
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


# --------------------------------------------------------------------------------------
# ADMIN
# --------------------------------------------------------------------------------------

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
        must_change_password=True
    )
    u.set_password("change-me")  # προσωρινός
    db.session.add(u)
    db.session.commit()

    flash("Ο χρήστης δημιουργήθηκε (προσωρινός κωδ.: change-me).", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν μπορείς να διαγράψεις τον admin.", "warning")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/resetpw", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    u.set_password("change-me")
    u.must_change_password = True
    db.session.commit()
    flash("Ο κωδικός επαναφέρθηκε σε 'change-me'.", "success")
    return redirect(url_for("admin"))


# ---- Teams (CRUD + ορισμός leader) ----

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

    # GET: λίστες για template
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

    users = User.query.order_by(User.username.asc()).all()
    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, users=users, members=members)


@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    # αποσύνδεσε τα μέλη πριν τη διαγραφή
    User.query.filter_by(team_id=team.id).update({User.team_id: None})
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))


# --------------------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # μην εμφανίζεις stacktrace στον χρήστη
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# --------------------------------------------------------------------------------------
# Είσοδος εφαρμογής (το Render τρέχει gunicorn app:app)
# Στην εκκίνηση φτιάχνουμε πίνακες και σπέρνουμε admin/κενά passwords.
# --------------------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    ensure_admin_and_fix_passwords()

# Προαιρετικό dev run τοπικά
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
