import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------
# App & DB setup
# --------------------------------------------------------------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Instance folder (for sqlite fallback file αν ποτέ χρειαστεί)
os.makedirs(app.instance_path, exist_ok=True)
sqlite_path = os.path.join(app.instance_path, "app.db")

DB_URL = os.getenv("DATABASE_URL")  # από Render

def _fix_database_url(u: str) -> str:
    """
    - Heroku-style -> official
    - driver -> pg8000
    - SSL για pg8000 -> use 'ssl=true' (ΟΧΙ sslmode=require)
    """
    if not u:
        return None
    # 1) postgres:// -> postgresql://
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    # 2) postgresql:// -> postgresql+pg8000://
    if u.startswith("postgresql://"):
        u = u.replace("postgresql://", "postgresql+pg8000://", 1)
    # 3) sslmode=require -> ssl=true (για pg8000)
    if "sslmode=require" in u:
        u = u.replace("sslmode=require", "ssl=true")
    # 4) αν δεν υπάρχει ssl παράμετρος, βάλε ssl=true
    if "ssl=" not in u:
        u = u + ("&ssl=true" if "?" in u else "?ssl=true")
    return u

DB_URL = _fix_database_url(DB_URL)
if DB_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + sqlite_path

# σταθερές συνδέσεις
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --------------------------------------------------------------------
# Models
# --------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    leader = db.relationship("User", foreign_keys=[leader_id], backref="leading_teams", lazy="joined")
    members = db.relationship("User", backref="team", lazy=True)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    # βασικά
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)

    # νέα πεδία που ζήτησες
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_card = db.Column(db.String(50), nullable=True)
    color = db.Column(db.String(20), nullable=True, default="#3273dc")

    # κωδικός/ρόλος
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    # ομαδα
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open/done
    progress = db.Column(db.Integer, default=0)  # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assignee = db.relationship("User", backref="tasks")

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User", backref="notes")

# --------------------------------------------------------------------
# Small helpers (auth/session)
# --------------------------------------------------------------------
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

def current_user() -> User | None:
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

# --------------------------------------------------------------------
# One-time DDL safety: προσθέτουμε στήλες αν λείπουν (για υπαρκτή DB)
# --------------------------------------------------------------------
def ensure_optional_columns():
    # Δουλεύει σε Postgres (και αγνοείται σε SQLite)
    try:
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql+pg8000://"):
            with db.engine.begin() as conn:
                conn.exec_driver_sql("""
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS email TEXT;
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS phone TEXT;
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS id_card TEXT;
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#3273dc';
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS password_hash TEXT;
                    ALTER TABLE IF NOT EXISTS users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;
                """)
    except Exception as e:
        app.logger.warning("ensure_optional_columns skipped: %s", e)

# --------------------------------------------------------------------
# Init DB & seed admin/default team
# --------------------------------------------------------------------
@app.before_request
def _boot_once():
    # τρέχει γρήγορα κάθε request αλλά κάνει πραγματική δουλειά μόνο στο πρώτο
    if not getattr(app, "_booted", False):
        db.create_all()
        ensure_optional_columns()

        # default team
        team = Team.query.filter_by(name="Default Team").first()
        if not team:
            team = Team(name="Default Team")
            db.session.add(team)
            db.session.commit()

        # admin user
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                name="Admin",
                email="admin@example.com",
                is_admin=True,
                color="#3273dc",
                team_id=team.id,
                password_hash=generate_password_hash("admin123"),
                must_change_password=False,  # μπορείς να το βάλεις True αν θες υποχρεωτική αλλαγή
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Δημιουργήθηκε Admin (admin/admin123).")

        app._booted = True

# --------------------------------------------------------------------
# Health
# --------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# --------------------------------------------------------------------
# Home / Auth
# --------------------------------------------------------------------
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

    u = User.query.filter_by(username=username).first()
    if not u or not u.password_hash or not check_password_hash(u.password_hash, password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    if u.must_change_password:
        flash("Παρακαλώ άλλαξε τον προσωρινό κωδικό.", "warning")
        return redirect(url_for("settings"))
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# --------------------------------------------------------------------
# Dashboard & basic pages
# --------------------------------------------------------------------
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

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Admin βλέπει όλους – αλλιώς φιλτράρουμε προαιρετικά ανά ομάδα
    users = (User.query.order_by(User.username.asc()).all()
             if u.is_admin else
             User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all())
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

# Ρυθμίσεις – αλλαγή κωδικού χρήστη
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()
    if request.method == "POST":
        new_pass = (request.form.get("new_password") or "").strip()
        if not new_pass:
            flash("Βάλε νέο κωδικό.", "warning")
            return redirect(url_for("settings"))
        u.password_hash = generate_password_hash(new_pass)
        u.must_change_password = False
        db.session.commit()
        flash("Ο κωδικός άλλαξε.", "success")
        return redirect(url_for("dashboard"))
    return render_template("settings.html", user=u)

# --------------------------------------------------------------------
# ADMIN: Users
# --------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    """
    Δημιουργία χρήστη με:
    username, name, email, phone, id_card, color, is_admin, team_id (optional),
    temp_password (αν δεν σταλεί => δημιουργείται τυχαίος)
    """
    username = (request.form.get("username") or "").strip()
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    id_card = (request.form.get("id_card") or "").strip()
    color = (request.form.get("color") or "#3273dc").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_id = request.form.get("team_id")
    temp_password = (request.form.get("password") or "").strip()

    if not username:
        flash("Username υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    if not temp_password:
        temp_password = secrets.token_urlsafe(8)

    u = User(
        username=username,
        name=name or username,
        email=email or None,
        phone=phone or None,
        id_card=id_card or None,
        color=color or "#3273dc",
        is_admin=is_admin,
        team_id=int(team_id) if team_id else None,
        password_hash=generate_password_hash(temp_password),
        must_change_password=True,  # θα αναγκαστεί να το αλλάξει στο πρώτο login
    )
    db.session.add(u)
    db.session.commit()
    flash(f"Ο χρήστης δημιουργήθηκε. Προσωρινός κωδικός: {temp_password}", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    temp = secrets.token_urlsafe(8)
    u.password_hash = generate_password_hash(temp)
    u.must_change_password = True
    db.session.commit()
    flash(f"Νέος προσωρινός κωδικός για {u.username}: {temp}", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν γίνεται διαγραφή του βασικού admin.", "danger")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# --------------------------------------------------------------------
# ADMIN: Teams (CRUD) + μέλη
# --------------------------------------------------------------------
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
        # Ανάθεση/Αφαίρεση μέλους
        username = (request.form.get("username") or "").strip()
        action = (request.form.get("action") or "add").strip()  # add/remove

        if not username:
            flash("Διάλεξε χρήστη.", "warning")
            return redirect(url_for("admin_team_members", team_id=team_id))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Ο χρήστης δεν βρέθηκε.", "danger")
            return redirect(url_for("admin_team_members", team_id=team_id))

        if action == "remove":
            if user.team_id == team.id:
                user.team_id = None
                db.session.commit()
                flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
            else:
                flash("Ο χρήστης δεν ανήκει σε αυτή την ομάδα.", "warning")
        else:
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
    if team.name == "Default Team":
        flash("Δεν γίνεται διαγραφή της προεπιλεγμένης ομάδας.", "danger")
        return redirect(url_for("admin_teams"))
    # αποσύνδεσε τα μέλη
    User.query.filter_by(team_id=team.id).update({"team_id": None})
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

# --------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Προσπάθησε να δείξεις κάτι χρήσιμο χωρίς stacktrace
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# --------------------------------------------------------------------
# Gunicorn entry (Render χρησιμοποιεί: gunicorn app:app)
# --------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
