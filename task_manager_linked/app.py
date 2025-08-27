import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

# -----------------------------------------------------------------------------
# App factory & DB config
# -----------------------------------------------------------------------------
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # Δημιούργησε τον φάκελο instance (χρειάζεται για SQLite fallback)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    # Πάρε DATABASE_URL από Render (ή κενό -> SQLite)
    uri = os.environ.get("DATABASE_URL")

    if uri:
        # 1) Heroku style -> επίσημο
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)

        # 2) Χρήση driver pg8000 αντί για psycopg2
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

        # ΣΗΜΕΙΩΣΗ: Δεν βάζουμε ούτε ?ssl ούτε connect_args, το pg8000 χειρίζεται SSL
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        # μικρά engine options
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
        }
    else:
        # Fallback σε SQLite για τοπική ανάπτυξη
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    token = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    color = db.Column(db.String(20), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

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
# DB init + seed (ΧΩΡΙΣ before_first_request)
# -----------------------------------------------------------------------------
def init_db_and_seed():
    """Δημιουργεί πίνακες και seed-άρει έναν admin + default team αν δεν υπάρχουν."""
    try:
        db.create_all()
    except Exception as e:
        app.logger.error("DB init failed: %s", e)

    # Admin user
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            token=secrets.token_urlsafe(16),
        )
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Δημιουργήθηκε Admin (username=admin).")

    # Default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # Συνδέσεις
    if team.leader_id is None:
        team.leader_id = admin.id
    if admin.team_id != team.id:
        admin.team_id = team.id
    db.session.commit()

# Εκτέλεση seed στην εκκίνηση εφαρμογής
with app.app_context():
    try:
        init_db_and_seed()
    except Exception as e:
        app.logger.error("Startup init failed: %s", e)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# Αρχική
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# Login (mock): μόνο username=admin κάνει is_admin True (κωδικός αγνοείται)
@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # δεν ελέγχεται στο mock

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user:
        # Αν δώσουν άλλο username, φτιάξ’ τον on the fly (όχι admin)
        user = User(name=username.title(), username=username, is_admin=False)
        db.session.add(user)
        db.session.commit()

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# Dashboard
@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect(url_for("index"))

    role = "Διαχειριστής" if u.is_admin else "Μέλος"
    # Μικρό status ping για να φαίνεται κάτω δεξιά
    status = {"healthz": "ok"}
    return render_template("dashboard.html", user=u, role=role, status=status)

# Admin (παράδειγμα)
@app.route("/admin")
@admin_required
def admin_home():
    u = current_user()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin.html", user=u, users=users)

# Προσωπικές ρυθμίσεις (dummy)
@app.route("/settings")
def settings_page():
    u = current_user()
    if not u:
        return redirect(url_for("index"))
    return render_template("settings.html", user=u)

# Πρόοδος (dummy πίνακας)
@app.route("/progress")
def progress_view():
    u = current_user()
    if not u:
        return redirect(url_for("index"))

    rows = []
    # Ένα απλό παράδειγμα υπολογισμών
    total = Task.query.filter_by(assignee_id=u.id).count()
    done = Task.query.filter_by(assignee_id=u.id, status="done").count()
    open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
    avg_prog = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0

    rows.append({
        "user": u,
        "total": total,
        "done": done,
        "open": open_cnt,
        "avg": int(round(avg_prog)),
    })

    return render_template("progress.html", rows=rows, user=u)

# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Μην πετάμε stacktrace στον χρήστη — Δείξε φιλικό μήνυμα
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Gunicorn entry (Render)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Για τοπικό debug αν θες
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
