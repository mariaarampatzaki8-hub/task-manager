import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

# -------------------------------------------------
# App factory & DB config
# -------------------------------------------------
def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # Secret key
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # ---- DB URL από Render (Postgres) ή fallback SQLite ----
    raw_url = (os.environ.get("DATABASE_URL") or "").strip()
    if raw_url:
        # 1) postgres://  ->  postgresql://
        url = raw_url.replace("postgres://", "postgresql://", 1)
        # 2) Χρήση driver pg8000
        url = url.replace("postgresql://", "postgresql+pg8000://", 1)

        # ΣΗΜΑΝΤΙΚΟ: ΔΕΝ βάζουμε sslmode / connect_args εδώ για pg8000
        app.config["SQLALCHEMY_DATABASE_URI"] = url
        # Λίγο πιο ανθεκτικό pool για serverless
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
        }
    else:
        # Fallback σε SQLite (τοπικά)
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app_final.db")

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)

# -------------------------------------------------
# Models
# -------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(200), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(16), nullable=True)
    # απλό μοντέλο για τώρα – δεν ελέγχουμε κωδικό
    password_hash = db.Column(db.String(255), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    token = db.Column(db.String(64), nullable=True, unique=False)


# -------------------------------------------------
# Init DB & seed admin/default team (idempotent)
# -------------------------------------------------
@app.before_first_request
def init_db_and_seed():
    try:
        db.create_all()
    except Exception as e:
        app.logger.error("DB init failed: %s", e)

    # Admin χρήστης
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            name="Admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            token=secrets.token_urlsafe(16),
        )
        db.session.add(admin)
        db.session.commit()

    # Default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # Ορίσε leader = admin και βάλε admin στο team αν δεν είναι ήδη
    if team.leader_id is None:
        team.leader_id = admin.id
    if admin.team_id != team.id:
        admin.team_id = team.id
    db.session.commit()


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

@app.context_processor
def inject_user():
    """Να υπάρχει πάντα 'user' στα templates."""
    return {"user": current_user()}


def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Παρακαλώ συνδέσου πρώτα.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


# -------------------------------------------------
# Health
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


# -------------------------------------------------
# Home / Auth
# -------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, πήγαινε στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # για αργότερα

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    # Βρες/φτιάξε χρήστη πρόχειρα για demo (αν δεν υπάρχει)
    u = User.query.filter_by(username=username).first()
    if not u:
        # Οτιδήποτε εκτός από 'admin' μπαίνει ως μη-διαχειριστής
        u = User(
            username=username,
            name=username.capitalize(),
            is_admin=(username == "admin"),
            color="#999999",
        )
        db.session.add(u)
        db.session.commit()

    # Κράτησε session
    session["uid"] = u.id
    session["name"] = u.name or u.username
    session["is_admin"] = bool(u.is_admin)

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# -------------------------------------------------
# Pages
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Ελαφρύ context – user inject γίνεται από inject_user()
    return render_template("dashboard.html", now=datetime.utcnow())


@app.route("/admin")
@login_required
def admin_home():
    u = current_user()
    if not (u and u.is_admin):
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("admin.html")


@app.route("/progress")
@login_required
def progress_view():
    # Placeholder σελίδα για να μην σπάνε template links
    rows = []
    return render_template("progress.html", rows=rows)


@app.route("/catalog")
@login_required
def catalog_view():
    return render_template("catalog.html")


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")


# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Προσπάθησε να εμφανίσεις φιλικό μήνυμα
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# -------------------------------------------------
# Gunicorn entry (Render τρέχει 'app:app')
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
