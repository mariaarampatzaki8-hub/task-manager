import os
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")

# -----------------------------------------------------------------------------
# Database config (Render Postgres via pg8000, fallback SQLite)
# -----------------------------------------------------------------------------
raw_url = os.environ.get("DATABASE_URL", "").strip()
if raw_url:
    # Render δίνει συνήθως "postgresql://..." ή "postgres://..."
    url = raw_url.replace("postgres://", "postgresql://", 1)
    # Χρήση pg8000 driver
    url = url.replace("postgresql://", "postgresql+pg8000://", 1)

    # Ασφαλές SSL: προσθέτουμε sslmode=require αν δεν υπάρχει ήδη
    if "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"

    app.config["SQLALCHEMY_DATABASE_URI"] = url
else:
    # local fallback (instance/app_final.db)
    os.makedirs("instance", exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///instance/app_final.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models (μίνιμαλ που καλύπτουν το UI)
# -----------------------------------------------------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    color = db.Column(db.String(20))
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

# (προαιρετικά placeholders αν τα templates τα αναφέρουν)
class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    status = db.Column(db.String(20), default="open")
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"))

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)

# -----------------------------------------------------------------------------
# Seed startup (Flask 3: ΧΩΡΙΣ before_first_request)
# -----------------------------------------------------------------------------
def seed_db():
    """Φτιάχνει πίνακες & admin/default team αν λείπουν."""
    db.create_all()

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
        )
        db.session.add(admin)
        db.session.commit()

    default_team = Team.query.filter_by(name="Default Team").first()
    if not default_team:
        default_team = Team(name="Default Team", leader_id=admin.id)
        db.session.add(default_team)
        db.session.commit()

    # βεβαιώσου ότι ο admin ανήκει στην default ομάδα
    if admin.team_id != default_team.id:
        admin.team_id = default_team.id
        db.session.commit()

with app.app_context():
    seed_db()

# -----------------------------------------------------------------------------
# Helpers / decorators
# -----------------------------------------------------------------------------
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
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        if not session.get("is_admin", False):
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

def current_user_dict():
    """Φέρνει τον τρέχοντα user από DB και επιστρέφει dict για τα templates."""
    uid = session.get("uid")
    if not uid:
        return None
    u = User.query.get(uid)
    if not u:
        # session “ορφανό”: καθάρισέ το
        session.clear()
        return None
    return {
        "id": u.id,
        "username": u.username,
        "is_admin": bool(u.is_admin),
        "team_id": u.team_id,
    }

# -----------------------------------------------------------------------------
# Health check
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
    """
    DB-backed “απλό” login:
      - Αν δεν υπάρχει user με αυτό το username, τον δημιουργεί.
      - Αν username == 'admin' => is_admin=True.
      - Δεν ελέγχει κωδικό (UI mock).
    """
    username = (request.form.get("username") or "").strip()
    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u:
        u = User(
            username=username,
            is_admin=(username.lower() == "admin"),
        )
        db.session.add(u)
        db.session.commit()

    # set session
    session["uid"] = u.id
    session["name"] = u.username
    session["is_admin"] = bool(u.is_admin)

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user_dict()
    return render_template("dashboard.html", user=user)

@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress_view():
    # δείγμα κενά δεδομένα – δένεις αργότερα με Task
    rows = []
    return render_template("progress.html", rows=rows)

@app.route("/board")
@login_required
def board():
    return redirect(url_for("progress"))

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html")

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    return render_template("admin_teams.html")

@app.route("/catalog")
@login_required
def catalog():
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    # Μπορείς να φέρεις users από DB αν χρειαστεί:
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

# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Local run (Render χρησιμοποιεί gunicorn app:app)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
