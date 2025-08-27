# app.py
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
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # local sqlite fallback file
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    # Render DATABASE_URL (Postgres) or fallback SQLite
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # heroku-style postgres -> sqlachemy official
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # use pg8000 driver
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        # engine options – safe defaults
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
        }
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

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

    # βασικά στοιχεία
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_card = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=True)
    token = db.Column(db.String(255), nullable=True)

    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    color = db.Column(db.String(20), nullable=True)

    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(30), default="open", nullable=False)  # open / done
    progress = db.Column(db.Integer, default=0, nullable=False)        # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Απαιτείται σύνδεση.", "warning")
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

# -------------------------------------------------
# Initial DB & seed (τρέχει μία φορά στο boot)
# -------------------------------------------------
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
        )
        db.session.add(admin)
        db.session.commit()

    # default team & σύνδεση admin
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()
    if not team.leader_id:
        team.leader_id = admin.id
        db.session.commit()
    if not admin.team_id:
        admin.team_id = team.id
        db.session.commit()

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
    # αν είσαι ήδη συνδεδεμένος, πήγαινε κατευθείαν στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    session["name"] = u.name
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
    u = current_user()
    # μικρό health ping να φαίνεται στη σελίδα
    status = "ok"
    return render_template("dashboard.html", user=u, status=status)

@app.route("/progress", methods=["GET"])
@login_required
def progress():
    """Συγκεντρωτικά progress ανά χρήστη."""
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        # μέσος όρος progress (0 αν δεν έχει εργασίες)
        avg_prog = (
            db.session.query(db.func.avg(Task.progress))
            .filter(Task.assignee_id == u.id)
            .scalar() or 0
        )
        rows.append({
            "user": u,
            "total": total,
            "done": done,
            "open": open_cnt,
            "avg": int(round(avg_prog)),
        })
    return render_template("progress.html", rows=rows)

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")  # αν ο πίνακας σου είναι άλλο template, άλλαξέ το

@app.route("/teams", methods=["GET"])
@login_required
def teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

@app.route("/admin")
@admin_required
def admin():
    notes = Note.query.order_by(Note.created_at.desc()).all()
    return render_template("admin.html", notes=notes)

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))
        db.session.add(Team(name=name))
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # leaders βλέπουν τον κατάλογο (πχ leader ή admin)
    if not (u.is_admin or (u.team_id and u.id == (u.team.leader_id if u.team else None))):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -------------------------------------------------
# Gunicorn entry (Render χρησιμοποιεί: gunicorn app:app)
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
