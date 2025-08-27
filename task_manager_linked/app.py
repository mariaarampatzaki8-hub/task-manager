import os, secrets
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------
# App & DB config
# --------------------------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Instance folder (για το sqlite file)
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app.db")

# DATABASE_URL από Render (Postgres) ή fallback SQLite
uri = os.environ.get("DATABASE_URL")
if uri:
    # 1) heroku-style -> επίσημο
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    # 2) pg8000 driver
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    # 3) sslmode=require στο URL (σωστό για pg8000)
    sep = "&" if "?" in uri else "?"
    if "sslmode=" not in uri and "ssl=" not in uri:
        uri = f"{uri}{sep}sslmode=require"

    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# προληπτικά για σταθερές συνδέσεις
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True
}

db = SQLAlchemy(app)

# --------------------------------
# Models
# --------------------------------
class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    members = db.relationship("User", backref="team", lazy=True)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(20), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"))

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")
    progress = db.Column(db.Integer, default=0)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --------------------------------
# DB init / seed (χωρίς before_first_request)
# Εκτελείται μία φορά στο import.
# --------------------------------
with app.app_context():
    db.create_all()

    # Default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # Admin
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
            team=team,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
    else:
        # βεβαιώσου ότι έχει ρόλο admin & ανήκει σε ομάδα
        changed = False
        if not admin.is_admin:
            admin.is_admin = True
            changed = True
        if not admin.team_id:
            admin.team = team
            changed = True
        if changed:
            db.session.commit()

    # Leader στην default team
    if team.leader_id is None:
        team.leader_id = admin.id
        db.session.commit()

# --------------------------------
# Helpers
# --------------------------------
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
            flash("Πρέπει να συνδεθείς.", "warning")
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

# --------------------------------
# Health & Home / Auth
# --------------------------------
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
        flash("Συμπλήρωσε username & password.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.pop("uid", None)
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# --------------------------------
# Dashboard & απλές σελίδες
# --------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return render_template("dashboard.html", user=u)

@app.route("/progress-view")
@login_required
def progress_view():
    # απλό mock—μελλοντικά θα βάλεις queries στα tasks
    u = current_user()
    rows = [{
        "user": u.username,
        "total": Task.query.filter_by(assignee_id=u.id).count(),
        "open": Task.query.filter_by(assignee_id=u.id, status="open").count(),
        "avg": db.session.query(db.func.coalesce(db.func.avg(Task.progress), 0)).scalar() or 0
    }]
    return render_template("progress.html", rows=rows)

# alias για παλιό endpoint 'progress'
@app.route("/progress", endpoint="progress")
def progress_alias():
    return redirect(url_for("progress_view"))

@app.route("/board")
@login_required
def board():
    return render_template("catalog.html")

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")

@app.route("/teams")
@login_required
def teams_page():
    return render_template("teams.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    if not (u.is_admin or (u.team_id and u.id == (u.team.leader_id if u.team else None))):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

# --------------------------------
# Admin: users & teams
# --------------------------------
@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin.html", users=users)

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_name = (request.form.get("team") or "").strip()

    if not username or not password:
        flash("Username & password είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin_home"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin_home"))

    team = None
    if team_name:
        team = Team.query.filter_by(name=team_name).first()
        if not team:
            team = Team(name=team_name)
            db.session.add(team)
            db.session.flush()

    u = User(username=username, email=email, is_admin=is_admin, team=team)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin_home"))

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        leader_username = (request.form.get("leader") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        team = Team.query.filter_by(name=name).first()
        if team:
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
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin_teams.html", teams=teams)

# --------------------------------
# Error handlers
# --------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# --------------------------------
# Dev entry (δεν χρησιμοποιείται στο Render)
# --------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
