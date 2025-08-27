import os, secrets
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- App Config ----------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "app.db")

# Database URL (Render → Postgres / τοπικά → SQLite)
uri = os.environ.get("DATABASE_URL")
if uri:
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    if uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    if "sslmode=" not in uri and "ssl=" not in uri:
        sep = "&" if "?" in uri else "?"
        uri = f"{uri}{sep}sslmode=require"
    app.config["SQLALCHEMY_DATABASE_URI"] = uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)

# ---------------- Models ----------------
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    members = db.relationship("User", backref="team", lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(20), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"))

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")
    progress = db.Column(db.Integer, default=0)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Init / Seed ----------------
with app.app_context():
    db.create_all()
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", email="admin@example.com", is_admin=True, team=team, color="#ff0000")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
    else:
        if not admin.is_admin:
            admin.is_admin = True
            db.session.commit()

    if team.leader_id is None:
        team.leader_id = admin.id
        db.session.commit()

# ---------------- Helpers ----------------
def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*a, **k)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}

# ---------------- Routes ----------------
@app.route("/healthz")
def healthz(): return "ok", 200

@app.route("/")
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user.id
    flash("Συνδέθηκες!", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.pop("uid", None)
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return render_template("dashboard.html", user=u)

@app.route("/progress-view")
@login_required
def progress_view():
    u = current_user()
    tasks = Task.query.filter_by(assignee_id=u.id).all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

@app.route("/progress", endpoint="progress")
def progress_alias(): return redirect(url_for("progress_view"))

@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    u = current_user()
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            note = Note(content=content, user_id=u.id)
            db.session.add(note)
            db.session.commit()
            flash("Η σημείωση αποθηκεύτηκε.", "success")
    notes = Note.query.filter_by(user_id=u.id).all()
    return render_template("notes.html", notes=notes)

@app.route("/teams")
@login_required
def teams_page():
    teams = Team.query.all()
    return render_template("teams.html", teams=teams)

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    if not (u.is_admin or (u.team and u.team.leader_id == u.id)):
        flash("Μόνο διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.all()
    return render_template("directory.html", users=users)

@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    is_admin = True if request.form.get("is_admin") else False
    color = request.form.get("color") or "#3273dc"
    if not username or not password:
        flash("Username & password υποχρεωτικά.", "warning")
        return redirect(url_for("admin_home"))
    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη αυτό το username.", "danger")
        return redirect(url_for("admin_home"))
    u = User(username=username, email=email, is_admin=is_admin, color=color)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin_home"))

# ---------------- Errors ----------------
@app.errorhandler(404)
def nf(e): return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def err(e): return render_template("error.html", code=500, message="Σφάλμα server."), 500

# ---------------- Main ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
