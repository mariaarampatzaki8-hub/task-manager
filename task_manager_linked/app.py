import os, secrets
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- App ----------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# ---------------- DB CONFIG ----------------
def build_db_uri():
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
    elif uri.startswith("postgresql://"):
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    return uri

app.config["SQLALCHEMY_DATABASE_URI"] = build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default="pending")
    progress = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- HELPERS ----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- ROUTES ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/")
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session["uid"] = user.id
        session["is_admin"] = user.is_admin
        flash("Συνδέθηκες επιτυχώς.", "success")
        return redirect(url_for("dashboard"))
    flash("Λάθος στοιχεία.", "danger")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["uid"])
    return render_template("dashboard.html", user=user)

@app.route("/progress")
@login_required
def progress_view():
    tasks = Task.query.all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html")

@app.route("/admin")
@login_required
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("dashboard"))
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/admin/create_user", methods=["POST"])
@login_required
def create_user():
    if not session.get("is_admin"):
        return redirect(url_for("dashboard"))
    username = request.form.get("username")
    password = request.form.get("password")
    is_admin = True if request.form.get("is_admin") == "on" else False
    if not username or not password:
        flash("Συμπλήρωσε όλα τα πεδία!", "danger")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "warning")
        return redirect(url_for("admin"))
    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε!", "success")
    return redirect(url_for("admin"))

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# ---------------- INIT ----------------
@app.before_request
def ensure_admin():
    """Αν δεν υπάρχει admin, τον φτιάχνει"""
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", is_admin=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
