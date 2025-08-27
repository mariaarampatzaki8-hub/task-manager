# app.py
import os, secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- App ----------------
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# ---------------- DB config (Render Postgres ή SQLite fallback) ----------------
def build_db_uri():
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        # local fallback
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")

    # Heroku/Render μπορεί να δώσουν 'postgres://' -> γύρνα το σε SQLAlchemy + pg8000
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
    elif uri.startswith("postgresql://") and "+pg8000" not in uri:
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

    # ΜΗΝ βάλεις connect_args με sslmode εδώ (pg8000 δεν το θέλει).
    return uri

app.config["SQLALCHEMY_DATABASE_URI"] = build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending|done
    progress = db.Column(db.Integer, default=0)           # 0..100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers ----------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_user():
    u = User.query.get(session["uid"]) if session.get("uid") else None
    return {"user": u}

# ---------------- Health ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- Auth ----------------
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or not password:
        flash("Συμπλήρωσε username και κωδικό.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    session["is_admin"] = bool(u.is_admin)
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------- Pages ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Στο template φαίνεται ο ρόλος με βάση user.is_admin
    return render_template("dashboard.html")

@app.route("/progress-view")
@login_required
def progress_view():
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

# Alias για templates που είχαν url_for('progress')
@app.route("/progress", endpoint="progress")
@login_required
def progress_alias():
    return redirect(url_for("progress_view"))

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/board")
@login_required
def board():
    # απλή σελίδα-βιτρίνα
    return render_template("catalog.html")

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

# ---------------- Admin ----------------
@app.route("/admin")
@login_required
def admin():
    if not session.get("is_admin"):
        flash("Μόνο για διαχειριστές.", "warning")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin.html", users=users)

@app.route("/admin/create_user", methods=["POST"])
@login_required
def admin_create_user():
    if not session.get("is_admin"):
        flash("Μόνο για διαχειριστές.", "warning")
        return redirect(url_for("dashboard"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    is_admin = bool(request.form.get("is_admin"))

    if not username or not password:
        flash("Συμπλήρωσε username & κωδικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(username=username, is_admin=is_admin)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

# ---------------- Error pages ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------------- Bootstrap DB (μία φορά) ----------------
def bootstrap_db():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", is_admin=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

# ---------------- Entry ----------------
if __name__ == "__main__":
    with app.app_context():
        bootstrap_db()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
else:
    # Όταν τρέχει με gunicorn στο Render
    with app.app_context():
        bootstrap_db()
