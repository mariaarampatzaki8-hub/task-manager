import os
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# --- Flask setup ---
app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

db_path = os.path.join(app.instance_path, "app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # ΠΡΟΣΟΧΗ: Integer
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)

    # Για login με username/κωδικό
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return bool(self.password_hash) and check_password_hash(self.password_hash, password)

    tasks = relationship("Task", back_populates="assignee", cascade="all, delete")


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default="open")  # open, done
    completed_at = db.Column(db.DateTime, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = relationship("User", back_populates="tasks")

# --- Lightweight migration for SQLite ---
with app.app_context():
    db.create_all()
    try:
        cols = [r[1] for r in db.session.execute(text("PRAGMA table_info('user')")).fetchall()]
        if "username" not in cols:
            db.session.execute(text("ALTER TABLE user ADD COLUMN username VARCHAR(80) UNIQUE"))
        if "password_hash" not in cols:
            db.session.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)"))
        db.session.commit()
    except Exception:
        pass

# --- Routes ---

@app.route("/")
def index():
    u = None
    if "uid" in session:
        u = User.query.get(session["uid"])
    return render_template("index.html", user=u)

# ✅ Login με username/κωδικό
@app.route("/login", methods=["POST"])
def login_password():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Συμπληρώστε username και κωδικό.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία σύνδεσης.", "danger")
        return redirect(url_for("index"))

    session["uid"] = user.id
    flash(f"Καλωσήρθες, {user.name}!", "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))
