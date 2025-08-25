import os
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import relationship

# -----------------------
# Setup
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    os.makedirs(app.instance_path, exist_ok=True)

    # ⚠️ Reset DB name ώστε να ξεκινήσει από την αρχή
    db_path = os.path.join(app.instance_path, "app2.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    return app

app = create_app()
db = SQLAlchemy(app)

# -----------------------
# Models
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=True, unique=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(32), nullable=True)

    tasks = relationship("Task", back_populates="assignee")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)
    status = db.Column(db.String(20), default="open")  # open / done
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    assignee = relationship("User", back_populates="tasks")


# -----------------------
# DB Init + Admin bootstrap
# -----------------------
with app.app_context():
    db.create_all()

    # Αν δεν υπάρχει admin, φτιάξε έναν
    has_admin = db.session.execute(text("SELECT 1 FROM user WHERE is_admin = 1 LIMIT 1")).first()
    if not has_admin:
        admin = User(name="Admin", is_admin=True, username="admin")
        admin.set_password("admin123")  # αρχικός κωδικός
        db.session.add(admin)
        db.session.commit()
        print("Δημιουργήθηκε Admin με username=admin και password=admin123")
        print("/login/" + admin.token)

    # Τύπωσε πάντα τα admin login links
    rows = db.session.execute(text("SELECT name, token FROM user WHERE is_admin = 1")).fetchall()
    if rows:
        print("=== Admin login links ===")
        for name, token in rows:
            print(f"{name}: /login/{token}")
        print("=== End admin links ===")


# -----------------------
# Routes
# -----------------------
@app.context_processor
def inject_user():
    uid = session.get("user_id")
    user = User.query.get(uid) if uid else None
    return dict(user=user)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login/<token>")
def login_token(token):
    user = User.query.filter_by(token=token).first()
    if not user:
        return render_template("error.html", code=404, message="Μη έγκυρο link")
    session["user_id"] = user.id
    flash("Συνδέθηκες ως " + user.name, "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))


@app.route("/login", methods=["POST"])
def login_password():
    username = request.form.get("username")
    password = request.form.get("password")
    user = User.query.filter_by(username=username).first()
    if user and user.password_hash and user.check_password(password):
        session["user_id"] = user.id
        flash("Συνδέθηκες ως " + user.name, "success")
        return redirect(url_for("admin" if user.is_admin else "dashboard"))
    flash("Λάθος στοιχεία", "danger")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες", "info")
    return redirect(url_for("index"))


# -----------------------
# Admin panel
# -----------------------
@app.route("/admin")
def admin():
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user or not user.is_admin:
        return render_template("error.html", code=403, message="Δεν έχεις δικαιώματα")
    users = User.query.all()
    tasks = Task.query.all()
    return render_template("admin.html", users=users, tasks=tasks)


@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    uid = session.get("user_id")
    admin = User.query.get(uid)
    if not admin or not admin.is_admin:
        return render_template("error.html", code=403, message="Δεν έχεις δικαιώματα")

    name = request.form.get("name")
    email = request.form.get("email")
    color = request.form.get("color")
    username = request.form.get("username")
    password = request.form.get("password")

    u = User(name=name, email=email, color=color, username=username)
    if password:
        u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("Δημιουργήθηκε ο χρήστης " + name, "success")
    return redirect(url_for("admin"))


@app.route("/admin/create_task", methods=["POST"])
def admin_create_task():
    uid = session.get("user_id")
    admin = User.query.get(uid)
    if not admin or not admin.is_admin:
        return render_template("error.html", code=403, message="Δεν έχεις δικαιώματα")

    title = request.form.get("title")
    description = request.form.get("description")
    due_date = request.form.get("due_date")
    due_time = request.form.get("due_time")
    assignee_id = request.form.get("assignee_id")

    task = Task(
        title=title,
        description=description,
        due_date=datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None,
        due_time=datetime.strptime(due_time, "%H:%M").time() if due_time else None,
        assignee_id=int(assignee_id) if assignee_id else None
    )
    db.session.add(task)
    db.session.commit()
    flash("Η εργασία αποθηκεύτηκε", "success")
    return redirect(url_for("admin"))


# -----------------------
# Dashboard (χρήστης)
# -----------------------
@app.route("/dashboard")
def dashboard():
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user:
        return render_template("error.html", code=403, message="Δεν έχεις πρόσβαση")

    open_tasks = Task.query.filter_by(assignee_id=user.id, status="open").all()
    done_tasks = Task.query.filter_by(assignee_id=user.id, status="done").all()
    return render_template("dashboard.html", user=user, open_tasks=open_tasks, done_tasks=done_tasks)


@app.route("/toggle_task/<int:task_id>", methods=["POST"])
def toggle_task(task_id):
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user:
        return render_template("error.html", code=403, message="Δεν έχεις πρόσβαση")

    task = Task.query.get(task_id)
    if not task or task.assignee_id != user.id:
        return render_template("error.html", code=403, message="Δεν έχεις δικαιώματα")

    if task.status == "open":
        task.status = "done"
        task.completed_at = datetime.utcnow()
    else:
        task.status = "open"
        task.completed_at = None
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/me/change_password", methods=["POST"])
def me_change_password():
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user:
        return render_template("error.html", code=403, message="Δεν έχεις πρόσβαση")

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm = request.form.get("confirm_password")

    if user.password_hash and not user.check_password(current_password):
        flash("Λάθος τρέχων κωδικός", "danger")
        return redirect(url_for("dashboard"))

    if new_password != confirm:
        flash("Οι νέοι κωδικοί δεν ταιριάζουν", "danger")
        return redirect(url_for("dashboard"))

    user.set_password(new_password)
    db.session.commit()
    flash("Ο κωδικός άλλαξε!", "success")
    return redirect(url_for("dashboard"))
