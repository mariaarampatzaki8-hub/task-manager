
import os
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app

app = create_app()
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), nullable=True, unique=True)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)
    tasks = relationship("Task", back_populates="assignee", cascade="all, delete")

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default="open")  # open, done
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = relationship("User", back_populates="tasks")

# --- Helpers ---
def current_user():
    uid = session.get("uid")
    if uid:
        return User.query.get(uid)
    return None

def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Χρειάζεται σύνδεση μέσω του ειδικού συνδέσμου.", "warning")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapper

def admin_required(view):
    from functools import wraps
    @wraps(view)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο ο διαχειριστής έχει πρόσβαση εδώ.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapper

# --- Routes ---
@app.route("/")
def index():
    u = current_user()
    return render_template("index.html", user=u)

@app.route("/login/<token>")
def login_token(token):
    user = User.query.filter_by(token=token).first()
    if not user:
        flash("Μη έγκυρος σύνδεσμος.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user.id
    flash(f"Καλωσήρθες, {user.name}!", "success")
    if user.is_admin:
        return redirect(url_for("admin"))
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδεθήκατε.", "info")
    return redirect(url_for("index"))

@app.route("/me")
@login_required
def dashboard():
    u = current_user()
    tasks = Task.query.filter_by(assignee_id=u.id).order_by(Task.status, Task.due_date).all()
    return render_template("dashboard.html", user=u, tasks=tasks)

@app.route("/task/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    u = current_user()
    task = Task.query.get_or_404(task_id)
    if task.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    task.status = "done" if task.status == "open" else "open"
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

# --- Admin ---
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.is_admin.desc(), User.name).all()
    tasks = Task.query.order_by(Task.due_date, Task.status).all()
    base_url = request.host_url.rstrip("/")
    return render_template("admin.html", users=users, tasks=tasks, base_url=base_url)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = request.form.get("name","").strip()
    email = request.form.get("email","").strip() or None
    if not name:
        flash("Το όνομα είναι υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))
    token = secrets.token_urlsafe(16)
    user = User(name=name, email=email, token=token, is_admin=False)
    db.session.add(user)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@admin_required
def admin_make_admin(user_id):
    if user_id == current_user().id:
        flash("Είστε ήδη διαχειριστής.", "info")
        return redirect(url_for("admin"))
    u = User.query.get_or_404(user_id)
    u.is_admin = True
    db.session.commit()
    flash("Ο χρήστης έγινε διαχειριστής.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user().id:
        flash("Δεν μπορείτε να διαγράψετε τον εαυτό σας.", "warning")
        return redirect(url_for("admin"))
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = request.form.get("title","").strip()
    description = request.form.get("description","").strip()
    due = request.form.get("due_date","").strip()
    assignee_id = request.form.get("assignee_id")
    if not title:
        flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
        return redirect(url_for("admin"))
    due_date = datetime.strptime(due, "%Y-%m-%d").date() if due else None
    assignee = User.query.get(int(assignee_id)) if assignee_id else None
    task = Task(title=title, description=description, due_date=due_date, assignee=assignee)
    db.session.add(task)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/assign/<int:task_id>", methods=["POST"])
@admin_required
def admin_assign(task_id):
    task = Task.query.get_or_404(task_id)
    assignee_id = request.form.get("assignee_id")
    task.assignee_id = int(assignee_id) if assignee_id else None
    db.session.commit()
    flash("Η ανάθεση ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/delete_task/<int:task_id>", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# --- Init command ---
@app.cli.command("init-db")
def init_db():
    db.create_all()
    # Create default admin if none
    if not User.query.filter_by(is_admin=True).first():
        admin_user = User(name="Admin", email=None, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("Δημιουργήθηκε διαχειριστής με όνομα 'Admin'. Σύνδεσμος: /login/" + admin_user.token)
    else:
        print("Υπάρχει ήδη διαχειριστής.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Ensure at least one admin exists
        if not User.query.filter_by(is_admin=True).first():
            admin_user = User(name="Admin", email=None, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Σύνδεσμος διαχειριστή:", "http://127.0.0.1:5000/login/" + admin_user.token)
    app.run(debug=True)
