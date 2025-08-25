import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, Response
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# Flask & Database setup
# -----------------------
app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# Postgres (Render) ή SQLite fallback
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///" + os.path.join(app.instance_path, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------
# Models
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)

    # login με username/κωδικό
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)

    # προτιμώμενο χρώμα θέματος
    color = db.Column(db.String(32), nullable=True, default="blue")

    tasks = relationship("Task", back_populates="assignee", cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return bool(self.password_hash) and check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)
    status = db.Column(db.String(20), default="open")  # open | done
    completed_at = db.Column(db.DateTime, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = relationship("User", back_populates="tasks")

# -----------------------
# Auto-migrations (SQLite) + Safe admin bootstrap + ALWAYS print admin tokens
# -----------------------
with app.app_context():
    db.create_all()

    # 1) Προσθήκη στηλών που ίσως λείπουν (SQLite PRAGMA)
    try:
        cols_user = [r[1] for r in db.session.execute(text("PRAGMA table_info('user')")).fetchall()]
        if "username" not in cols_user:
            db.session.execute(text("ALTER TABLE user ADD COLUMN username VARCHAR(80) UNIQUE"))
        if "password_hash" not in cols_user:
            db.session.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)"))
        if "color" not in cols_user:
            db.session.execute(text("ALTER TABLE user ADD COLUMN color VARCHAR(32)"))
        db.session.commit()
    except Exception:
        pass

    # 2) Αν δεν υπάρχει admin, δημιούργησε έναν
    try:
        has_admin = db.session.execute(text("SELECT 1 FROM user WHERE is_admin = 1 LIMIT 1")).first()
    except Exception:
        has_admin = None

    if not has_admin:
        admin = User(name="Admin", is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Δημιουργήθηκε Admin με token:")
        print("/login/" + admin.token)

    # 3) ΠΑΝΤΑ τύπωσε όλα τα admin tokens για να τα βρίσκουμε στα Logs
    try:
        rows = db.session.execute(text("SELECT name, token FROM user WHERE is_admin = 1")).fetchall()
        if rows:
            print("=== Admin login links ===")
            for name, token in rows:
                print(f"{name}: /login/{token}")
            print("=== End admin links ===")
    except Exception:
        pass

# -----------------------
# Helpers
# -----------------------
def current_user():
    if "uid" in session:
        return User.query.get(session["uid"])
    return None

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
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
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

# -----------------------
# Public / Auth routes
# -----------------------
@app.route("/")
def index():
    return render_template("index.html", user=current_user())

# Token login
@app.route("/login/<token>")
def login_token(token):
    user = User.query.filter_by(token=token).first()
    if not user:
        flash("Μη έγκυρος σύνδεσμος.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user.id
    flash(f"Καλωσήρθες, {user.name}!", "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))

# Username/password login (POST από αρχική)
@app.route("/login", methods=["POST"])
def login_password():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία σύνδεσης.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user.id
    flash(f"Καλωσήρθες, {user.name}!", "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))

@app.route("/logout")
def logout():
    session.pop("uid", None)
    flash("Αποσυνδεθήκατε.", "info")
    return redirect(url_for("index"))

# -----------------------
# Admin panel
# -----------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.id).all()
    tasks = Task.query.order_by(
        Task.status.desc(),
        Task.due_date.nulls_last(),
        Task.due_time.nulls_last()
    ).all()
    return render_template("admin.html", users=users, tasks=tasks, user=current_user())

# Δημιουργία χρήστη (με ΠΡΟΑΙΡΕΤΙΚΟ αρχικό username/κωδικό & χρώμα)
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip() or None
    color = request.form.get("color", "").strip() or "blue"
    initial_username = request.form.get("username", "").strip() or None
    initial_password = request.form.get("password", "")

    if not name:
        flash("Το όνομα είναι υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    u = User(name=name, email=email, color=color, username=initial_username)
    if initial_password:
        u.set_password(initial_password)

    db.session.add(u)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

# Ορισμός/αλλαγή username & password από Admin
@app.route("/admin/set_credentials/<int:user_id>", methods=["POST"])
@admin_required
def admin_set_credentials(user_id):
    u = User.query.get_or_404(user_id)
    new_username = request.form.get("username", "").strip() or None
    new_password = request.form.get("password", "")

    if new_username:
        clash = User.query.filter(User.username == new_username, User.id != u.id).first()
        if clash:
            flash("Το username χρησιμοποιείται ήδη.", "warning")
            return redirect(url_for("admin"))
        u.username = new_username

    if new_password:
        u.set_password(new_password)

    db.session.commit()
    flash("Τα στοιχεία σύνδεσης ενημερώθηκαν.", "success")
    return redirect(url_for("admin"))

# Ανανέωση token link
@app.route("/admin/reset_token/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_token(user_id):
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Ανανεώθηκε το προσωπικό link του χρήστη.", "info")
    return redirect(url_for("admin"))

# Αλλαγή χρώματος χρήστη
@app.route("/admin/set_color/<int:user_id>", methods=["POST"])
@admin_required
def admin_set_color(user_id):
    u = User.query.get_or_404(user_id)
    color = (request.form.get("color") or "blue").strip().lower()
    u.color = color
    db.session.commit()
    flash("Ενημερώθηκε το χρώμα του χρήστη.", "success")
    return redirect(url_for("admin"))

# Δημιουργία & ανάθεση εργασίας
@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip() or None
    assignee_id = request.form.get("assignee_id")
    due_date_str = request.form.get("due_date", "").strip()  # YYYY-MM-DD
    due_time_str = request.form.get("due_time", "").strip()  # HH:MM

    if not title:
        flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
        return redirect(url_for("admin"))

    dd = None
    tt = None
    try:
        if due_date_str:
            dd = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        if due_time_str:
            tt = datetime.strptime(due_time_str, "%H:%M").time()
    except ValueError:
        flash("Μη έγκυρη ημερομηνία/ώρα.", "warning")
        return redirect(url_for("admin"))

    t = Task(title=title, description=description, due_date=dd, due_time=tt)
    if assignee_id:
        try:
            t.assignee_id = int(assignee_id)
        except ValueError:
            pass

    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

# Διαγραφή εργασίας
@app.route("/admin/delete_task/<int:task_id>", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# Εξαγωγή CSV
@app.route("/admin/export_csv")
@admin_required
def export_csv():
    import csv
    from io import StringIO
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["id", "title", "assignee", "status", "due_date", "due_time", "completed_at"])
    for t in Task.query.order_by(Task.id).all():
        w.writerow([
            t.id,
            t.title,
            (t.assignee.name if t.assignee else ""),
            t.status,
            (t.due_date.isoformat() if t.due_date else ""),
            (t.due_time.strftime("%H:%M") if t.due_time else ""),
            (t.completed_at.isoformat(sep=" ") if t.completed_at else "")
        ])
    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=tasks.csv"}
    )

# -----------------------
# User dashboard & actions
# -----------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(
        Task.due_date.nulls_last(), Task.due_time.nulls_last()
    ).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(
        Task.completed_at.desc().nulls_last()
    ).all()
    return render_template("dashboard.html", user=u, open_tasks=open_tasks, done_tasks=done_tasks)

# Ολοκλήρωση/επαναφορά εργασίας
@app.route("/task/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    if t.status == "open":
        t.status = "done"
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.completed_at = None
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

# Αλλαγή κωδικού από τον ΙΔΙΟ τον χρήστη
@app.route("/me/change_password", methods=["POST"])
@login_required
def me_change_password():
    u = current_user()
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")
    if not new_pw or new_pw != confirm_pw:
        flash("Οι νέοι κωδικοί δεν ταιριάζουν.", "warning")
        return redirect(url_for("dashboard"))
    # Αν είχε ήδη κωδικό, ζήτα τον τωρινό
    if u.password_hash and not u.check_password(current_pw):
        flash("Ο τωρινός κωδικός δεν είναι σωστός.", "danger")
        return redirect(url_for("dashboard"))
    u.set_password(new_pw)
    db.session.commit()
    flash("Ο κωδικός άλλαξε επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

# -----------------------
# Errors
# -----------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Η σελίδα δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------
# Local run
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
