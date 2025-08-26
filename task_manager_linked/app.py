import os
import secrets
from datetime import datetime, date, time

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App & DB ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # SECRET_KEY: από env ή random για dev
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")  # νέο καθαρό όνομα DB
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app

app = create_app()
db = SQLAlchemy(app)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # στοιχεία
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    username = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)

    # πρόσβαση
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    # εμφάνιση
    color = db.Column(db.String(16), nullable=True)  # hex χρώμα

    tasks = relationship("Task", backref="assignee", cascade="all, delete-orphan", lazy="dynamic", foreign_keys="Task.assignee_id")
    notes = relationship("Note", backref="user", cascade="all, delete-orphan", lazy="dynamic")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=True)

    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)

    progress = db.Column(db.Integer, default=0)      # 0..100
    status = db.Column(db.String(20), default="open")  # open|done
    completed_at = db.Column(db.DateTime, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ---------- Helpers ----------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
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
            flash("Απαιτείται πρόσβαση διαχειριστή.", "danger")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}

# ---------- Initial DB & bootstrap admin ----------
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email=None,
            is_admin=True,
            color="#111827"
        )
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        print("== Admin δημιουργήθηκε με username=admin και password=admin123")
    # πάντα δείξε link σύνδεσης admin στα logs
    print("== Admin login links ==")
    print("Admin:", f"/login/{admin.token}")
    print("== End admin links ==")

# ---------- Routes: Public / Auth ----------
@app.route("/")
def index():
    # απλή αρχική (login φόρμα στο index.html)
    return render_template("index.html")

@app.route("/login/<token>")
def login_token(token):
    u = User.query.filter_by(token=token).first()
    if not u:
        flash("Μη έγκυρο link.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    if u.is_admin:
        return redirect(url_for("admin"))
    return redirect(url_for("dashboard"))

@app.route("/login_password", methods=["POST"])
def login_password():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    if u.is_admin:
        return redirect(url_for("admin"))
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------- Routes: Dashboard / Tasks / Notes για χρήστη ----------
@app.route("/dashboard")
@login_required
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()

    # εργασίες μόνο του χρήστη
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()

    # για την καρτέλα Πρόοδος Ομάδας
    users = User.query.order_by(User.name.asc()).all()
    user_tasks = {
        usr.id: Task.query.filter_by(assignee_id=usr.id).order_by(Task.status.desc(), Task.id.desc()).all()
        for usr in users
    }

    return render_template(
        "dashboard.html",
        open_tasks=open_tasks,
        done_tasks=done_tasks,
        notes=notes,
        users=users,
        user_tasks=user_tasks
    )
@login_required
def toggle_task(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    if t.status == "open":
        t.status = "done"
        t.progress = 100 if t.progress < 100 else t.progress
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.completed_at = None
        if t.progress == 100:
            t.progress = 90
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/tasks/<int:task_id>/progress", methods=["POST"])
@login_required
def update_task_progress(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    try:
        p = int(request.form.get("progress", 0))
    except ValueError:
        p = 0
    p = max(0, min(100, p))
    t.progress = p
    if p == 100:
        t.status = "done"
        t.completed_at = datetime.utcnow()
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/me/add_note", methods=["POST"])
@login_required
def me_add_note():
    u = current_user()
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Το σημείωμα είναι κενό.", "warning")
        return redirect(url_for("dashboard"))
    db.session.add(Note(content=content, user_id=u.id))
    db.session.commit()
    flash("Η σημείωση αποθηκεύτηκε.", "success")
    return redirect(url_for("dashboard"))

# --- Edit/Delete σημειώσεων (χρήστης ή admin) ---
@app.route("/me/notes/<int:note_id>/edit", methods=["POST"])
@login_required
def me_update_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Το σημείωμα δεν μπορεί να είναι κενό.", "warning")
        return redirect(url_for("dashboard"))
    n.content = new_content
    db.session.commit()
    flash("Η σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("dashboard"))

@app.route("/me/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def me_delete_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    db.session.delete(n)
    db.session.commit()
    flash("Η σημείωση διαγράφηκε.", "info")
    return redirect(url_for("dashboard"))

@app.route("/me/change_password", methods=["POST"])
@login_required
def me_change_password():
    u = current_user()
    if u.must_change_password:
        # μετά από reset δεν απαιτείται current_password
        current_ok = True
    else:
        current_ok = u.check_password(request.form.get("current_password",""))
    if not current_ok:
        flash("Λάθος τρέχων κωδικός.", "danger")
        return redirect(url_for("dashboard"))
    new_pw = request.form.get("new_password","")
    confirm = request.form.get("confirm_password","")
    if not new_pw or new_pw != confirm:
        flash("Οι νέοι κωδικοί δεν ταιριάζουν.", "warning")
        return redirect(url_for("dashboard"))
    u.set_password(new_pw)
    u.must_change_password = False
    db.session.commit()
    flash("Ο κωδικός άλλαξε επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

# ---------- Σελίδα κοινής προόδου ----------
@app.route("/progress")
@login_required
def all_progress():
    users = User.query.order_by(User.name.asc()).all()
    # εργασίες ανά χρήστη
    user_tasks = {u.id: Task.query.filter_by(assignee_id=u.id).order_by(Task.status.desc(), Task.id.desc()).all()
                  for u in users}
    return render_template("progress.html", users=users, user_tasks=user_tasks)

# ---------- Admin ----------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()

    # στατιστικά per user
    stats = []
    for u in users:
        open_count = Task.query.filter_by(assignee_id=u.id, status="open").count()
        done_q = Task.query.filter_by(assignee_id=u.id, status="done")
        done_count = done_q.count()
        avg = 0
        tasks_all = Task.query.filter_by(assignee_id=u.id).all()
        if tasks_all:
            avg = int(sum(t.progress for t in tasks_all) / len(tasks_all))
        last_done = done_q.order_by(Task.completed_at.desc()).first()
        stats.append({
            "user": u, "open": open_count, "done": done_count,
            "avg_progress": avg,
            "last_done": (last_done.completed_at if last_done else None)
        })

    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    color = request.form.get("color") or "#3273dc"
    raw_pw = (request.form.get("password") or "").strip()

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if email and User.query.filter_by(email=email).first():
        flash("Το email υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))
    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, color=color)
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u)
    db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    due_date_s = request.form.get("due_date") or ""
    due_time_s = request.form.get("due_time") or ""
    assignee_id = request.form.get("assignee_id") or None

    if not title:
        flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
        return redirect(url_for("admin"))

    d = None
    t = None
    try:
        if due_date_s:
            y, m, dday = map(int, due_date_s.split("-"))
            d = date(y, m, dday)
        if due_time_s:
            hh, mm = map(int, due_time_s.split(":"))
            t = time(hh, mm)
    except Exception:
        pass

    task = Task(title=title, description=description, due_date=d, due_time=t)
    if assignee_id:
        task.assignee_id = int(assignee_id)
    db.session.add(task)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/credentials", methods=["POST"])
@admin_required
def admin_set_credentials(user_id):
    u = User.query.get_or_404(user_id)
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if username:
        if User.query.filter(User.id != u.id, User.username == username).first():
            flash("Το username χρησιμοποιείται.", "danger")
            return redirect(url_for("admin"))
        u.username = username

    if password:
        u.set_password(password)
        u.must_change_password = False

    db.session.commit()
    flash("Τα στοιχεία ενημερώθηκαν.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    tmp = "reset-" + secrets.token_hex(3)
    u.set_password(tmp)
    u.must_change_password = True
    db.session.commit()
    flash(f"Προσωρινός κωδικός για {u.name}: {tmp}", "warning")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/color", methods=["POST"])
@admin_required
def admin_set_color(user_id):
    u = User.query.get_or_404(user_id)
    color = request.form.get("color") or "#3273dc"
    u.color = color
    db.session.commit()
    flash("Το χρώμα ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin_reset_token", methods=["POST"])
@admin_required
def admin_reset_token():
    user_id = int(request.form.get("user_id", 0))
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Το προσωπικό link ανανεώθηκε.", "info")
    return redirect(url_for("admin"))

# --- Admin edit/delete notes ---
@app.route("/admin/notes/<int:note_id>/edit", methods=["POST"])
@admin_required
def admin_update_note(note_id):
    n = Note.query.get_or_404(note_id)
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Το σημείωμα δεν μπορεί να είναι κενό.", "warning")
        return redirect(url_for("admin"))
    n.content = new_content
    db.session.commit()
    flash(f"Η σημείωση του/της {n.user.name} ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    n = Note.query.get_or_404(note_id)
    uname = n.user.name
    db.session.delete(n)
    db.session.commit()
    flash(f"Η σημείωση του/της {uname} διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# --- Admin delete user by username (φόρμα κάτω-κάτω στο admin.html) ---
@app.route("/admin_delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    username = (request.form.get("username") or "").strip()
    if not username:
        flash("Δώσε username για διαγραφή.", "warning")
        return redirect(url_for("admin"))

    u = User.query.filter_by(username=username).first()
    if not u:
        flash("Δεν βρέθηκε χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    me = current_user()
    if u.id == me.id:
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "danger")
        return redirect(url_for("admin"))
    if u.is_admin:
        flash("Η διαγραφή διαχειριστή δεν επιτρέπεται.", "danger")
        return redirect(url_for("admin"))

    name = u.name
    db.session.delete(u)  # cascade θα καθαρίσει tasks & notes
    db.session.commit()
    flash(f"Ο/Η «{name}» διαγράφηκε μαζί με εργασίες & σημειώσεις.", "info")
    return redirect(url_for("admin"))

# ---------- Export CSV ----------
@app.route("/admin/export_csv")
@admin_required
def export_csv():
    # φτιάχνουμε απλό CSV στη μνήμη
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["User", "Username", "Task", "Status", "Progress", "DueDate", "DueTime", "CompletedAt"])
    tasks = Task.query.order_by(Task.id.desc()).all()
    for t in tasks:
        u = t.assignee.name if t.assignee else ""
        dd = t.due_date.isoformat() if t.due_date else ""
        dt = t.due_time.strftime("%H:%M") if t.due_time else ""
        ca = t.completed_at.isoformat() if t.completed_at else ""
        writer.writerow([u, t.assignee.username if t.assignee else "", t.title, t.status, t.progress, dd, dt, ca])
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name="tasks_export.csv"
    )

# ---------- Error handlers ----------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Η σελίδα δεν βρέθηκε."), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# For gunicorn: expose `app`
# if __name__ == "__main__":  # για local δοκιμές
#     app.run(debug=True)
