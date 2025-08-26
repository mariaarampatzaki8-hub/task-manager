import os
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, Response
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


# =========================
# App & Database bootstrap
# =========================
app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# DATABASE_URL (Postgres) αν υπάρχει, αλλιώς SQLite καθαρή βάση
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///" + os.path.join(app.instance_path, "app_final.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========
# Models
# =========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Προβολή/ταυτοποίηση
    name = db.Column(db.String(120), nullable=False)                 # Ονοματεπώνυμο/εμφάνιση
    username = db.Column(db.String(80), unique=True, nullable=False) # Login username
    email = db.Column(db.String(200), unique=True, nullable=True)    # κρατάμε unique όπως ζήτησες
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)

    # Προτιμήσεις/κατάσταση
    color = db.Column(db.String(32), nullable=True, default="#3273dc")
    must_change_password = db.Column(db.Boolean, default=False)      # μετά από reset από admin

    # Σχέσεις
    tasks = relationship("Task", back_populates="assignee", cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="user", cascade="all, delete-orphan", order_by="desc(Note.created_at)")

    # Helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Προθεσμία
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)

    # Κατάσταση & πρόοδος
    status = db.Column(db.String(20), default="open")  # open | done
    progress = db.Column(db.Integer, default=0)        # 0..100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Ανάθεση
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = relationship("User", back_populates="tasks")


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="notes")


# =========================
# Initial DB & Admin seed
# =========================
with app.app_context():
    db.create_all()

    # Αν δεν υπάρχει admin, φτιάξε έναν
    try:
        has_admin = db.session.execute(text("SELECT 1 FROM user WHERE is_admin = 1 LIMIT 1")).first()
    except Exception:
        has_admin = None

    if not has_admin:
        admin = User(
            name="Admin",
            username="admin",
            email="admin@example.com",
            is_admin=True,
            color="#3273dc",
        )
        admin.set_password("admin123")  # αρχικός κωδικός
        db.session.add(admin)
        db.session.commit()
        print("Δημιουργήθηκε Admin: username=admin password=admin123")
        print("/login/" + admin.token)

    # Τύπωσε ΠΑΝΤΑ όλα τα admin token links για εύρεση στα Logs
    try:
        rows = db.session.execute(text("SELECT name, token FROM user WHERE is_admin = 1")).fetchall()
        if rows:
            print("=== Admin login links ===")
            for name, token in rows:
                print(f"{name}: /login/{token}")
            print("=== End admin links ===")
    except Exception:
        pass


# =========================
# Helpers & Guards
# =========================
def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Απαιτείται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}


# ==========
# Auth
# ==========
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login/<token>")
def login_token(token):
    user = User.query.filter_by(token=token).first()
    if not user:
        return render_template("error.html", code=404, message="Μη έγκυρο link"), 404
    session["uid"] = user.id
    if user.must_change_password:
        flash("Ο κωδικός σας έχει επαναφερθεί — παρακαλώ αλλάξτε τον.", "warning")
    flash(f"Καλωσήρθες, {user.name}!", "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))

@app.route("/login", methods=["POST"])
def login_password():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Λάθος στοιχεία σύνδεσης.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user.id
    if user.must_change_password:
        flash("Ο κωδικός σας έχει επαναφερθεί — παρακαλώ αλλάξτε τον.", "warning")
    flash(f"Καλωσήρθες, {user.name}!", "success")
    return redirect(url_for("admin" if user.is_admin else "dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδεθήκατε.", "info")
    return redirect(url_for("index"))


# ==========
# Admin
# ==========
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    tasks = Task.query.order_by(Task.status.desc(), Task.due_date.nulls_last(), Task.due_time.nulls_last()).all()

    # Στατιστικά ανά χρήστη για εποπτεία
    stats = []
    for u in users:
        utasks = [t for t in tasks if t.assignee_id == u.id]
        open_count = sum(1 for t in utasks if t.status == "open")
        done_count = sum(1 for t in utasks if t.status == "done")
        avg_progress = round(sum(t.progress for t in utasks) / len(utasks), 1) if utasks else 0
        last_done = max((t.completed_at for t in utasks if t.completed_at), default=None)
        stats.append({
            "user": u,
            "open": open_count,
            "done": done_count,
            "avg_progress": avg_progress,
            "last_done": last_done
        })

    # Σημειώσεις για εποπτεία (οι πρόσφατες)
    recent_notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()

    return render_template("admin.html", users=users, tasks=tasks, stats=stats, notes=recent_notes)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    password = request.form.get("password") or ""
    color = request.form.get("color") or "#3273dc"

    if not name or not username or not password:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    # Uniqueness checks (φιλικό μήνυμα αντί για 500)
    if User.query.filter_by(username=username).first():
        flash("Το username χρησιμοποιείται ήδη.", "danger")
        return redirect(url_for("admin"))
    if email and User.query.filter_by(email=email).first():
        flash("Το email χρησιμοποιείται ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, color=color)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash(f"Ο χρήστης «{name}» δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/reset_token/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_token(user_id):
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash(f"Ανανεώθηκε το link για τον/την {u.name}.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/set_color/<int:user_id>", methods=["POST"])
@admin_required
def admin_set_color(user_id):
    u = User.query.get_or_404(user_id)
    u.color = request.form.get("color") or u.color
    db.session.commit()
    flash("Ενημερώθηκε το χρώμα.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/set_credentials/<int:user_id>", methods=["POST"])
@admin_required
def admin_set_credentials(user_id):
    u = User.query.get_or_404(user_id)
    new_username = (request.form.get("username") or "").strip()
    new_password = request.form.get("password") or ""

    if new_username and new_username != u.username:
        if User.query.filter(User.username == new_username, User.id != u.id).first():
            flash("Το username χρησιμοποιείται ήδη.", "danger")
            return redirect(url_for("admin"))
        u.username = new_username

    if new_password:
        u.set_password(new_password)
        u.must_change_password = False

    db.session.commit()
    flash("Ενημερώθηκαν τα στοιχεία σύνδεσης.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/reset_password/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    # Δημιούργησε προσωρινό password και ζήτα αλλαγή στο επόμενο login
    temp_pw = "reset-" + secrets.token_hex(3)  # π.χ. reset-a1b2c3
    u.set_password(temp_pw)
    u.must_change_password = True
    db.session.commit()
    flash(f"Προσωρινός κωδικός για {u.name}: {temp_pw}", "warning")
    print(f"[ADMIN RESET PW] {u.username} -> {temp_pw}")
    return redirect(url_for("admin"))

@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    assignee_id = request.form.get("assignee_id") or None
    due_date_str = (request.form.get("due_date") or "").strip()
    due_time_str = (request.form.get("due_time") or "").strip()

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
        flash("Μη έγκυρη ημερομηνία/ώρα.", "danger")
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

@app.route("/admin/delete_task/<int:task_id>", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/export_csv")
@admin_required
def export_csv():
    import csv
    from io import StringIO
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["id", "title", "assignee", "status", "progress", "due_date", "due_time", "completed_at"])
    for t in Task.query.order_by(Task.id).all():
        w.writerow([
            t.id,
            t.title,
            (t.assignee.name if t.assignee else ""),
            t.status,
            t.progress,
            (t.due_date.isoformat() if t.due_date else ""),
            (t.due_time.strftime("%H:%M") if t.due_time else ""),
            (t.completed_at.isoformat(sep=" ") if t.completed_at else "")
        ])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=tasks.csv"})


# ==========
# User area
# ==========
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
    my_notes = Note.query.filter_by(user_id=u.id).order_by(Note.created_at.desc()).all()
    return render_template("dashboard.html", user=u, open_tasks=open_tasks, done_tasks=done_tasks, notes=my_notes)

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
        t.progress = 100
    else:
        t.status = "open"
        t.completed_at = None
        if t.progress == 100:
            t.progress = 90  # μικρή «επιστροφή» για να φανεί ότι ξανάνοιξε
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/task/<int:task_id>/progress", methods=["POST"])
@login_required
def update_task_progress(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    try:
        p = int(request.form.get("progress", 0))
        p = max(0, min(100, p))
    except Exception:
        p = t.progress
    t.progress = p
    if p >= 100:
        t.status = "done"
        t.completed_at = t.completed_at or datetime.utcnow()
    else:
        if t.status == "done":
            t.status = "open"
            t.completed_at = None
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/me/change_password", methods=["POST"])
@login_required
def me_change_password():
    u = current_user()
    force = u.must_change_password
    current_pw = request.form.get("current_password") or ""
    new_pw = request.form.get("new_password") or ""
    confirm_pw = request.form.get("confirm_password") or ""

    if not new_pw or new_pw != confirm_pw:
        flash("Οι νέοι κωδικοί δεν ταιριάζουν.", "warning")
        return redirect(url_for("dashboard"))

    # Αν έχει επιβληθεί αλλαγή από admin, δεν απαιτούμε τρέχον κωδικό
    if not force:
        if not u.check_password(current_pw):
            flash("Λάθος τρέχων κωδικός.", "danger")
            return redirect(url_for("dashboard"))

    u.set_password(new_pw)
    u.must_change_password = False
    db.session.commit()
    flash("Ο κωδικός άλλαξε επιτυχώς.", "success")
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
# Σελίδα κοινής προόδου για όλους
@app.route("/progress")
@login_required
def all_progress():
    users = User.query.order_by(User.name.asc()).all()
    # Προφορτωμένες εργασίες για όλους (για απλή εμφάνιση)
    user_tasks = {u.id: Task.query.filter_by(assignee_id=u.id).order_by(Task.status.desc(), Task.title.asc()).all()
                  for u in users}
    return render_template("progress.html", users=users, user_tasks=user_tasks)


# ==========
# Errors
# ==========
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Η σελίδα δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# ==========
# Local run
# ==========
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
