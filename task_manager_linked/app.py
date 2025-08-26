import os
import secrets
from datetime import datetime, date, time

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


# ---------- App & DB ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # --- DB config (Render Postgres αν υπάρχει DATABASE_URL, αλλιώς SQLite fallback) ---
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    uri = os.environ.get("DATABASE_URL")  # π.χ. postgresql://... από Render

    if uri:
        # 1) Heroku-style -> επίσημο
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) Χρήση driver pg8000 αντί για psycopg2
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        # 3) SSL on (Render Postgres)
        if "ssl=" not in uri and "sslmode=" not in uri:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}ssl=true"

        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        # engine options για σταθερές συνδέσεις και pg8000
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
            "connect_args": {"sslmode": "require"},  # για pg8000
        }
    else:
        # Fallback σε SQLite για τοπική ανάπτυξη
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)


# ---------- Models ----------
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)

    def __repr__(self):
        return f"<Team {self.name}>"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))

    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    color = db.Column(db.String(10), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

    # relations
    notes = relationship("Note", backref="user", lazy="dynamic")
    tasks_assigned = relationship("Task", backref="assignee", foreign_keys="Task.assignee_id", lazy="dynamic")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    @property
    def progress(self):
        total = self.tasks_assigned.count()
        if total == 0:
            return 0
        done = self.tasks_assigned.filter_by(status="done").count()
        return int(done * 100 / total)

    def __repr__(self):
        return f"<User {self.username}>"


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)

    status = db.Column(db.String(20), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Task {self.title}>"


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return "<Note {}>".format(self.id)


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
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
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


# ---------- Init DB & seed admin ----------
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        app.logger.error("DB init/seed failed: %s", e)

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email=None,
            is_admin=True,
            color="#3273dc",
        )
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Δημιουργήθηκε Admin με username=admin και password=admin123")
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Δημιουργήθηκε Admin με username=admin και password=admin123")

    # Εκτύπωση login link στα logs (με το token του admin)
    app.logger.info("== Admin login links ==")
    app.logger.info("Admin: /login/%s", admin.token)
    app.logger.info("== End admin links ==")


# ---------- Routes: Auth ----------
@app.route("/")
def index():
    u = current_user()
    if u:
        return redirect(url_for("admin") if u.is_admin else url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not username or not password:
        flash("Συμπλήρωσε username & κωδικό.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("admin") if u.is_admin else url_for("dashboard"))


# Login με token (φαίνεται στα logs)
@app.route("/login/<token>")
def login_token(token):
    u = User.query.filter_by(token=token).first()
    if not u:
        flash("Μη έγκυρο link σύνδεσης.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("admin") if u.is_admin else url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# ---------- Dashboard / Tasks / Notes (χρήστης) ----------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()

    # για την καρτέλα Προόδου Ομάδας μέσα στο dashboard (λίστα όλων)
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
        user_tasks=user_tasks,
    )


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))

    if t.status == "open":
        t.status = "done"
        t.progress = 100
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.progress = 0
        t.completed_at = None

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


@app.route("/me/notes/<int:note_id>/edit", methods=["POST"])
@login_required
def me_edit_note(note_id):
    u = current_user()
    n = Note.query.get_or_404(note_id)
    if n.user_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
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


# ---------- Προόδος (κοινή σελίδα) ----------
@app.route("/progress")
@login_required
def all_progress():
    users = User.query.order_by(User.name.asc()).all()
    user_tasks = {
        u.id: Task.query.filter_by(assignee_id=u.id).order_by(Task.status.desc(), Task.id.desc()).all()
        for u in users
    }
    return render_template("progress.html", users=users, user_tasks=user_tasks)


# ---------- Teams (public read-only για όλους) ----------
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)


# ---------- Κατάλογος (Admins & Leaders) ----------
@app.route("/directory")
@login_required
def directory():
    u = current_user()
    if not (u.is_admin or (u.team and u.team.leader_id == u.id)):
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("catalog.html", users=users)


# ---------- Οδηγίες (απλή σελίδα) ----------
@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")


# ---------- Admin ----------
@app.route("/admin")
@login_required
def admin():
    u = current_user()
    if not u.is_admin:
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))

    users = User.query.order_by(User.name.asc()).all()

    stats = {
        "total_users": User.query.count(),
        "total_tasks": Task.query.count(),
        "done_tasks": Task.query.filter_by(status="done").count(),
        "open_tasks": Task.query.filter_by(status="open").count(),
    }

    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)


# --- Admin: διαχείριση χρηστών ---
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    phone = (request.form.get("phone") or "").strip() or None
    id_number = (request.form.get("id_number") or "").strip() or None
    color = request.form.get("color") or "#3273dc"
    raw_pw = (request.form.get("password") or "").strip()

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, phone=phone, id_number=id_number, color=color)
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u)
    db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if current_user().id == user_id:
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "warning")
        return redirect(url_for("admin"))
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)
    new_pw = "reset-" + secrets.token_urlsafe(4)
    u.set_password(new_pw)
    u.must_change_password = True
    db.session.commit()
    flash(f"Νέος κωδικός για {u.name}: {new_pw}", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = request.form.get("is_admin") in ("1", "on", "true", "True")
    if make_admin:
        u.is_admin = True
        db.session.commit()
        flash(f"Ο/Η {u.name} έγινε Διαχειριστής.", "success")
    else:
        admins_left = User.query.filter_by(is_admin=True).count()
        if u.is_admin and admins_left <= 1:
            flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        else:
            u.is_admin = False
            db.session.commit()
            flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/set_color", methods=["POST"])
@admin_required
def admin_set_color(user_id):
    u = User.query.get_or_404(user_id)
    color = request.form.get("color") or "#3273dc"
    u.color = color
    db.session.commit()
    flash("Αποθηκεύτηκε χρώμα.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/reset_token/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset_token(user_id):
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Ανανέωση link σύνδεσης.", "info")
    return redirect(url_for("admin"))


# --- Admin: Εργασίες ---
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

    ddate = datetime.strptime(due_date_s, "%Y-%m-%d").date() if due_date_s else None
    dtime = datetime.strptime(due_time_s, "%H:%M").time() if due_time_s else None

    t = Task(
        title=title,
        description=description,
        due_date=ddate,
        due_time=dtime,
        assignee_id=int(assignee_id) if assignee_id else None,
    )
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or "").strip() or None

    due_date_s = request.form.get("due_date") or ""
    due_time_s = request.form.get("due_time") or ""
    t.due_date = datetime.strptime(due_date_s, "%Y-%m-%d").date() if due_date_s else None
    t.due_time = datetime.strptime(due_time_s, "%H:%M").time() if due_time_s else None

    assignee_id = request.form.get("assignee_id") or ""
    t.assignee_id = int(assignee_id) if assignee_id else None

    status = request.form.get("status")
    if status in ("open", "done"):
        t.status = status
        if status == "done":
            t.progress = 100
            t.completed_at = datetime.utcnow()
        else:
            t.progress = 0
            t.completed_at = None

    db.session.commit()
    flash("Η εργασία ενημερώθηκε.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))


# --- Admin: Σημειώσεις χρηστών ---
@app.route("/admin/notes/<int:note_id>/edit", methods=["POST"])
@admin_required
def admin_edit_note(note_id):
    n = Note.query.get_or_404(note_id)
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("admin"))
    n.content = new_content
    db.session.commit()
    flash("Σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    n = Note.query.get_or_404(note_id)
    db.session.delete(n)
    db.session.commit()
    flash("Σημείωση διαγράφηκε.", "info")
    return redirect(url_for("admin"))


# --- Admin: Ομάδες (CRUD + ανάθεση μελών/leader) ---
@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))
        db.session.add(Team(name=name))
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("teams_manage.html", teams=teams, users=users)


@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    t = Team.query.get_or_404(team_id)
    for m in t.members.all():
        m.team_id = None
    db.session.delete(t)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/<int:team_id>/assign", methods=["POST"])
@admin_required
def admin_assign_team(team_id):
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Επέλεξε χρήστη.", "warning")
        return redirect(url_for("admin_teams"))
    u = User.query.get_or_404(user_id)
    u.team_id = team_id
    db.session.commit()
    flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/<int:team_id>/set_leader", methods=["POST"])
@admin_required
def admin_set_leader(team_id):
    user_id = request.form.get("user_id")
    team = Team.query.get_or_404(team_id)
    if not user_id:
        team.leader_id = None
    else:
        u = User.query.get_or_404(user_id)
        team.leader_id = u.id
    db.session.commit()
    flash("Ορίστηκε leader.", "success")
    return redirect(url_for("admin_teams"))


# ---------- Error handlers ----------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def internal(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# ---------- Main (για τοπικό run) ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
