import os
import secrets
from datetime import datetime, date, time

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App & DB ----------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # --- DB config (Postgres αν υπάρχει DATABASE_URL, αλλιώς SQLite fallback) ---
    db_path = os.path.join(app.instance_path, "app_final.db")
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # 1) postgres:// → postgresql://
        uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) Χρήση driver pg8000
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        # 3) SSL για Render Postgres
        if "?" in uri:
            if "ssl=" not in uri and "sslmode=" not in uri:
                uri += "&ssl=true"
        else:
            uri += "?ssl=true"

        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
            "connect_args": {"ssl": True},  # για pg8000
        }
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app

app = create_app()
db  = SQLAlchemy(app)

# ---------- Models ----------

class Team(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(200), nullable=False, unique=True)
    leader_id= db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    members  = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader   = relationship("User", foreign_keys=[leader_id], uselist=False)

class User(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(200), nullable=False)
    username  = db.Column(db.String(200), nullable=False, unique=True)
    email     = db.Column(db.String(200), nullable=True, unique=False)
    phone     = db.Column(db.String(50),  nullable=True)
    id_number = db.Column(db.String(50),  nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    token     = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    color     = db.Column(db.String(20), nullable=True, default="#3273dc")

    is_admin  = db.Column(db.Boolean, default=False, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)

    team_id   = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tasks   = relationship("Task", backref="assignee", foreign_keys="Task.assignee_id", lazy="dynamic")
    notes   = relationship("Note", backref="author", foreign_keys="Note.user_id", lazy="dynamic")

    # helpers
    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status      = db.Column(db.String(20), default="open")  # open|done
    progress    = db.Column(db.Integer, default=0)          # 0..100

    due_date    = db.Column(db.String(20), nullable=True)   # απλό string για ευκολία
    due_time    = db.Column(db.String(20), nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    team_id     = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at= db.Column(db.DateTime, nullable=True)

class Note(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content   = db.Column(db.Text, nullable=False)
    created_at= db.Column(db.DateTime, default=datetime.utcnow)
    updated_at= db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ---------- Helpers / decorators ----------

def current_user():
    uid = session.get("uid")
    if not uid: return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u.is_admin:
            flash("Δεν επιτρέπεται.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **kw)
    return wrapper

def leader_or_admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("index"))
        if u.is_admin:
            return fn(*a, **kw)
        # leader: αν είναι leader κάποιας ομάδας
        is_leader = Team.query.filter_by(leader_id=u.id).count() > 0
        if not is_leader:
            flash("Δεν επιτρέπεται.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **kw)
    return wrapper

# ---------- Init DB & seed admin ----------

@app.before_first_request
def init_db_and_seed():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            name="Admin",
            username="admin",
            email=None,
            is_admin=True,
            color="#3273dc"
        )
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Δημιουργήθηκε Admin με username=admin και password=admin123")

    # κάθε boot γράφουμε προσωρινό login link στα logs
    magic = secrets.token_urlsafe(8)
    session_key = f"adm:{magic}"
    app.config["ADM_LINK"] = f"/login/{magic}"
    app.logger.info("== Admin login links ==")
    app.logger.info("Admin: %s", app.config["ADM_LINK"])
    app.logger.info("== End admin links ==")

# ---------- Routes: Auth ----------

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    u = User.query.filter_by(username=username).first()
    if not u or not u.check_password(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("admin" if u.is_admin else "dashboard"))

# magic link (εμφανίζεται στα logs)
@app.route("/login/<token>")
def login_token(token):
    u = User.query.filter_by(token=token).first()
    if not u:
        flash("Μη έγκυρο link.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες.", "success")
    return redirect(url_for("admin" if u.is_admin else "dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------- Routes: Dashboard / Tasks / Notes ----------

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()

    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes      = u.notes.order_by(Note.created_at.desc()).all()

    # για καρτέλα «Πρόοδος»
    users = User.query.order_by(User.name.asc()).all()
    user_tasks = {
        usr.id: Task.query.filter_by(assignee_id=usr.id).order_by(Task.status.desc(), Task.id.desc()).all()
        for usr in users
    }

    return render_template("dashboard.html",
                           open_tasks=open_tasks,
                           done_tasks=done_tasks,
                           notes=notes,
                           users=users,
                           user_tasks=user_tasks)

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
        t.progress = 100 if t.progress < 100 else t.progress
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
        t.progress = min(t.progress, 99)
        t.completed_at = None
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/tasks/<int:task_id>/set_progress", methods=["POST"])
@login_required
def set_progress(task_id):
    u = current_user()
    t = Task.query.get_or_404(task_id)
    if t.assignee_id != u.id and not u.is_admin:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    try:
        p = int(request.form.get("progress") or "0")
        p = max(0, min(100, p))
        t.progress = p
        if p == 100:
            t.status = "done"
            t.completed_at = datetime.utcnow()
        elif t.status == "done":
            t.status = "open"
            t.completed_at = None
        db.session.commit()
    except ValueError:
        flash("Μη έγκυρη τιμή προόδου.", "warning")
    return redirect(url_for("dashboard"))

# Notes (user)
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
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Κενό περιεχόμενο.", "warning")
        return redirect(url_for("dashboard"))
    n.content = content
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

# ---------- Public: Πρόοδος (όλοι) ----------

@app.route("/progress")
@login_required
def all_progress():
    users = User.query.order_by(User.name.asc()).all()
    user_tasks = {
        u.id: Task.query.filter_by(assignee_id=u.id).order_by(Task.status.desc(), Task.id.desc()).all()
        for u in users
    }
    return render_template("progress.html", users=users, user_tasks=user_tasks)

# ---------- Teams (list για όλους) & Διαχείριση (admins) ----------

@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

@app.route("/admin/teams")
@admin_required
def admin_teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/teams/create", methods=["POST"])
@admin_required
def admin_create_team():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Όνομα ομάδας απαιτείται.", "warning")
        return redirect(url_for("admin_teams"))
    if Team.query.filter_by(name=name).first():
        flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
        return redirect(url_for("admin_teams"))
    db.session.add(Team(name=name))
    db.session.commit()
    flash("Η ομάδα δημιουργήθηκε.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    t = Team.query.get_or_404(team_id)
    # αποσύνδεσε μέλη
    for m in t.members.all():
        m.team_id = None
    db.session.delete(t)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

@app.route("/admin/assign_team", methods=["POST"])
@admin_required
def admin_assign_team():
    user_id = request.form.get("user_id")
    team_id = request.form.get("team_id") or None
    u = User.query.get_or_404(user_id)
    u.team_id = int(team_id) if team_id else None
    db.session.commit()
    flash("Ενημερώθηκε η ομάδα χρήστη.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/set_team_leader", methods=["POST"])
@admin_required
def admin_set_team_leader():
    team_id = request.form.get("team_id")
    user_id = request.form.get("user_id")
    t = Team.query.get_or_404(team_id)
    u = User.query.get_or_404(user_id)
    if u.team_id != t.id:
        flash("Ο leader πρέπει να είναι μέλος της ομάδας.", "warning")
        return redirect(url_for("admin_teams"))
    t.leader_id = u.id
    db.session.commit()
    flash("Ορίστηκε team leader.", "success")
    return redirect(url_for("admin_teams"))

# ---------- Κατάλογος (Admins & Team Leaders) ----------

@app.route("/directory")
@leader_or_admin_required
def directory():
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# ---------- Admin panel ----------

@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    stats = {
        "users": User.query.count(),
        "tasks": Task.query.count(),
        "open":  Task.query.filter_by(status="open").count(),
        "done":  Task.query.filter_by(status="done").count()
    }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name      = (request.form.get("name") or "").strip()
    username  = (request.form.get("username") or "").strip()
    email     = (request.form.get("email") or "").strip() or None
    phone     = (request.form.get("phone") or "").strip() or None
    idnum     = (request.form.get("id_number") or "").strip() or None
    color     = request.form.get("color") or "#3273dc"
    raw_pw    = (request.form.get("password") or "").strip()
    team_id   = request.form.get("team_id") or None
    make_admin= request.form.get("is_admin") in ("1","on","true","True")

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, phone=phone,
             id_number=idnum, color=color, is_admin=make_admin)
    if team_id:
        try: u.team_id = int(team_id)
        except: pass
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u)
    db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash("Δεν γίνεται να διαγράψεις τον τελευταίο Admin.", "danger")
        return redirect(url_for("admin"))
    # διαγραφή των σημειώσεων και εργασιών του
    for t in u.tasks.all(): db.session.delete(t)
    for n in u.notes.all(): db.session.delete(n)
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = request.form.get("is_admin") in ("1","on","true","True")
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

@app.route("/admin/reset_token", methods=["POST"])
@admin_required
def admin_reset_token():
    user_id = request.form.get("user_id")
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Ανανέωση login link έγινε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/reset_password", methods=["POST"])
@admin_required
def admin_reset_password():
    user_id = request.form.get("user_id")
    new_pw  = request.form.get("new_password") or "changeme123"
    u = User.query.get_or_404(user_id)
    u.set_password(new_pw)
    u.must_change_password = True
    db.session.commit()
    flash("Ο κωδικός άλλαξε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/set_color", methods=["POST"])
@admin_required
def admin_set_color():
    user_id = request.form.get("user_id")
    color   = request.form.get("color") or "#3273dc"
    u = User.query.get_or_404(user_id)
    u.color = color
    db.session.commit()
    flash("Αποθηκεύτηκε χρώμα.", "success")
    return redirect(url_for("admin"))

# Admin: Tasks
@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    due_date = request.form.get("due_date") or ""
    due_time = request.form.get("due_time") or ""
    assignee_id = request.form.get("assignee_id")
    if not title or not assignee_id:
        flash("Τίτλος & χρήστης απαιτούνται.", "warning")
        return redirect(url_for("admin"))
    t = Task(title=title, description=description, assignee_id=int(assignee_id),
             due_date=due_date, due_time=due_time, status="open", progress=0)
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/update", methods=["POST"])
@admin_required
def admin_update_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or t.description) or None
    t.due_date = request.form.get("due_date") or t.due_date
    t.due_time = request.form.get("due_time") or t.due_time
    prog = request.form.get("progress")
    if prog is not None:
        try:
            p = int(prog); p = max(0, min(100, p))
            t.progress = p
            if p == 100:
                t.status = "done"; t.completed_at = datetime.utcnow()
            elif t.status == "done":
                t.status = "open"; t.completed_at = None
        except: pass
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

# Admin: Επεξεργασία σημειώσεων χρηστών
@app.route("/admin/notes/<int:note_id>/edit", methods=["POST"])
@admin_required
def admin_edit_note(note_id):
    n = Note.query.get_or_404(note_id)
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Κενό περιεχόμενο.", "warning")
        return redirect(url_for("admin"))
    n.content = content
    db.session.commit()
    flash("Η σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    n = Note.query.get_or_404(note_id)
    db.session.delete(n)
    db.session.commit()
    flash("Η σημείωση διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# ---------- Settings (χρήστης) ----------

@app.route("/settings")
@login_required
def settings_view():
    return render_template("settings.html", u=current_user())

@app.route("/settings/change_password", methods=["POST"])
@login_required
def settings_change_password():
    u = current_user()
    new_pw = (request.form.get("new_password") or "").strip()
    if len(new_pw) < 6:
        flash("Ο νέος κωδικός πρέπει να έχει ≥6 χαρακτήρες.", "warning")
        return redirect(url_for("settings_view"))
    u.set_password(new_pw)
    u.must_change_password = False
    db.session.commit()
    flash("Ο κωδικός άλλαξε.", "success")
    return redirect(url_for("settings_view"))

# ---------- Οδηγίες ----------

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

# ---------- Error handlers ----------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------- Run (για τοπικό) ----------
if __name__ == "__main__":
    app.run(debug=True)
