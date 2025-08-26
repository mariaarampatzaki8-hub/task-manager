import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


# ================== App & DB ==================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # Instance folder (SQLite fallback file)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    # DATABASE_URL από Render (Postgres) ή fallback SQLite
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # 1) postgres:// -> postgresql://
        uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) Driver pg8000
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        # 3) SSL (Render Postgres)
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
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)


# ================== Models ==================
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255))
    token = db.Column(db.String(100))  # magic login link seed
    is_admin = db.Column(db.Boolean, default=False)
    is_leader = db.Column(db.Boolean, default=False)

    color = db.Column(db.String(20), default="#3273dc")
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"))

    notes = relationship("Note", backref="user", lazy="dynamic")
    tasks = relationship("Task", backref="assignee", lazy="dynamic")

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, pw)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="open")  # open|done
    progress = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


# ================== Helpers ==================
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            flash("Χρειάζεται σύνδεση.", "warning")
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
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper

def admin_or_leader_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not (u.is_admin or u.is_leader):
            flash("Δεν επιτρέπεται.", "danger")
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper


# ================== Init DB & seed admin ==================
@app.before_request
def init_db_and_seed():
    if getattr(app, "_db_initialized", False):
        return
    try:
        db.create_all()

        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                name="Admin",
                username="admin",
                is_admin=True,
                color="#3273dc",
            )
            admin.set_password("admin123")
            admin.token = secrets.token_urlsafe(16)
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Δημιουργήθηκε Admin (admin/admin123).")

        magic = secrets.token_urlsafe(8)
        app.config["ADM_LINK"] = f"/login/{magic}"
        app.logger.info("== Admin login links ==")
        app.logger.info("Admin: %s", app.config["ADM_LINK"])
        app.logger.info("== End admin links ==")
    except Exception:
        app.logger.exception("DB init/seed failed")
    finally:
        app._db_initialized = True


# Healthcheck
@app.route("/healthz")
def healthz():
    return "ok", 200


# ================== Auth ==================
@app.route("/")
def index():
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
    return redirect(url_for("dashboard"))

# προσωρινό login link για admin από logs
@app.route("/login/<magic>")
def login_magic(magic):
    if magic != app.config.get("ADM_LINK", "/x"):
        abort(404)
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        abort(404)
    session["uid"] = admin.id
    flash("Συνδέθηκες ως admin.", "success")
    return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# ================== User Dashboard / Tasks / Notes ==================
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()

    # για την καρτέλα προόδου (sidebar συνοπτικά)
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
        t.progress = 100 if t.progress < 100 else t.progress
        t.completed_at = datetime.utcnow()
    else:
        t.status = "open"
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
    if n.user_id != u.id:
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
    if n.user_id != u.id:
        flash("Δεν επιτρέπεται.", "danger")
        return redirect(url_for("dashboard"))
    db.session.delete(n)
    db.session.commit()
    flash("Η σημείωση διαγράφηκε.", "info")
    return redirect(url_for("dashboard"))


# ================== Progress (όλοι βλέπουν όλους) ==================
@app.route("/progress")
@login_required
def progress():
    users = User.query.order_by(User.name.asc()).all()
    data = []
    for usr in users:
        total = Task.query.filter_by(assignee_id=usr.id).count()
        done = Task.query.filter_by(assignee_id=usr.id, status="done").count()
        pct = int(100 * done / total) if total else 0
        last_done = Task.query.filter_by(assignee_id=usr.id, status="done") \
                              .order_by(Task.completed_at.desc()).first()
        data.append({
            "user": usr,
            "total": total,
            "done": done,
            "pct": pct,
            "last_done": (last_done.completed_at if last_done else None)
        })
    return render_template("progress.html", data=data)


# ================== Settings (χρήστης) ==================
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    u = current_user()
    if request.method == "POST":
        new_color = (request.form.get("color") or u.color).strip() or u.color
        u.color = new_color

        new_pw = (request.form.get("new_password") or "").strip()
        if new_pw:
            u.set_password(new_pw)
            flash("Ο κωδικός άλλαξε.", "success")
        db.session.commit()
        flash("Οι ρυθμίσεις αποθηκεύτηκαν.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", user=u)


# ================== Catalog (Admin & Leaders) ==================
@app.route("/catalog")
@admin_or_leader_required
def catalog():
    users = User.query.order_by(User.name.asc()).all()
    return render_template("catalog.html", users=users)


# ================== Teams (δημόσια λίστα) ==================
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)


# ================== Admin: Users / Tasks / Teams / Notes ==================
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    # Στατιστικά απλά
    stats = {
        "users": User.query.count(),
        "tasks": Task.query.count(),
        "done": Task.query.filter_by(status="done").count(),
        "open": Task.query.filter_by(status="open").count(),
    }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes, teams=teams)

# --- Users ---
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or None)
    phone = (request.form.get("phone") or "").strip() or None
    id_number = (request.form.get("id_number") or "").strip() or None
    color = (request.form.get("color") or "#3273dc").strip()
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
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Δεν γίνεται διαγραφή του βασικού admin.", "danger")
        return redirect(url_for("admin"))
    # διαγραφή και σχετικών
    Task.query.filter_by(assignee_id=u.id).delete()
    Note.query.filter_by(user_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/reset_token", methods=["POST"])
@admin_required
def admin_reset_token(user_id):
    u = User.query.get_or_404(user_id)
    u.token = secrets.token_urlsafe(16)
    db.session.commit()
    flash("Ανανέωση link (token) ολοκληρώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/set_admin", methods=["POST"])
@admin_required
def admin_set_admin(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = request.form.get("is_admin") in ("1", "on", "true", "True")
    if make_admin:
        u.is_admin = True
        db.session.commit()
        flash(f"Ο/Η {u.name} έγινε Διαχειριστής.", "success")
    else:
        # διασφάλισε ότι μένει τουλάχιστον ένας admin
        admins_left = User.query.filter_by(is_admin=True).count()
        if u.is_admin and admins_left <= 1:
            flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        else:
            u.is_admin = False
            db.session.commit()
            flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/set_leader", methods=["POST"])
@admin_required
def admin_set_leader(user_id):
    u = User.query.get_or_404(user_id)
    make_leader = request.form.get("is_leader") in ("1", "on", "true", "True")
    u.is_leader = bool(make_leader)
    db.session.commit()
    flash("Ρόλος leader ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

# --- Tasks (admin) ---
@app.route("/admin/create_task", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    assignee_id = request.form.get("assignee_id") or None
    if not title or not assignee_id:
        flash("Τίτλος και ανάθεση είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))
    t = Task(title=title, description=description, assignee_id=int(assignee_id), status="open", progress=0)
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or t.description).strip()
    new_status = (request.form.get("status") or t.status).strip()
    t.status = new_status if new_status in ("open", "done") else t.status
    try:
        t.progress = max(0, min(100, int(request.form.get("progress", t.progress))))
    except Exception:
        pass
    if t.status == "done" and not t.completed_at:
        t.completed_at = datetime.utcnow()
    if t.status == "open":
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

# --- Notes (admin μπορεί να επεξεργαστεί/σβήσει σημειώσεις χρηστών) ---
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

# --- Teams (admin) ---
@app.route("/admin/teams")
@admin_required
def admin_teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/teams/create", methods=["POST"])
@admin_required
def admin_teams_create():
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

@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_teams_delete(team_id):
    team = Team.query.get_or_404(team_id)
    # Αφαίρεσε team από μέλη
    for m in team.members.all():
        m.team_id = None
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/set_leader", methods=["POST"])
@admin_required
def admin_teams_set_leader(team_id):
    team = Team.query.get_or_404(team_id)
    leader_id = request.form.get("leader_id") or None
    if not leader_id:
        team.leader_id = None
    else:
        leader = User.query.get(int(leader_id))
        if not leader:
            flash("Άκυρος χρήστης.", "danger")
            return redirect(url_for("admin_teams"))
        team.leader_id = leader.id
        leader.is_leader = True
    db.session.commit()
    flash("Ο leader ορίστηκε.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/add_member", methods=["POST"])
@admin_required
def admin_teams_add_member(team_id):
    team = Team.query.get_or_404(team_id)
    user_id = request.form.get("user_id")
    u = User.query.get(int(user_id))
    if not u:
        flash("Άκυρος χρήστης.", "danger")
        return redirect(url_for("admin_teams"))
    u.team_id = team.id
    db.session.commit()
    flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/remove_member/<int:user_id>", methods=["POST"])
@admin_required
def admin_teams_remove_member(team_id, user_id):
    team = Team.query.get_or_404(team_id)
    u = User.query.get_or_404(user_id)
    if u.team_id != team.id:
        flash("Ο χρήστης δεν είναι σε αυτή την ομάδα.", "warning")
        return redirect(url_for("admin_teams"))
    u.team_id = None
    if team.leader_id == u.id:
        team.leader_id = None
        u.is_leader = False
    db.session.commit()
    flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
    return redirect(url_for("admin_teams"))


# ================== Οδηγίες ==================
@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")


# ================== Error Handlers ==================
@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def err_500(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500
