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
        # --- DB config (Postgres αν υπάρχει DATABASE_URL, αλλιώς SQLite fallback) ---
    db_path = os.path.join(app.instance_path, "app_final.db")
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # Αν τυχόν ξεκινάει με 'postgres://', αλλάξ’ το σε 'postgresql://'
        uri = uri.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # στοιχεία
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    username = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    id_number = db.Column(db.String(40), nullable=True)   # ΑΔΤ

    # πρόσβαση
    token = db.Column(db.String(64), unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    # εμφάνιση
    color = db.Column(db.String(16), nullable=True)  # hex

    # ομάδα
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

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

    progress = db.Column(db.Integer, default=0)           # 0..100
    status = db.Column(db.String(20), default="open")      # open|done
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
    return User.query.get(uid) if uid else None

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

def admin_or_leader_required(fn):
    """Πρόσβαση για Admin ή για όποιον είναι leader σε κάποια ομάδα."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        if u.is_admin:
            return fn(*args, **kwargs)
        is_leader = Team.query.filter_by(leader_id=u.id).count() > 0
        if is_leader:
            return fn(*args, **kwargs)
        flash("Δεν έχεις δικαίωμα πρόσβασης.", "danger")
        return redirect(url_for("index"))
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}


# ---------- Initial DB & bootstrap admin ----------
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(name="Admin", username="admin", email=None, is_admin=True, color="#111827")
        admin.set_password("admin123")
        admin.token = secrets.token_urlsafe(16)
        db.session.add(admin)
        db.session.commit()
        print("== Δημιουργήθηκε αρχικός Admin: username=admin password=admin123")
    print("== Admin login links ==")
    print("Admin:", f"/login/{admin.token}")
    print("== End admin links ==")


# ---------- Public & Auth ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/help")
def help_page():
    return render_template("help.html")

@app.route("/login/<token>")
def login_token(token):
    u = User.query.filter_by(token=token).first()
    if not u:
        flash("Μη έγκυρο link.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("admin" if u.is_admin else "dashboard"))

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
    return redirect(url_for("admin" if u.is_admin else "dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# ---------- Dashboard / Tasks / Notes (User) ----------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()

    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()

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


# ---------- Κοινή Πρόοδος ----------
@app.route("/progress")
@login_required
def all_progress():
    users = User.query.order_by(User.name.asc()).all()
    user_tasks = {
        u.id: Task.query.filter_by(assignee_id=u.id).order_by(Task.status.desc(), Task.id.desc()).all()
        for u in users
    }
    return render_template("progress.html", users=users, user_tasks=user_tasks)


# ---------- Admin ----------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template("admin.html", users=users, teams=teams, notes=notes, tasks=tasks)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    raw_pw = (request.form.get("password") or "").strip()
    color = request.form.get("color") or "#3273dc"
    make_admin = request.form.get("is_admin") in ("on", "1", "true", "True")
    phone = (request.form.get("phone") or "").strip() or None
    id_number = (request.form.get("id_number") or "").strip() or None
    team_id = request.form.get("team_id")

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if email and User.query.filter_by(email=email).first():
        flash("Το email υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(
        name=name, username=username, email=email, color=color,
        is_admin=make_admin, phone=phone, id_number=id_number
    )
    if team_id:
        try:
            u.team_id = int(team_id)
        except ValueError:
            u.team_id = None

    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)

    db.session.add(u)
    db.session.commit()

    role = " (Admin)" if make_admin else ""
    flash(f"Δημιουργήθηκε χρήστης {name}{role}.", "success")
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

def _parse_dt(due_date_s, due_time_s):
    d = None
    tm = None
    try:
        if due_date_s:
            y, m, dd = map(int, due_date_s.split("-"))
            d = date(y, m, dd)
        if due_time_s:
            hh, mm = map(int, due_time_s.split(":"))
            tm = time(hh, mm)
    except Exception:
        pass
    return d, tm

@app.route("/admin/tasks/<int:task_id>/update", methods=["POST"])
@admin_required
def admin_update_task(task_id):
    tsk = Task.query.get_or_404(task_id)

    tsk.title = (request.form.get("title") or tsk.title).strip()
    tsk.description = (request.form.get("description") or "").strip() or None

    d_s = request.form.get("due_date") or ""
    tm_s = request.form.get("due_time") or ""
    d, tm = _parse_dt(d_s, tm_s)
    tsk.due_date = d
    tsk.due_time = tm

    assignee_id = request.form.get("assignee_id")
    if assignee_id:
        try:
            tsk.assignee_id = int(assignee_id)
        except ValueError:
            pass

    try:
        p = int(request.form.get("progress", tsk.progress or 0))
    except ValueError:
        p = tsk.progress or 0
    p = max(0, min(100, p))
    tsk.progress = p

    status = (request.form.get("status") or tsk.status).strip()
    if status not in ("open", "done"):
        status = "open"
    tsk.status = status
    if status == "done" and not tsk.completed_at:
        tsk.completed_at = datetime.utcnow()
    if status == "open":
        tsk.completed_at = None
        if tsk.progress == 100:
            tsk.progress = 90

    db.session.commit()
    flash("Η εργασία ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    tsk = Task.query.get_or_404(task_id)
    db.session.delete(tsk)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
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

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    me = current_user()
    if u.id == me.id:
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "danger")
        return redirect(url_for("admin"))
    if u.is_admin:
        admins_left = User.query.filter_by(is_admin=True).count()
        if admins_left <= 1:
            flash("Δεν γίνεται να διαγράψεις τον τελευταίο Admin.", "danger")
            return redirect(url_for("admin"))
    name = u.name
    db.session.delete(u)
    db.session.commit()
    flash(f"Ο/Η «{name}» διαγράφηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = (request.form.get("is_admin") in ("1", "on", "true", "True"))
    if make_admin:
        u.is_admin = True
        db.session.commit()
        flash(f"Ο/Η {u.name} έγινε Διαχειριστής.", "success")
        return redirect(url_for("admin"))
    admins_left = User.query.filter_by(is_admin=True).count()
    if u.is_admin and admins_left <= 1:
        flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        return redirect(url_for("admin"))
    u.is_admin = False
    db.session.commit()
    flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))
@app.route("/admin/assign_team", methods=["POST"])
@admin_required
def admin_assign_team():
    """Ανάθεση/αλλαγή ομάδας σε χρήστη από το admin.html."""
    try:
        user_id = int(request.form.get("user_id", 0))
    except ValueError:
        flash("Μη έγκυρα στοιχεία χρήστη.", "danger")
        return redirect(url_for("admin"))
    team_id = request.form.get("team_id")  # μπορεί να είναι "" (καμία ομάδα)

    u = User.query.get_or_404(user_id)
    if team_id:
        try:
            u.team_id = int(team_id)
        except ValueError:
            u.team_id = None
    else:
        u.team_id = None

    # Αν ήταν leader σε άλλη ομάδα και τον βγάζουμε, καθάρισε leader αν χρειάζεται
    t_lead = Team.query.filter_by(leader_id=u.id).first()
    if t_lead and (u.team_id != t_lead.id):
        t_lead.leader_id = None

    db.session.commit()
    flash("Η ομάδα του χρήστη ενημερώθηκε.", "success")
    return redirect(url_for("admin"))

# ---------- Teams ----------
# Δημόσια (για όλους τους συνδεδεμένους): λίστα ομάδων (read-only)
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams, users=[])

# Διαχείριση ομάδων (admin μόνο)
@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if name:
            if Team.query.filter_by(name=name).first():
                flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "warning")
            else:
                team = Team(name=name)
                db.session.add(team)
                db.session.commit()
                flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc()).all()
    return render_template("teams.html", teams=teams, users=users)

# Ενημέρωση ονόματος & leader
@app.route("/admin/teams/<int:team_id>/update", methods=["POST"])
@admin_required
def admin_update_team(team_id):
    team = Team.query.get_or_404(team_id)
    team.name = (request.form.get("name") or team.name).strip()
    leader_id = request.form.get("leader_id")
    if leader_id:
        try:
            team.leader_id = int(leader_id)
        except ValueError:
            team.leader_id = None
    else:
        team.leader_id = None
    db.session.commit()
    flash("Η ομάδα ενημερώθηκε.", "success")
    return redirect(url_for("admin_teams"))

# Διαγραφή ομάδας
@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    for u in team.members:
        u.team_id = None
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

# Προσθήκη μέλους σε ομάδα
@app.route("/admin/teams/<int:team_id>/add_member", methods=["POST"])
@admin_required
def admin_team_add_member(team_id):
    team = Team.query.get_or_404(team_id)
    try:
        user_id = int(request.form.get("user_id", 0))
    except ValueError:
        flash("Μη έγκυρα στοιχεία.", "danger")
        return redirect(url_for("admin_teams"))
    u = User.query.get_or_404(user_id)
    u.team_id = team.id
    db.session.commit()
    flash(f"Ο/Η {u.name} προστέθηκε στην ομάδα «{team.name}».", "success")
    return redirect(url_for("admin_teams"))

# Αφαίρεση μέλους από ομάδα
@app.route("/admin/teams/<int:team_id>/remove_member/<int:user_id>", methods=["POST"])
@admin_required
def admin_team_remove_member(team_id, user_id):
    team = Team.query.get_or_404(team_id)
    u = User.query.get_or_404(user_id)
    if u.team_id == team.id:
        u.team_id = None
        if team.leader_id == u.id:
            team.leader_id = None
        db.session.commit()
        flash(f"Ο/Η {u.name} αφαιρέθηκε από την ομάδα «{team.name}».", "info")
    return redirect(url_for("admin_teams"))


# ---------- Directory (Admins & Leaders) ----------
@app.route("/directory")
@admin_or_leader_required
def directory():
    users = User.query.order_by(User.name.asc()).all()
    teams = {t.id: t for t in Team.query.all()}
    return render_template("directory.html", users=users, teams=teams)


# ---------- Error handlers ----------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Η σελίδα δεν βρέθηκε."), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# if __name__ == "__main__":
#     app.run(debug=True)
