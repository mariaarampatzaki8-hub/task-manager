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

# ================== App & DB ==================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # Instance folder (SQLite fallback file lives here)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app_final.db")

    # Render Postgres via DATABASE_URL (else SQLite fallback)
    uri = os.environ.get("DATABASE_URL")  # e.g. postgresql://... from Render

    if uri:
        # 1) heroku-style -> official
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) force pg8000 driver
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        # 3) ensure sslmode=require (pg8000 δέχεται από το URL)
        if "sslmode=" not in uri:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}sslmode=require"

        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
        # Fallback σε SQLite για τοπική ανάπτυξη
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    # engine options
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True
    }
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
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=True, unique=False)
    phone = db.Column(db.String(50), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(16), default="#3273dc")

    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # optional link to own leader

    token = db.Column(db.String(40), nullable=True, unique=False)

    notes = relationship("Note", backref="user", lazy="dynamic")
    tasks = relationship("Task", backref="assignee", lazy="dynamic")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(220), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)        # 0..100
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.String(10), nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ================== Helpers ==================

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

# ================== DB init (once) ==================

_DB_READY = False

@app.before_request
def init_db_and_seed():
    global _DB_READY
    if _DB_READY:
        return
    try:
        db.create_all()
    except Exception as e:
        app.logger.error("DB init/seed failed: %s", e)
        # Μην σταματήσεις το request, ας προσπαθήσει ξανά στο επόμενο
        return
    # seed admin
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
        app.logger.info("Δημιουργήθηκε Admin (username=admin / password=admin123)")

    # γράψε προσωρινό admin login link στα logs (όπως παλιά)
    magic = secrets.token_urlsafe(8)
    app.config["ADM_LINK"] = f"/login/{magic}"
    app.logger.info("== Admin login links ==")
    app.logger.info("Admin: %s", app.config["ADM_LINK"])
    app.logger.info("== End admin links ==")

    _DB_READY = True

# ================== Routes: Auth ==================

@app.route("/")
def index():
    # απλή σελίδα login
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def do_login():
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

# Προσωρινός link login (γράφεται στα logs στο boot)
@app.route("/login/<magic>")
def magic_login(magic):
    link = app.config.get("ADM_LINK")
    # απλός (μη αυστηρός) έλεγχος ώστε να δουλέψει μόνο το τρέχον link boot
    if not link or not link.endswith(magic):
        return redirect(url_for("index"))
    u = User.query.filter_by(username="admin").first()
    if not u:
        return redirect(url_for("index"))
    session["uid"] = u.id
    flash("Συνδέθηκες (admin link).", "info")
    return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ================== Dashboard / Tasks / Notes ==================

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    open_tasks = Task.query.filter_by(assignee_id=u.id, status="open").order_by(Task.id.desc()).all()
    done_tasks = Task.query.filter_by(assignee_id=u.id, status="done").order_by(Task.completed_at.desc()).all()
    notes = u.notes.order_by(Note.created_at.desc()).all()
    return render_template("dashboard.html",
                           open_tasks=open_tasks,
                           done_tasks=done_tasks,
                           notes=notes)

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

@app.route("/me/add_note", methods=["POST"])
@login_required
def me_add_note():
    u = current_user()
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("dashboard"))
    db.session.add(Note(content=content, user_id=u.id))
    db.session.commit()
    flash("Η σημείωση αποθηκεύτηκε.", "success")
    return redirect(url_for("dashboard"))

# ================== Progress (ορατό σε όλους) ==================

@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress_view():
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        # μέσος όρος progress στα tasks του χρήστη
        avg_prog = db.session.query(db.func.avg(Task.progress)).filter(Task.assignee_id == u.id).scalar() or 0
        rows.append({
            "user": u,
            "total": total,
            "done": done,
            "open": open_cnt,
            "avg": int(round(avg_prog)),
        })
    return render_template("progress.html", rows=rows)

# ================== Teams (list for all) ==================

@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# ================== Admin panel ==================

@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    users = User.query.order_by(User.name.asc()).all()
    # Στατιστικά ανά χρήστη για admin.html
    stats = {}
    for u in users:
        total = u.tasks.count()
        done = u.tasks.filter_by(status="done").count()
        open_cnt = u.tasks.filter_by(status="open").count()
        stats[u.id] = {
            "total": total,
            "done": done,
            "open": open_cnt,
            "last_done": u.tasks.filter_by(status="done").order_by(Task.completed_at.desc()).first()
        }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

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
    if email and User.query.filter_by(email=email).first():
        flash("Το email υπάρχει ήδη.", "danger")
        return redirect(url_for("admin"))

    u = User(name=name, username=username, email=email, phone=phone, id_number=id_number, color=color)
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

    ddate = None
    if due_date_s:
        try:
            y, m, d = [int(x) for x in due_date_s.split("-")]
            ddate = date(y, m, d)
        except Exception:
            ddate = None

    t = Task(title=title, description=description, due_date=ddate, due_time=due_time_s or None,
             assignee_id=int(assignee_id) if assignee_id else None)
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.title = (request.form.get("title") or t.title).strip()
    t.description = (request.form.get("description") or t.description) or None
    t.status = request.form.get("status") or t.status
    try:
        t.progress = max(0, min(100, int(request.form.get("progress", t.progress))))
    except Exception:
        pass
    assignee_id = request.form.get("assignee_id")
    t.assignee_id = int(assignee_id) if assignee_id else None
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

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash("Δεν γίνεται να διαγραφεί ο τελευταίος Admin.", "danger")
        return redirect(url_for("admin"))
    # delete tasks & notes of user
    Task.query.filter_by(assignee_id=u.id).delete()
    Note.query.filter_by(user_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
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
    # remove admin
    admins_left = User.query.filter_by(is_admin=True).count()
    if u.is_admin and admins_left <= 1:
        flash("Δεν γίνεται να αφαιρέσεις τον τελευταίο Admin.", "danger")
        return redirect(url_for("admin"))
    u.is_admin = False
    db.session.commit()
    flash(f"Ο/Η {u.name} έγινε απλός χρήστης.", "info")
    return redirect(url_for("admin"))

# -------- Admin: edit/delete notes (ώστε admin να διορθώνει) --------

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

# -------- Admin: Teams CRUD & assignment --------

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
    return render_template("admin_teams.html", teams=teams, users=users)

@app.route("/admin/assign_team", methods=["POST"])
@admin_required
def admin_assign_team():
    user_id = request.form.get("user_id")
    team_id = request.form.get("team_id")
    leader = (request.form.get("leader") in ("1", "on", "true", "True"))
    u = User.query.get_or_404(user_id)
    t = Team.query.get_or_404(team_id)
    u.team_id = t.id
    db.session.commit()
    if leader:
        t.leader_id = u.id
        db.session.commit()
    flash("Ενημέρωση ομάδας χρήστη ολοκληρώθηκε.", "success")
    return redirect(url_for("admin_teams"))

# ================== Directory (admins & leaders) ==================

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # leaders βλέπουν τον κατάλογο, εκτός από admin φυσικά
    if not (u.is_admin or (u.team_id and u.id == (u.team.leader_id if u.team else None))):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# ================== Help / Settings / Instructions ==================

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")

@app.route("/instructions")
@login_required
def instructions_page():
    return render_template("instructions.html")

# ================== Error handlers ==================

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # Μη δείχνεις stacktrace σε production
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ================== Gunicorn entry ==================
# (Render τρέχει: gunicorn app:app)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
