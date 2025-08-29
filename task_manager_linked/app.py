# app.py
import os, secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# App
# -------------------------------------------------
app = Flask(
    __name__,
    instance_relative_config=True,
    template_folder="templates",
    static_folder="static",
)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))
os.makedirs(app.instance_path, exist_ok=True)

# -------------------------------------------------
# DB CONFIG (Render Postgres via pg8000 ή SQLite fallback)
# -------------------------------------------------
def build_db_uri() -> str:
    uri = (os.environ.get("DATABASE_URL") or "").strip()
    if not uri:
        # τοπικό fallback
        return "sqlite:///" + os.path.join(app.instance_path, "site.db")
    # Μετατροπή για SQLAlchemy + pg8000
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
    elif uri.startswith("postgresql://") and "+pg8000" not in uri:
        uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
    return uri

app.config["SQLALCHEMY_DATABASE_URI"] = build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------------------------------------------------
# Models (prefix tm_*)
# -------------------------------------------------
class Team(db.Model):
    __tablename__ = "tm_teams"
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"), nullable=True)

class User(db.Model):
    __tablename__ = "tm_users"

    id            = db.Column(db.Integer, primary_key=True)
    # Ονοματεπώνυμο
    name          = db.Column(db.String(200), nullable=False)  
    # Μοναδικό username (login)
    username      = db.Column(db.String(120), unique=True, nullable=False)
    # Email, Τηλέφωνο, ΑΔΤ
    email         = db.Column(db.String(200))
    phone         = db.Column(db.String(50))
    id_card       = db.Column(db.String(50))
    # Κωδικός (hashed)
    password_hash = db.Column(db.String(255), nullable=False)
    # Σημαία admin
    is_admin      = db.Column(db.Boolean, default=False, nullable=False)
    # Προσωπικό χρώμα
    color         = db.Column(db.String(20), default="#3273dc")
    # Ομάδα
    team_id       = db.Column(db.Integer, db.ForeignKey("tm_teams.id"), nullable=True)
    # Ημερομηνία δημιουργίας
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # -------- Helpers για password --------
    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    __tablename__ = "tm_tasks"
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    status      = db.Column(db.String(20), default="open")   # open|done
    progress    = db.Column(db.Integer, default=0)           # 0..100
    assignee_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# -------------------------------------------------
# Bootstrap / Seed + ασφαλές auto-migration
# -------------------------------------------------
def bootstrap_db():
    db.create_all()

    # safe, idempotent migrations (για Render που κρατάει παλιό schema)
    with db.engine.begin() as conn:
        conn.execute(text("ALTER TABLE tm_users ADD COLUMN IF NOT EXISTS name VARCHAR(200)"))
        conn.execute(text("ALTER TABLE tm_users ADD COLUMN IF NOT EXISTS phone VARCHAR(50)"))
        conn.execute(text("ALTER TABLE tm_users ADD COLUMN IF NOT EXISTS id_card VARCHAR(50)"))

    # default team
    team = Team.query.filter_by(name="Default Team").first()
    if not team:
        team = Team(name="Default Team")
        db.session.add(team)
        db.session.commit()

    # admin user
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            name="Administrator",
            email="admin@example.com",
            is_admin=True,
            color="#ff4444",
            team_id=team.id,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    bootstrap_db()

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*a, **k)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return wrapper
def is_leader(user: "User") -> bool:
    if not user:
        return False
    return db.session.query(Team.id).filter(Team.leader_id == user.id).first() is not None

@app.context_processor
def inject_user():
    u = current_user()
    return {
        "user": u,
        "is_leader": is_leader(u) if u else False,
    }
# κοινό helper (βάλε το ψηλά, δίπλα στα άλλα helpers)
def build_user_maps():
    users = User.query.all()
    user_map    = {u.id: (u.name or u.username or f"user#{u.id}") for u in users}
    user_colors = {u.id: (u.color or "#3273dc") for u in users}
    user_objs   = {u.id: u for u in users}
    return user_map, user_colors, user_objs
    
# -------------------------------------------------
# Health / Diag
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/__diag")
def __diag():
    insp = inspect(db.engine)
    data = {
        "tables": insp.get_table_names(),
        "users": db.session.query(User).count(),
        "tasks": db.session.query(Task).count(),
    }
    return (str(data), 200, {"Content-Type": "text/plain"})

@app.route("/_ping")
def _ping():
    return "pong", 200

# -------------------------------------------------
# Auth
# -------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
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
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -------------------------------------------------
# Pages
# -------------------------------------------------

from datetime import datetime

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()

    # Admin βλέπει όλα, αλλιώς μόνο τα δικά του
    if u and u.is_admin:
        tasks = Task.query.order_by(Task.created_at.desc()).all()
    else:
        tasks = (
            Task.query.filter_by(assignee_id=u.id)
            .order_by(Task.created_at.desc())
            .all()
        )

    # ---- Χρήστες/χρώματα από helper ----
    # πρέπει να έχεις ορίσει πιο πάνω:
    # def build_user_maps():
    #     users = User.query.all()
    #     user_map    = {usr.id: usr.username for usr in users}
    #     user_colors = {usr.id: (usr.color or "#3273dc") for usr in users}
    #     user_objs   = {usr.id: usr for usr in users}
    #     return user_map, user_colors, user_objs
    user_map, user_colors, user_objs = build_user_maps()

    # Ομάδες + grouping ανά ομάδα
    teams = Team.query.all()
    team_map = {t.id: t.name for t in teams}

    def team_name_for(task):
        assignee = user_objs.get(task.assignee_id)
        if assignee and assignee.team_id:
            return team_map.get(assignee.team_id, "Χωρίς Ομάδα")
        return "Χωρίς Ομάδα"

    grouped = {}
    for t in tasks or []:
        grouped.setdefault(team_name_for(t), []).append(t)

    total = len(tasks or [])
    done = len([t for t in tasks or [] if t.status == "done"])
    avg = int(sum(t.progress for t in tasks or []) / total) if total else 0

    return render_template(
        "dashboard.html",
        tasks=tasks or [],
        grouped=grouped,
        user_map=user_map,
        user_colors=user_colors,
        total=total,
        done=done,
        avg=avg,
        now=datetime.now(),
    )
    
@app.route("/progress-view")
@login_required
def progress_view():
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0
    return render_template("progress.html", total=total, done=done, avg=avg)

@app.route("/progress", endpoint="progress")
@login_required
def progress_alias():
    return redirect(url_for("progress_view"))

@app.route("/catalog")
@login_required
def catalog():
    from collections import defaultdict
    now = datetime.now()
    now_str = now.strftime("%d/%m/%Y %H:%M")

    # φέρε όλα τα tasks (μπορείς να βάλεις φίλτρα αργότερα)
    tasks = Task.query.order_by(Task.created_at.desc()).all()

    # users map για να δείχνουμε ονόματα
    users = User.query.all()
    user_map = {u.id: (u.username or f"user-{u.id}") for u in users}

    # φέρε teams για να βρούμε ονόματα ομάδων
    teams = {t.id: t.name for t in Team.query.all()}

    # group by team name (ή "Χωρίς Ομάδα")
    grouped = defaultdict(list)
    for t in tasks:
        # βρίσκω την ομάδα του ανατιθέμενου χρήστη
        assignee_team_id = None
        if t.assignee_id and t.assignee_id in [u.id for u in users]:
            # βρίσκω τον χρήστη
            # (πιο αποδοτικά: κάνε user_by_id = {u.id: u} πάνω)
            pass
    # αποδοτικό: χτίζουμε user_by_id μία φορά
    user_by_id = {u.id: u for u in users}

    grouped = defaultdict(list)
    for task in tasks:
        assignee = user_by_id.get(task.assignee_id)
        team_name = teams.get(assignee.team_id) if assignee and assignee.team_id else "Χωρίς Ομάδα"
        grouped[team_name].append(task)

    # υπολογισμοί per team
    team_stats = {}
    for team_name, items in grouped.items():
        total = len(items)
        done = sum(1 for i in items if i.status == "done")
        avg = int(sum(i.progress for i in items) / total) if total else 0
        team_stats[team_name] = {"total": total, "done": done, "avg": avg}

    # συνολικά
    total_all = len(tasks)
    done_all = sum(1 for i in tasks if i.status == "done")
    avg_all = int(sum(i.progress for i in tasks) / total_all) if total_all else 0

    # ταξινόμηση ομάδων αλφαβητικά με “Χωρίς Ομάδα” τελευταία
    sorted_groups = sorted(grouped.items(), key=lambda kv: (kv[0] == "Χωρίς Ομάδα", kv[0].lower()))

    return render_template(
        "catalog.html",
        now_str=now_str,
        groups=sorted_groups,        # λίστα (team_name, [tasks])
        team_stats=team_stats,       # dict με μετρικές ομάδας
        user_map=user_map,
        total=total_all, done=done_all, avg=avg_all,
    )
from datetime import datetime
from sqlalchemy import func

@app.route("/board")
@login_required
def board():
    # Όλοι οι χρήστες -> dict {id: User}
    users_list = User.query.all()
    users = {u.id: u for u in users_list}

    # Όλες οι ομάδες με αλφαβητική σειρά
    teams = Team.query.order_by(Team.name.asc()).all()

    team_buckets = []

    for team in teams:
        # μέλη της συγκεκριμένης ομάδας
        member_ids = [u.id for u in users_list if u.team_id == team.id]

        if member_ids:
            tasks = (Task.query
                     .filter(Task.assignee_id.in_(member_ids))
                     .order_by(Task.created_at.desc())
                     .all())
        else:
            tasks = []

        total = len(tasks)
        done = sum(1 for t in tasks if t.status == "done")
        avg = int(sum(t.progress for t in tasks) / total) if total else 0

        team_buckets.append({
            "team": team,
            "tasks": tasks,
            "stats": {"total": total, "done": done, "avg": avg},
        })

    # Tasks χρηστών χωρίς ομάδα (team_id is None)
    no_team_member_ids = [u.id for u in users_list if u.team_id is None]
    if no_team_member_ids:
        no_team_tasks = (Task.query
                         .filter(Task.assignee_id.in_(no_team_member_ids))
                         .order_by(Task.created_at.desc())
                         .all())
    else:
        no_team_tasks = []

    total_nt = len(no_team_tasks)
    done_nt = sum(1 for t in no_team_tasks if t.status == "done")
    avg_nt = int(sum(t.progress for t in no_team_tasks) / total_nt) if total_nt else 0
    no_team_stats = {"total": total_nt, "done": done_nt, "avg": avg_nt}

    return render_template(
        "board.html",
        team_buckets=team_buckets,
        users=users,                 # ώστε στο template να δουλεύει το users[assignee_id]
        no_team_tasks=no_team_tasks,
        no_team_stats=no_team_stats,
    )
    
@app.route("/tasks", methods=["GET"], endpoint="tasks_list")
@login_required
def tasks_list():
    u = current_user()
    tasks = Task.query.order_by(Task.created_at.desc()).all() if (u and u.is_admin) \
            else Task.query.filter_by(assignee_id=u.id).order_by(Task.created_at.desc()).all()
    users = User.query.all()
    user_map = {usr.id: (usr.name or usr.username) for usr in users}
    return render_template("tasks.html", tasks=tasks, user_map=user_map)

# ---- Update task progress (user ή admin) ----
@app.route("/tasks/<int:task_id>/progress", methods=["POST"])
@login_required
def task_update_progress(task_id):
    t = Task.query.get_or_404(task_id)
    u = current_user()

    # Μόνο ο ανατεθειμένος ή admin μπορούν να αλλάξουν πρόοδο
    if not (u.is_admin or (t.assignee_id == u.id)):
        flash("Δεν έχεις δικαίωμα να ενημερώσεις αυτό το task.", "danger")
        return redirect(url_for("tasks_list"))

    progress_raw = (request.form.get("progress") or "").strip()
    try:
        progress = max(0, min(100, int(progress_raw)))
    except ValueError:
        progress = t.progress

    t.progress = progress
    if progress >= 100:
        t.status = "done"
    elif t.status == "done":
        t.status = "open"

    db.session.commit()
    flash("Η πρόοδος ενημερώθηκε.", "success")
    return redirect(request.referrer or url_for("tasks_list"))


# ---- Toggle done/open (user ή admin) ----
@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def task_toggle(task_id):
    t = Task.query.get_or_404(task_id)
    u = current_user()

    if not (u.is_admin or (t.assignee_id == u.id)):
        flash("Δεν έχεις δικαίωμα για αυτή την ενέργεια.", "danger")
        return redirect(url_for("tasks_list"))

    if t.status == "done":
        t.status = "open"
        if t.progress == 100:
            t.progress = 99
    else:
        t.status = "done"
        t.progress = 100

    db.session.commit()
    flash("Η κατάσταση ενημερώθηκε.", "info")
    return redirect(request.referrer or url_for("tasks_list"))

@app.route("/teams")
@login_required
def teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

@app.route("/directory")
@login_required
def directory():
    # Όλοι οι χρήστες βλέπουν όλα τα μέλη, ομαδοποιημένα ανά ομάδα.
    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.name.asc(), User.username.asc()).all()

    users_by_team = {t.id: [] for t in teams}
    no_team = []
    for u in users:
        if u.team_id and u.team_id in users_by_team:
            users_by_team[u.team_id].append(u)
        else:
            no_team.append(u)

    return render_template(
        "directory.html",
        teams=teams,
        users_by_team=users_by_team,
        no_team=no_team,
    )
    
@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

@app.route("/notes")
@login_required
def notes():
    return render_template("notes.html")

# -------------------------------------------------
# Settings
# -------------------------------------------------
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/settings/profile", methods=["POST"])
@login_required
def update_profile():
    u = current_user()
    u.email   = (request.form.get("email") or "").strip() or None
    u.phone   = (request.form.get("phone") or "").strip() or None
    u.id_card = (request.form.get("id_card") or "").strip() or None
    u.color   = (request.form.get("color") or "").strip() or "#3273dc"
    # Αν θέλεις ο χρήστης να αλλάζει και όνομα:
    if request.form.get("name") is not None:
        u.name = (request.form.get("name") or "").strip() or None
    db.session.commit()
    flash("Το προφίλ ενημερώθηκε.", "success")
    return redirect(url_for("settings"))

@app.route("/settings/password", methods=["POST"])
@login_required
def update_password():
    u = current_user()
    current_pw = (request.form.get("current_password") or "").strip()
    new_pw     = (request.form.get("new_password") or "").strip()
    confirm_pw = (request.form.get("confirm_password") or "").strip()

    if not current_pw or not new_pw or not confirm_pw:
        flash("Συμπλήρωσε όλα τα πεδία.", "warning")
        return redirect(url_for("settings"))
    if not u.check_password(current_pw):
        flash("Λάθος τρέχων κωδικός.", "danger")
        return redirect(url_for("settings"))
    if new_pw != confirm_pw:
        flash("Η επιβεβαίωση δεν ταιριάζει.", "warning")
        return redirect(url_for("settings"))
    if len(new_pw) < 6:
        flash("Ο νέος κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες.", "warning")
        return redirect(url_for("settings"))

    u.set_password(new_pw)
    db.session.commit()
    flash("Ο κωδικός άλλαξε επιτυχώς.", "success")
    return redirect(url_for("settings"))

# -------------------------------------------------
# Admin
# -------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    user_map = {u.id: (u.name or u.username) for u in users}
    return render_template("admin.html", users=users, teams=teams, tasks=tasks, user_map=user_map)

# Δημιουργία χρήστη από admin
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    # πεδία από τη φόρμα
    name     = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()  # προσωρινός κωδικός
    email    = (request.form.get("email") or "").strip() or None
    phone    = (request.form.get("phone") or "").strip() or None
    id_card  = (request.form.get("id_card") or "").strip() or None
    color    = (request.form.get("color") or "").strip() or "#3273dc"
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_id  = request.form.get("team_id") or None

    # βασικοί έλεγχοι
    if not name or not username or not password:
        flash("Ονοματεπώνυμο, username και προσωρινός κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη αυτό το username.", "danger")
        return redirect(url_for("admin"))

    # εύρεση ομάδας (αν έχει δοθεί)
    team = Team.query.get(team_id) if team_id else None

    # δημιουργία χρήστη
    u = User(
        name=name,
        username=username,
        email=email,
        phone=phone,
        id_card=id_card,
        is_admin=is_admin,
        color=color,
        team_id=(team.id if team else None),
    )
    u.set_password(password)  # hash του προσωρινού κωδικού

    db.session.add(u)
    db.session.commit()

    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))
# ------- Admin: ενημέρωση στοιχείων χρήστη -------
@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@admin_required
def admin_update_user(user_id):
    u = User.query.get_or_404(user_id)

    u.email   = (request.form.get("email") or "").strip() or None
    u.phone   = (request.form.get("phone") or "").strip() or None
    u.id_card = (request.form.get("id_card") or "").strip() or None
    u.color   = (request.form.get("color") or "").strip() or "#3273dc"
    u.is_admin = True if request.form.get("is_admin") == "on" else False

    team_id = (request.form.get("team_id") or "").strip()
    u.team_id = int(team_id) if team_id.isdigit() else None

    db.session.commit()
    flash(f"Το προφίλ του χρήστη «{u.username}» ενημερώθηκε.", "success")
    return redirect(url_for("admin"))
    
# ------- Admin: delete user -------
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    me = current_user()
    u = User.query.get_or_404(user_id)

    # Ασφάλεια: μην σβήσεις τον εαυτό σου
    if me.id == u.id:
        flash("Δεν μπορείς να διαγράψεις τον εαυτό σου.", "warning")
        return redirect(url_for("admin"))

    # Ασφάλεια: μην μείνει το σύστημα χωρίς admin
    if u.is_admin:
        other_admin = User.query.filter(User.id != u.id, User.is_admin == True).first()
        if not other_admin:
            flash("Δεν γίνεται να διαγράψεις τον τελευταίο admin.", "danger")
            return redirect(url_for("admin"))

    db.session.delete(u)
    db.session.commit()
    flash(f"Ο χρήστης «{u.username}» διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# ------- Admin: reset password -------
@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)

    temp_pw = secrets.token_urlsafe(8)[:10]
    u.set_password(temp_pw)
    db.session.commit()

    flash(f"Προσωρινός κωδικός για {u.username}: {temp_pw}", "info")
    return redirect(url_for("admin"))
    
# Ομάδες (λίστα/δημιουργία)
@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        leader_username = (request.form.get("leader_username") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))

        team = Team(name=name)
        if leader_username:
            leader = User.query.filter_by(username=leader_username).first()
            if leader:
                team.leader_id = leader.id
        db.session.add(team)
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

# Μέλη ομάδας
@app.route("/admin/teams/<int:team_id>/members", methods=["GET", "POST"])
@admin_required
def admin_team_members(team_id):
    team = Team.query.get_or_404(team_id)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if not username:
            flash("Διάλεξε χρήστη.", "warning")
            return redirect(url_for("admin_team_members", team_id=team_id))
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Ο χρήστης δεν βρέθηκε.", "danger")
            return redirect(url_for("admin_team_members", team_id=team_id))
        user.team_id = team.id
        db.session.commit()
        flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
        return redirect(url_for("admin_team_members", team_id=team_id))

    members = User.query.filter_by(team_id=team.id).order_by(User.username.asc()).all()
    users   = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, users=users)

@app.route("/admin/teams/<int:team_id>/members/<int:user_id>/remove", methods=["POST"])
@admin_required
def admin_team_member_remove(team_id, user_id):
    user = User.query.get_or_404(user_id)
    if user.team_id == team_id:
        user.team_id = None
        db.session.commit()
        flash("Ο χρήστης αφαιρέθηκε από την ομάδα.", "info")
    return redirect(url_for("admin_team_members", team_id=team_id))
# ---------- Admin: ορισμός leader ομάδας ----------
@app.route("/admin/teams/<int:team_id>/leader", methods=["POST"])
@admin_required
def admin_set_leader(team_id):
    team = Team.query.get_or_404(team_id)
    leader_username = (request.form.get("leader_username") or "").strip()
    if not leader_username:
        flash("Δώσε username leader.", "warning")
        return redirect(url_for("admin_teams"))
    leader = User.query.filter_by(username=leader_username).first()
    if not leader:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
        return redirect(url_for("admin_teams"))
    team.leader_id = leader.id
    db.session.commit()
    flash("Ο leader ενημερώθηκε.", "success")
    return redirect(url_for("admin_teams"))

# ---------- Admin: διαγραφή ομάδας ----------
@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)

    # Αποσύνδεση μελών από την ομάδα
    for m in User.query.filter_by(team_id=team.id).all():
        m.team_id = None

    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))

# Tasks από admin
@app.route("/admin/tasks", methods=["POST"])
@admin_required
def admin_create_task():
    title = (request.form.get("title") or "").strip()
    assignee_username = (request.form.get("assignee_username") or "").strip()
    progress_raw = (request.form.get("progress") or "").strip()

    if not title or not assignee_username:
        flash("Τίτλος και Username αναλαμβάνοντος είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin"))

    user = User.query.filter_by(username=assignee_username).first()
    if not user:
        flash("Ο χρήστης δεν βρέθηκε.", "danger")
        return redirect(url_for("admin"))

    try:
        progress = max(0, min(100, int(progress_raw))) if progress_raw else 0
    except ValueError:
        progress = 0

    t = Task(title=title, assignee_id=user.id, status="open", progress=progress)
    db.session.add(t)
    db.session.commit()
    flash("Η εργασία δημιουργήθηκε και ανατέθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/create-task", methods=["GET"])
@admin_required
def create_task_form():
    users = User.query.order_by(User.username.asc()).all()
    return render_template("create_task.html", users=users)

@app.route("/admin/tasks/<int:task_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_task(task_id):
    t = Task.query.get_or_404(task_id)
    t.status = "done" if t.status != "done" else "open"
    if t.status == "done":
        t.progress = 100
    db.session.commit()
    flash("Η κατάσταση της εργασίας ενημερώθηκε.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@admin_required
def admin_delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("admin"))

# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    try:
        return render_template("error.html", code=500, message="Σφάλμα server."), 500
    except Exception:
        return "500 Internal Server Error", 500

# -------------------------------------------------
# Entry
# -------------------------------------------------
if __name__ == "__main__":
    # Το Render τρέχει με gunicorn app:app — το παρακάτω είναι μόνο για τοπικό debug
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
