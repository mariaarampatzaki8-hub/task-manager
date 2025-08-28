import os
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy

# --------------- App factory & DB config -----------------

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    # Secret key
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # ---- Database URL (Render Postgres or SQLite fallback) ----
    uri = os.environ.get("DATABASE_URL")  # βάζεις εδώ το External Database URL από Render
    if uri:
        # 1) postgres:// -> postgresql+pg8000://
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql+pg8000://", 1)
        # 2) SSL απαραίτητο στο Render. Το περνάμε ως query param (ΟΧΙ connect_args)
        if "sslmode=" not in uri:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}sslmode=require"
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
        # Τοπικά, απλό SQLite
        db_path = os.path.join(app.instance_path, "app_final.db")
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    return app


app = create_app()
db = SQLAlchemy(app)

# --------------- Models (ΧΩΡΙΣ σύγκρουση με παλιά tables) -----------------
# Χρησιμοποιούμε ονόματα πινάκων tm_* για να μην "χτυπάνε" με ό,τι υπήρχε ήδη.

class Team(db.Model):
    __tablename__ = "tm_teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"), nullable=True)

    leader = db.relationship("User", foreign_keys=[leader_id], backref="leading_team", lazy="joined")


class User(db.Model):
    __tablename__ = "tm_users"
    id = db.Column(db.Integer, primary_key=True)
    # Προαιρετικό πλήρες όνομα για εμφάνιση
    name = db.Column(db.String(200), nullable=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(240), nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey("tm_teams.id"), nullable=True)
    color = db.Column(db.String(16), nullable=True)

    team = db.relationship("Team", foreign_keys=[team_id], backref="members", lazy="joined")


class Task(db.Model):
    __tablename__ = "tm_tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="open", nullable=False)  # open | done
    progress = db.Column(db.Integer, default=0, nullable=False)        # 0..100
    due_date = db.Column(db.Date, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("tm_users.id"), nullable=True)
    team_id = db.Column(db.Integer, db.ForeignKey("tm_teams.id"), nullable=True)

    assignee = db.relationship("User", foreign_keys=[assignee_id], lazy="joined")
    team = db.relationship("Team", foreign_keys=[team_id], lazy="joined")


# --------------- Helpers: session & permissions -----------------

def current_user():
    """Επιστρέφει τον τρέχοντα χρήστη (mock) ή None."""
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

# --------------- One-time init/seed (ασφαλές σε πολλαπλούς workers) --------

def safe_seed():
    """
    Δημιουργεί πίνακες & βασικά δεδομένα αν δεν υπάρχουν:
    - Default Team
    - Admin χρήστης (username=admin)
    """
    with app.app_context():
        db.create_all()

        default = Team.query.filter_by(name="Default Team").first()
        if not default:
            default = Team(name="Default Team")
            db.session.add(default)
            db.session.commit()

        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                name="Admin",
                username="admin",
                email="admin@example.com",
                is_admin=True,
                team=default,
                color="#3273dc",
            )
            db.session.add(admin)
            db.session.commit()
safe_seed()

# --------------- Health & root -----------------

@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/", methods=["GET"])
def index():
    # Αρχική (login φόρμα)
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# --------------- Auth (mock login) -----------------
# Για απλότητα: username=admin => admin, αλλιώς user.
# Μπορούμε μετά να το κάνουμε πραγματικό auth με hash κ.λπ.

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    # Αν υπάρχει ήδη στη νέα tm_users, χρησιμοποίησέ τον
    user = User.query.filter_by(username=username).first()
    if not user:
        # Αν δεν υπάρχει, φτιάξε απλό user στη default ομάδα (γρήγορο onboarding)
        default = Team.query.filter_by(name="Default Team").first()
        user = User(username=username, name=username, is_admin=(username=="admin"), team=default)
        db.session.add(user)
        db.session.commit()

    session["uid"] = user.id
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# --------------- Dashboard -----------------

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    # Μικρό status ping για να φαίνεται και στο UI
    health = "ok"
    return render_template("dashboard.html", user=u, health=health)

# --------------- Progress (πίνακας προόδου) -----------------

@app.route("/progress", methods=["GET"])
@login_required
def progress_view():
    """
    Δείχνει συνοπτικά προόδους από τις tm_tasks.
    - total, done, open, avg progress
    """
    tasks = Task.query.all()
    total = len(tasks)
    done = len([t for t in tasks if t.status == "done"])
    open_cnt = len([t for t in tasks if t.status != "done"])
    avg = int(sum(t.progress for t in tasks) / total) if total else 0

    # Αν θες ανα χρήστη:
    rows = []
    users = User.query.order_by(User.username.asc()).all()
    for u in users:
        tu = [t for t in tasks if t.assignee_id == u.id]
        if not tu:
            rows.append({"user": u, "total": 0, "done": 0, "open": 0, "avg": 0})
            continue
        tot = len(tu)
        dn = len([t for t in tu if t.status == "done"])
        op = tot - dn
        av = int(sum(t.progress for t in tu) / tot)
        rows.append({"user": u, "total": tot, "done": dn, "open": op, "avg": av})

    return render_template("progress.html",
                           total=total, done=done, open=open_cnt, avg=avg, rows=rows)

# --------------- Teams -----------------

@app.route("/teams", methods=["GET"])
@login_required
def teams():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# --------------- Admin area -----------------

@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_add_user():
    username = (request.form.get("username") or "").strip()
    name = (request.form.get("name") or "").strip() or username
    email = (request.form.get("email") or "").strip() or None
    is_admin = True if request.form.get("is_admin") == "on" else False
    team_id = request.form.get("team_id")

    if not username:
        flash("Username υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    team = Team.query.get(team_id) if team_id else Team.query.filter_by(name="Default Team").first()
    user = User(username=username, name=name, email=email, is_admin=is_admin, team=team)
    db.session.add(user)
    db.session.commit()
    flash("Ο χρήστης δημιουργήθηκε.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        leader_id = request.form.get("leader_id")
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))
        if Team.query.filter_by(name=name).first():
            flash("Υπάρχει ήδη ομάδα με αυτό το όνομα.", "danger")
            return redirect(url_for("admin_teams"))
        team = Team(name=name)
        if leader_id:
            leader = User.query.get(leader_id)
            if leader:
                team.leader_id = leader.id
        db.session.add(team)
        db.session.commit()
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = Team.query.order_by(Team.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_teams.html", teams=teams, users=users)

# --------------- Catalog / Board / Directory / Help / Settings -----------------

@app.route("/catalog")
@login_required
def catalog():
    # Ελεύθερη σελίδα περιεχομένου (ταιριάζει στο template σου)
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template("catalog.html", tasks=tasks)

@app.route("/board")
@login_required
def board():
    # Μπορείς να το δέσεις με Kanban αργότερα
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Leaders βλέπουν μόνο την ομάδα τους (εκτός admin)
    if not (u and u.is_admin):
        if u and u.team_id:
            users = User.query.filter(User.team_id == u.team_id).order_by(User.username.asc()).all()
        else:
            users = []
    else:
        users = User.query.order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# --------------- Error handlers -----------------

@app.errorhandler(404)
def not_found(e):
    # Το error.html σου πρέπει να κάνει extend το base.html
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# --------------- Local dev (Render τρέχει με gunicorn) -----------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
