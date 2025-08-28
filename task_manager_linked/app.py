import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# --------------------------- App factory ---------------------------

def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    # Instance folder (for SQLite fallback file)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "app.db")

    # DATABASE_URL from Render or fallback to SQLite
    uri = os.environ.get("DATABASE_URL")

    if uri:
        # Heroku-style -> official
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # Use pg8000 driver
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)


# --------------------------- Models ---------------------------

class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    # Ο αρχηγός της ομάδας (User)
    leader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    leader = db.relationship("User", foreign_keys=[leader_id], backref="led_team", uselist=False)

    # Τα μέλη της ομάδας – προσοχή: δείξε ρητά ποιο FK ενώνει (για να μην μπερδεύεται με το leader_id)
    members = db.relationship(
        "User",
        foreign_keys="User.team_id",
        backref=db.backref("team", lazy=True),
        lazy=True
    )

    def __repr__(self) -> str:
        return f"<Team {self.name}>"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False, default=generate_password_hash("temp1234"))
    is_admin = db.Column(db.Boolean, default=False)

    # Προαιρετικά στοιχεία προφίλ για μεταγενέστερη χρήση (ΑΔΤ/τηλέφωνο/email/χρώμα)
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    id_card = db.Column(db.String(50), nullable=True)
    color = db.Column(db.String(20), nullable=True)

    must_change_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Συσχέτιση με ομάδα (αυτό είναι το FK που χρησιμοποιεί η Team.members)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)

    # Tasks assigned to user
    tasks = db.relationship("Task", backref="assignee", lazy=True)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open | done
    progress = db.Column(db.Integer, default=0)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    def __repr__(self) -> str:
        return f"<Task {self.title} {self.status}>"


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Note {self.id}>"


# --------------------------- Auth helpers ---------------------------

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Πρέπει να συνδεθείς.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper


# --------------------------- Routes ---------------------------

@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, πήγαινε στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()

    if user:
        # Αν έχει οριστεί κωδικός, έλεγξε τον. Αν δεν στάλθηκε, άφησέ τον να περάσει (φιλικό mock).
        if password:
            if not user.check_password(password):
                flash("Λάθος κωδικός.", "danger")
                return redirect(url_for("index"))
    else:
        # Δημιούργησε χρήστη επί τόπου (διευκολύνει τα πρώτα βήματα)
        user = User(username=username, is_admin=(username == "admin"))
        user.set_password(password or "admin")
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


@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    # απλή επισκόπηση + healthz για debug
    try:
        hz = "ok"
    except Exception:
        hz = "fail"
    return render_template("dashboard.html", user=u, healthz=hz)


@app.route("/board")
@login_required
def board():
    # απλά φορτώνει τον πίνακα (mock UI)
    return render_template("catalog.html")


# Προσοχή στο όνομα endpoint: τα templates κάνουν url_for('progress')
@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress_view():
    # Μικρά συνοπτικά metrics
    total = Task.query.count()
    done = Task.query.filter_by(status="done").count()
    open_cnt = Task.query.filter_by(status="open").count()
    avg = int(sum(t.progress for t in Task.query.all()) / total) if total else 0
    return render_template("progress.html", total=total, done=done, open_cnt=open_cnt, avg=avg)


@app.route("/directory")
@login_required
def directory():
    u = current_user()
    if u.is_admin or (u.team_id and u.led_team):  # admin/leader βλέπουν όλους (προαιρετικά)
        users = User.query.order_by(User.username.asc()).all()
    else:
        users = User.query.filter_by(team_id=u.team_id).order_by(User.username.asc()).all()
    return render_template("directory.html", users=users)


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


# --------------------------- Admin ---------------------------

@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin.html", users=users, teams=teams)


@app.route("/admin/create-user", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    id_card = (request.form.get("id_card") or "").strip()
    color = (request.form.get("color") or "").strip()
    is_admin = bool(request.form.get("is_admin"))

    if not username:
        flash("Το username είναι υποχρεωτικό.", "warning")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Υπάρχει ήδη χρήστης με αυτό το username.", "danger")
        return redirect(url_for("admin"))

    temp_pw = secrets.token_hex(4)
    u = User(
        username=username,
        email=email or None,
        phone=phone or None,
        id_card=id_card or None,
        color=color or None,
        is_admin=is_admin,
        must_change_password=True
    )
    u.set_password(temp_pw)
    db.session.add(u)
    db.session.commit()

    flash(f"Ο χρήστης δημιουργήθηκε. Προσωρινός κωδικός: {temp_pw}", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = db.session.get(User, user_id)
    if not u:
        flash("Ο χρήστης δεν βρέθηκε.", "warning")
        return redirect(url_for("admin"))
    if u.is_admin:
        flash("Δεν επιτρέπεται διαγραφή άλλου διαχειριστή από εδώ.", "danger")
        return redirect(url_for("admin"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin"))


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

    # GET: λίστες για template
    users = User.query.order_by(User.username.asc()).all()
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("admin_teams.html", users=users, teams=teams)


@app.route("/admin/teams/<int:team_id>/members", methods=["GET", "POST"])
@admin_required
def admin_team_members(team_id):
    team = Team.query.get_or_404(team_id)

    if request.method == "POST":
        # Προσθήκη μέλους με username
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
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_team_members.html", team=team, members=members, users=users)


@app.route("/admin/teams/<int:team_id>/delete", methods=["POST"])
@admin_required
def admin_delete_team(team_id):
    team = Team.query.get_or_404(team_id)

    # Αποδέσμευσε τα μέλη
    User.query.filter_by(team_id=team.id).update({User.team_id: None})
    db.session.delete(team)
    db.session.commit()
    flash("Η ομάδα διαγράφηκε.", "info")
    return redirect(url_for("admin_teams"))


# --------------------------- Error handlers ---------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # Μην εμφανίζεις stacktrace στον χρήστη
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# --------------------------- Local run (προαιρετικό) ---------------------------

if __name__ == "__main__":
    # Δημιούργησε πίνακες αν δεν υπάρχουν (το Render τρέχει gunicorn, αυτό εδώ είναι μόνο για local)
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
