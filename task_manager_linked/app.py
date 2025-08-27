# -*- coding: utf-8 -*-
import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

# =====================  App  =====================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# ======= DB config: Render Postgres (pg8000) ή SQLite fallback =======
def _configure_database(app: Flask) -> None:
    os.makedirs(app.instance_path, exist_ok=True)
    sqlite_path = os.path.join(app.instance_path, "app_final.db")

    uri = os.environ.get("DATABASE_URL")
    if uri:
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        app.logger.info("DB: Postgres via pg8000")
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + sqlite_path
        app.logger.info("DB: SQLite fallback")

_configure_database(app)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)

# =====================  Models  =====================
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    members = relationship("User", backref="team", foreign_keys="User.team_id", lazy="dynamic")
    leader = relationship("User", foreign_keys=[leader_id], uselist=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=True, unique=False)
    phone = db.Column(db.String(50), nullable=True)
    id_card = db.Column(db.String(50), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(50), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(10), default="#3273dc")

    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)

    notes = relationship("Note", backref="user", lazy="dynamic", cascade="all, delete")
    tasks = relationship("Task", backref="assignee", lazy="dynamic", cascade="all, delete")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_pw(self, raw):
        return check_password_hash(self.password_hash, raw)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(240), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="open")  # open / done
    progress = db.Column(db.Integer, default=0)        # 0..100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# =====================  Seed DB  =====================
def init_db_and_seed():
    """Δημιουργεί πίνακες κι έναν βασικό admin αν δεν υπάρχει."""
    with app.app_context():
        db.create_all()
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
            app.logger.info("Δημιουργήθηκε Admin (admin / admin123)")

init_db_and_seed()

# =====================  Helpers  =====================
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Απαιτείται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Απαιτείται σύνδεση.", "warning")
            return redirect(url_for("index"))
        if not session.get("is_admin"):
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None

# =====================  Health / Diag  =====================
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/_db")
def db_diag():
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    return ("db: postgres", 200) if uri.startswith("postgresql+pg8000://") else ("db: sqlite", 200)

# =====================  Home / Auth  =====================
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
        flash("Συμπλήρωσε username και κωδικό.", "warning")
        return redirect(url_for("index"))

    u = User.query.filter_by(username=username).first()
    if not u or not u.check_pw(password):
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))

    session["uid"] = u.id
    session["name"] = u.name or u.username
    session["is_admin"] = bool(u.is_admin)

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# =====================  Dashboard  =====================
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return render_template(
        "dashboard.html",
        user_name=u.name,
        user_role=("Διαχειριστής" if u.is_admin else "Χρήστης"),
        health_status=request.host_url.rstrip("/") + "/healthz -> ok",
    )

# =====================  Notes (για τον χρήστη)  =====================
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

# =====================  Progress (για όλους)  =====================
@app.route("/progress")
@login_required
def progress():
    # απλή συγκεντρωτική εικόνα ανά χρήστη
    users = User.query.order_by(User.name.asc()).all()
    rows = []
    for u in users:
        total = Task.query.filter_by(assignee_id=u.id).count()
        done = Task.query.filter_by(assignee_id=u.id, status="done").count()
        open_cnt = Task.query.filter_by(assignee_id=u.id, status="open").count()
        # μέσος όρος progress στα open
        avg_prog = db.session.query(db.func.avg(Task.progress)).filter(
            Task.assignee_id == u.id
        ).scalar() or 0
        rows.append({
            "user": u,
            "total": total,
            "done": done,
            "open": open_cnt,
            "avg": int(round(avg_prog)),
        })
    return render_template("progress.html", rows=rows)

# =====================  Teams (δημόσια λίστα σε όλους)  =====================
@app.route("/teams")
@login_required
def teams_view():
    teams = Team.query.order_by(Team.name.asc()).all()
    return render_template("teams.html", teams=teams)

# =====================  Admin πίνακας  =====================
@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.order_by(User.name.asc()).all()
    # μικρά στατιστικά ανά χρήστη
    stats = {}
    for u in users:
        last_done = Task.query.filter_by(assignee_id=u.id, status="done")\
                              .order_by(Task.completed_at.desc()).first()
        stats[u.id] = {
            "open": Task.query.filter_by(assignee_id=u.id, status="open").count(),
            "done": Task.query.filter_by(assignee_id=u.id, status="done").count(),
            "last_done": (last_done.completed_at if last_done else None)
        }
    notes = Note.query.order_by(Note.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, stats=stats, notes=notes)

# --- Admin: Δημιουργία χρήστη ---
@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    name = (request.form.get("name") or "").strip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    raw_pw = (request.form.get("password") or "").strip()
    color = request.form.get("color") or "#3273dc"

    if not name or not username or not raw_pw:
        flash("Όνομα, username και κωδικός είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin_home"))

    if User.query.filter_by(username=username).first():
        flash("Το username υπάρχει ήδη.", "danger")
        return redirect(url_for("admin_home"))

    u = User(name=name, username=username, email=email, color=color)
    u.set_password(raw_pw)
    u.token = secrets.token_urlsafe(16)
    db.session.add(u)
    db.session.commit()
    flash(f"Δημιουργήθηκε χρήστης {name}.", "success")
    return redirect(url_for("admin_home"))

# --- Admin: Διαγραφή χρήστη ---
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.is_admin:
        admins_left = User.query.filter_by(is_admin=True).count()
        if admins_left <= 1:
            flash("Δεν γίνεται να διαγραφεί ο τελευταίος Admin.", "danger")
            return redirect(url_for("admin_home"))
    db.session.delete(u)
    db.session.commit()
    flash("Ο χρήστης διαγράφηκε.", "info")
    return redirect(url_for("admin_home"))

# --- Admin: Εναλλαγή ρόλου admin ---
@app.route("/admin/users/<int:user_id>/set_role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    u = User.query.get_or_404(user_id)
    make_admin = (request.form.get("is_admin") in ("1", "on", "true", "True"))
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
    return redirect(url_for("admin_home"))

# --- Admin: Επεξεργασία / Διαγραφή σημειώσεων χρηστών ---
@app.route("/admin/notes/<int:note_id>/edit", methods=["POST"])
@admin_required
def admin_edit_note(note_id):
    n = Note.query.get_or_404(note_id)
    new_content = (request.form.get("content") or "").strip()
    if not new_content:
        flash("Κενό κείμενο.", "warning")
        return redirect(url_for("admin_home"))
    n.content = new_content
    db.session.commit()
    flash("Σημείωση ενημερώθηκε.", "success")
    return redirect(url_for("admin_home"))

@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    n = Note.query.get_or_404(note_id)
    db.session.delete(n)
    db.session.commit()
    flash("Σημείωση διαγράφηκε.", "info")
    return redirect(url_for("admin_home"))

# =====================  Admin: Ομάδες (CRUD + ανάθεση μελών/leader)  =====================
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
    t = Team.query.get_or_404(team_id)
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Διάλεξε χρήστη.", "warning")
        return redirect(url_for("admin_teams"))
    u = User.query.get_or_404(int(user_id))
    u.team_id = t.id
    db.session.commit()
    flash("Ο χρήστης προστέθηκε στην ομάδα.", "success")
    return redirect(url_for("admin_teams"))

@app.route("/admin/teams/<int:team_id>/set_leader", methods=["POST"])
@admin_required
def admin_set_leader(team_id):
    t = Team.query.get_or_404(team_id)
    leader_id = request.form.get("leader_id")
    if not leader_id:
        flash("Διάλεξε leader.", "warning")
        return redirect(url_for("admin_teams"))
    t.leader_id = int(leader_id)
    db.session.commit()
    flash("Ορίστηκε leader.", "success")
    return redirect(url_for("admin_teams"))

# =====================  Κατάλογος (admin & leaders)  =====================
@app.route("/directory")
@login_required
def directory():
    u = current_user()
    # Leaders βλέπουν κατάλογο– μόνο αν είναι leader ομάδας ή admin
    is_leader = False
    if u.team_id and u.id == (u.team.leader_id if u.team else None):
        is_leader = True
    if not (u.is_admin or is_leader):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.name.asc()).all()
    return render_template("directory.html", users=users)

# =====================  Λοιπές καρτέλες  =====================
@app.route("/catalog")
@login_required
def catalog():
    users = User.query.order_by(User.name.asc()).all()
    return render_template("catalog.html", users=users)

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# =====================  Errors  =====================
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    # δείξε μήνυμα – logs στο Render θα έχουν λεπτομέρειες
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# =====================  Local run  =====================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
