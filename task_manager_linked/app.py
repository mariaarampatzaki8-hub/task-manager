# task_manager_linked/app.py
import os
from functools import wraps
from flask import (
    Flask, render_template, redirect,
    url_for, request, session, flash
)

# ---------------- App ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + os.urandom(16).hex())


# ---------------- Helpers (auth) ----------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Απαιτείται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
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


# ---------------- Health ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200


# ---------------- Home / Auth ----------------
@app.route("/", methods=["GET"])
def index():
    """
    Αρχική σελίδα. Αν είναι ήδη συνδεδεμένος, πάει στο dashboard.
    """
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    """
    ΠΟΛΥ απλό login μόνο για να δουλεύει το UI χωρίς DB:
    - Αν βάλεις username = admin -> is_admin = True
    - Οτιδήποτε άλλο -> is_admin = False
    Κωδικός αγνοείται σε αυτό το mock.
    """
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # δεν ελέγχεται στο mock

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    session["uid"] = 1  # mock user id
    session["name"] = username
    session["is_admin"] = (username.lower() == "admin")
    session["is_leader"] = False  # μπορείς να το αλλάξεις χειροκίνητα αν θες να δεις την καρτέλα καταλόγου

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))


# ---------------- Core Pages (templates) ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/progress")
@login_required
def progress():
    # εδώ απλά περνάμε κενά δεδομένα για να φορτώνει το template
    rows = []
    return render_template("progress.html", rows=rows)


@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    # mock δεδομένα για να εμφανίζεται ο πίνακας
    users = [
        {"id": 1, "name": "Admin", "username": "admin", "email": None, "is_admin": True, "color": "#3273dc"},
    ]
    stats = {}
    notes = []
    return render_template("admin.html", users=users, stats=stats, notes=notes)


@app.route("/admin/teams", methods=["GET"])
@admin_required
def admin_teams():
    # mock λίστα ομάδων για εμφάνιση
    teams = [
        {"id": 1, "name": "Team A", "leader_id": None},
        {"id": 2, "name": "Team B", "leader_id": None},
    ]
    # mock users για dropdowns κτλ
    users = [
        {"id": 1, "name": "Admin", "username": "admin"},
    ]
    return render_template("admin_teams.html", teams=teams, users=users)


@app.route("/teams")
@login_required
def teams():
    teams = [
        {"id": 1, "name": "Team A"},
        {"id": 2, "name": "Team B"},
    ]
    return render_template("teams.html", teams=teams)


@app.route("/directory")
@login_required
def directory():
    """
    Κατάλογος: ο admin το βλέπει πάντα.
    Για non-admin σ’ αυτό το mock, πρέπει να είναι leader (session["is_leader"]=True) για να περάσει.
    """
    if not (session.get("is_admin") or session.get("is_leader")):
        flash("Πρόσβαση μόνο σε διαχειριστές ή leaders.", "danger")
        return redirect(url_for("dashboard"))

    users = [
        {"name": "Admin", "email": "", "phone": "", "id_number": "", "team": "—"},
    ]
    return render_template("directory.html", users=users)


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """
    Placeholder settings σελίδα — μπορείς να βάλεις φόρμες για αλλαγή κωδικού κτλ.
    """
    if request.method == "POST":
        flash("Οι ρυθμίσεις αποθηκεύτηκαν (mock).", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html")


# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # Αν κάτι σκάσει, θα βλέπεις το template αντί για default σελίδα.
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# ---------------- Local dev entry (προαιρετικό) ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
