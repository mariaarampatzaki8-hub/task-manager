# app.py
import os
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

# ---------------- App setup ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")

# ---------------- Helpers ----------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
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
    Πολύ απλό mock login χωρίς DB:
    - username == admin  -> is_admin=True
    - οτιδήποτε άλλο     -> is_admin=False
    Το password αγνοείται στο mock.
    """
    username = (request.form.get("username") or "").strip()

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    # mock user/session
    session["uid"] = 1
    session["name"] = username
    session["is_admin"] = (username.lower() == "admin")

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------------- Main pages ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/progress")
@login_required
def progress():
    # Placeholder: εμφανίζει το templates/progress.html
    return render_template("progress.html")

# Κάποιες βάσεις έχουν menu "Πίνακας" -> δώσε δύο endpoints για σιγουριά
@app.route("/board")
@login_required
def board():
    # Αν δεν έχεις ξεχωριστό template, δείξε απλώς το dashboard
    return render_template("dashboard.html")

@app.route("/pinakas")
@login_required
def pinakas():
    return render_template("dashboard.html")

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html")

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")

@app.route("/admin/teams", methods=["GET", "POST"])
@admin_required
def admin_teams():
    # placeholder μέχρι να μπει κανονικό CRUD
    return render_template("admin_teams.html")

@app.route("/directory")
@login_required
def directory():
    return render_template("directory.html")

@app.route("/catalog")
@login_required
def catalog():
    return render_template("catalog.html")

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

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    # Το error.html πρέπει να κάνει extend το base.html
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------------- Gunicorn entry (Render) ----------------
# Στο Render το entry point είναι "gunicorn app:app"
if __name__ == "__main__":
    # Για τοπικό debug μόνο
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
