import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

# ---------------- App setup ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")

# ---------------- Helpers ----------------
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

# ---------------- Health ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- Home / Auth ----------------
@app.route("/", methods=["GET"])
def index():
    # Αρχική σελίδα. Αν είναι ήδη συνδεδεμένος, πάει στο dashboard.
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """
    Πολύ απλό login για να δουλεύει το UI χωρίς DB:
    - Αν βάλεις username = admin => is_admin = True
    - Οτιδήποτε άλλο => is_admin = False
    Το password αγνοείται σε αυτό το mock.
    """
    username = (request.form.get("username") or "").strip()

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    # mock "session user"
    session["uid"] = 1
    session["name"] = username
    session["is_admin"] = (username.lower() == "admin")

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------------- Main pages ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Εμφάνιση κατάστασης health επάνω στη σελίδα
    health_status = "ok"
    role = "Διαχειριστής" if session.get("is_admin") else "Χρήστης"
    return render_template("dashboard.html", role=role, health_status=health_status)

@app.route("/catalog")
@login_required
def catalog():
    # Ζητήθηκε από το template: url_for('catalog')
    return render_template("catalog.html")

@app.route("/progress")
@login_required
def progress():
    # Μπορείς να περάσεις rows όταν συνδέσεις DB.
    rows = []
    return render_template("progress.html", rows=rows)

@app.route("/teams")
@login_required
def teams():
    return render_template("teams.html")

@app.route("/admin")
@login_required
def admin():
    # Εδώ μπορείς να ελέγχεις session["is_admin"] για περιορισμούς.
    return render_template("admin.html")

@app.route("/admin/teams")
@login_required
def admin_teams():
    return render_template("admin_teams.html")

@app.route("/directory")
@login_required
def directory():
    return render_template("directory.html")

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------------- Local run (ignored on Render) ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
