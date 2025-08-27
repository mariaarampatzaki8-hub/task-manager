import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")

# -----------------------------------------------------------------------------
# Helpers / decorators
# -----------------------------------------------------------------------------
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
        if not session.get("uid"):
            flash("Χρειάζεται σύνδεση.", "warning")
            return redirect(url_for("index"))
        if not session.get("is_admin", False):
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# -----------------------------------------------------------------------------
# Home / Auth (mock)
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, στείλ’ τον στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """
    Mock login:
      - Αν username == "admin" => is_admin=True
      - Ο,τιδήποτε άλλο => is_admin=False
      - Δεν ελέγχουμε κωδικό (UI mock)
    """
    username = (request.form.get("username") or "").strip()

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    # Αποθηκεύουμε 'σύνδεση' στο session
    session["uid"] = 1                # fake user id
    session["name"] = username
    session["is_admin"] = (username.lower() == "admin")

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -----------------------------------------------------------------------------
# Main pages
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    # ΠΕΡΝΑΜΕ user στο template (fix για 'user is undefined')
    user = {
        "username": session.get("name"),
        "is_admin": session.get("is_admin", False),
    }
    return render_template("dashboard.html", user=user)

# Endpoint name = 'progress' γιατί έτσι το ζητάνε τα templates (url_for('progress'))
@app.route("/progress", methods=["GET"], endpoint="progress")
@login_required
def progress_view():
    rows = []  # βάλ’ το αργότερα να έρχεται από DB
    return render_template("progress.html", rows=rows)

@app.route("/board")
@login_required
def board():
    # Αν έχεις template board.html βάλε το εδώ. Αλλιώς δείξε progress ως placeholder.
    return redirect(url_for("progress"))

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
    # placeholder – το UI σου θα δουλέψει, λογική CRUD μπαίνει αργότερα
    return render_template("admin_teams.html")

@app.route("/catalog")
@login_required
def catalog():
    return render_template("catalog.html")

@app.route("/directory")
@login_required
def directory():
    return render_template("directory.html", users=[])

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -----------------------------------------------------------------------------
# Local run (Render χρησιμοποιεί gunicorn app:app)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
