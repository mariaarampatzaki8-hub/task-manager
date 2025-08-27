# -*- coding: utf-8 -*-
import os
import secrets

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

# -------------------------------------------------
# App init
# -------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# -------------------------------------------------
# Database config (Render Postgres με pg8000 ή SQLite fallback)
# -------------------------------------------------
def _configure_database(app: Flask) -> None:
    """
    Αν υπάρχει DATABASE_URL από το Render:
      - μετατροπή 'postgres://' -> 'postgresql://'
      - χρήση οδηγού 'pg8000': 'postgresql://...' -> 'postgresql+pg8000://...'
    Αλλιώς, fallback σε SQLite στο instance folder.
    """
    # Δημιούργησε instance dir για SQLite fallback
    os.makedirs(app.instance_path, exist_ok=True)
    sqlite_path = os.path.join(app.instance_path, "app_final.db")

    uri = os.environ.get("DATABASE_URL")
    if uri:
        # 1) Heroku/legacy style
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        # 2) Χρήση pg8000 driver
        if uri.startswith("postgresql://"):
            uri = uri.replace("postgresql://", "postgresql+pg8000://", 1)

        # Χωρίς connect_args/ssl param — ο pg8000 το χειρίζεται μόνος του στο Render
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        app.logger.info("DB in use: Postgres via pg8000")
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + sqlite_path
        app.logger.info("DB in use: SQLite fallback")

# Ρύθμισε DB (ακόμη κι αν δεν τη χρησιμοποιούμε λειτουργικά τώρα)
_configure_database(app)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# -------------------------------------------------
# Helpers
# -------------------------------------------------
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
        if session.get("role") != "admin":
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

# -------------------------------------------------
# Health / Diagnostics
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/_db")
def db_diag():
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if uri.startswith("postgresql+pg8000://"):
        return "db: postgres", 200
    return "db: sqlite", 200

# -------------------------------------------------
# Home / Auth
# -------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """
    Αρχική σελίδα με φόρμα σύνδεσης.
    Αν είσαι ήδη συνδεδεμένος, σε στέλνει στο dashboard.
    """
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """
    Πολύ απλό mock login για να λειτουργεί το UI χωρίς DB:
    - Αν username == admin -> role=admin
    - Αλλιώς role=user
    - Κωδικός δεν ελέγχεται (mock).
    """
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # mock – δεν το ελέγχουμε

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    session["uid"] = 1  # mock user id
    session["name"] = username
    session["role"] = "admin" if username.lower() == "admin" else "user"
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# -------------------------------------------------
# App pages (render μόνο – δεδομένα mock)
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        user_name=session.get("name"),
        user_role="Διαχειριστής" if session.get("role") == "admin" else "Χρήστης",
        health_status=request.host_url.rstrip("/") + "/healthz -> ok",
    )

@app.route("/progress")
@login_required
def progress():
    # Εδώ μελλοντικά θα μπουν πραγματικά δεδομένα προόδου
    rows = []  # mock
    return render_template("progress.html", rows=rows)

@app.route("/teams")
@login_required
def teams():
    # Μόνο εμφάνιση placeholder UI
    return render_template("teams.html")

@app.route("/admin")
@admin_required
def admin():
    # Placeholder admin UI
    return render_template("admin.html")

@app.route("/admin/teams")
@admin_required
def admin_teams():
    return render_template("admin_teams.html")

@app.route("/catalog")
@login_required
def catalog():
    # Ο κατάλογος χρηστών/στοιχείων θα γεμίσει όταν μπει DB
    data = []
    return render_template("catalog.html", data=data)

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

@app.route("/directory")
@admin_required
def directory():
    # Admin-only προς το παρόν (ή leaders αν προστεθεί ρόλος)
    users = []  # mock
    return render_template("directory.html", users=users)

# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# -------------------------------------------------
# Local run (το Render χρησιμοποιεί το gunicorn app:app)
# -------------------------------------------------
if __name__ == "__main__":
    # Για τοπικό δοκιμή: python app.py
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
