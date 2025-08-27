import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")

# ---------------- Health / Root ----------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- Home / Auth ----------------
@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, πάει στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """
    Mock login:
    - Αν βάλεις username == admin => is_admin = True
    - Οτιδήποτε άλλο => is_admin = False
    - Δεν ελέγχουμε κωδικό σε αυτό το mock
    """
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # δεν χρησιμοποιείται στο mock

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    session["uid"] = 1            # mock user id
    session["name"] = username
    session["is_admin"] = (username.lower() == "admin")

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------------- Core pages (mock περιεχόμενο) ----------------
def current_user():
    """Μικρό helper για το template context."""
    return {
        "id": session.get("uid"),
        "name": session.get("name"),
        "is_admin": session.get("is_admin", False),
    }

@app.route("/dashboard")
def dashboard():
    if not session.get("uid"):
        return redirect(url_for("index"))
    u = current_user()
    role = "Διαχειριστής" if u["is_admin"] else "Χρήστης"
    return render_template("dashboard.html", name=u["name"], role=role)

@app.route("/progress")
def progress():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("progress.html")

@app.route("/teams")
def teams():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("teams.html")

@app.route("/admin")
def admin():
    if not session.get("uid"):
        return redirect(url_for("index"))
    if not session.get("is_admin"):
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("admin.html")

@app.route("/admin/teams")
def admin_teams():
    if not session.get("uid"):
        return redirect(url_for("index"))
    if not session.get("is_admin"):
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("admin_teams.html")

@app.route("/catalog")
def catalog():
    if not session.get("uid"):
        return redirect(url_for("index"))
    # Ο κατάλογος (προσωπικών στοιχείων) τον βλέπουν admin + leaders
    # Στο mock: επιτρέπουμε ΜΟΝΟ admin για απλότητα
    if not session.get("is_admin"):
        flash("Πρόσβαση μόνο σε διαχειριστές (mock).", "danger")
        return redirect(url_for("dashboard"))
    return render_template("catalog.html")

@app.route("/settings")
def settings():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("settings.html")

@app.route("/help")
def help_page():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("help.html")

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500

# ---------------- Dev entry (το Render τρέχει gunicorn app:app) ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
