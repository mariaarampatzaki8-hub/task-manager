import os, secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

# --------- FAKE DATA (στη μνήμη) ---------
users = [
    {"id": 1, "username": "admin", "password": "admin123", "is_admin": True,  "color": "#ff4444"},
    {"id": 2, "username": "user1", "password": "user123",  "is_admin": False, "color": "#3273dc"},
]
teams = [
    {"id": 1, "name": "Default Team", "leader_id": 1},
]
tasks = [
    {"id": 1, "title": "Δοκιμαστικό Task", "status": "open", "assignee_id": 2, "progress": 0}
]

# --------- Helpers ---------
def current_user():
    uid = session.get("uid")
    return next((u for u in users if u["id"] == uid), None)

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
        if not u or not u["is_admin"]:
            flash("Μόνο για διαχειριστές.", "danger")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return wrapper

@app.context_processor
def inject_user():
    return {"user": current_user()}

# --------- Routes ---------
@app.route("/")
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    u = next((u for u in users if u["username"] == username and u["password"] == password), None)
    if not u:
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))
    session["uid"] = u["id"]
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
    return render_template("dashboard.html", tasks=tasks)

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html", users=users, teams=teams, tasks=tasks)

# --------- Error handlers ---------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Σφάλμα server."), 500

# --------- Local run ---------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
