# app.py — σταθερός σκελετός χωρίς DB για να δούμε UI/ροές

from flask import Flask, render_template_string, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "dev-only-secret"  # βάλε ένα τυχαίο αργότερα

# ───────────── Health ─────────────
@app.route("/healthz")
def healthz():
    return "ok", 200

# ───────────── HTML templates μέσα στον κώδικα για να μην λείπει τίποτα ─────────────
BASE = """
<!doctype html>
<html lang="el">
<head>
  <meta charset="utf-8">
  <title>Task Manager</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:40px;}
    .nav a{margin-right:14px;text-decoration:none}
    .flash{padding:10px;border-radius:6px;margin:10px 0}
    .success{background:#e6ffed}
    .danger{background:#ffe6e6}
    .warning{background:#fff9e6}
  </style>
</head>
<body>
  <div class="nav">
    <a href="{{ url_for('index') }}">Αρχική</a>
    {% if session.get('uid') %}
      <a href="{{ url_for('dashboard') }}">Dashboard</a>
      <a href="{{ url_for('logout') }}">Αποσύνδεση</a>
    {% endif %}
  </div>

  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% if msgs %}
      {% for cat,msg in msgs %}
        <div class="flash {{cat}}">{{ cat }}: {{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</body>
</html>
"""

INDEX = """
{% extends base %}
{% block content %}
  <h1>Καλώς ήρθες</h1>
  <p>Συνδέσου για να μπεις στο dashboard.</p>
  <form method="post" action="{{ url_for('login') }}">
    <div><label>Username <input name="username" required></label></div>
    <div><label>Password <input name="password" type="password" required></label></div>
    <button type="submit">Σύνδεση</button>
  </form>
{% endblock %}
"""

DASHBOARD = """
{% extends base %}
{% block content %}
  <h1>Dashboard</h1>
  <p>Γεια σου, <strong>{{ user['username'] }}</strong>!
     Ο ρόλος σου είναι: <strong>{{ 'Διαχειριστής' if user['is_admin'] else 'Χρήστης' }}</strong>.
  </p>
{% endblock %}
"""

# ───────────── Mock “βάση” μνήμης για login ─────────────
# admin / admin123
MOCK_USERS = {
    "admin": {"id": 1, "username": "admin", "password": "admin123", "is_admin": True},
    "maria": {"id": 2, "username": "maria", "password": "1234", "is_admin": False},
}

# ───────────── Routes ─────────────
@app.route("/", methods=["GET"])
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template_string(INDEX, base=BASE)

@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    user = MOCK_USERS.get(username)
    if not user or user["password"] != password:
        flash("Λάθος στοιχεία.", "danger")
        return redirect(url_for("index"))
    session["uid"] = user["id"]
    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    uid = session.get("uid")
    if not uid:
        flash("Πρέπει να συνδεθείς.", "warning")
        return redirect(url_for("index"))
    # βρες τον χρήστη από το MOCK_USERS
    user = next((u for u in MOCK_USERS.values() if u["id"] == uid), None)
    if not user:
        session.clear()
        flash("Η συνεδρία έληξε.", "warning")
        return redirect(url_for("index"))
    return render_template_string(DASHBOARD, base=BASE, user=user)
