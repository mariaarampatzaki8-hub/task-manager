from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "dev-secret"  # άλλαξέ το με δικό σου secret key αν θες

# ---------- Health check ----------
@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------- Home / Index ----------
@app.route("/", methods=["GET"])
def index():
    """
    Αρχική σελίδα. Αν είναι ήδη συνδεδεμένος, πάει στο dashboard.
    """
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# ---------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET -> δείχνει τη φόρμα (index.html)
    POST -> mock login
    """
    if request.method == "GET":
        return render_template("index.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password")  # στο demo δεν το ελέγχουμε

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    is_admin = (username.lower() == "admin")

    session["uid"] = 1 if is_admin else 2
    session["name"] = username
    session["is_admin"] = is_admin

    flash("Συνδέθηκες επιτυχώς.", "success")
    return redirect(url_for("dashboard"))

# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Αποσυνδέθηκες.", "info")
    return redirect(url_for("index"))

# ---------- Dashboard ----------
@app.route("/dashboard")
def dashboard():
    if not session.get("uid"):
        flash("Χρειάζεται σύνδεση.", "warning")
        return redirect(url_for("index"))

    name = session.get("name", "Χρήστης")
    role = "Διαχειριστής" if session.get("is_admin") else "Χρήστης"
    return render_template("dashboard.html", name=name, role=role)

# ---------- Main ----------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
