from flask import Flask, render_template

app = Flask(__name__)

@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/")
def index():
    return render_template("index.html")
@app.route("/")
def index():
    # Αν είναι ήδη συνδεδεμένος, πήγαινε κατευθείαν στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    # Αλλιώς δείξε την κανονική αρχική με login/signup κουμπιά
    return render_template("index.html")
