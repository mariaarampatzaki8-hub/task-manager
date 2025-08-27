from flask import Flask, render_template

app = Flask(__name__)

@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/")
def index():
    return render_template("index.html")
