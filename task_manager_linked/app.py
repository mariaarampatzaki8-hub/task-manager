import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from sqlalchemy import create_engine, text

# ------------------------------------------------------------------------------
#  App & DB
# ------------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-please-change")

# Render Postgres URL από ENV
_raw_url = os.environ.get("DATABASE_URL")  # π.χ. postgresql://user:pass@host/db
DB_URL = None
if _raw_url:
    # driver για SQLAlchemy + pg8000
    DB_URL = _raw_url.replace("postgres://", "postgresql+pg8000://")

engine = create_engine(
    DB_URL,
    pool_pre_ping=True
) if DB_URL else None


# ------------------------------------------------------------------------------
#  DB bootstrap (δημιουργία πινάκων + seed admin)
# ------------------------------------------------------------------------------

def ensure_schema_and_seed():
    """Δημιουργεί τους πίνακες αν δεν υπάρχουν και κάνει seed έναν admin."""
    if not engine:
        return

    with engine.begin() as conn:
        # Πίνακες
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS teams (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR(200) UNIQUE NOT NULL,
            leader_id   INTEGER
        );
        """))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id                      SERIAL PRIMARY KEY,
            name                    VARCHAR(200),
            username                VARCHAR(120) UNIQUE NOT NULL,
            email                   VARCHAR(200),
            phone                   VARCHAR(50),
            id_card                 VARCHAR(50),
            password_hash           VARCHAR(255),
            token                   VARCHAR(255),
            is_admin                BOOLEAN NOT NULL DEFAULT FALSE,
            must_change_password    BOOLEAN NOT NULL DEFAULT FALSE,
            color                   VARCHAR(20),
            team_id                 INTEGER REFERENCES teams(id)
        );
        """))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS tasks (
            id          SERIAL PRIMARY KEY,
            title       VARCHAR(200) NOT NULL,
            status      VARCHAR(20) NOT NULL DEFAULT 'open',
            assignee_id INTEGER REFERENCES users(id),
            progress    INTEGER NOT NULL DEFAULT 0
        );
        """))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS notes (
            id          SERIAL PRIMARY KEY,
            content     TEXT NOT NULL,
            user_id     INTEGER REFERENCES users(id)
        );
        """))

        # Seed admin user
        conn.execute(text("""
        INSERT INTO users (name, username, email, is_admin, color)
        VALUES ('Admin', 'admin', 'admin@example.com', TRUE, '#3273dc')
        ON CONFLICT (username) DO NOTHING;
        """))

        # Default team & δέσιμο admin
        conn.execute(text("""
        INSERT INTO teams (name) VALUES ('Default Team')
        ON CONFLICT (name) DO NOTHING;
        """))

        conn.execute(text("""
        UPDATE teams
           SET leader_id = (SELECT id FROM users WHERE username='admin')
         WHERE name='Default Team';
        """))

        conn.execute(text("""
        UPDATE users
           SET team_id = (SELECT id FROM teams WHERE name='Default Team')
         WHERE username='admin' AND team_id IS NULL;
        """))


# Κάλεσέ το μία φορά στην εκκίνηση του processo
try:
    ensure_schema_and_seed()
except Exception as e:
    # μην ρίξεις όλο το app αν η DB είναι στιγμιαία μη διαθέσιμη
    app.logger.error("DB bootstrap failed: %s", e)


# ------------------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------------------

def current_user():
    """Επιστρέφει dict με {id, name, is_admin} από το session ή None."""
    if not session.get("uid"):
        return None
    return {
        "id": session.get("uid"),
        "name": session.get("name") or "",
        "is_admin": bool(session.get("is_admin", False)),
    }


@app.context_processor
def inject_user():
    """Διαθέσιμο σε όλα τα templates: current_user."""
    return {"current_user": current_user()}


# ------------------------------------------------------------------------------
#  Healthz
# ------------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    # Αν έχουμε DB, κάνε ένα πολύ ελαφρύ ping
    if engine:
        try:
            with engine.begin() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as e:
            app.logger.error("healthz DB check failed: %s", e)
            return "db_error", 500
    return "ok", 200


# ------------------------------------------------------------------------------
#  Home / Auth
# ------------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    # Αν είναι ήδη συνδεδεμένος, στείλ' τον στο dashboard
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    # password = request.form.get("password")  # (προαιρετικό – δεν το ελέγχουμε εδώ)

    if not username:
        flash("Συμπλήρωσε username.", "warning")
        return redirect(url_for("index"))

    if engine:
        # Βρες τον χρήστη στη βάση
        with engine.begin() as conn:
            row = conn.execute(text("""
                SELECT id, COALESCE(name, username) AS name, is_admin
                FROM users
                WHERE username = :u
                LIMIT 1
            """), {"u": username}).fetchone()

        if not row:
            flash("Ο χρήστης δεν βρέθηκε στη βάση.", "danger")
            return redirect(url_for("index"))

        session["uid"] = int(row.id)
        session["name"] = row.name
        session["is_admin"] = bool(row.is_admin)
    else:
        # Fallback mock
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


# ------------------------------------------------------------------------------
#  Pages
# ------------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    if not session.get("uid"):
        flash("Κάνε σύνδεση πρώτα.", "warning")
        return redirect(url_for("index"))

    name = session.get("name", "")
    is_admin = bool(session.get("is_admin", False))
    role = "Διαχειριστής" if is_admin else "Χρήστης"

    # Προαιρετικό double-check από DB (αν άλλαξε ο ρόλος):
    if engine:
        try:
            with engine.begin() as conn:
                r = conn.execute(text("""
                    SELECT COALESCE(name, username) AS name, is_admin
                    FROM users
                    WHERE id = :i
                """), {"i": session["uid"]}).fetchone()
            if r:
                name = r.name
                role = "Διαχειριστής" if bool(r.is_admin) else "Χρήστης"
                session["name"] = name
                session["is_admin"] = bool(r.is_admin)
        except Exception as e:
            app.logger.warning("dashboard DB read failed: %s", e)

    # μικρό status για healthz
    health_status = "ok"
    return render_template("dashboard.html", name=name, role=role, health=health_status)


@app.route("/board")
def board():
    if not session.get("uid"):
        return redirect(url_for("index"))
    # απλή σελίδα-κενό (το template σου έχει περιεχόμενο/placeholder)
    return render_template("catalog.html")  # ή "board.html" αν έχεις τέτοιο template


@app.route("/progress")
def progress():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("progress.html")


@app.route("/teams")
def teams_view():
    if not session.get("uid"):
        return redirect(url_for("index"))

    teams = []
    if engine:
        with engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT t.id, t.name,
                       u.username AS leader_username,
                       u.name     AS leader_name
                FROM teams t
                LEFT JOIN users u ON u.id = t.leader_id
                ORDER BY t.name ASC
            """)).mappings().all()
            teams = list(rows)

    return render_template("teams.html", teams=teams)


@app.route("/admin")
def admin():
    # μόνο admin
    if not session.get("uid"):
        return redirect(url_for("index"))
    if not session.get("is_admin", False):
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))

    users = []
    if engine:
        with engine.begin() as conn:
            users = list(conn.execute(text("""
                SELECT id, username, COALESCE(name, username) AS name,
                       email, is_admin, team_id
                FROM users
                ORDER BY username
            """)).mappings().all())

    return render_template("admin.html", users=users)


@app.route("/admin/teams", methods=["GET", "POST"])
def admin_teams():
    # μόνο admin
    if not session.get("uid"):
        return redirect(url_for("index"))
    if not session.get("is_admin", False):
        flash("Μόνο για διαχειριστές.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST" and engine:
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Όνομα ομάδας υποχρεωτικό.", "warning")
            return redirect(url_for("admin_teams"))

        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO teams (name) VALUES (:n)
                ON CONFLICT (name) DO NOTHING
            """), {"n": name})
        flash("Η ομάδα δημιουργήθηκε.", "success")
        return redirect(url_for("admin_teams"))

    teams = []
    if engine:
        with engine.begin() as conn:
            teams = list(conn.execute(text("""
                SELECT t.id, t.name,
                       u.username AS leader_username,
                       u.name     AS leader_name
                FROM teams t
                LEFT JOIN users u ON u.id = t.leader_id
                ORDER BY t.name ASC
            """)).mappings().all())

    return render_template("admin_teams.html", teams=teams)


@app.route("/directory")
def directory():
    if not session.get("uid"):
        return redirect(url_for("index"))

    # Admin βλέπει όλους. (Leader per-team μπορείς να το προσθέσεις αργότερα.)
    if not session.get("is_admin", False):
        flash("Πρόσβαση μόνο σε διαχειριστές (προς το παρόν).", "warning")
        return redirect(url_for("dashboard"))

    users = []
    if engine:
        with engine.begin() as conn:
            users = list(conn.execute(text("""
                SELECT id, username, COALESCE(name, username) AS name,
                       email, phone, id_card, is_admin, team_id
                FROM users
                ORDER BY name NULLS LAST, username
            """)).mappings().all())

    return render_template("directory.html", users=users)


@app.route("/help")
def help_page():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("help.html")


@app.route("/settings")
def settings():
    if not session.get("uid"):
        return redirect(url_for("index"))
    return render_template("settings.html")


# ------------------------------------------------------------------------------
#  Error handlers
# ------------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Δεν βρέθηκε."), 404


@app.errorhandler(500)
def server_error(e):
    # log για να δούμε τι παίζει
    app.logger.error("500 error: %s", e)
    return render_template("error.html", code=500, message="Κάτι πήγε στραβά."), 500


# ------------------------------------------------------------------------------
#  Local dev (Render τρέχει gunicorn app:app)
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
