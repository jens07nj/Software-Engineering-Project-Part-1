
# -------------------- IMPORTS --------------------
import logging
import datetime
import sqlite3 as sql
import bcrypt
import requests
from flask import Flask, redirect, render_template, request, jsonify, session, url_for
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header

import userManagement as dbHandler  # Custom module to handle database functions


# -------------------- LOGGING --------------------
# Setup logging to a file for CSP and security events
app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)


# -------------------- FLASK APP SETUP --------------------
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"  # Secret key for session security
csrf = CSRFProtect(app)


# -------------------- CONSTANTS --------------------
GOAL = 100  # points needed for a coffee
DB_PATH = "databaseFiles/database.db"


# -------------------- CONTEXT INJECTORS --------------------
def inject_role():
    # Injects role into every template render
    return {"staff_role": session.get("role")}


@app.context_processor
def inject_rewards_progress():
    """Make points/coffees/total_points/progress_percent/threshold available in ALL templates."""
    username = session.get("username")
    if not username:
        return dict(points=0, coffees=0, total_points=0, progress_percent=0, threshold=GOAL)

    points, coffees, total_points = get_user_totals(username)
    return dict(
        points=points,
        coffees=coffees,
        total_points=total_points,
        progress_percent=calc_progress(points, GOAL),
        threshold=GOAL,
    )


# -------------------- UTILITY FUNCTIONS --------------------
def get_user_totals(username=None):
    """Return (points, coffees, total_points) using a JOIN."""
    if username is None:
        username = session.get("username")
    if not username:
        return (0, 0, 0)

    con = sql.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT
              COALESCE(sp.points, 0),
              COALESCE(sp.coffees, 0),
              COALESCE(sp.total_points, 0)
            FROM Staff AS s
            LEFT JOIN Staff_points AS sp
              ON sp.Username = s.Username
            WHERE s.Username = ?;
        """, (username,))
        row = cur.fetchone()
        return row if row else (0, 0, 0)
    finally:
        con.close()


def calc_progress(points: int, threshold: int = GOAL) -> int:
    """Return a 0..100 percentage for the progress bar."""
    try:
        pct = int(round((points / float(threshold)) * 100))
        return max(0, min(100, pct))
    except Exception:
        return 0


def getCoffees():
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT Username, coffees FROM Staff_points;")
    coffees = cur.fetchall()
    con.close()
    return coffees


# -------------------- ROUTES --------------------
# Root + Security
@app.route("/", methods=["POST", "GET"])
@csp_header({
    "base-uri": "'self'",
    "default-src": "'self'",
    "style-src": "'self'",
    "script-src": "'self'",
    "img-src": "'self' data:",
    "media-src": "'self'",
    "font-src": "'self'",
    "object-src": "'self'",
    "child-src": "'self'",
    "connect-src": "'self'",
    "worker-src": "'self'",
    "report-uri": "/csp_report",
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "frame-src": "'none'",
})
def home():
    return redirect("/login.html")


@app.route("/csp_report", methods=["POST"])
@csrf.exempt  # Disable CSRF for this route
def csp_report():
    app.logger.critical(request.data.decode())  # Log violation reports
    return "done"


# Authentication
@app.route("/login.html", methods=["GET", "POST"])
def login_page():
    return login()


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login.html")


# Index + redirects
@app.route("/index.html", methods=["GET"])
def index_page():
    return index()


@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
def root():
    return redirect("/login.html", 302)


# Other pages
@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


@app.route("/screenform.html", methods=["GET", "POST"])
def screenform():
    if request.method == 'POST':
        pretester = session.get("username")
        patient_id = request.form.get("patient_id")
        recorded_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        screen_complete = request.form.get("screen_complete") == "yes"
        reason_declined = request.form.get("reason_declined")
        hearing_loss = request.form.get("hearing_loss") == "yes"
        booked = request.form.get("booked") == "yes"
        pls_call = request.form.get("pls_call") == "yes"

        dbHandler.insert_screen_data(
            pretester,
            patient_id,
            screen_complete,
            reason_declined,
            hearing_loss,
            booked,
            pls_call,
            recorded_time
        )

        if screen_complete and pretester:
            dbHandler.addPoints(pretester)

        points, coffees, total_points = get_user_totals(pretester)
        progress_percent = calc_progress(points)

        return render_template(
            "/screenform.html",
            username=pretester,
            submitted="True",
            points=points,
            coffees=coffees,
            total_points=total_points,
            progress_percent=progress_percent,
            threshold=GOAL
        )

    pretester = session.get("username")
    points, coffees, total_points = get_user_totals(pretester) if pretester else (0, 0, 0)
    progress_percent = calc_progress(points)

    return render_template(
        "/screenform.html",
        username=pretester,
        submitted=False,
        points=points,
        coffees=coffees,
        total_points=total_points,
        progress_percent=progress_percent,
        threshold=GOAL
    )


@app.route("/claimCoffee/<username>", methods=["POST"])
def claimCoffee(username):
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        UPDATE Staff_points
        SET coffees = coffees - 1
        WHERE Username = ? AND coffees > 0;
    """, (username,))
    con.commit()
    con.close()
    return redirect(url_for('coffees'))


@app.route("/coffees", methods=["GET"])
def coffees():
    coffees_list = getCoffees()
    return render_template("coffees.html", coffees=coffees_list)


@app.route("/AddUser", methods=["GET", "POST"])
def AddUser():
    if request.method == "POST":
        Username = request.form.get("username")
        password = request.form.get("password")

        if not Username or not password:
            return render_template("AddUser.html", error="Please fill in all fields.")

        salt = bcrypt.gensalt()
        dbHandler.AddUser(Username, password)

        return render_template("AddUser.html", success=True)

    return render_template("AddUser.html")


# -------------------- LOGIC FUNCTIONS --------------------
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if dbHandler.validate_user(username, password):
            session["username"] = username
            role = dbHandler.get_user_role(username)
            session["role"] = role
            return redirect("/index.html")
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


def index():
    if "username" not in session:
        return redirect("/login.html")

    selected_pretester = request.args.get("pretester", "All")
    sc = request.args.get("screen_completion", "All")
    hl = request.args.get("hearing_loss", "All")
    pc = request.args.get("pls_call", "All")

    conn = sql.connect('databaseFiles/database.db')
    conn.row_factory = sql.Row
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT Pretester FROM ScreenData WHERE Pretester IS NOT NULL AND Pretester <> '' ORDER BY Pretester")
    pretesters = [r["Pretester"] for r in cur.fetchall()]

    base_sql = """
        SELECT Pretester, RecordedTime, Patientid, ScreenCompletion,
               HearingLoss, Booked, PlsCall, ReasonDeclined
        FROM ScreenData
    """
    where, params = [], []

    def add_eq(column, value):
        if value and value != "All":
            where.append(f"{column} = ?")
            params.append(value)

    def add_bool(column, value):
        if not value or value.lower() == "all":
            return
        if value.lower() in ("yes", "1", "true"):
            where.append(f"{column} = 1")
        elif value.lower() in ("no", "0", "false"):
            where.append(f"{column} = 0")

    add_eq("Pretester", selected_pretester)
    add_bool("ScreenCompletion", sc)
    add_bool("HearingLoss", hl)
    add_bool("PlsCall", pc)

    if where:
        base_sql += " WHERE " + " AND ".join(where)

    base_sql += " ORDER BY datetime(RecordedTime) DESC, rowid DESC"

    cur.execute(base_sql, params)
    data = cur.fetchall()
    conn.close()

    return render_template(
        "index.html",
        data=data,
        pretesters=pretesters,
        selected_pretester=selected_pretester,
        selected_screen_completion=sc,
        selected_hearing_loss=hl,
        selected_pls_call=pc,
        staff_role=session.get("role"),
    )


# -------------------- RUN APP --------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
