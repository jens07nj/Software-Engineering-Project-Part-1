
from flask import Flask, redirect, render_template, request, jsonify, session, url_for
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import requests
from flask import request
import logging
import userManagement as dbHandler  # Custom module to handle database functions
import datetime
import bcrypt
import sqlite3 as sql
# Setup logging to a file for CSP and security events
app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Initialize the Flask app and enable CSRF protection
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"  # Secret key for session security
csrf = CSRFProtect(app)
def inject_role():
    # injects role into every template render
    return {"staff_role": session.get("role")}

# -------------------- ROUTES --------------------

# Display login page
@app.route("/login.html", methods=["GET", "POST"])
def login_page():
    return login()

# Display index page (if logged in)
@app.route("/index.html", methods=["GET"])
def index_page():
    return index()

# Redirect various index-related paths and AddUser.html to the login page
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
def root():
    return redirect("/login.html", 302)

# Root route with strong server-side CSP headers for security
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
    "report-uri": "/csp_report",  # Where CSP violation reports are sent
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "frame-src": "'none'",
})
def home():
    return redirect("/login.html")

# Logout and clear user session
@app.route("/logout")
def logout():
    session.clear()  # Clear all session data
    return redirect("/login.html")

# Privacy policy page
@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


GOAL = 100  # points needed for a coffee
DB_PATH = "databaseFiles/database.db"

def get_user_totals(username=None):
    """Return (points, coffees, total_points) using a JOIN."""
    if username is None:
        username = session.get("username")
    if not username:
        return (0, 0, 0)

    con = sql.connect(DB_PATH)
    try:
        cur = con.cursor()
        # No need for PRAGMA here (we're just reading), but harmless if you keep it.
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

@app.route("/screenform.html", methods=["GET", "POST"])
def screenform():
    if request.method == 'POST':
        # Get logged-in user's username
        pretester = session.get("username")

        # Get all form data submitted
        patient_id = request.form.get("patient_id")
        recorded_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        screen_complete = request.form.get("screen_complete") == "yes"
        reason_declined = request.form.get("reason_declined")
        hearing_loss = request.form.get("hearing_loss") == "yes"
        booked = request.form.get("booked") == "yes"
        pls_call = request.form.get("pls_call") == "yes"

        # Save the form data
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

        # Award a point only if the screen was actually completed
        if screen_complete and pretester:
            dbHandler.addPoints(pretester)

        # Fetch latest totals for progress bar
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

    # GET request — show form + current progress (if logged in)
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
# CSP violation report endpoint
@app.route("/csp_report", methods=["POST"])
@csrf.exempt  # Disable CSRF for this route (it's used by browsers, not forms)
def csp_report():
    app.logger.critical(request.data.decode())  # Log violation reports
    return "done"

# -------------------- LOGIC FUNCTIONS --------------------

# Handles login form POST and displays login form on GET
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate user with database
        if dbHandler.validate_user(username, password):
            session["username"] = username  # Save user in session
            print(session["username"])     # Debug print
            # get the staff role from the database
            role = dbHandler.get_user_role(username)
            print (role)
            session["role"] = role  # Store role in session
            return redirect("/index.html") # Redirect to index page
        else:
            error = "Invalid username or password."  # Show error

    return render_template("login.html", error=error)  # Show login form

# Render index.html template
def index():
    if "username" not in session:
        return redirect("/login.html")

    # Read filters from querystring (?pretester=...&screen_completion=... etc.)
    selected_pretester = request.args.get("pretester", "All")
    sc = request.args.get("screen_completion", "All")  # ScreenCompletion
    hl = request.args.get("hearing_loss", "All")       # HearingLoss
    pc = request.args.get("pls_call", "All")           # PlsCall

    conn = sql.connect('databaseFiles/database.db')
    conn.row_factory = sql.Row
    cur = conn.cursor()

    # Distinct list for Pretester dropdown
    cur.execute("SELECT DISTINCT Pretester FROM ScreenData WHERE Pretester IS NOT NULL AND Pretester <> '' ORDER BY Pretester")
    pretesters = [r["Pretester"] for r in cur.fetchall()]

    base_sql = """
        SELECT Pretester, RecordedTime, Patientid, ScreenCompletion,
               HearingLoss, Booked, PlsCall, ReasonDeclined
        FROM ScreenData
    """
    where, params = [], []

    # Helper for "Pretester = ?"
    def add_eq(column, value):
        if value and value != "All":
            where.append(f"{column} = ?")
            params.append(value)

    # Helper for tri-state boolean filters (expects Yes/No/All)
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

    # Newest first; tie-breaker on rowid
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
        staff_role=session.get("role"),  # keep if your templates check 'staff_role'
    )


def getCoffees():
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT Username, coffees FROM Staff_points;")
    coffees = cur.fetchall()   # get the rows
    con.close()
    print(coffees)
    return coffees

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
    return redirect(url_for('coffees'))  # redirect to the /coffees route

@app.route("/coffees", methods=["GET"])
def coffees():
    coffees_list = getCoffees()
    return render_template("coffees.html", coffees=coffees_list)


@app.route("/AddUser", methods=["GET", "POST"])
def AddUser():
    if request.method == "POST":
        Username = request.form.get("username")
        password = request.form.get("password")
        print (Username)
        print (password)
        
        # Optional: sanitize and validate inputs
        if not Username or not password:
            return render_template("AddUser.html", error="Please fill in all fields.")

        # Hash the password (e.g., using bcrypt)
        salt = bcrypt.gensalt()
        #hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)

        # Insert into the database using your `dbHandler`
        dbHandler.AddUser(Username, password)

        return render_template("AddUser.html", success=True)

    return render_template("AddUser.html")

# -------------------- RUN APP --------------------

if __name__ == "__main__":
    # Run the app locally on port 5000
    app.run(debug=True, host="0.0.0.0", port=5000)
