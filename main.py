
from flask import Flask, redirect, render_template, request, jsonify, session
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import requests
import logging
import userManagement as dbHandler  # Custom module to handle database functions
import datetime
import bcrypt

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

# Handle the screening form
@app.route("/screenform.html", methods=["GET", "POST"])
def screenform():
    if request.method == 'POST':
        print('post')  # Debug log

        # Get logged-in user's username
        pretester = session.get("username")

        # Get all form data submitted
        patient_id = request.form.get("patient_id")
        recorded_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current timestamp
        screen_complete = request.form.get("screen_complete") == "yes"
        reason_declined = request.form.get("reason_declined")
        hearing_loss = request.form.get("hearing_loss") == "yes"
        booked = request.form.get("booked") == "yes"
        pls_call = request.form.get("pls_call") == "yes"

        # Save the form data using dbHandler function
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

        # Reload page with confirmation message
        return render_template("/screenform.html", username=session.get("username"), submitted=True)

    # GET request — just show the form
    return render_template("/screenform.html")

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
            return redirect("/index.html") # Redirect to index page
        else:
            error = "Invalid username or password."  # Show error

    return render_template("login.html", error=error)  # Show login form

# Render index.html template
def index():
    return render_template("/index.html")

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
