from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
from flask import session
import userManagement as dbHandler
import datetime

# Code snippet for logging a message
# app.logger.critical("message")

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
csrf = CSRFProtect(app)



@app.route("/login.html", methods=["GET", "POST"])
def login_page():
    return login()
@app.route("/index.html", methods=["GET"])
def index_page():
    return index()
# Redirect index.html to domain root for consistent UX


@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/login.html", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
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
    }
)



#@app.route("/AddUser.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])

# def AddUser():
#     # Redirect to another URL if the `url` parameter is used
#     if request.method == "GET" and request.args.get("url"):
#         url = request.args.get("url", "")
#         return redirect(url, code=302)

#     # If the form is submitted (POST)
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         # Sanitize username
#         username = sanitiser.make_web_safe(username)

#         try:
#             # Validate and encode password
#             password = sanitiser.check_password(password)
#         except ValueError as e:
#             return render_template("AddUser.html", error=str(e))

#         # Hash password with salt
#         salt = bcrypt.gensalt()
#         hashed_password = bcrypt.hashpw(password=password, salt=salt)

#         # Store in database
#         dbHandler.insertUser(username, hashed_password, salt)

#         return render_template("AddUser.html", success=True)

#     return render_template("AddUser.html")

def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if dbHandler.validate_user(username, password):
            session["username"] = username  # Store the username in the session
            current_user = session["username"]
            print (current_user)
            return redirect("/index.html")
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)
def index():
    return render_template("/index.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login.html")

@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")

@app.route("/screenform.html", methods=["GET","POST"])  # Define route for form submission (POST)
def screenform():
    if request.method == 'POST':
        print ('post')
        # Check if user is logged in (username is stored in the session)
        #if "username" not in sessions:
            #return "Unauthorized", 403  # Return a 403 Forbidden if user is not authenticated

        #  Get the pretester username from the session
        #pretester = sessions["username"]

        #  Collect form data submitted by the user
        pretester = session.get("username")
        patient_id = request.form.get("patient_id")   
        recorded_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                # Text field
        screen_complete = request.form.get("screen_complete") == "yes"  # Convert to boolean
        reason_declined = request.form.get("reason_declined")         # Optional text field
        hearing_loss = request.form.get("hearing_loss") == "yes"      # Convert to boolean
        booked = request.form.get("booked") == "yes"                  # Convert to boolean
        pls_call = request.form.get("pls_call") == "yes"              # Convert to boolean
        #  Automatically generate the current date and time
        
        #  Insert data into the database using a helper function
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

        #  Return a simple success message
        return render_template("/screenform.html", username =session.get("username"), submitted = True)
    return render_template("/screenform.html")
# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
