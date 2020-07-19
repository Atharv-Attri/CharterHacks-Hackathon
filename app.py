import os

from datetime import datetime
from SQL import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime, time
from helpers import apology, login_required

import geocoder
# Configure application
app = Flask(__name__)

IP = None

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///NOTME.db")



@app.route("/")
def index():
    if not session:
        return render_template("index.html")
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def data ():
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    raw = db.execute("SELECT * FROM location WHERE id=?;", session["user_id"])
    parsed = []
    for i in raw:
        lat = i["lat"]
        lng = i["long"]
        timedate = i["timedate"].split()
        date = timedate[0]
        times = timedate[1]
        coordinates = i["lat"], i["long"]
        location = locator.reverse(coordinates)
        print(location.raw)
        parsed.append([lat, lng, date, times])
    return render_template("data.html",username=username[0]["username"], locations=parsed, adds=adds )
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/positive", methods=["POST"])
@login_required
def positive():
    db.execute("UPDATE users SET pos=1 WHERE id = ?", session["user_id"])
    return redirect("/dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

p1ID = None

@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "GET":
        if request.form.get("person"):
            userinf = db.execute("SELECT gov FROM users WHERE id = ?", session["user_id"])
            if userinf["gov"] == 0:
                return apology("You do not have permission to start a chat.", 403)
        texts = db.execute("SELECT * FROM chat WHERE person0= ? AND person1= ?", session["user_id"], request.form.get("person"))
        person0txt = []
        person1txt = []
        for i in texts:
            if i["sender"] == i["person0"]:
                person0txt.append(i["text"])
            else:
                person1txt.append(i["text"])
        return render_template("chat.html", p0txt=person0txt, p1txt = person1txt)
    db.execute("INSERT INTO chat (person0, person1, text, sender) VALUES (:p0, :p1, :txt, :sender)", p0=session["user_id"], p1=request.form.get("person"), txt=request.form.get("text"), sender=session["user_id"])
    """Get stock quote."""
    return apology("SOMETHING WENT WRONG, IDK WHAT", 404)


@app.route("/faq")
@login_required
def faq():
    return render_template("faq.html")
    """Get stock quote."""
    return apology("SOMETHING WENT WRONG, IDK WHAT", 404)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username")
    password = request.form.get("password")
    password_c = request.form.get("password_c")
    username_list = db.execute("Select username FROM users")
    for i in username_list:
        if username == i["username"]:
            return apology("Username Taken", 403)

    if not password == password_c:
        return apology("Passwords don't match", 403)
    hashed = generate_password_hash(password,method='pbkdf2:sha256', salt_length=8)
    db.execute("INSERT INTO users (username, hash) Values (?, ?);", username, hashed)
    return redirect("/")


def infected(id):
    usr_loc = db.execute("SELECT * FROM location WHERE id = ?", id)
    inf_p = db.execute("SELECT * FROM users WHERE pos = 1")
    inf_loc = []
    for i in inf_p:
        inf_loc.append([i["lat"], i["long"], i["timedate"].split()])
    
    return apology("SORRY")




def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
