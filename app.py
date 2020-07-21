# import libaries
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

# Configure application
app = Flask(__name__)

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

# Configure SQL Library to use SQLite database
db = SQL("sqlite:///NOTME.db")


@app.route("/")
def index():
    # if session is not set, return index, else send to dashboard
    if not session:
        return render_template("index.html")
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def data ():
    # check for infection
    infected(session["user_id"])
    usrpos = db.execute("SELECT pos FROM users WHERE id = ?", session["user_id"])
    if usrpos[0]["pos"] == 0:
        POSITIVE = False
    else:
        POSITIVE = True
    # get raw data
    raw = db.execute("SELECT * FROM location WHERE id=?;", session["user_id"])
    parsed = []
    # parse the data
    for i in raw:
        lat = i["lat"]
        lng = i["long"]
        timedate = i["timedate"].split()
        date = timedate[0]
        times = timedate[1]
        coordinates = i["lat"], i["long"]
        parsed.append([lat, lng, date, times])
    # return the template
    return render_template("data.html", locations=parsed, positive=POSITIVE, id=session["user_id"] )


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


@app.route("/faq")
@login_required
def faq():
    return render_template("faq.html")


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "POST":
        # p as in person
        session["p0id"] = session["user_id"]
        session["p1id"] = int(request.form.get("id"))
        session["P1"] = session["p1id"]
        session["chatdata"] = db.execute("SELECT * FROM chat WHERE person0=:p0 AND person1=:p1 OR person1=:p0 AND person0=:p1", p0=session["p0id"], p1=session["P1"])
    return render_template("chat.html", chatdata=session["chatdata"], p0=session["user_id"])


@app.route("/chatadd", methods=["POST"])
@login_required
def chatadd():
    session["text"] = request.form.get("text")
    db.execute("INSERT INTO chat (person0, person1, text, sender) Values (?, ?, ?, ?);", session["user_id"], session["P1"], session["text"],  session["user_id"])
    session["chatdata"] = db.execute("SELECT * FROM chat WHERE person0=:p0 AND person1=:p1 OR person1=:p0 AND person0=:p1", p0=session["user_id"], p1=session["P1"])
    return redirect("/chat")


@app.route("/chatdel", methods=["POST"])
@login_required
def chatdel():
    db.execute("DELETE FROM chat WHERE person0=:p0 AND person1=:p1 OR person1=:p0 AND person0=:p1;", p0=session["user_id"], p1=session["P1"])
    return redirect("/chat")


@app.route("/locationAdd", methods=["POST"])
@login_required
def locadd():
    date = request.form.get("date")
    timein = request.form.get("time")
    lat = request.form.get("lat")
    lng = request.form.get("long")
    timedate = date + " " + timein
    usrpref = db.execute("SELECT * FROM pref WHERE id=?", session["user_id"])
    for i in usrpref:
        if usrpref[0]["lat"] + 0.003 > float(lat) > usrpref[0]["lat"] - 0.003 or usrpref[0]["long"] + 0.003 > float(lng) > usrpref[0]["long"] - 0.003:
            return redirect("/")
    db.execute("INSERT INTO location (id, lat, long, timedate) Values (:id, :lat, :lng, :td)", id=session["user_id"], lat=lat, lng=lng, td=timedate)
    return redirect("/")


@app.route("/notTrack", methods=["GET","POST"])
@login_required
def notTrack():
    lat = request.form.get("lat")
    lng = request.form.get("long")
    if not lat or not lng:
        return apology("NO LAT OR LONG")
    db.execute("INSERT INTO pref (id, lat, long) Values (:id, :lat, :lng)", id=session["user_id"], lat=lat, lng=lng)
    return redirect("/")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "GET":
        return render_template("delete.html")
    dated = request.form.get("date")
    timed = request.form.get("time")
    timedate = dated + " " + timed
    db.execute("DELETE FROM location WHERE id = :id AND timedate = :timedate", id=session["user_id"], timedate=timedate)
    return redirect("/")


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
    # get data 
    usr_loc = db.execute("SELECT * FROM location WHERE id = ?", id)
    inf_p = db.execute("SELECT * FROM users WHERE pos = 1")
    inf_loc = []
    for i in inf_p:
        inf_loc = db.execute("SELECT * FROM location WHERE id= ?", i["id"])
        print(inf_loc)
        for i in inf_loc:
            try:
                # CHECK
                sep = i["timedate"].split()
                inf_loc.append([i["lat"], i["long"], i["timedate"].split()])
                for y in usr_loc:
                    ysep = y["timedate"].split()
                    if y["lat"]+0.003 > i["lat"] > y["lat"]-0.003 and  y["long"]+0.003 > i["long"] > y["long"]-0.003 and ysep[0] == sep[0] :
                        db.execute("UPDATE users SET pos=1 WHERE id = ?", id)
            except:
                pass
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
