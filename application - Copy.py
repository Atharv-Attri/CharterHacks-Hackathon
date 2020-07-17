import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    data = db.execute("SELECT * FROM stocks WHERE id = ?;", int(session["user_id"]))
    us_data = db.execute("SELECT cash FROM users WHERE id = ?", int(session["user_id"]))
    print(data)
    tot_m = 0
    for i in data:
        tot_m += float(i["total"])
    tot_m += us_data[0]["cash"]
    return render_template("index.html", stocks = data, total_money = round(tot_m, 2), cash_money = round(us_data[0]["cash"], 2))
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        stock = request.form.get("Symbol")
        num = request.form.get("num")
        data = lookup(stock)
        if data == None:
            return apology("NOT VALID SYMBOL",)
        name = data["name"]
        price = data["price"]
        money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        print(money)
        if float(price) * int(num) > float(money[0]["cash"]):
            return apology("NOT ENOUGH CASH")
        tot = float(price) * int(num)
        now = datetime.now()
        print(now)
        stock_db = db.execute("SELECT * FROM stocks WHERE id = ?;", session["user_id"])
        added = False
        for i in stock_db:
            if i["symbol"] == stock:
                pre_data = db.execute("SELECT * FROM stocks WHERE id=? AND symbol = ?", int(session["user_id"]), stock)

                db.execute("UPDATE stocks SET shares = ?, total = ? WHERE id = ? AND symbol = ?",
                    i["shares"] + int(num), float(pre_data[0]["total"]) + int(num) * price, session["user_id"], stock)
                added = True;
                break
        if not added:
            db.execute("INSERT INTO stocks (id, symbol, shares, price, name, total) VALUES (?, ?, ?, ?, ?, ?)", int(session["user_id"]),stock, int(num), round(float(price), 2), name, int(num) * round(float(price), 2) )
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money[0]["cash"] - tot, session["user_id"])
        db.execute("INSERT INTO history (id, symbol, shares, date, price) Values (?,?,?,?, ?)", session["user_id"], stock, num, now, round(float(pre_data[0]["total"]) + int(num) * price, 2) )
        print("complete")
        return redirect("/")


    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    data = db.execute("SELECT * FROM history WHERE id = ?", session["user_id"])
    return render_template("history.html", data=data )
    return apology("TODO")


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        stock = request.form.get("Symbol")
        data = lookup(stock)
        if data == None:
            return apology("NOT VALID SYMBOL",)
        price = data["price"]
        name = data["name"]
        symbol = data["symbol"]
        return render_template("quoted.html", price = price, name = name, symbol = symbol)
    """Get stock quote."""
    return apology("SOMETHING WENT WRONG, IDK WHAT", 404)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username=request.form.get("username")
        password = request.form.get("password")
        passc = request.form.get("password_c")
        if password != passc:
            return apology("Password does not match.")
        if len(password) <8:
            return apology("Password must be at least 8 letters")
        counter = 0
        for i in password:
            if ord(i) >47 or ord(i) < 58:
                counter +=1
        if counter ==0:
            return apology("Must contain a number")
        uniques = db.execute("SELECT username FROM users")
        print(uniques)
        for i in uniques:
            if i["username"] == username:
                return apology("Username exists")

        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        print(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password);",  username=username, password=password)
        return redirect("/login")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    stock = request.form.get("stock")
    quan = request.form.get("num")
    stock_db_u = db.execute("SELECT * FROM stocks WHERE id = ?", session["user_id"])
    if request.method == "GET":
        return render_template("sell.html", stocks = stock_db_u )
    stock_db = db.execute("SELECT * FROM stocks WHERE id = ? and symbol = ?", session["user_id"], stock)
    if stock_db[0]["shares"] -int(quan) < 0:
        return apology("NOT ENOUGH SHARES")

    db.execute("UPDATE stocks SET shares = ? WHERE id = ? AND symbol = ?", (stock_db[0]["shares"] - int(quan)), session["user_id"], stock)
    stock_info = lookup(stock)
    usr_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    db.execute("UPDATE users SET cash = :cash WHERE id = :ids", cash = usr_info[0]["cash"] + stock_info["price"] * int(quan), ids = session["user_id"])
    print(stock, quan)
    for i in stock_db_u:
        if int(i["shares"]) == 0:
            db.execute("DELETE FROM stocks WHERE id = ? AND symbol = ?", session["user_id"], i["symbol"])
    if int(stock_db[0]["shares"]) == 0:
        db.execute("DELETE FROM stocks WHERE id = ? AND symbol = ?", session["user_id"], i["symbol"])
    now = datetime.now()
    db.execute("INSERT INTO history (id, symbol, shares, date, price) Values (?,?,?,?,?)", session["user_id"], stock, -int(quan), now, round(stock_info["price"] * int(quan), 2) )
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
