import os

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
    rows = db.execute("SELECT * FROM users WHERE id = :us", us=session["user_id"])
    shares = db.execute("SELECT * FROM shares WHERE user_id = :i AND n > 0 ORDER BY symbol ASC",i=session["user_id"])
    stotal = rows[0]["cash"]
    for i in range(len(shares)):
        shr = lookup(shares[i]["symbol"])
        shares[i]["name"] = shr["name"]
        shares[i]["symbol"] = shr["symbol"]
        shares[i]["price"] = shr["price"]
        stotal = stotal + shares[i]["price"]*shares[i]["n"]
    return render_template("index.html", rows=shares, stotal=stotal, cas=rows[0]["cash"])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method=="POST":
        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol")

        sym = lookup(request.form.get("symbol"))["symbol"]

        qty = int(request.form.get("shares"))
        if qty < 0:
            return apology("cannot buy negative amount of shares", 400)
        price = lookup(sym)['price']
        pr = price
        qty = float(qty)
        price = price * qty
        row = db.execute("SELECT * FROM users WHERE id = :i", i = session["user_id"])

        if price > float(row[0]['cash']):
            return apology("not enough cash", 400)
        ca = float(row[0]['cash']) - price
        db.execute("update users set cash = :cas where id =:i", cas=ca, i=session["user_id"])
        f = db.execute("SELECT * FROM shares WHERE user_id = :i AND symbol = :s", i = session["user_id"], s = sym)
        if len(f) != 1:
            db.execute("INSERT INTO shares (user_id, symbol, n) VALUES (:ui, :s, :n)",ui=session["user_id"], s=sym, n=qty)
        else:
            db.execute("UPDATE shares SET n = :sh WHERE user_id = :i AND symbol = :s",sh = f[0]["n"]+int(qty), i = session["user_id"], s=sym )
        db.execute("INSERT INTO history (id, symbol, price, shares, time) VALUES (:i, :sy, :p, :sh, datetime('now', 'localtime'))", i=session["user_id"], sy=sym, p=pr, sh=qty)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    rows=db.execute("SELECT * FROM history WHERE id = :i", i=session["user_id"])
    return render_template("history.html", rows=rows)



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
    if request.method=="POST":
        quote = lookup(request.form.get("symbol"))
        if quote == None:
            return apology("invalid symbol", 400)
        else:
            return render_template("quoted.html",quote=quote)
    else:
        return render_template("quote.html")

##personal touch##

@app.route("/changepass", methods=["GET", "POST"])
@login_required
def change():
    if request.method=="POST":
        if not request.form.get("oldpass") or not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Fill up the form again", 400)
        rows=db.execute("SELECT * FROM users WHERE id=:i", i = session["user_id"])
        if not check_password_hash(rows[0]["hash"], request.form.get("oldpass")):
            return apology("wrong password", 400)
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match")
        db.execute("UPDATE users SET hash = :h WHERE id=:i", h = generate_password_hash(request.form.get("password")), i=session["user_id"])
        return redirect("/")

    else:
        return render_template("change.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords don't match", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(rows) != 0:
            return apology("Username already exists", 403)

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :h)",
            username=request.form.get("username"), h = generate_password_hash(request.form.get("password")))
            return redirect("/")
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method=="POST":
        k = db.execute("SELECT * FROM shares WHERE user_id = :u AND symbol=:s", u=session["user_id"], s=request.form.get("symbol"))
        if int(request.form.get("shares")) > k[0]["n"]:
            return apology("Not enough stocks", 400)
        q = db.execute("SELECT * FROM users WHERE id = :i", i=session["user_id"])
        c = q[0]["cash"]
        price = lookup(request.form.get("symbol"))["price"]
        pr = price

        price = price * float(request.form.get("shares"))
        c = c + price
        sy = lookup(request.form.get("symbol"))["symbol"]
        sh = int(request.form.get("shares"))
        sh = sh*(-1)
        db.execute("UPDATE users SET cash = :cas WHERE id = :i", cas=c, i=session["user_id"])
        db.execute("UPDATE shares SET n = :ne WHERE user_id = :i AND symbol=:sym",ne = k[0]["n"] - int(request.form.get("shares")), i = session["user_id"], sym=request.form.get("symbol"))
        db.execute("INSERT INTO history (id, symbol, price, shares, time) VALUES (:i, :sy, :pr, :sh, datetime('now', 'localtime'))",i = session["user_id"], sy=sy,pr=pr, sh=sh)
        return redirect("/")

    else:
        rows=db.execute("SELECT * FROM shares WHERE user_id = :i AND n>0", i = session["user_id"])
        return render_template("sell.html", rows=rows)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
