import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import re
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
#Info de la db de shares
 shares=db.execute("SELECT name_share, symbol ,SUM(num_share) AS num_share, price_share FROM shares WHERE user_id=? GROUP BY symbol;"
                      ,session["user_id"])
 #Dinero de users
 cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])[0]['cash']
 Total = 0
 for share in shares:
  Total+= round(share["price_share"]*share["num_share"],2)
 return render_template("index.html",shares=shares,cash=cash, total=Total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
 if request.method == "GET":
    return render_template("buy.html")
 else:
      item=lookup(request.form.get("symbol"))
      if item == None:
          return apology("Must use a valid symbol")

      shares =request.form.get("shares")
      if not shares:
       return apology("Must enter number of shares")
      elif not shares.isdigit() or int(shares) <= 0:
       return apology("Invalid number of shares")
      price = item["price"]
      user_id=session["user_id"]
      rows = db.execute("SELECT * FROM users WHERE id = ?;", user_id)
      # Usar solo la columna que contiene el dinero
      user_cash = rows[0]["cash"]
      new_balance = user_cash - (price*int(request.form.get("shares")))
      if new_balance < 0:
            return apology("not enough money")

      else:
            db.execute("INSERT INTO transactions(user_id, symbol, num_share, price_share, date, transaction_type) VALUES (?, ?, ?, ?, ?, 'bought')",
                   user_id,item["symbol"] ,shares, price, datetime.datetime.now())
            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance,user_id)
            db.execute("INSERT INTO shares (user_id, symbol, name_share, num_share,price_share, date) VALUES(?, ?, ?, ?, ?,?)"
            ,user_id , item["symbol"], item["name"],shares, price, datetime.datetime.now())
      flash("Successufully purchased action")

      return redirect("/")

@app.route("/history")
@login_required
def history():
 user_id=session["user_id"]
 transactions = db.execute("SELECT * FROM transactions  WHERE user_id=?",user_id)
 return render_template("history.html", transactions=transactions)



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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
 if request.method == "POST":

      symbol= request.form.get("symbol")

      if symbol==None:
          return apology("Must type a symbol")
      item = lookup(symbol)
      if item == None:
          return apology(f"Must type a valid symbol {symbol}")

      return render_template("quoted.html",name=item["name"], price=item["price"], sym=item["symbol"])
 else:
    return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
 if request.method == "POST":
    password = request.form.get("password")
    username = request.form.get("username")
    confirmation = request.form.get("confirmation")
    rows = db.execute("SELECT * FROM users WHERE username = ?", username)

    # Ensure username and password were submitted
    if not username:
        return apology("Must use a username")
    elif not password:
        return apology("Must provide a password")

    # Ensure passwords match
    elif not confirmation:
        return apology("Must fill password confirmation")
    elif confirmation != password:
        return apology("Password and password confirmation do not match")

    # Validate password complexity
    if not is_password_complex(password):
        return apology("Password must contain at least one letter, one number, and one symbol")

    # Check if username is already in use
    elif len(rows) > 0:
        return apology("Username already in use")

    else:
        # Hash the password and store the hashed password
        hashedp = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashedp)

        # Retrieve the inserted user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]

        flash("Registered!")
        return redirect("/")
 else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
 if request.method == "GET":
        # Get a list of the symbols the user owns and pass them to the sell form
        user_id = session["user_id"]
        rows = db.execute("SELECT symbol FROM shares WHERE user_id = ? GROUP BY symbol", user_id)
        symbols = [row["symbol"] for row in rows]
        return render_template("sell.html", symbols=symbols)
 else:
        # Get the symbol, number of shares, and user ID from the form submission
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        user_id = session["user_id"]

        # Ensure symbol and shares were submitted
        if not symbol:
            return apology("Must select a symbol")
        if not shares:
            return apology("Must enter number of shares")

        # Ensure shares is a positive integer
        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares must be a positive integer")

        # Look up the current price of the stock
        item = lookup(symbol)
        if item is None:
            return apology("Invalid symbol")

        # Get the user's current shares of the stock
        rows = db.execute("SELECT * FROM shares WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(rows) == 0:
            return apology("You do not own any shares of this stock")
        user_shares = sum(row["num_share"] for row in rows)

        # Ensure the user has enough shares to sell
        if user_shares < shares:
            return apology("You do not own that many shares of this stock")

        # Calculate the total value of the shares being sold
        price = item["price"]
        total = price * shares

        # Update the user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total, user_id)

        # Update the shares table
        if user_shares == shares:
            # Delete the entire row if the user is selling all of their shares
            db.execute("DELETE FROM shares WHERE user_id = ? AND symbol = ?", user_id, symbol)
        else:
            # Update the row with the new number of shares
            db.execute("UPDATE shares SET num_share = ? WHERE user_id = ? AND symbol = ?", user_shares - shares, user_id, symbol)

        # Log the transaction
        db.execute("INSERT INTO transactions(user_id, symbol, num_share, price_share, date, transaction_type) VALUES (?, ?, ?, ?, ?, 'sold')",
                   user_id, symbol, -shares, price, datetime.datetime.now())
        return redirect("/")


        flash(f"Sold {shares} shares of {symbol} for {usd(total)}")
def is_password_complex(password):
    pattern = r"^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
    if re.match(pattern, password):
        return True
    else:
        return False
