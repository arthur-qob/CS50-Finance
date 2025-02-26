import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters['usd'] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL('sqlite:///finance.db')


@app.after_request
def after_request(response):
    '''Ensure responses aren't cached'''
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/')
@login_required
def index():
    '''Show portfolio of stocks'''

    user_id = session['user_id']

    user_transactions = db.execute('''
                           SELECT *
                           FROM transactions
                           WHERE user_id = ?
                           ''', user_id)

    user_cash = db.execute('''
                           SELECT cash
                           FROM users
                           WHERE id = ?
                           ''', user_id)

    total_purch = []
    price = 0
    all_purch = 0
    for r in user_transactions:
        price = ''.join(c for c in r['price'] if c.isdigit() or c == '.')
        total_purch.append(float(price) * r['shares'])

    for r in total_purch:
        all_purch += r

    return render_template('index.html', transactions = user_transactions, total_1 = total_purch, total_2 = usd(all_purch), price = price, cash = usd(user_cash[0]['cash']))


@app.route('/buy', methods = ['GET', 'POST'])
@login_required
def buy():
    '''Buy shares of stock'''

    if request.method == 'POST':
        user_id = session['user_id']

        sbl = request.form.get('symbol')
        shrs = request.form.get('shares')

        if not sbl:
            return apology('Symbol field must be filled')

        if not shrs:
            return apology('Shares field must be filled')

        qte = lookup(sbl.upper())

        if qte == None:
            return apology('Symbol could not be found')

        del sbl

        if not shrs.isdigit() or int(shrs) < 0:
            return apology('Number of shares must be an integer')

        transaction_value = float(shrs) * qte['price']

        user_cash = db.execute('''
                               SELECT cash
                               FROM users
                               WHERE id = ?
                               ''', user_id)

        if user_cash[0]['cash'] < transaction_value:
            return apology('Not enough funds')

        else:
            transactionDate = datetime.datetime.now()

            db.execute('''
                       INSERT INTO transactions (user_id, name, symbol, shares, price, date)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ''', user_id, qte['name'], qte['symbol'], shrs, usd(qte['price']), transactionDate)

            updt_cash = float(user_cash[0]['cash']) - transaction_value

            db.execute('''
                       UPDATE users
                       SET cash = ?
                       WHERE id = ?
                       ''', updt_cash, user_id)

            if int(shrs) > 1:
                flash(f"Bought {shrs} shares of {qte['name']} for a total of {usd(transaction_value)} ({usd(qte['price'])} each)!")

            else:
                flash(f"Bought {shrs} share of {qte['name']} for {usd(transaction_value)}!")

            return redirect('/')

    else:
        return render_template('buy.html')


@app.route('/history')
@login_required
def history():
    '''Show history of transactions'''
    user_id = session['user_id']

    all_transactions = db.execute('''
                                  SELECT *
                                  FROM transactions
                                  WHERE id = ?
                                  ''', user_id)

    return render_template('history.html', transactions = all_transactions)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    '''Log user in'''

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form.get('username'):
            return apology('must provide username', 403)

        # Ensure password was submitted
        elif not request.form.get('password'):
            return apology('must provide password', 403)

        # Query database for username
        rows = db.execute('SELECT * FROM users WHERE username = ?', request.form.get('username'))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]['hash'], request.form.get('password')):
            return apology('invalid username and/or password', 403)

        # Remember which user has logged in
        session['user_id'] = rows[0]['id']

        # Redirect user to home page
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    '''Log user out'''

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect('/')


@app.route('/quote', methods = ['GET', 'POST'])
@login_required
def quote():
    '''Get stock quote.'''

    if request.method == 'POST':
        sbl = request.form.get('symbol')

        if not sbl:
            return apology('Symbol field must be filled')

        qte = lookup(sbl.upper())

        if qte == None:
            return apology('Symbol not found')

        return render_template('quote.html', quote = qte)

    else:
        return render_template('quote.html')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    '''Register user'''

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confPsswd = request.form.get('confirmation')

        if not username:
            return apology('Username field must be filled')

        elif not password:
            return apology('Password field must be filled!')

        elif not confPsswd:
            return apology('Must confirm password!')

        elif password != confPsswd:
            return apology('Passwords do not match')

        else:
            psswd_hash = generate_password_hash(password)

            try:
                user_session = db.execute('''
                        INSERT INTO users (username, hash)
                        VALUES (?, ?)
                        ''', username, psswd_hash)
            except:
                return apology('Username already being used')

            session['user_id'] = user_session

            return redirect('/')

    else:
        return render_template('register.html')


@app.route('/sell', methods = ['GET', 'POST'])
@login_required
def sell():
    '''Sell shares of stock'''

    if request.method == 'POST':
        user_id = session['user_id']

        sbl = request.form.get('symbol')
        shrs = request.form.get('shares')

        if not sbl:
            return apology('Symbol field must be filled')

        if not shrs:
            return apology('Shares field must be filled')

        if not sbl and not shrs:
            return apology('All fields must be filled')

        shrs = int(shrs)

        num_shrs = db.execute('''
                              SELECT shares
                              FROM transactions
                              WHERE user_id = ? AND
                              symbol = ?
                              ''', user_id, sbl)

        num_shrs = num_shrs[0]['shares']

        if not isinstance(shrs, int):
            return apology('Number of shares must be an integer')

        if shrs > int(num_shrs):
            return apology('You do not own as many shares')

        qte = lookup(sbl.upper())

        if qte == None:
            return apology('Symbol could not be found')

        del sbl

        transaction_value = float(shrs) * qte['price']

        user_cash = db.execute('''
                               SELECT cash
                               FROM users
                               WHERE id = ?
                               ''', user_id)

        transactionDate = datetime.datetime.now()

        db.execute('''
                    INSERT INTO transactions (user_id, name, symbol, shares, price, date)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''', user_id, qte['name'], qte['symbol'], shrs * (-1), usd(qte['price']), transactionDate)

        updt_cash = float(user_cash[0]['cash']) + transaction_value

        db.execute('''
                    UPDATE users
                    SET cash = ?
                    WHERE id = ?
                    ''', updt_cash, user_id)

        db.execute('''
                   UPDATE transactions
                   SET shares = ?
                   WHERE user_id = ?
                   ''', shrs, user_id)

        if int(shrs) > 1:
            flash(f"Sold {shrs} shares of {qte['name']} for a total of {usd(transaction_value)} ({usd(qte['price'])} each)!")

        else:
            flash(f"Sold {shrs} share of {qte['name']} for {usd(transaction_value)}!")

        return redirect('/')

    else:
        user_id = session['user_id']

        user_sbls = db.execute('''
                               SELECT symbol
                               FROM transactions
                               WHERE user_id = ?
                               GROUP BY symbol
                               ''', user_id)

        list_user_sbls = []
        for s in user_sbls:
            list_user_sbls.append(s['symbol'])

        return render_template('sell.html', sbls = list_user_sbls)


@app.route('/wallet', methods = ['GET', 'POST'])
@login_required
def wallet():

    '''Allows user to manage his wallet'''

    if request.method == 'POST':
        user_id = session['user_id']

        cash_add = request.form.get('cash_add')
        cash_ext = request.form.get('cash_ext')

        user_cash = db.execute('''
                               SELECT cash
                               FROM users
                               WHERE id = ?
                               ''', user_id)

        if cash_add:
            cash_updt = user_cash + cash_add

            db.execute('''
                       UPDATE users
                       SET cash = ?
                       WHERE id = ?
                       ''', cash_updt, user_id)

            flash(f'Deposited {cash_add} into account')

        elif cash_ext:
            cash_updt = user_cash - cash_ext

            db.execute('''
                       UPDATE users
                       SET cash = ?
                       WHERE id = ?
                       ''', cash_updt, user_id)

            flash(f'Extracted {cash_ext} from account')

        else:
            return apology('One of the fields must be filled')

    else:
        user_id = session['user_id']

        user_cash = db.execute('''
                               SELECT cash
                               FROM users
                               WHERE id = ?
                               ''', user_id)

        user_cash = user_cash[0]['cash']

        return render_template('wallet.html', cash = user_cash)