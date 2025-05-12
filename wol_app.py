from flask import Flask, request, render_template, abort, redirect, url_for, Response, session, g, current_app
from wakeonlan import send_magic_packet
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Set a secret key for the session

# --- Configuration ---
TARGET_MAC_ADDRESSES = os.environ.get('TARGET_MAC_ADDRESSES')
if not TARGET_MAC_ADDRESSES:
    TARGET_MAC_ADDRESSES = ""
MAC_ADDRESSES = [mac.strip() for mac in TARGET_MAC_ADDRESSES.split(',')]
DATABASE_FILE = '/data/wol.db'  # Path to the SQLite database file
# --- End Configuration ---

# --- Database Functions ---
def get_db():
    """Opens a database connection if there isn't one yet for the current application context."""
    if 'sqlite_db' not in g:
        g.sqlite_db = sqlite3.connect(DATABASE_FILE)
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request or the application."""
    if 'sqlite_db' in g:
        g.sqlite_db.close()

def init_db():
    """Initializes the database with the user table."""
    with current_app.app_context(): # Wrap the database operations
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    """Queries the database and returns the results."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if one:
        if 'COUNT(*)' in query:
            return rv[0][0] if rv else 0  # Return the count directly
        else:
            return dict(zip([column[0] for column in cur.description], rv[0])) if rv else None
    else:
        return [dict(zip([column[0] for column in cur.description], row)) for row in rv]


def commit_db():
    """Commits changes to the database."""
    db = get_db()
    db.commit()
# --- End Database Functions ---

# --- Authentication ---
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def get_user_by_username(username):
    """Gets a user from the database by username."""
    return query_db('SELECT * FROM user WHERE username = ?', [username], one=True)

def create_user(username, password):
    """Creates a new user in the database."""
    hashed_password = generate_password_hash(password)
    db = get_db()
    db.execute('INSERT INTO user (username, password) VALUES (?, ?)', [username, hashed_password])
    db.commit()
    return get_user_by_username(username)

def check_first_run():
    """Checks if this is the first time the application is run."""
    return query_db('SELECT COUNT(*) FROM user', one=True)[0] == 0

# --- End Authentication ---

@app.before_request
def before_request():
    """Called before each request to handle setup and authentication."""
    if check_first_run():
        if request.endpoint != 'setup' and request.endpoint != 'static': # Allow access to the setup route and static files
            return redirect(url_for('setup'))
    else:
        if 'user_id' not in session and request.endpoint != 'login' and request.endpoint != 'static': #  Allow access to the login route and static files.
            return authenticate()

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Handles the first-time setup: creates the admin user."""
    if not check_first_run():
        return redirect(url_for('index'))  # Redirect if setup is already done

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            return render_template('setup.html', error='Username and password are required')
        user = create_user(username, password)
        session['user_id'] = user['id']
        return redirect(url_for('index'))
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
@requires_auth
def index():
    return render_template('index.html', mac_addresses=MAC_ADDRESSES)

@app.route('/wol', methods=['POST'])
@requires_auth
def wake_server():
    mac_address = request.form.get('mac_address')
    if not mac_address:
        return render_template('result.html', message="No MAC address selected", success=False)
    if mac_address not in MAC_ADDRESSES:
        abort(400, f"Invalid MAC address: {mac_address}")
    try:
        send_magic_packet(mac_address)
        message = f"Wake-on-LAN packet sent to {mac_address}"
        success = True
    except Exception as e:
        message = f"Error sending packet: {e}"
        success = False
    return render_template('result.html', message=message, success=success)

if __name__ == '__main__':
    # Ensure the database exists
    with app.app_context():
        init_db()  # Initialize the database
    app.run(host='0.0.0.0', port=8888, debug=True) # make sure this is 8888