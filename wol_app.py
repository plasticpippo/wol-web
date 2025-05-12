from flask import Flask, request, render_template, abort, redirect, url_for, Response
from wakeonlan import send_magic_packet
import os
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# --- Configuration ---
TARGET_MAC_ADDRESSES = os.environ.get('TARGET_MAC_ADDRESSES')
if not TARGET_MAC_ADDRESSES:
    TARGET_MAC_ADDRESSES = ""
MAC_ADDRESSES = [mac.strip() for mac in TARGET_MAC_ADDRESSES.split(',')]
WOL_USERNAME = os.environ.get('WOL_USERNAME')
WOL_PASSWORD = os.environ.get('WOL_PASSWORD')
if not WOL_USERNAME or not WOL_PASSWORD:
    raise ValueError("WOL_USERNAME and WOL_PASSWORD environment variables must be set")
# --- End Configuration ---

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
        auth = request.authorization
        if not auth or not check_password_hash(WOL_PASSWORD, auth.password) or auth.username != WOL_USERNAME:
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# --- End Authentication ---

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
    app.run(host='0.0.0.0', port=8888, debug=True)
