from flask import Flask, request, render_template
from wakeonlan import send_magic_packet

app = Flask(__name__)

# --- Configuration ---
TARGET_MAC_ADDRESS = 'YOUR_SERVER_MAC_ADDRESS'  # Replace with the actual MAC address of your SMB server
# --- End Configuration ---

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/wol', methods=['POST'])
def wake_server():
    try:
        send_magic_packet(TARGET_MAC_ADDRESS)
        message = f"Wake-on-LAN packet sent to {TARGET_MAC_ADDRESS}"
        success = True
    except Exception as e:
        message = f"Error sending packet: {e}"
        success = False
    return render_template('result.html', message=message, success=success)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
