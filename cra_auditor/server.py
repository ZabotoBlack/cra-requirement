from flask import Flask, jsonify, request, send_from_directory
import os
import threading
import time
from datetime import datetime
from scan_logic import CRAScanner

app = Flask(__name__)

# Configuration
# Auto-detect the correct frontend build folder
FRONTEND_DIR = "/app/dist"
if not os.path.exists(FRONTEND_DIR):
    if os.path.exists("/app/build"):
        FRONTEND_DIR = "/app/build"
    elif os.path.exists("dist"): # Local dev fallback
        FRONTEND_DIR = os.path.abspath("dist")
    else:
        print("Warning: Frontend directory not found.")
        FRONTEND_DIR = None

# Global State
latest_report = None
is_scanning = False
scanner = CRAScanner()

@app.route('/')
def index():
    if FRONTEND_DIR:
        return send_from_directory(FRONTEND_DIR, 'index.html')
    return "Backend Running. Frontend not found.", 404

@app.route('/<path:path>')
def serve_static(path):
    if FRONTEND_DIR and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    # SPA Fallback
    if FRONTEND_DIR:
        return send_from_directory(FRONTEND_DIR, 'index.html')
    return "File not found", 404

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global is_scanning
    if is_scanning:
        return jsonify({"status": "error", "message": "Scan already in progress"}), 409
    
    data = request.json
    subnet = data.get('subnet')
    if not subnet:
        return jsonify({"status": "error", "message": "Subnet required"}), 400

    thread = threading.Thread(target=run_scan_background, args=(subnet,))
    thread.start()
    return jsonify({"status": "success", "message": "Scan started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({"scanning": is_scanning})

@app.route('/api/report', methods=['GET'])
def get_report():
    if latest_report:
        return jsonify(latest_report)
    return jsonify(None)

def run_scan_background(subnet):
    global is_scanning, latest_report
    is_scanning = True
    try:
        devices = scanner.scan_subnet(subnet)
        
        # Calculate summary
        total = len(devices)
        compliant = sum(1 for d in devices if d['status'] == 'Compliant')
        warning = sum(1 for d in devices if d['status'] == 'Warning')
        non_compliant = sum(1 for d in devices if d['status'] == 'Non-Compliant')

        latest_report = {
            "timestamp": datetime.now().isoformat(),
            "targetRange": subnet,
            "devices": devices,
            "summary": {
                "total": total,
                "compliant": compliant,
                "warning": warning,
                "nonCompliant": non_compliant
            }
        }
        print(f"Scan finished. Report generated with {total} devices.")
    except Exception as e:
        print(f"Scan failed: {e}")
    finally:
        is_scanning = False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099)