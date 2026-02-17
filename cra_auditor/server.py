from flask import Flask, jsonify, request, send_from_directory
import logging
import os
import re
import threading
import time
import sqlite3
import json
from datetime import datetime
from scan_logic import CRAScanner

# Configure logging (replaces print() for structured HA output)
logger = logging.getLogger(__name__)

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
        logger.warning("Frontend directory not found.")
        FRONTEND_DIR = None

# Global State
scanner = CRAScanner()
DB_FILE = "scans.db"

FEATURE_FLAG_KEYS = {
    "network_discovery",
    "port_scan",
    "os_detection",
    "service_version",
    "netbios_info",
    "compliance_checks",
    "auth_brute_force",
    "web_crawling",
}


def normalize_scan_options(payload):
    """Normalize legacy and new scan option styles into a single options object."""
    payload = payload or {}
    raw_options = payload.get('options', {})
    if not isinstance(raw_options, dict):
        raw_options = {}

    normalized = dict(raw_options)

    requested_profile = (
        payload.get('scan_type')
        or payload.get('type')
        or raw_options.get('profile')
        or raw_options.get('scan_type')
        or raw_options.get('type')
    )

    # Legacy booleans from early frontend iterations.
    if raw_options.get('discovery') is True:
        requested_profile = 'discovery'
    elif raw_options.get('standard') is True:
        requested_profile = 'standard'
    elif raw_options.get('deep') is True:
        requested_profile = 'deep'

    profile_name = str(requested_profile or 'deep').lower()
    normalized['profile'] = profile_name
    normalized['scan_type'] = profile_name

    raw_feature_map = raw_options.get('features')
    if not isinstance(raw_feature_map, dict):
        raw_feature_map = {}

    merged_features = dict(raw_feature_map)
    for key in FEATURE_FLAG_KEYS:
        value = None
        if key in raw_options:
            value = raw_options.get(key)
        elif key in raw_feature_map:
            value = raw_feature_map.get(key)

        if isinstance(value, bool):
            merged_features[key] = value

    if 'port_range' in raw_options:
        merged_features['port_range'] = raw_options.get('port_range')
    elif 'port_range' in raw_feature_map:
        merged_features['port_range'] = raw_feature_map.get('port_range')

    if merged_features:
        normalized['features'] = merged_features

    return normalized

def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_range TEXT NOT NULL,
            summary TEXT NOT NULL,
            full_report TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            is_scanning INTEGER NOT NULL DEFAULT 0,
            scan_error TEXT
        )
    ''')
    c.execute('INSERT OR IGNORE INTO scan_state (id, is_scanning) VALUES (1, 0)')
    conn.commit()
    conn.close()

def reset_scan_state():
    """Reset scan state on startup to clear zombie states from crashes."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('UPDATE scan_state SET is_scanning = 0, scan_error = NULL WHERE id = 1')
        conn.commit()

def try_claim_scan() -> bool:
    """Atomically try to claim the scan lock. Returns True if acquired."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.execute(
            'UPDATE scan_state SET is_scanning = 1, scan_error = NULL WHERE id = 1 AND is_scanning = 0'
        )
        conn.commit()
        return c.rowcount > 0

def get_scan_state() -> dict:
    """Read the current scan state from the database."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT is_scanning, scan_error FROM scan_state WHERE id = 1').fetchone()
    if row:
        return {"scanning": bool(row['is_scanning']), "error": row['scan_error']}
    return {"scanning": False, "error": None}

def set_scan_state(scanning: bool, error: str = None):
    """Update the scan state in the database."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            'UPDATE scan_state SET is_scanning = ?, scan_error = ? WHERE id = 1',
            (int(scanning), error)
        )
        conn.commit()

# Initialize DB and reset zombie state on startup
init_db()
reset_scan_state()

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

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON body"}), 400
    subnet = data.get('subnet')
    options = normalize_scan_options(data)
    
    if not subnet:
        return jsonify({"status": "error", "message": "Subnet required"}), 400
    
    # Basic CIDR/IP validation
    if not re.match(r'^[\d./\-]+$', subnet):
        return jsonify({"status": "error", "message": "Invalid subnet format"}), 400
    
    # Atomic lock: only one scan at a time across all workers
    if not try_claim_scan():
        return jsonify({"status": "error", "message": "Scan already in progress"}), 409
    
    thread = threading.Thread(target=run_scan_background, args=(subnet, options))
    thread.start()
    return jsonify({"status": "success", "message": "Scan started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    state = get_scan_state()
    result = {"scanning": state["scanning"]}
    if state["error"]:
        result["error"] = state["error"]
    return jsonify(result)

@app.route('/api/config', methods=['GET'])
def get_config():
    """
    Returns frontend configuration flags.
    NEVER return the actual API key here.
    """
    has_gemini = bool(os.environ.get('GEMINI_API_KEY'))
    has_nvd = bool(os.environ.get('NVD_API_KEY'))
    return jsonify({
        "gemini_enabled": has_gemini,
        "nvd_enabled": has_nvd,
        "version": "1.0.9"
    })

@app.route('/api/report', methods=['GET'])
def get_latest_report():
    """Get the most recent report from the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute('SELECT full_report FROM scan_history ORDER BY id DESC LIMIT 1')
            row = c.fetchone()
        if row:
            return jsonify(json.loads(row[0]))
        return jsonify(None)
    except sqlite3.Error as e:
        logger.error(f"Error fetching latest report: {e}")
        return jsonify({"error": "Database error"}), 500
@app.route('/api/history', methods=['GET'])
def get_history():
    """Get list of past scans with search and sort."""
    search_query = request.args.get('search', '').strip()
    # Whitelist sort_by to prevent SQL injection (user input goes into query)
    ALLOWED_SORT = {'timestamp': 'timestamp', 'target': 'target_range'}
    sort_by = ALLOWED_SORT.get(request.args.get('sort_by', 'timestamp'), 'timestamp')
    order = 'ASC' if request.args.get('order', 'desc').lower() == 'asc' else 'DESC'

    query = 'SELECT id, timestamp, target_range, summary FROM scan_history'
    params = []
    
    if search_query:
        query += ' WHERE target_range LIKE ?'
        params.append(f'%{search_query}%')
    
    query += f' ORDER BY {sort_by} {order}'

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(query, params)
            rows = c.fetchall()
        
        history = []
        for row in rows:
            history.append({
                "id": row['id'],
                "timestamp": row['timestamp'],
                "target_range": row['target_range'],
                "summary": json.loads(row['summary'])
            })
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_history_detail(scan_id):
    """Get full report for a specific scan."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute('SELECT full_report FROM scan_history WHERE id = ?', (scan_id,))
            row = c.fetchone()
        
        if row:
            return jsonify(json.loads(row[0]))
        return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_history_item(scan_id):
    """Delete a scan from history."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM scan_history WHERE id = ?', (scan_id,))
            conn.commit()
            deleted = c.rowcount > 0
        
        if deleted:
            return jsonify({"status": "success"})
        return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_scan_background(subnet, options=None):
    scan_type = (options or {}).get('profile') or (options or {}).get('scan_type', 'deep')
    logger.info(f"[SCAN] Background scan starting: subnet={subnet}, type={scan_type}")
    bg_start = time.time()
    try:
        devices = scanner.scan_subnet(subnet, options)
        
        # Calculate summary
        total = len(devices)
        compliant = sum(1 for d in devices if d['status'] == 'Compliant')
        warning = sum(1 for d in devices if d['status'] == 'Warning')
        non_compliant = sum(1 for d in devices if d['status'] == 'Non-Compliant')

        summary = {
            "total": total,
            "compliant": compliant,
            "warning": warning,
            "nonCompliant": non_compliant
        }

        report = {
            "timestamp": datetime.now().isoformat(),
            "targetRange": subnet,
            "devices": devices,
            "summary": summary
        }
        
        # Save to DB
        try:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO scan_history (timestamp, target_range, summary, full_report)
                    VALUES (?, ?, ?, ?)
                ''', (report['timestamp'], subnet, json.dumps(summary), json.dumps(report)))
                conn.commit()
                last_id = c.lastrowid
            elapsed = time.time() - bg_start
            logger.info(
                f"[SCAN] Scan saved to DB (ID: {last_id}). "
                f"Total: {total} devices ({compliant}C/{warning}W/{non_compliant}NC) in {elapsed:.1f}s"
            )
        except Exception as db_err:
            logger.error(f"[SCAN] Failed to save scan to DB: {db_err}")

    except Exception as e:
        logger.error(f"[SCAN] Scan failed: {e}")
        set_scan_state(False, error=str(e))
    else:
        set_scan_state(False)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099)  # Gunicorn takes over in production via run.sh