from flask import Flask, jsonify, request, send_from_directory
import os
import threading
import time
import sqlite3
import json
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
is_scanning = False
scanner = CRAScanner()
DB_FILE = "scans.db"

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
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

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
    options = data.get('options', {}) # Extract options
    
    if not subnet:
        return jsonify({"status": "error", "message": "Subnet required"}), 400

    thread = threading.Thread(target=run_scan_background, args=(subnet, options))
    thread.start()
    return jsonify({"status": "success", "message": "Scan started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({"scanning": is_scanning})

@app.route('/api/config', methods=['GET'])
def get_config():
    """
    Returns frontend configuration flags.
    NEVER return the actual API key here.
    """
    has_gemini = bool(os.environ.get('GEMINI_API_KEY'))
    return jsonify({
        "gemini_enabled": has_gemini,
        "version": "1.0.9"
    })

@app.route('/api/report', methods=['GET'])
def get_latest_report():
    """Get the most recent report from the database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT full_report FROM scan_history ORDER BY id DESC LIMIT 1')
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify(json.loads(row[0]))
        return jsonify(None)
    except Exception as e:
        print(f"Error fetching latest report: {e}")
        return jsonify(None), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get list of past scans with search and sort."""
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'timestamp') # timestamp, target
    order = request.args.get('order', 'desc') # asc, desc

    query = 'SELECT id, timestamp, target_range, summary FROM scan_history'
    params = []
    
    if search_query:
        query += ' WHERE target_range LIKE ?'
        params.append(f'%{search_query}%')
    
    if sort_by == 'target':
        query += ' ORDER BY target_range'
    else:
        query += ' ORDER BY timestamp'
        
    if order == 'asc':
        query += ' ASC'
    else:
        query += ' DESC'

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
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
        print(f"Error fetching history: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_history_detail(scan_id):
    """Get full report for a specific scan."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT full_report FROM scan_history WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()
        
        if row:
            return jsonify(json.loads(row[0]))
        return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_history_item(scan_id):
    """Delete a scan from history."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('DELETE FROM scan_history WHERE id = ?', (scan_id,))
        conn.commit()
        deleted = c.rowcount > 0
        conn.close()
        
        if deleted:
            return jsonify({"status": "success"})
        return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_scan_background(subnet, options=None):
    global is_scanning
    is_scanning = True
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
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('''
                INSERT INTO scan_history (timestamp, target_range, summary, full_report)
                VALUES (?, ?, ?, ?)
            ''', (report['timestamp'], subnet, json.dumps(summary), json.dumps(report)))
            conn.commit()
            conn.close()
            print(f"Scan finished and saved to DB. ID: {c.lastrowid}")
        except Exception as db_err:
            print(f"Failed to save scan to DB: {db_err}")

    except Exception as e:
        print(f"Scan failed: {e}")
    finally:
        is_scanning = False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099)