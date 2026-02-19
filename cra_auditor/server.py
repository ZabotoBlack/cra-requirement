from flask import Flask, jsonify, request, send_from_directory
from collections import deque
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shutil
import socket
import threading
import time
import sqlite3
import json
import ipaddress
import requests
from datetime import datetime
from pathlib import Path
from scan_logic import CRAScanner

# Configure logging (replaces print() for structured HA output)
logger = logging.getLogger(__name__)

LOG_BUFFER: deque[str] = deque(maxlen=300)


def _resolve_runtime_log_file() -> Path:
    env_dir = os.environ.get("CRA_DATA_DIR")
    if env_dir:
        return Path(env_dir) / "cra_auditor.log"

    container_data = Path("/data")
    if container_data.exists() and container_data.is_dir():
        return container_data / "cra_auditor.log"

    return Path(__file__).resolve().parent / "cra_auditor.log"


RUNTIME_LOG_FILE = _resolve_runtime_log_file()


class InMemoryLogHandler(logging.Handler):
    def emit(self, record):
        try:
            LOG_BUFFER.append(self.format(record))
        except Exception:
            pass


def _configure_log_buffer() -> None:
    root_logger = logging.getLogger()
    if any(isinstance(handler, InMemoryLogHandler) for handler in root_logger.handlers):
        return

    try:
        RUNTIME_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    try:
        if not any(
            isinstance(handler, RotatingFileHandler)
            and Path(getattr(handler, "baseFilename", "")).resolve() == RUNTIME_LOG_FILE.resolve()
            for handler in root_logger.handlers
        ):
            file_handler = RotatingFileHandler(
                RUNTIME_LOG_FILE,
                maxBytes=1_500_000,
                backupCount=1,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
            root_logger.addHandler(file_handler)
    except Exception:
        pass

    buffer_handler = InMemoryLogHandler()
    buffer_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    root_logger.addHandler(buffer_handler)

    if root_logger.level in (logging.NOTSET, logging.WARNING):
        root_logger.setLevel(logging.INFO)


def _subnet_from_ip(ip_address: str, prefix: int = 24) -> str | None:
    try:
        interface = ipaddress.ip_interface(f"{ip_address}/{prefix}")
        return str(interface.network)
    except ValueError:
        return None


def _subnet_from_cidr(cidr: str) -> str | None:
    try:
        interface = ipaddress.ip_interface(cidr)
        if interface.version != 4:
            return None
        return str(interface.network)
    except ValueError:
        return None


def _subnet_from_ip_mask(ip_address: str, mask: str | int) -> str | None:
    try:
        network = ipaddress.ip_network(f"{ip_address}/{mask}", strict=False)
        if network.version != 4:
            return None
        return str(network)
    except ValueError:
        return None


def _extract_ipv4_subnet_from_structure(payload) -> str | None:
    if payload is None:
        return None

    stack = [payload]
    while stack:
        current = stack.pop()

        if isinstance(current, str):
            if '/' in current:
                subnet = _subnet_from_cidr(current.strip())
                if subnet:
                    return subnet
            continue

        if isinstance(current, list):
            stack.extend(reversed(current))
            continue

        if not isinstance(current, dict):
            continue

        network_value = current.get('network')
        if isinstance(network_value, str):
            try:
                parsed_network = ipaddress.ip_network(network_value.strip(), strict=False)
                if parsed_network.version == 4:
                    return str(parsed_network)
            except ValueError:
                pass

        ip_candidate = None
        for key in ('address', 'ip', 'local', 'host'):
            value = current.get(key)
            if isinstance(value, str):
                ip_candidate = value.strip()
                break

        if ip_candidate:
            if '/' in ip_candidate:
                subnet = _subnet_from_cidr(ip_candidate)
                if subnet:
                    return subnet
            else:
                for mask_key in ('prefix', 'prefixlen', 'cidr', 'netmask', 'mask'):
                    mask_value = current.get(mask_key)
                    if isinstance(mask_value, (int, str)):
                        subnet = _subnet_from_ip_mask(ip_candidate, mask_value)
                        if subnet:
                            return subnet

        for nested_key in ('ipv4', 'addresses', 'address', 'addr_info', 'configuration'):
            if nested_key in current:
                stack.append(current[nested_key])

    return None


def _detect_home_assistant_primary_subnet() -> str | None:
    supervisor_token = os.environ.get('SUPERVISOR_TOKEN')
    if not supervisor_token:
        return None

    headers = {
        'Authorization': f'Bearer {supervisor_token}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get('http://supervisor/network/info', headers=headers, timeout=5)
        if response.status_code != 200:
            logger.debug(f"[NET] Supervisor network info returned {response.status_code}")
            return None

        raw_payload = response.json()
    except Exception as exc:
        logger.debug(f"[NET] Failed to fetch Supervisor network info: {exc}")
        return None

    payload = raw_payload.get('data') if isinstance(raw_payload, dict) else raw_payload
    if not isinstance(payload, dict):
        return None

    interfaces = payload.get('interfaces')
    if isinstance(interfaces, dict):
        interface_items = list(interfaces.values())
    elif isinstance(interfaces, list):
        interface_items = interfaces
    else:
        interface_items = []

    primary_items = [
        item for item in interface_items
        if isinstance(item, dict) and (item.get('primary') is True or item.get('default') is True)
    ]

    for candidate in primary_items:
        subnet = _extract_ipv4_subnet_from_structure(candidate)
        if subnet:
            logger.info(f"[NET] Using Home Assistant primary subnet: {subnet}")
            return subnet

    for candidate in interface_items:
        subnet = _extract_ipv4_subnet_from_structure(candidate)
        if subnet:
            logger.info(f"[NET] Using Home Assistant interface subnet: {subnet}")
            return subnet

    return _extract_ipv4_subnet_from_structure(payload)


def _extract_candidate_ipv4_addresses() -> list[str]:
    candidates: list[str] = []

    try:
        hostname_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        candidates.extend(hostname_ips)
    except Exception:
        pass

    for target in ('8.8.8.8', '1.1.1.1'):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((target, 80))
            candidates.append(probe.getsockname()[0])
        except Exception:
            continue
        finally:
            probe.close()

    try:
        import netifaces  # type: ignore

        for iface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for address_info in addresses:
                addr = address_info.get('addr')
                if addr:
                    candidates.append(addr)
    except Exception:
        pass

    unique: list[str] = []
    seen: set[str] = set()
    for raw_ip in candidates:
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue

        if ip_obj.version != 4 or ip_obj.is_loopback:
            continue

        normalized = str(ip_obj)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)

    return unique


def _detect_default_subnet() -> str | None:
    ha_subnet = _detect_home_assistant_primary_subnet()
    if ha_subnet:
        return ha_subnet

    candidates = _extract_candidate_ipv4_addresses()
    if not candidates:
        return None

    selected_ip = None
    for candidate in candidates:
        try:
            candidate_obj = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        if candidate_obj.is_private:
            selected_ip = candidate
            break

    if selected_ip is None:
        selected_ip = candidates[0]

    return _subnet_from_ip(selected_ip, prefix=24)


_configure_log_buffer()

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


def _resolve_data_dir() -> Path | None:
    """Resolve persistent data directory preference.

    Priority:
    1) CRA_DATA_DIR env var (for local testing/overrides)
    2) /data when running in Home Assistant add-on container
    """
    env_dir = os.environ.get("CRA_DATA_DIR")
    if env_dir:
        return Path(env_dir)

    container_data = Path("/data")
    if container_data.exists() and container_data.is_dir():
        return container_data

    return None


def _tail_shared_log_lines(limit: int) -> list[str]:
    try:
        if not RUNTIME_LOG_FILE.exists():
            return []
        return RUNTIME_LOG_FILE.read_text(encoding='utf-8', errors='replace').splitlines()[-limit:]
    except Exception:
        return []


APP_DIR = Path(__file__).resolve().parent
LEGACY_DB_FILE = APP_DIR / "scans.db"
DATA_DIR = _resolve_data_dir()
DB_FILE = str((DATA_DIR / "scans.db") if DATA_DIR else LEGACY_DB_FILE)

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


def migrate_data():
    """Migrate scans.db from legacy app directory into persistent data directory."""
    if not DATA_DIR:
        return

    source_db = LEGACY_DB_FILE
    target_db = Path(DB_FILE)

    try:
        if source_db.resolve() == target_db.resolve():
            return
    except Exception:
        pass

    if source_db.exists() and not target_db.exists():
        target_db.parent.mkdir(parents=True, exist_ok=True)
        try:
            try:
                os.replace(str(source_db), str(target_db))
            except OSError:
                shutil.copy2(str(source_db), str(target_db))
                try:
                    source_db.unlink()
                except Exception:
                    logger.info(
                        "Copied legacy scan database to persistent storage; legacy file remains and will be ignored: %s",
                        source_db,
                    )
            logger.info("Migrated scan database to persistent storage: %s", target_db)
        except Exception:
            logger.warning("Failed to migrate scan database from %s to %s", source_db, target_db, exc_info=True)

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
migrate_data()
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

    if not isinstance(subnet, str) or not subnet.strip():
        return jsonify({"status": "error", "message": "Subnet required"}), 400

    subnet = subnet.strip()

    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
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


@app.route('/api/network/default', methods=['GET'])
def get_default_network_subnet():
    subnet = _detect_default_subnet()
    if subnet:
        return jsonify({"subnet": subnet, "source": "auto"})

    return jsonify({
        "subnet": None,
        "source": "fallback-required",
        "message": "Unable to automatically detect local subnet"
    }), 404


@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        limit = int(request.args.get('limit', 120))
    except ValueError:
        limit = 120

    limit = max(1, min(limit, 300))
    logs = _tail_shared_log_lines(limit)
    if not logs:
        logs = list(LOG_BUFFER)[-limit:]
    return jsonify({"logs": logs})

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
    scan_options = options or {}
    scan_type = scan_options.get('profile') or scan_options.get('scan_type', 'deep')
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
            "scanProfile": scan_type,
            "scanFeatures": scan_options.get('features', {}),
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