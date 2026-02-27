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

TRACE = 5
SCAN_INFO = 15
logging.addLevelName(TRACE, "TRACE")
logging.addLevelName(SCAN_INFO, "SCAN_INFO")

_LOG_LEVEL_MAP = {
    "trace": TRACE,
    "debug": logging.DEBUG,
    "scan_info": SCAN_INFO,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.FATAL,
}


def _resolve_log_level(level_name: str | None) -> int:
    """Map a configured log level string to a numeric logging level."""
    if not level_name:
        return logging.INFO
    return _LOG_LEVEL_MAP.get(str(level_name).strip().lower(), logging.INFO)


from scan_logic import CRAScanner, ScanAbortedError

# Configure logging (replaces print() for structured HA output)
logger = logging.getLogger(__name__)

LOG_BUFFER: deque[str] = deque(maxlen=300)


def _resolve_persistent_base_dir(default_dir: Path | None = None) -> Path:
    """Resolve the base directory for persistent runtime data files."""
    env_dir = os.environ.get("CRA_DATA_DIR")
    if env_dir and env_dir.strip():
        return Path(env_dir.strip())

    container_data = Path("/data")
    if container_data.exists() and container_data.is_dir():
        return container_data

    return default_dir if default_dir is not None else Path(__file__).resolve().parent


def _resolve_runtime_log_file() -> Path:
    """Return the path used for the shared rotating runtime log file."""
    return _resolve_persistent_base_dir(Path(__file__).resolve().parent) / "cra_auditor.log"


def _resolve_data_dir() -> Path | None:
    """Resolve persistent data directory preference.

    Priority:
    1) CRA_DATA_DIR env var (for local testing/overrides)
    2) /data when running in Home Assistant add-on container
    """
    env_dir = os.environ.get("CRA_DATA_DIR")
    container_data = Path("/data")
    default_dir = Path(__file__).resolve().parent

    if env_dir and env_dir.strip():
        return _resolve_persistent_base_dir(default_dir)
    if container_data.exists() and container_data.is_dir():
        return _resolve_persistent_base_dir(default_dir)

    return None


RUNTIME_LOG_FILE = _resolve_runtime_log_file()


class InMemoryLogHandler(logging.Handler):
    def emit(self, record):
        """Append formatted log records to the in-memory ring buffer."""
        try:
            LOG_BUFFER.append(self.format(record))
        except Exception:
            pass


def _configure_log_buffer() -> None:
    """Attach runtime log handlers and configure the root logger level once."""
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

    configured_level_name = os.environ.get("LOG_LEVEL", "info")
    configured_level = _resolve_log_level(configured_level_name)
    root_logger.setLevel(configured_level)
    logger.info(
        "[LOG] Root logger level set to %s (%s)",
        logging.getLevelName(configured_level),
        configured_level_name,
    )


def _subnet_from_ip(ip_address: str, prefix: int = 24) -> str | None:
    """Build a CIDR subnet from an IP address and prefix length."""
    try:
        interface = ipaddress.ip_interface(f"{ip_address}/{prefix}")
        return str(interface.network)
    except ValueError:
        return None


def _subnet_from_cidr(cidr: str) -> str | None:
    """Normalize an IPv4 CIDR string into canonical network notation."""
    try:
        interface = ipaddress.ip_interface(cidr)
        if interface.version != 4:
            return None
        return str(interface.network)
    except ValueError:
        return None


def _subnet_from_ip_mask(ip_address: str, mask: str | int) -> str | None:
    """Create an IPv4 subnet from separate address and mask/prefix values."""
    try:
        network = ipaddress.ip_network(f"{ip_address}/{mask}", strict=False)
        if network.version != 4:
            return None
        return str(network)
    except ValueError:
        return None


def _extract_ipv4_subnet_from_structure(payload) -> str | None:
    """Walk nested network payloads and extract the first valid IPv4 subnet."""
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
    """Read Home Assistant Supervisor network info and return the primary IPv4 subnet."""
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
            logger.debug("[NET] Supervisor network info returned %s", response.status_code)
            return None

        raw_payload = response.json()
    except Exception as exc:
        logger.debug("[NET] Failed to fetch Supervisor network info: %s", exc)
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
            logger.info("[NET] Using Home Assistant primary subnet: %s", subnet)
            return subnet

    for candidate in interface_items:
        subnet = _extract_ipv4_subnet_from_structure(candidate)
        if subnet:
            logger.info("[NET] Using Home Assistant interface subnet: %s", subnet)
            return subnet

    return _extract_ipv4_subnet_from_structure(payload)


def _extract_candidate_ipv4_addresses() -> list[str]:
    """Collect likely local IPv4 addresses from hostname, sockets, and interfaces."""
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
    """Determine the best default subnet for scans using HA data or local interfaces."""
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


def _tail_shared_log_lines(limit: int) -> list[str]:
    """Read the last N lines from the shared runtime log file."""
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
            scan_error TEXT,
            progress_total INTEGER NOT NULL DEFAULT 0,
            progress_done INTEGER NOT NULL DEFAULT 0,
            progress_stage TEXT,
            progress_message TEXT,
            started_at REAL,
            last_update_at REAL,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            timeout_detected INTEGER NOT NULL DEFAULT 0,
            last_outcome TEXT,
            last_end_reason TEXT,
            last_finished_at REAL
        )
    ''')
    c.execute('INSERT OR IGNORE INTO scan_state (id, is_scanning) VALUES (1, 0)')
    conn.commit()
    conn.close()


def ensure_scan_state_schema():
    """Ensure newer scan_state columns exist for progress/abort compatibility."""
    required_columns = {
        "progress_total": "INTEGER NOT NULL DEFAULT 0",
        "progress_done": "INTEGER NOT NULL DEFAULT 0",
        "progress_stage": "TEXT",
        "progress_message": "TEXT",
        "started_at": "REAL",
        "last_update_at": "REAL",
        "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
        "timeout_detected": "INTEGER NOT NULL DEFAULT 0",
        "last_outcome": "TEXT",
        "last_end_reason": "TEXT",
        "last_finished_at": "REAL",
    }

    with sqlite3.connect(DB_FILE) as conn:
        existing = {
            row[1]
            for row in conn.execute("PRAGMA table_info(scan_state)").fetchall()
        }

        for column_name, column_def in required_columns.items():
            if column_name in existing:
                continue
            conn.execute(f"ALTER TABLE scan_state ADD COLUMN {column_name} {column_def}")

        conn.commit()

def reset_scan_state():
    """Reset scan state on startup to clear zombie states from crashes."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            '''
            UPDATE scan_state
            SET is_scanning = 0,
                scan_error = NULL,
                progress_total = 0,
                progress_done = 0,
                progress_stage = NULL,
                progress_message = NULL,
                started_at = NULL,
                last_update_at = NULL,
                cancel_requested = 0,
                timeout_detected = 0,
                last_outcome = NULL,
                last_end_reason = NULL,
                last_finished_at = NULL
            WHERE id = 1
            '''
        )
        conn.commit()

def try_claim_scan() -> bool:
    """Atomically try to claim the scan lock. Returns True if acquired."""
    logger.debug("[SCAN] Attempting to claim scan lock")
    now = time.time()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.execute(
            '''
            UPDATE scan_state
            SET is_scanning = 1,
                scan_error = NULL,
                progress_total = 0,
                progress_done = 0,
                progress_stage = ?,
                progress_message = ?,
                started_at = ?,
                last_update_at = ?,
                cancel_requested = 0,
                timeout_detected = 0
            WHERE id = 1 AND is_scanning = 0
            ''',
            ('initializing', 'Scan starting', now, now),
        )
        conn.commit()
        claimed = c.rowcount > 0
        logger.debug("[SCAN] Scan lock claim result: %s", claimed)
        return claimed

def get_scan_state() -> dict:
    """Read the current scan state from the database."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            '''
            SELECT
                is_scanning,
                scan_error,
                progress_total,
                progress_done,
                progress_stage,
                progress_message,
                started_at,
                last_update_at,
                cancel_requested,
                timeout_detected,
                last_outcome,
                last_end_reason,
                last_finished_at
            FROM scan_state
            WHERE id = 1
            '''
        ).fetchone()
    if row:
        return {
            "scanning": bool(row['is_scanning']),
            "error": row['scan_error'],
            "progress_total": int(row['progress_total'] or 0),
            "progress_done": int(row['progress_done'] or 0),
            "progress_stage": row['progress_stage'],
            "progress_message": row['progress_message'],
            "started_at": row['started_at'],
            "last_update_at": row['last_update_at'],
            "cancel_requested": bool(row['cancel_requested']),
            "timeout_detected": bool(row['timeout_detected']),
            "last_outcome": row['last_outcome'],
            "last_end_reason": row['last_end_reason'],
            "last_finished_at": row['last_finished_at'],
        }
    return {
        "scanning": False,
        "error": None,
        "progress_total": 0,
        "progress_done": 0,
        "progress_stage": None,
        "progress_message": None,
        "started_at": None,
        "last_update_at": None,
        "cancel_requested": False,
        "timeout_detected": False,
        "last_outcome": None,
        "last_end_reason": None,
        "last_finished_at": None,
    }


def _public_scan_error(error: str | None) -> str | None:
    """Hide internal scan error details from API responses."""
    if not error:
        return None
    safe_error = str(error).strip().lower()
    if "timed out" in safe_error or "timeout" in safe_error:
        return "Scan timed out and was aborted."
    if "abort" in safe_error:
        return "Scan was aborted."
    return "Scan failed. Check logs for details."


def _public_end_reason(reason: str | None) -> str | None:
    """Return safe, user-facing completion reason text for status polling."""
    if not reason:
        return None

    normalized = str(reason).strip().lower()
    if "timeout" in normalized or "timed out" in normalized:
        return "Scan timed out and was aborted."
    if "abort" in normalized:
        return "Scan was aborted by user request."
    if "complete" in normalized or "success" in normalized:
        return "Scan completed successfully."
    return "Scan finished."


def finalize_scan_state(outcome: str, end_reason: str | None = None) -> None:
    """Finalize scan lock state and retain last outcome metadata for status/history hints."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            '''
            UPDATE scan_state
            SET is_scanning = 0,
                scan_error = ?,
                progress_total = 0,
                progress_done = 0,
                progress_stage = NULL,
                progress_message = NULL,
                started_at = NULL,
                last_update_at = ?,
                cancel_requested = 0,
                timeout_detected = 0,
                last_outcome = ?,
                last_end_reason = ?,
                last_finished_at = ?
            WHERE id = 1
            ''',
            (
                end_reason if outcome.lower() != "completed" else None,
                time.time(),
                str(outcome or "failed").lower(),
                end_reason,
                time.time(),
            )
        )
        conn.commit()

def set_scan_state(scanning: bool, error: str = None):
    """Update the scan state in the database."""
    now = time.time()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            '''
            UPDATE scan_state
            SET is_scanning = ?,
                scan_error = ?,
                progress_total = CASE WHEN ? = 1 THEN progress_total ELSE 0 END,
                progress_done = CASE WHEN ? = 1 THEN progress_done ELSE 0 END,
                progress_stage = CASE WHEN ? = 1 THEN progress_stage ELSE NULL END,
                progress_message = CASE WHEN ? = 1 THEN progress_message ELSE NULL END,
                started_at = CASE WHEN ? = 1 THEN COALESCE(started_at, ?) ELSE NULL END,
                last_update_at = ?,
                cancel_requested = CASE WHEN ? = 1 THEN cancel_requested ELSE 0 END,
                timeout_detected = CASE WHEN ? = 1 THEN timeout_detected ELSE 0 END
            WHERE id = 1
            ''',
            (
                int(scanning),
                error,
                int(scanning),
                int(scanning),
                int(scanning),
                int(scanning),
                int(scanning),
                now,
                now,
                int(scanning),
                int(scanning),
            )
        )
        conn.commit()


def update_scan_progress(
    *,
    total: int | None = None,
    completed: int | None = None,
    stage: str | None = None,
    message: str | None = None,
) -> None:
    """Persist scan progress counters/message for status polling."""
    state = get_scan_state()
    if not state.get("scanning"):
        return

    effective_total = max(0, int(total if total is not None else state.get("progress_total", 0)))
    effective_completed = max(0, int(completed if completed is not None else state.get("progress_done", 0)))
    effective_completed = min(effective_completed, effective_total) if effective_total > 0 else effective_completed

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            '''
            UPDATE scan_state
            SET progress_total = ?,
                progress_done = ?,
                progress_stage = ?,
                progress_message = ?,
                last_update_at = ?
            WHERE id = 1
            ''',
            (
                effective_total,
                effective_completed,
                stage if stage is not None else state.get("progress_stage"),
                message if message is not None else state.get("progress_message"),
                time.time(),
            )
        )
        conn.commit()


def request_scan_abort(reason: str, timeout_detected: bool = False) -> bool:
    """Mark a running scan as canceled; scanner checks this cooperatively."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.execute(
            '''
            UPDATE scan_state
            SET cancel_requested = 1,
                timeout_detected = CASE WHEN ? = 1 THEN 1 ELSE timeout_detected END,
                progress_message = ?,
                last_update_at = ?
            WHERE id = 1 AND is_scanning = 1
            ''',
            (int(timeout_detected), reason, time.time())
        )
        conn.commit()
        return c.rowcount > 0


def _resolve_abort_signal() -> str | None:
    """Return an abort reason string when cancellation has been requested."""
    state = get_scan_state()
    if not state.get("scanning"):
        return None

    if state.get("cancel_requested"):
        return state.get("progress_message") or "Scan aborted by user request"

    return None

# Initialize DB and reset zombie state on startup
migrate_data()
init_db()
ensure_scan_state_schema()
reset_scan_state()

@app.route('/')
def index():
    """Serve the SPA entry point or a backend-only fallback message."""
    if FRONTEND_DIR:
        return send_from_directory(FRONTEND_DIR, 'index.html')
    return "Backend Running. Frontend not found.", 404

@app.route('/<path:path>')
def serve_static(path):
    """Serve built static frontend assets with SPA fallback routing."""
    if FRONTEND_DIR and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    # SPA Fallback
    if FRONTEND_DIR:
        return send_from_directory(FRONTEND_DIR, 'index.html')
    return "File not found", 404

# Security headers middleware
@app.after_request
def set_security_headers(response):
    """Attach strict security headers to every HTTP response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Validate scan input, claim scan lock, and launch background scan execution."""
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
        logger.debug("[SCAN] Rejecting scan start because lock is already held")
        return jsonify({"status": "error", "message": "Scan already in progress"}), 409
    
    thread = threading.Thread(target=run_scan_background, args=(subnet, options))
    thread.start()
    logger.debug("[SCAN] Started background scan thread: %s", thread.name)
    return jsonify({"status": "success", "message": "Scan started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    """Return current scanner state with sanitized error messaging."""
    _resolve_abort_signal()
    state = get_scan_state()
    started_at = state.get("started_at")
    elapsed_seconds = max(0, int(time.time() - float(started_at))) if started_at else 0
    total_checks = max(0, int(state.get("progress_total", 0)))
    completed_checks = max(0, int(state.get("progress_done", 0)))

    result = {
        "scanning": state["scanning"],
        "cancelRequested": bool(state.get("cancel_requested")),
        "elapsedSeconds": elapsed_seconds,
        "progress": {
            "completed": completed_checks,
            "total": total_checks,
            "remaining": max(0, total_checks - completed_checks),
            "stage": state.get("progress_stage"),
            "message": state.get("progress_message"),
        },
        "lastScan": {
            "outcome": state.get("last_outcome"),
            "reason": _public_end_reason(state.get("last_end_reason")),
            "finishedAt": state.get("last_finished_at"),
        },
    }
    public_error = _public_scan_error(state.get("error"))
    if public_error:
        result["error"] = public_error
    return jsonify(result)


@app.route('/api/scan/abort', methods=['POST'])
def abort_scan():
    """Request cancellation of an active scan."""
    if request_scan_abort("Scan aborted by user request", timeout_detected=False):
        return jsonify({"status": "success", "message": "Abort requested"})
    return jsonify({"status": "error", "message": "No active scan"}), 409

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
    """Return an automatically detected default subnet for the UI."""
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
    """Return recent runtime log lines for expert-mode diagnostics."""
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
        logger.error("Error fetching latest report: %s", e)
        logger.debug("Latest report DB traceback", exc_info=True)
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
        logger.error("Error fetching history: %s", e)
        logger.debug("History query traceback", exc_info=True)
        return jsonify({"error": "Failed to fetch scan history"}), 500

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
    except Exception:
        logger.error("Error fetching scan history detail", exc_info=True)
        return jsonify({"error": "Failed to fetch scan details"}), 500

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
    except Exception:
        logger.error("Error deleting scan history item", exc_info=True)
        return jsonify({"error": "Failed to delete scan history item"}), 500

def run_scan_background(subnet, options=None):
    """Run a subnet scan, persist the report, and update global scan state."""
    scan_options = options or {}
    scan_type = scan_options.get('profile') or scan_options.get('scan_type', 'deep')
    logger.info("[SCAN] Background scan starting: subnet=%s, type=%s", subnet, scan_type)
    bg_start = time.time()
    update_scan_progress(total=1, completed=0, stage='initializing', message='Preparing scanner')

    def should_abort():
        return _resolve_abort_signal()

    def on_progress(update: dict):
        update_scan_progress(
            total=update.get('total'),
            completed=update.get('completed'),
            stage=update.get('stage'),
            message=update.get('message'),
        )

    try:
        devices = scanner.scan_subnet(
            subnet,
            options,
            progress_callback=on_progress,
            should_abort=should_abort,
        )
        
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
                "[SCAN] Scan saved to DB (ID: %s). Total: %s devices (%sC/%sW/%sNC) in %.1fs",
                last_id,
                total,
                compliant,
                warning,
                non_compliant,
                elapsed,
            )
        except Exception as db_err:
            logger.error("[SCAN] Failed to save scan to DB: %s", db_err)
            logger.debug("[SCAN] Save-to-DB traceback", exc_info=True)

    except ScanAbortedError as e:
        logger.info("[SCAN] Scan aborted: %s", e)
        abort_reason = str(e)
        outcome = "timeout" if "timeout" in abort_reason.lower() else "aborted"
        finalize_scan_state(outcome, end_reason=abort_reason)
    except Exception as e:
        logger.error("[SCAN] Scan failed: %s", e)
        logger.debug("[SCAN] Background scan traceback", exc_info=True)
        finalize_scan_state("failed", end_reason=str(e))
    else:
        finalize_scan_state("completed", end_reason="Scan completed")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099)  # Gunicorn takes over in production via run.sh