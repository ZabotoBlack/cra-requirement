# CRA Compliance Auditor Add-on for Home Assistant

## Project Overview
The CRA Compliance Auditor is a Home Assistant Add-on designed to perform comprehensive Cyber Resilience Act (CRA) compliance scanning on a local network. It discovers devices, checks for open ports, identifies known vulnerabilities (CVEs), and evaluates security compliance. It features a React frontend and a Python (Flask) backend, using Nmap for network scanning and SQLite for state and history persistence.

## Key Technologies
- **Frontend**: React, TypeScript, Vite, Tailwind CSS (via PostCSS).
- **Backend**: Python, Flask, Gunicorn.
- **Data & APIs**: SQLite (local database), `python-nmap` (network scanning), NVD API (vulnerability lookups), Gemini API (AI-powered security insights).
- **Environment**: Docker-based Home Assistant Add-on runtime.

## Directory Structure
The core project resides in the `cra_auditor/` directory:
- **Frontend Source**: `components/`, `services/`, `utils/`, `index.tsx`, `App.tsx` (React application code).
- **Backend Source**: `server.py` (Flask server and API endpoints), `scan_logic.py` (Nmap scanning logic), `vulnerability_data/` (NVD API and rules processing).
- **Add-on Configuration**: `config.yaml` (Home Assistant add-on spec), `Dockerfile`, `run.sh` (container entrypoint and Gunicorn startup), `apparmor.txt`.
- **Dependencies**: `package.json` (Node.js/Vite), `requirements.txt` (Python).
- **Documentation**: `README.md` and `DOCS.md`.

## Building and Running

### Development
1. **Frontend**:
   ```bash
   cd cra_auditor
   npm install
   npm run dev
   ```
2. **Backend**:
   Ensure `nmap` is installed on your local system.
   ```bash
   cd cra_auditor
   pip install -r requirements.txt
   python server.py
   ```
   *Note: In development, set `CRA_DATA_DIR` if you want to explicitly define where `scans.db` and the NVD cache are stored.*

### Production (Home Assistant)
The Add-on is built and executed as a Docker container within Home Assistant:
- The frontend is built into `dist/` (via Dockerfile).
- `run.sh` initializes the runtime environment, applies configurations from Home Assistant (like API keys and target subnet), and starts the backend using Gunicorn (`gunicorn server:app`).
- Network capabilities are managed via `privileged` settings in `config.yaml` to allow raw socket access for Nmap.

## Development Conventions
- **Dashboard Tiers**: The application UI is divided into End User (Basic), Intermediate, and Expert modes. Make sure frontend changes respect these tiers.
- **Scan Profiles**: Scanning is controlled by profiles (`discovery`, `standard`, `deep`) and granular feature flags passed via the `/api/scan` endpoint.
- **Database & State**: Scan state (running status, progress, aborts) and history are stored in `scans.db`. The backend uses an atomic lock pattern in SQLite to prevent concurrent scans.
- **Logging**: The system uses a centralized log buffer exposed via `/api/logs` for the Expert dashboard. Standard logging outputs are controlled via the `log_level` setting in the Home Assistant add-on configuration.
- **Testing**: Python tests are available in the `cra_auditor/tests/` directory. (e.g., `pytest tests/`).
