# Copilot Instructions for CRA Compliance Auditor

## Project shape
- This repo is a Home Assistant add-on with a React frontend and Flask backend in one container.
- Core code lives in `cra_auditor/`: frontend SPA (`App.tsx`, `components/`, `services/`) + backend API (`server.py`) + scan engine (`scan_logic.py`).
- `server.py` serves built frontend assets from `dist/` and exposes `/api/*`; treat Flask as the integration boundary.

## End-to-end flow (important)
- Frontend starts scans via `POST /api/scan` (`services/api.ts`) and polls `/api/status` every 3s (`App.tsx`).
- Backend normalizes scan options in `normalize_scan_options()` (`server.py`) before calling `CRAScanner.scan_subnet()`.
- `CRAScanner` executes staged scanning in `scan_logic.py`: discovery -> optional detailed port scan -> HA merge -> optional compliance checks.
- Scan results are stored in SQLite (`scan_history`) and lock state in `scan_state` (`server.py`), then returned via `/api/report` and `/api/history`.

## Scan options conventions
- Support both legacy and modular options. Do not break compatibility with `scan_type` / `auth_checks`.
- Canonical model is profile + feature flags (`discovery`, `standard`, `deep`) from `_SCAN_PROFILES` in `scan_logic.py`.
- `discovery` profile is intentionally strict inventory mode (no port scan compliance checks).
- Feature keys must stay aligned between backend `FEATURE_FLAG_KEYS` and frontend `ScanFeatureFlags` in `types.ts`.

## Data and persistence rules
- Runtime data directory priority: `CRA_DATA_DIR` -> `/data` -> local fallback (`server.py`, `vulnerability_data/nvd.py`).
- DB file is `<data_dir>/scans.db`; NVD cache is `<data_dir>/nvd_cache.json` with TTL-based invalidation.
- Keep `scan_state` lock semantics intact (`try_claim_scan`, `set_scan_state`) to prevent concurrent scans.

## Integrations and external dependencies
- Home Assistant integration uses `SUPERVISOR_TOKEN` and Supervisor APIs in `scan_logic.py` (`/core/api/states`, `/config/device_registry`).
- Vulnerability data comes from NVD (`vulnerability_data/nvd.py`) with rate limiting and file cache.
- Optional Gemini advice is frontend-side (`services/geminiService.ts`) using `process.env.API_KEY` from `vite.config.ts`.
- Security logging probe paths come from `data/security_logging_paths.yaml` or `CRA_SECURITY_LOG_PATHS_FILE`.

## Build, run, and test workflows
- From `cra_auditor/`: `npm install`, `npm run build` for production frontend assets (`dist/`).
- Backend local run: `pip3 install -r requirements.txt` then `python server.py` (dev) or `gunicorn ... server:app` (see `run.sh`).
- Frontend-only dev server is `npm run dev` on port 3000; API calls are relative (`api/...`), so full-stack behavior is through Flask-served app unless a proxy is added.
- Tests are Python `unittest` style with heavy mocking in `tests/` (no real network scans expected in CI).

## Editing guidance for agents
- Prefer minimal, surgical changes in `scan_logic.py`; many tests assert specific scan arguments and merge behavior.
- Keep API response field shapes stable (`summary.nonCompliant`, `scanProfile`, `scanFeatures`) because UI consumes them directly.
- When adding scan checks, update both backend report payload and TypeScript interfaces in `types.ts`.
- Preserve Home Assistant add-on constraints in `config.yaml` and `Dockerfile` (`host_network`, network capabilities, nmap tooling).