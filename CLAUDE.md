# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CRA Compliance Auditor — a Home Assistant add-on that scans local networks for IoT devices and evaluates their compliance with the EU Cyber Resilience Act (CRA). It combines Nmap network scanning, CVE lookups, and optional Google Gemini AI advice into a React dashboard.

## Architecture

Two-tier app inside a single Docker container:

- **Frontend** (`cra_auditor/`): React 19 + TypeScript + Vite + Tailwind CSS SPA. Entry point is `App.tsx` → renders Dashboard, DeviceList, HistoryView components. API calls go through `services/api.ts`. Gemini AI integration in `services/geminiService.ts`.
- **Backend** (`cra_auditor/server.py`): Python Flask server on port 8099. Serves the built frontend and exposes REST API. Scan logic lives in `scan_logic.py` (CRAScanner class). Data stored in SQLite (`scans.db`).
- **Deployment**: Runs as a privileged Home Assistant add-on with `host_network: true` for raw socket access. Ingress routing via HA supervisor. Entrypoint is `run.sh`.

### Data Flow

User provides subnet → `POST /api/scan` → CRAScanner runs Nmap discovery (`-sn -PR`) → detailed port/OS scan → compliance checks (secure defaults, encryption, CVEs via circl.lu API) → merges with HA device registry → stores in SQLite → frontend polls `/api/status` every 3s → displays results.

### Key API Endpoints

- `POST /api/scan` — Start scan (body: `{ subnet, options }`)
- `GET /api/status` — Poll scan progress
- `GET /api/report` — Latest scan results
- `GET /api/history` — List past scans (supports search, sort)
- `GET /api/history/<id>` — Specific scan report
- `DELETE /api/history/<id>` — Remove scan record

## Build & Development Commands

All commands run from `cra_auditor/` directory:

```bash
# Frontend
npm install              # Install JS dependencies
npm run dev              # Vite dev server (port 3000)
npm run build            # Production build to dist/

# Backend
pip3 install -r requirements.txt
python server.py         # Start Flask server (port 8099)

# Testing
python verify_logic.py   # Smoke tests (Tuya, Telnet, Kasa detection)

# Docker (from cra_auditor/)
docker build -t cra-auditor .
```

## Key Types

TypeScript types in `types.ts`: `Device`, `ScanReport`, `ScanOptions`, `ComplianceStatus` ('Compliant' | 'Warning' | 'Non-Compliant'), `Vulnerability`, `PortScan`.

## Compliance Logic (scan_logic.py)

CRAScanner performs three categories of checks per device:
- **`check_secure_by_default()`** — Detects telnet, weak credentials, unauthenticated HTTP
- **`check_confidentiality()`** — Flags unencrypted ports (FTP/21, Telnet/23, HTTP/80)
- **`check_vulnerabilities()`** — Queries CVE.circl.lu API for critical CVEs

Vendor-specific detection covers: Tuya, Sonoff, Kasa, Shelly, Hue, IKEA.

## Database Schema

Single SQLite table `scan_history` with columns: `id`, `timestamp`, `target_range`, `summary` (JSON), `full_report` (JSON).

## Environment Variables

- `GEMINI_API_KEY` — Optional, enables AI remediation advice
- `SUPERVISOR_TOKEN` — Auto-set by Home Assistant for device registry access

## Conventions

- Frontend uses dark theme with Tailwind utility classes throughout
- Charts use Recharts library
- Icons from Lucide React
- Scan types: quick discovery vs detailed (port scan + OS fingerprinting)
- Container requires `NET_ADMIN`, `NET_RAW` capabilities and root privileges for Nmap
