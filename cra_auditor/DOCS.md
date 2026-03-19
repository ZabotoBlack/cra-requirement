# CRA Compliance Auditor — Developer Documentation / Entwickler-Dokumentation

This document provides technical and developer-oriented documentation for the CRA Compliance Auditor Add-on.
Dieses Dokument bietet technische und entwicklerorientierte Dokumentation für das CRA Compliance Auditor Add-on.

---

## Table of Contents / Inhaltsverzeichnis

- [English](#-english)
  - [Architecture Overview](#architecture-overview)
  - [Data Flow](#data-flow)
  - [Directory Structure](#directory-structure)
  - [Key Technologies](#key-technologies)
  - [Build & Development](#build--development)
  - [Testing](#testing)
  - [Docker & Deployment](#docker--deployment)
  - [AppArmor Security Profile](#apparmor-security-profile)
  - [Environment Variables](#environment-variables)
  - [Database Schema](#database-schema)
  - [Frontend Architecture](#frontend-architecture)
  - [Backend Architecture](#backend-architecture)
  - [Mock & Debug Tools](#mock--debug-tools)
  - [Development Conventions](#development-conventions)
- [Deutsch](#-deutsch)

---

## English

### Architecture Overview

Two-tier application inside a single Docker container:

```
┌─────────────────────────────────────────────────┐
│                 Docker Container                 │
│                                                  │
│  ┌──────────────────┐  ┌──────────────────────┐  │
│  │   React Frontend │  │   Flask Backend       │  │
│  │   (Vite SPA)     │──│   (Gunicorn, :8099)   │  │
│  │                  │  │                        │  │
│  │  App.tsx         │  │  server.py (REST API)  │  │
│  │  Dashboard       │  │  scan_logic.py (Nmap)  │  │
│  │  DeviceList      │  │  vulnerability_data/   │  │
│  │  HistoryView     │  │  data/*.yaml           │  │
│  └──────────────────┘  └──────────┬─────────────┘  │
│                                   │                │
│                          ┌────────▼────────┐       │
│                          │  SQLite (scans.db)│      │
│                          │  NVD Cache (.json)│      │
│                          └─────────────────┘       │
└─────────────────────────────────────────────────┘
```

- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS SPA. Built into `dist/` and served by Flask.
- **Backend**: Python Flask server on port 8099 behind Gunicorn (2 workers, 2 threads). Exposes REST API and serves static frontend assets.
- **Deployment**: Runs as a privileged Home Assistant add-on with `host_network: true` for raw socket access. Ingress routing via HA supervisor. Entrypoint is `run.sh`.

### Data Flow

```
User provides subnet
    → POST /api/scan
    → CRAScanner runs Nmap discovery (-sn -PR)
    → mDNS/NetBIOS hostname enrichment
    → Detailed port/OS/service scan (per profile)
    → 8 compliance checks per device
    → CVE lookup via NVD API (circl.lu fallback)
    → Merges with HA device registry (if SUPERVISOR_TOKEN available)
    → Stores results in SQLite
    → Frontend polls GET /api/status every 3s
    → Displays results in tiered dashboard
```

### Directory Structure

```
cra_auditor/
├── App.tsx                    # React app shell, view routing
├── index.tsx                  # React entry point
├── types.ts                   # TypeScript type definitions
├── translations.ts            # EN/DE translation strings (150+ keys)
├── vite.config.ts             # Vite build configuration
│
├── components/
│   ├── Dashboard.tsx          # Dashboard orchestrator (routes to tier views)
│   ├── dashboard/
│   │   ├── BasicDashboard.tsx
│   │   ├── IntermediateDashboard.tsx
│   │   └── ExpertDashboard.tsx
│   ├── DeviceList.tsx         # Device list with expandable detail cards
│   ├── HistoryView.tsx        # Scan history with search/sort
│   ├── SettingsModal.tsx      # Scan depth, vendors, feature flags
│   ├── LanguageSelector.tsx   # EN/DE toggle
│   ├── LanguageContext.tsx    # i18n React context provider
│   ├── TourOverlay.tsx        # Guided tour step overlays
│   ├── TourWelcomeModal.tsx   # First-visit welcome dialog
│   ├── TourContext.tsx        # Tour state context
│   └── ui/                    # Reusable UI primitives
│       ├── GlassCard.tsx
│       ├── StatusBadge.tsx
│       └── TechButton.tsx
│
├── services/
│   ├── api.ts                 # 12 API client functions
│   └── geminiService.ts       # Gemini AI advice client
│
├── utils/
│   ├── status.ts              # Compliance status localization
│   └── statusRationale.ts     # Human-readable check failure explanations
│
├── server.py                  # Flask WSGI app (11 routes)
├── scan_logic.py              # CRAScanner class (40+ methods)
│
├── vulnerability_data/
│   ├── cpe.py                 # CPE string sanitization & building
│   ├── nvd.py                 # NVD API client with local file cache
│   └── rules.py               # Vendor rule loader (YAML → lookup)
│
├── data/
│   ├── vendor_rules.yaml      # 60+ vendor SBOM/firmware/security.txt mappings
│   └── security_logging_paths.yaml  # HTTP log endpoint probe paths
│
├── tests/
│   ├── test_scan_logic.py     # Nmap args, hostname extraction, scan profiles
│   ├── test_server.py         # API endpoint tests
│   ├── test_scan.py           # Integration tests
│   ├── test_vulnerability_data.py  # NVD/CPE unit tests
│   └── test_timeout.py        # Timeout handling tests
│
├── scripts/
│   └── mock_security_logging_device.py  # Mock device for probe testing
│
├── media/
│   ├── cra-front.png          # Dashboard screenshot
│   └── cra-icon.png           # Add-on icon
│
├── config.yaml                # HA add-on specification
├── Dockerfile                 # 2-stage build (Node.js → Python/Nmap)
├── run.sh                     # Container entrypoint (env setup + Gunicorn)
├── apparmor.txt               # AppArmor security profile
├── requirements.txt           # Python dependencies
└── package.json               # Node.js/Vite dependencies
```

### Key Technologies

| Layer | Technology | Purpose |
|:------|:-----------|:--------|
| Frontend | React 19, TypeScript | UI components and state |
| Styling | Tailwind CSS (PostCSS) | Dark/light theme utility classes |
| Build | Vite | Frontend bundling and dev server |
| Charts | Recharts | Compliance score gauges, vendor risk charts |
| Icons | Lucide React | UI iconography |
| Backend | Python, Flask | REST API server |
| WSGI | Gunicorn | Production server (2 workers, 2 threads, 300s timeout) |
| Scanning | python-nmap | Network discovery and port scanning |
| Discovery | zeroconf | mDNS/Bonjour service discovery |
| Database | SQLite | Scan history and state persistence |
| CVE Data | NVD API | Vulnerability lookups by CPE |
| AI | Google Gemini API | Device-specific remediation advice |
| Container | Docker (Alpine) | 2-stage build, HA add-on runtime |
| Security | AppArmor | Filesystem and capability restriction |

### Build & Development

All commands run from the `cra_auditor/` directory:

#### Frontend
```bash
npm install              # Install JS dependencies
npm run dev              # Vite dev server (port 3000)
npm run build            # Production build to dist/
```

#### Backend
```bash
pip3 install -r requirements.txt
python server.py         # Start Flask dev server (port 8099)
```

> **Note:** Nmap must be installed on the host system for scanning to work. In development, set `CRA_DATA_DIR` to control where `scans.db` and the NVD cache are stored.

#### Docker
```bash
docker build -t cra-auditor .
```

### Testing

Python tests are in `cra_auditor/tests/`:

```bash
# Run all tests
pytest cra_auditor/tests/

# Individual test modules
pytest cra_auditor/tests/test_scan_logic.py        # Nmap args, hostname extraction
pytest cra_auditor/tests/test_server.py             # API endpoint tests
pytest cra_auditor/tests/test_vulnerability_data.py # NVD/CPE tests
pytest cra_auditor/tests/test_timeout.py            # Timeout handling
```

Smoke test for core detection:
```bash
python verify_logic.py   # Tuya, Telnet, Kasa detection checks
```

Tests do not require a committed NVD cache fixture — `test_vulnerability_data.py` uses temporary cache files.

### Docker & Deployment

#### 2-Stage Dockerfile

1. **Stage 1 (Node.js)**: Installs npm dependencies, builds React frontend into `dist/`.
2. **Stage 2 (Python/Nmap)**: Alpine-based image with Python 3, pip, Nmap, nmap-scripts, iputils. Copies built frontend and Python backend. Installs Python requirements.

#### Startup Script (`run.sh`)

Exports HA add-on configuration to environment variables:
- `CRA_DATA_DIR=/data` — Persistent storage for DB/cache/logs
- `GEMINI_API_KEY` — From add-on config
- `NVD_API_KEY` — From add-on config
- `CRA_API_TOKEN` — From `api_access_token` config
- `CRA_MAX_SCAN_HOSTS` — Host limit
- `CRA_MIN_IPV4_PREFIX` — Minimum CIDR prefix
- `LOG_LEVEL` — Logging verbosity
- `CRA_VERIFY_SSL` — SSL verification toggle

Launches Gunicorn with:
- 2 workers, 2 threads
- 300s timeout
- Log level mapped from add-on config

#### Supported Architectures
- `aarch64` (ARM64 — Raspberry Pi 4/5, etc.)
- `amd64` (x86_64)
- `armv7` (ARM 32-bit)

### AppArmor Security Profile

The custom AppArmor profile (`apparmor.txt`) restricts the container:

| Access | Paths | Permission |
|:-------|:------|:-----------|
| Read-only | `/**` (general filesystem) | `r` |
| Read/Write | `/data/**` (persistent storage) | `rwk` |
| Read/Write | `/tmp/**` | `rwk` |
| Execute | Nmap binary and scripts | `ix` |
| Execute | Python runtime | `ix` |
| Network | All network operations | Allowed |
| Capabilities | `NET_ADMIN`, `NET_RAW` | Granted |
| Devices | `/dev/null`, `/dev/urandom`, `/dev/tty` | `rw` |

### Environment Variables

| Variable | Source | Description |
|:---------|:-------|:------------|
| `CRA_DATA_DIR` | `run.sh` / manual | Data directory for DB, cache, logs (default: `/data` in HA) |
| `GEMINI_API_KEY` | Add-on config | Google Gemini API key |
| `NVD_API_KEY` | Add-on config | NVD API key for CVE lookups |
| `CRA_API_TOKEN` | Add-on config | API access token for endpoint protection |
| `CRA_MAX_SCAN_HOSTS` | Add-on config | Maximum hosts per scan (default: 65536) |
| `CRA_MIN_IPV4_PREFIX` | Add-on config | Minimum subnet prefix (default: 16) |
| `LOG_LEVEL` | Add-on config | Logging verbosity |
| `CRA_VERIFY_SSL` | Add-on config | SSL verification for outbound probes |
| `SUPERVISOR_TOKEN` | HA runtime | Auto-set by Home Assistant for device registry access |
| `CRA_SECURITY_LOG_PATHS_FILE` | Manual | Override path for security logging probe config |

### Database Schema

Single SQLite table `scan_history`:

| Column | Type | Description |
|:-------|:-----|:------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment scan ID |
| `timestamp` | TEXT | ISO 8601 scan timestamp |
| `target_range` | TEXT | Scanned CIDR range |
| `summary` | TEXT (JSON) | Compliance summary (device counts, status distribution) |
| `full_report` | TEXT (JSON) | Complete scan report with all device details |

- Automatic schema migration on startup
- Concurrent scan prevention via atomic SQLite lock pattern
- Persistent storage at `<CRA_DATA_DIR>/scans.db`

### Frontend Architecture

#### Key Types (`types.ts`)

**Enums:**
- `ComplianceStatus`: `DISCOVERED`, `COMPLIANT`, `WARNING`, `NON_COMPLIANT`
- `UserMode`: `basic`, `intermediate`, `expert`
- `ViewState`: `dashboard`, `devices`, `history`

**Core Interfaces:**
- `Device` — MAC, IP, vendor, hostname, status, checks, attack surface score, vulnerabilities
- `ScanReport` — timestamp, targetRange, devices[], summary
- `ScanOptions` — scan_type, vendors, auth_checks, features
- `ScanStatus` — scanning state, error, progress, lastScan
- `ScanProgress` — completed, total, remaining, stage, message
- `Vulnerability` — id, severity, description
- `FrontendConfig` — gemini_enabled, nvd_enabled, version

#### API Client (`services/api.ts`)
12 exported functions covering all backend endpoints, with error handling and response normalization.

#### Gemini Service (`services/geminiService.ts`)
- `getRemediationAdvice()` — Sends device context to backend `/api/gemini/advice`
- Internationalization support (responses localized to selected language)

### Backend Architecture

#### Server (`server.py`)
- Flask WSGI application with 11 routes
- `require_sensitive_api_access()` decorator for token-protected endpoints
- Security headers via `set_security_headers()` (CSP, X-Content-Type-Options, X-Frame-Options)
- Scan state management (start, progress, abort)
- SQLite connection management with automatic schema migration
- Sensitive log line redaction (tokens, API keys)

#### Scanner (`scan_logic.py`)
- `CRAScanner` class with 40+ methods
- Discovery pipeline: Nmap ping → mDNS → NetBIOS → Reverse DNS
- Per-device compliance evaluation (8 checks)
- Vendor-specific port and detection logic:
  - Tuya: ports 6668, 6669, 8081
  - Sonoff/ITEAD: port 8081
  - TP-Link Kasa: port 9999
  - Shelly: ports 80, 443, 8081
  - Philips Hue: ports 80, 443
  - IKEA Tradfri: port 5684
- Attack surface score calculation
- NVD/CVE integration via `vulnerability_data/` modules
- Configurable security logging probe paths

#### Vulnerability Data (`vulnerability_data/`)
- `cpe.py` — CPE string sanitization, building, and matching
- `nvd.py` — NVD API client with file-based cache (24h TTL), rate limiting (6.2s / 0.8s with key), CVSS metric extraction (v2, v3.0, v3.1)
- `rules.py` — YAML-based vendor rule loader and lookup

### Mock & Debug Tools

#### Mock Security Logging Device

Run a local mock device exposing log endpoints for probe testing:

```bash
# Full mock (HTTP + UDP syslog)
python scripts/mock_security_logging_device.py --http-port 8080 --udp-port 514

# HTTP only (if UDP/514 is restricted)
python scripts/mock_security_logging_device.py --http-port 8080 --disable-udp
```

Exposes:
- HTTP log endpoint at `/logs` and `/api/logs`
- Optional UDP syslog listener

### Development Conventions

- **Dashboard tiers**: All frontend changes must respect the 3-tier mode system (Basic/Intermediate/Expert).
- **Scan profiles**: Scanning is controlled by profiles (`discovery`, `standard`, `deep`) and granular feature flags.
- **Database concurrency**: The backend uses an atomic SQLite lock pattern to prevent concurrent scans.
- **Logging**: Centralized log buffer exposed via `/api/logs` for Expert console. Log verbosity controlled via `log_level` setting.
- **Translations**: All user-facing strings must have entries in both EN and DE sections of `translations.ts`.
- **Vendor rules**: New vendor support requires entries in `data/vendor_rules.yaml` for SBOM, firmware, and security.txt mappings.
- **Frontend theming**: Uses Tailwind utility classes. Dark theme is default. Both themes must be maintained.

---

## Deutsch

### Architekturübersicht

Zweischichtige Anwendung in einem einzelnen Docker-Container:

```
┌─────────────────────────────────────────────────┐
│                 Docker-Container                 │
│                                                  │
│  ┌──────────────────┐  ┌──────────────────────┐  │
│  │   React Frontend │  │   Flask Backend       │  │
│  │   (Vite SPA)     │──│   (Gunicorn, :8099)   │  │
│  │                  │  │                        │  │
│  │  App.tsx         │  │  server.py (REST-API)  │  │
│  │  Dashboard       │  │  scan_logic.py (Nmap)  │  │
│  │  DeviceList      │  │  vulnerability_data/   │  │
│  │  HistoryView     │  │  data/*.yaml           │  │
│  └──────────────────┘  └──────────┬─────────────┘  │
│                                   │                │
│                          ┌────────▼────────┐       │
│                          │  SQLite (scans.db)│      │
│                          │  NVD-Cache (.json)│      │
│                          └─────────────────┘       │
└─────────────────────────────────────────────────┘
```

- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS SPA. Wird in `dist/` gebaut und von Flask ausgeliefert.
- **Backend**: Python Flask Server auf Port 8099 hinter Gunicorn (2 Worker, 2 Threads). Stellt REST-API bereit und liefert statische Frontend-Assets aus.
- **Deployment**: Läuft als privilegiertes Home Assistant Add-on mit `host_network: true` für Raw-Socket-Zugriff. Ingress-Routing über HA Supervisor. Einstiegspunkt ist `run.sh`.

### Datenfluss

```
Benutzer gibt Subnetz ein
    → POST /api/scan
    → CRAScanner führt Nmap-Erkennung aus (-sn -PR)
    → mDNS/NetBIOS-Hostnamen-Anreicherung
    → Detaillierter Port-/OS-/Service-Scan (je nach Profil)
    → 8 Konformitätsprüfungen pro Gerät
    → CVE-Abfrage über NVD-API (circl.lu als Fallback)
    → Zusammenführung mit HA-Geräteregister (falls SUPERVISOR_TOKEN verfügbar)
    → Ergebnisse in SQLite speichern
    → Frontend fragt GET /api/status alle 3s ab
    → Darstellung im stufenbasierten Dashboard
```

### Verzeichnisstruktur

```
cra_auditor/
├── App.tsx                    # React-App-Shell, View-Routing
├── index.tsx                  # React-Einstiegspunkt
├── types.ts                   # TypeScript-Typdefinitionen
├── translations.ts            # EN/DE-Übersetzungsstrings (150+ Schlüssel)
├── vite.config.ts             # Vite-Build-Konfiguration
│
├── components/
│   ├── Dashboard.tsx          # Dashboard-Orchestrator (leitet an Stufen-Views weiter)
│   ├── dashboard/
│   │   ├── BasicDashboard.tsx
│   │   ├── IntermediateDashboard.tsx
│   │   └── ExpertDashboard.tsx
│   ├── DeviceList.tsx         # Geräteliste mit aufklappbaren Detailkarten
│   ├── HistoryView.tsx        # Scan-Verlauf mit Suche/Sortierung
│   ├── SettingsModal.tsx      # Scantiefe, Hersteller, Feature-Flags
│   ├── LanguageSelector.tsx   # EN/DE-Umschalter
│   ├── LanguageContext.tsx    # i18n React Context Provider
│   ├── TourOverlay.tsx        # Geführte Tour Schritt-Overlays
│   ├── TourWelcomeModal.tsx   # Willkommensdialog beim ersten Besuch
│   ├── TourContext.tsx        # Tour-Status-Context
│   └── ui/                    # Wiederverwendbare UI-Grundelemente
│
├── services/
│   ├── api.ts                 # 12 API-Client-Funktionen
│   └── geminiService.ts       # Gemini-KI-Beratungsclient
│
├── utils/
│   ├── status.ts              # Konformitätsstatus-Lokalisierung
│   └── statusRationale.ts     # Verständliche Erklärungen für Prüfungsfehler
│
├── server.py                  # Flask WSGI-App (11 Routen)
├── scan_logic.py              # CRAScanner-Klasse (40+ Methoden)
│
├── vulnerability_data/
│   ├── cpe.py                 # CPE-String-Bereinigung & -Erstellung
│   ├── nvd.py                 # NVD-API-Client mit lokalem Datei-Cache
│   └── rules.py               # Herstellerregelladeprogramm (YAML → Lookup)
│
├── data/
│   ├── vendor_rules.yaml      # 60+ Hersteller SBOM/Firmware/Security.txt-Zuordnungen
│   └── security_logging_paths.yaml  # HTTP-Log-Endpunkt-Prüfpfade
│
├── tests/
│   ├── test_scan_logic.py     # Nmap-Argumente, Hostnamen-Extraktion
│   ├── test_server.py         # API-Endpunkt-Tests
│   ├── test_scan.py           # Integrationstests
│   ├── test_vulnerability_data.py  # NVD/CPE-Unit-Tests
│   └── test_timeout.py        # Timeout-Behandlungstests
│
├── scripts/
│   └── mock_security_logging_device.py  # Mock-Gerät für Probe-Tests
│
├── config.yaml                # HA Add-on-Spezifikation
├── Dockerfile                 # 2-stufiger Build (Node.js → Python/Nmap)
├── run.sh                     # Container-Einstiegspunkt (Umgebung + Gunicorn)
├── apparmor.txt               # AppArmor-Sicherheitsprofil
├── requirements.txt           # Python-Abhängigkeiten
└── package.json               # Node.js/Vite-Abhängigkeiten
```

### Schlüsseltechnologien

| Schicht | Technologie | Zweck |
|:--------|:------------|:------|
| Frontend | React 19, TypeScript | UI-Komponenten und Zustandsverwaltung |
| Styling | Tailwind CSS (PostCSS) | Dark/Light-Theme Utility-Klassen |
| Build | Vite | Frontend-Bündelung und Entwicklungsserver |
| Diagramme | Recharts | Compliance-Score-Anzeigen, Hersteller-Risiko-Charts |
| Icons | Lucide React | UI-Ikonografie |
| Backend | Python, Flask | REST-API-Server |
| WSGI | Gunicorn | Produktionsserver (2 Worker, 2 Threads, 300s Timeout) |
| Scanning | python-nmap | Netzwerkerkennung und Port-Scanning |
| Erkennung | zeroconf | mDNS/Bonjour-Service-Erkennung |
| Datenbank | SQLite | Scan-Verlauf und Zustandspersistenz |
| CVE-Daten | NVD-API | Schwachstellenabfragen nach CPE |
| KI | Google Gemini API | Gerätespezifische Handlungsempfehlungen |
| Container | Docker (Alpine) | 2-stufiger Build, HA Add-on-Laufzeit |
| Sicherheit | AppArmor | Dateisystem- und Fähigkeitsbeschränkung |

### Build & Entwicklung

Alle Befehle werden aus dem `cra_auditor/`-Verzeichnis ausgeführt:

#### Frontend
```bash
npm install              # JS-Abhängigkeiten installieren
npm run dev              # Vite-Entwicklungsserver (Port 3000)
npm run build            # Produktions-Build nach dist/
```

#### Backend
```bash
pip3 install -r requirements.txt
python server.py         # Flask-Entwicklungsserver starten (Port 8099)
```

> **Hinweis:** Nmap muss auf dem Host-System installiert sein, damit Scanning funktioniert. In der Entwicklung kann `CRA_DATA_DIR` gesetzt werden, um das Speicherverzeichnis für `scans.db` und NVD-Cache festzulegen.

#### Docker
```bash
docker build -t cra-auditor .
```

### Tests

Python-Tests befinden sich in `cra_auditor/tests/`:

```bash
# Alle Tests ausführen
pytest cra_auditor/tests/

# Einzelne Testmodule
pytest cra_auditor/tests/test_scan_logic.py        # Nmap-Argumente, Hostnamen-Extraktion
pytest cra_auditor/tests/test_server.py             # API-Endpunkt-Tests
pytest cra_auditor/tests/test_vulnerability_data.py # NVD/CPE-Tests
pytest cra_auditor/tests/test_timeout.py            # Timeout-Behandlung
```

Smoke-Test für Kernerkennungen:
```bash
python verify_logic.py   # Tuya-, Telnet-, Kasa-Erkennungsprüfungen
```

Tests benötigen keine committete NVD-Cache-Datei — `test_vulnerability_data.py` verwendet temporäre Cache-Dateien.

### Docker & Deployment

#### 2-Stufiges Dockerfile

1. **Stufe 1 (Node.js)**: Installiert npm-Abhängigkeiten, baut React-Frontend nach `dist/`.
2. **Stufe 2 (Python/Nmap)**: Alpine-basiertes Image mit Python 3, pip, Nmap, nmap-scripts, iputils. Kopiert gebautes Frontend und Python-Backend. Installiert Python-Abhängigkeiten.

#### Startskript (`run.sh`)

Exportiert HA Add-on-Konfiguration als Umgebungsvariablen:
- `CRA_DATA_DIR=/data` — Persistenter Speicher für DB/Cache/Logs
- `GEMINI_API_KEY` — Aus Add-on-Konfiguration
- `NVD_API_KEY` — Aus Add-on-Konfiguration
- `CRA_API_TOKEN` — Aus `api_access_token`-Konfiguration
- `CRA_MAX_SCAN_HOSTS` — Host-Limit
- `CRA_MIN_IPV4_PREFIX` — Minimaler CIDR-Präfix
- `LOG_LEVEL` — Protokollverbosität
- `CRA_VERIFY_SSL` — SSL-Überprüfungsschalter

Startet Gunicorn mit:
- 2 Worker, 2 Threads
- 300s Timeout
- Log-Level aus Add-on-Konfiguration abgeleitet

#### Unterstützte Architekturen
- `aarch64` (ARM64 — Raspberry Pi 4/5 usw.)
- `amd64` (x86_64)
- `armv7` (ARM 32-Bit)

### AppArmor-Sicherheitsprofil

Das benutzerdefinierte AppArmor-Profil (`apparmor.txt`) beschränkt den Container:

| Zugriff | Pfade | Berechtigung |
|:--------|:------|:-------------|
| Nur lesen | `/**` (allgemeines Dateisystem) | `r` |
| Lesen/Schreiben | `/data/**` (persistenter Speicher) | `rwk` |
| Lesen/Schreiben | `/tmp/**` | `rwk` |
| Ausführen | Nmap-Binary und Skripte | `ix` |
| Ausführen | Python-Laufzeit | `ix` |
| Netzwerk | Alle Netzwerkoperationen | Erlaubt |
| Fähigkeiten | `NET_ADMIN`, `NET_RAW` | Gewährt |
| Geräte | `/dev/null`, `/dev/urandom`, `/dev/tty` | `rw` |

### Umgebungsvariablen

| Variable | Quelle | Beschreibung |
|:---------|:-------|:-------------|
| `CRA_DATA_DIR` | `run.sh` / manuell | Datenverzeichnis für DB, Cache, Logs (Standard: `/data` in HA) |
| `GEMINI_API_KEY` | Add-on-Konfiguration | Google Gemini API-Schlüssel |
| `NVD_API_KEY` | Add-on-Konfiguration | NVD API-Schlüssel für CVE-Abfragen |
| `CRA_API_TOKEN` | Add-on-Konfiguration | API-Zugriffstoken für Endpunktschutz |
| `CRA_MAX_SCAN_HOSTS` | Add-on-Konfiguration | Maximale Hosts pro Scan (Standard: 65536) |
| `CRA_MIN_IPV4_PREFIX` | Add-on-Konfiguration | Minimaler Subnetz-Präfix (Standard: 16) |
| `LOG_LEVEL` | Add-on-Konfiguration | Protokollverbosität |
| `CRA_VERIFY_SSL` | Add-on-Konfiguration | SSL-Überprüfung für ausgehende Probes |
| `SUPERVISOR_TOKEN` | HA-Laufzeit | Automatisch von Home Assistant gesetzt für Geräteregisterzugriff |
| `CRA_SECURITY_LOG_PATHS_FILE` | Manuell | Überschreibungspfad für Security-Logging-Probe-Konfiguration |

### Datenbankschema

Einzelne SQLite-Tabelle `scan_history`:

| Spalte | Typ | Beschreibung |
|:-------|:----|:-------------|
| `id` | INTEGER PRIMARY KEY | Auto-Increment Scan-ID |
| `timestamp` | TEXT | ISO 8601 Scan-Zeitstempel |
| `target_range` | TEXT | Gescannter CIDR-Bereich |
| `summary` | TEXT (JSON) | Konformitätszusammenfassung (Gerätezahlen, Statusverteilung) |
| `full_report` | TEXT (JSON) | Vollständiger Scanbericht mit allen Gerätedetails |

- Automatische Schema-Migration beim Start
- Verhinderung gleichzeitiger Scans über atomares SQLite-Lock-Muster
- Persistenter Speicher unter `<CRA_DATA_DIR>/scans.db`

### Frontend-Architektur

#### Schlüsseltypen (`types.ts`)

**Enums:**
- `ComplianceStatus`: `DISCOVERED`, `COMPLIANT`, `WARNING`, `NON_COMPLIANT`
- `UserMode`: `basic`, `intermediate`, `expert`
- `ViewState`: `dashboard`, `devices`, `history`

**Kerninterfaces:**
- `Device` — MAC, IP, Hersteller, Hostname, Status, Prüfungen, Angriffsflächenwert, Schwachstellen
- `ScanReport` — Zeitstempel, Zielbereich, Geräte[], Zusammenfassung
- `ScanOptions` — Scantyp, Hersteller, Auth-Prüfungen, Features
- `ScanStatus` — Scanzustand, Fehler, Fortschritt, letzter Scan
- `ScanProgress` — abgeschlossen, gesamt, verbleibend, Phase, Nachricht
- `Vulnerability` — ID, Schweregrad, Beschreibung
- `FrontendConfig` — gemini_enabled, nvd_enabled, version

#### API-Client (`services/api.ts`)
12 exportierte Funktionen für alle Backend-Endpunkte, mit Fehlerbehandlung und Antwortnormalisierung.

#### Gemini-Service (`services/geminiService.ts`)
- `getRemediationAdvice()` — Sendet Gerätekontext an Backend `/api/gemini/advice`
- Internationalisierungsunterstützung (Antworten in gewählter Sprache lokalisiert)

### Backend-Architektur

#### Server (`server.py`)
- Flask WSGI-Anwendung mit 11 Routen
- `require_sensitive_api_access()`-Dekorator für tokengeschützte Endpunkte
- Sicherheitsheader via `set_security_headers()` (CSP, X-Content-Type-Options, X-Frame-Options)
- Scan-Zustandsverwaltung (Start, Fortschritt, Abbruch)
- SQLite-Verbindungsverwaltung mit automatischer Schema-Migration
- Redigierung sensibler Logzeilen (Tokens, API-Schlüssel)

#### Scanner (`scan_logic.py`)
- `CRAScanner`-Klasse mit 40+ Methoden
- Erkennungspipeline: Nmap Ping → mDNS → NetBIOS → Reverse DNS
- Konformitätsbewertung pro Gerät (8 Prüfungen)
- Herstellerspezifische Port- und Erkennungslogik:
  - Tuya: Ports 6668, 6669, 8081
  - Sonoff/ITEAD: Port 8081
  - TP-Link Kasa: Port 9999
  - Shelly: Ports 80, 443, 8081
  - Philips Hue: Ports 80, 443
  - IKEA Tradfri: Port 5684
- Berechnung des Angriffsflächenwerts
- NVD/CVE-Integration über `vulnerability_data/`-Module
- Konfigurierbare Security-Logging-Prüfpfade

#### Schwachstellendaten (`vulnerability_data/`)
- `cpe.py` — CPE-String-Bereinigung, -Erstellung und -Abgleich
- `nvd.py` — NVD-API-Client mit dateibasiertem Cache (24h TTL), Ratenlimitierung (6,2s / 0,8s mit Schlüssel), CVSS-Metrik-Extraktion (v2, v3.0, v3.1)
- `rules.py` — YAML-basierter Herstellerregelladeprogramm und Lookup

### Mock- & Debug-Tools

#### Mock-Security-Logging-Gerät

Lokales Mock-Gerät starten, das Log-Endpunkte für Probe-Tests bereitstellt:

```bash
# Vollständiger Mock (HTTP + UDP-Syslog)
python scripts/mock_security_logging_device.py --http-port 8080 --udp-port 514

# Nur HTTP (falls UDP/514 eingeschränkt ist)
python scripts/mock_security_logging_device.py --http-port 8080 --disable-udp
```

Stellt bereit:
- HTTP-Log-Endpunkt unter `/logs` und `/api/logs`
- Optionaler UDP-Syslog-Listener

### Entwicklungskonventionen

- **Dashboard-Stufen**: Alle Frontend-Änderungen müssen das 3-Stufen-Modsystem (Basic/Fortgeschritten/Experte) berücksichtigen.
- **Scan-Profile**: Scanning wird durch Profile (`discovery`, `standard`, `deep`) und granulare Feature-Flags gesteuert.
- **Datenbanknebenläufigkeit**: Das Backend verwendet ein atomares SQLite-Lock-Muster zur Verhinderung gleichzeitiger Scans.
- **Protokollierung**: Zentralisierter Log-Puffer über `/api/logs` für die Experten-Konsole. Verbosität über `log_level` steuerbar.
- **Übersetzungen**: Alle benutzersichtbaren Strings müssen Einträge in beiden Sprachsektionen (EN und DE) von `translations.ts` haben.
- **Herstellerregeln**: Neue Herstellerunterstützung erfordert Einträge in `data/vendor_rules.yaml` für SBOM-, Firmware- und Security.txt-Zuordnungen.
- **Frontend-Theming**: Verwendet Tailwind Utility-Klassen. Dark Theme ist Standard. Beide Themes müssen gepflegt werden.
