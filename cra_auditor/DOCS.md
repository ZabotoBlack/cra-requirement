# Home Assistant Add-on: CRA Compliance Auditor

## Description
The **CRA Compliance Auditor** is a powerful network security tool designed for Home Assistant. It scans your local network (LAN) to identify devices and evaluate their compliance with the EU Cyber Resilience Act (CRA) guidelines.

## Features
- **Network Scanning**: Discover devices on your subnet.
- **Port Analysis**: Detect open ports and potential vulnerabilities.
- **Compliance Status**: Categorize devices as Compliant, Warning, or Non-Compliant.
- **AI Insights**: (Optional) Integrate with Google Gemini for detailed security analysis.
- **3-Tier Dashboard UX**: End User, Intermediate, and Expert views with fast mode switching.

## Dashboard Experience Levels

The web UI includes an experience selector (quick toggle in header + Settings modal):

- **End User (Basic)**
	- Attempts automatic subnet detection via `GET /api/network/default`
	- Locks subnet field and presents simple health-focused summaries
	- Hides advanced/raw technical data
- **Intermediate**
	- Keeps subnet configurable
	- Shows standard dashboard and a concise device overview section
- **Expert**
	- Exposes full dashboard and complete device table
	- Includes runtime logs console and JSON report export

If basic-mode subnet auto-detection fails, the UI prompts once for a CIDR input before scan start.

## Configuration
To enable AI insights, you can provide a Gemini API Key in the configuration tab.

### Options
| Option | Type | Description |
| :--- | :--- | :--- |
| `target_subnet` | string | The CIDR range to scan (e.g., `192.168.1.0/24`). |
| `gemini_api_key` | string | (Optional) Your Google Gemini API Key for enhanced analysis. |
| `nvd_api_key` | string | (Optional, recommended) NVD API key for higher-rate CPE/CVE lookups. |
| `log_level` | string | Backend logging verbosity (`trace`, `debug`, `scan_info`, `info`, `warning`, `error`, `fatal`). Default: `info`. |

## Logging Levels

Use `log_level` in add-on configuration to control runtime log detail.

- `info`: scan start/complete and stage summaries
- `scan_info`: detailed scan progress (discovered devices, per-device checks, detailed Nmap args)
- `debug`: internal diagnostics (DB lock/thread state and handled error tracebacks)

> [!IMPORTANT]
> Log output is now intentionally less verbose by default. Set `log_level: scan_info` (or `debug`) if you need detailed per-device progress in logs.

## API Scan Options (Modular)

`POST /api/scan` accepts both legacy and modular scan options.

### Request Body

```json
{
	"subnet": "192.168.1.0/24",
	"options": {
		"profile": "discovery",
		"vendors": "all",
		"features": {
			"port_scan": false,
			"compliance_checks": false
		}
	}
}
```

### Profiles
- `discovery`: discovery-only inventory (`Ping/ARP`), no compliance checks.
- `standard`: top 100 ports (+ vendor ports), web checks enabled, brute-force auth checks disabled.
- `deep`: broader port scan, OS detection, service versioning, and full checks enabled.

### Feature Flags
- `network_discovery`
- `port_scan`
- `os_detection`
- `service_version`
- `netbios_info`
- `compliance_checks`
- `auth_brute_force`
- `web_crawling`
- `port_range` (optional string override)

### Legacy Compatibility
The backend still accepts:
- `scan_type` (`discovery`, `standard`, `deep`)
- `auth_checks` (mapped to `auth_brute_force`)
- older boolean shortcuts such as `options.discovery=true`

### Important Discovery Behavior
Discovery mode now **skips all compliance checks** by design. It returns discovered device metadata only (IP/MAC/vendor/hostname and merged HA data where available).

## Additional API Endpoints

### `GET /api/network/default`

Returns detected subnet in `/24` form when available:

```json
{"subnet":"192.168.1.0/24","source":"auto"}
```

If detection fails:

```json
{"subnet":null,"source":"fallback-required","message":"Unable to automatically detect local subnet"}
```

### `GET /api/logs?limit=150`

Returns recent backend logs for the Expert dashboard console:

```json
{"logs":["..."]}
```

## Hostname Resolution (Reverse DNS + mDNS)

Device hostnames are now enriched in a post-discovery stage to improve identification of Apple devices, printers, and IoT devices that may not expose NetBIOS names.

Resolution priority is:
1. Nmap hostname / NetBIOS (`nbstat`) when available.
2. Reverse DNS (`PTR`) when hostname is missing or generic.
3. mDNS discovery (`.local`) via `zeroconf` for more descriptive local names.

When multiple non-generic names are found, the most descriptive one is used and additional names may be appended as aliases in the same `hostname` string field (for example: `PrimaryName (AliasName)`).

Notes:
- Python dependency: `zeroconf` (included in `requirements.txt`).
- mDNS uses multicast DNS behavior on UDP 5353; ensure container/network policy allows local multicast traffic.

## Security Logging Probe (CRA Annex I §1(3)(j))

HTTP log endpoint paths are configurable from YAML:

- Default file: `data/security_logging_paths.yaml`
- Optional override: environment variable `CRA_SECURITY_LOG_PATHS_FILE`

YAML shape:

```yaml
log_paths:
	- /api/logs
	- /logs
```

Manual validation helper is available at `scripts/mock_security_logging_device.py`.

Example:

```bash
python scripts/mock_security_logging_device.py --http-port 8080 --udp-port 514
```

## Developer Docs Map

Use this quick map to find where behavior lives before making changes.

### Core Runtime

| Module | Responsibility | Key Functions / Boundaries |
| :--- | :--- | :--- |
| `server.py` | Flask API, scan lifecycle state, DB persistence, static asset serving | `normalize_scan_options()`, `start_scan()`, `run_scan_background()`, `get_status()`, DB helpers (`init_db()`, lock/state helpers) |
| `scan_logic.py` | Network scan pipeline and per-device compliance evaluation | `CRAScanner.scan_subnet()`, `_resolve_scan_features()`, `_merge_devices()`, check methods (`check_*`) |
| `vulnerability_data/nvd.py` | NVD API client with cache + rate limiting | `NVDClient.search_cpes()`, `get_cves_for_cpe()`, `get_vendor_reference_url()` |
| `vulnerability_data/rules.py` | Vendor policy/rules lookup from YAML | `VendorRules` lookup methods for SBOM, security.txt, firmware URLs |
| `vulnerability_data/cpe.py` | CPE normalization and matching helpers | `build_cpe()`, `match_cpe()` |

### Frontend Shell and Views

| Module | Responsibility | Key Functions / Boundaries |
| :--- | :--- | :--- |
| `App.tsx` | App shell state, polling loop, scan launch flow, mode switching | `handleScan()`, `fetchData()`, subnet validation helpers |
| `components/dashboard/*` | Mode-specific dashboard rendering | `BasicDashboard`, `IntermediateDashboard`, `ExpertDashboard` |
| `components/DeviceList.tsx` | Device table, sorting/filtering, per-device dossier and AI advice trigger | `DeviceList`, `DeviceDossier`, sort helpers |
| `components/HistoryView.tsx` | History list/search/sort/delete/report reopen | `fetchHistory()`, `toggleSort()`, `handleDelete()` |
| `components/SettingsModal.tsx` | Scan profile/features controls by UI mode | `applyScanType()`, vendor selection logic |

### Frontend Services and Contexts

| Module | Responsibility | Key Functions / Boundaries |
| :--- | :--- | :--- |
| `services/api.ts` | Typed API calls to backend `/api/*` endpoints | `startScan()`, `getScanStatus()`, `getReport()`, `getHistory*()` |
| `services/geminiService.ts` | Gemini remediation advice prompt + response handling | `getRemediationAdvice()` |
| `LanguageContext.tsx` | UI localization state and translation lookup | `LanguageProvider`, `useLanguage()`, `detectLanguage()` |
| `TourContext.tsx` + `TourOverlay.tsx` | Guided onboarding step state + spotlight rendering | `TOUR_STEPS`, `useTour()`, overlay placement helpers |
| `utils/status.ts` | Shared compliance status label localization | `localizeStatus()` |

### Data and Config Files

| File | Purpose |
| :--- | :--- |
| `data/vendor_rules.yaml` | Vendor-specific compliance metadata and URLs |
| `data/security_logging_paths.yaml` | HTTP paths for security logging capability probes |
| `data/nvd_cache.json` | Runtime NVD response cache |
| `config.yaml` | Home Assistant add-on options and defaults |

### Where to change what

- Add or adjust scan profile behavior: update `_SCAN_PROFILES` and feature resolution in `scan_logic.py`, keep frontend `ScanFeatureFlags` in `types.ts` aligned.
- Add a new compliance check: implement in `scan_logic.py`, include it in device `checks` payload, then update TypeScript interfaces and UI rendering.
- Change scan API contract: update backend endpoints in `server.py` and matching client calls in `services/api.ts`.
- Modify persisted report shape: update DB write payload in `run_scan_background()` and all frontend consumers (`App.tsx`, dashboards, `DeviceList.tsx`, `HistoryView.tsx`).
