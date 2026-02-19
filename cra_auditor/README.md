# CRA Compliance Auditor Add-on for Home Assistant

<img src="media/cra-front.png" width="1200" height="475" alt="Logo">

A comprehensive Cyber Resilience Act (CRA) compliance scanner for your local network. This Home Assistant Add-on audits devices on your network, checks for common vulnerabilities, and provides security insights.

## Features
- **Network Discovery**: Automatically finds devices on your specified subnet.
- **Vulnerability Scanning**: Checks for open ports and known CVEs.
- **Compliance Reporting**: Categorizes devices based on EU Cyber Resilience Act standards.
- **AI Integration**: Optional integration with Gemini AI for enhanced security advice.
- **3-Tier Dashboard Modes**: End User, Intermediate, and Expert views for different technical levels.

## Dashboard Modes

The UI supports three switchable experience levels (quick toggle in the command header and in Settings):

- **End User (Basic)**
	- Auto-detects subnet via backend (`/api/network/default`) and locks subnet input
	- Uses simplified health summary cards and plain-language issue list
	- Hides advanced tables and raw data views
- **Intermediate**
	- Editable subnet input
	- Standard dashboard with simplified device overview and optional expanded detail
- **Expert**
	- Full dashboard plus full device list
	- In-app logs console via `/api/logs`
	- JSON export button for full report payload

### Basic-Mode Subnet Fallback

If automatic subnet detection is unavailable, the UI prompts once for a CIDR subnet before starting the scan.

## Scan Profiles & Feature Flags

The backend now supports modular scanning profiles and explicit feature flags via `/api/scan` options.

### Profile Defaults
- **discovery**
	- Discovery only (`Ping/ARP`)
	- `port_scan=false`, `compliance_checks=false`
	- Returns device inventory (IP, MAC, vendor, hostname) without CRA check execution
- **standard**
	- `port_scan=true` (`1-100` + vendor-specific ports)
	- `service_version=true`, `netbios_info=true`, `os_detection=false`
	- `compliance_checks=true`, `auth_brute_force=false`, `web_crawling=true`
- **deep**
	- `port_scan=true` (`1-1024` + vendor-specific ports)
	- `service_version=true`, `netbios_info=true`, `os_detection=true`
	- `compliance_checks=true`, `auth_brute_force=true`, `web_crawling=true`

### Supported Feature Flags
- `network_discovery`
- `port_scan`
- `os_detection`
- `service_version`
- `netbios_info`
- `compliance_checks`
- `auth_brute_force`
- `web_crawling`
- `port_range` (optional override, e.g. `"1-512"`)

### Example Payload

```json
{
	"subnet": "192.168.1.0/24",
	"options": {
		"profile": "standard",
		"vendors": "all",
		"features": {
			"auth_brute_force": false,
			"web_crawling": true,
			"port_range": "1-100"
		}
	}
}
```

Legacy `scan_type` and `auth_checks` are still accepted and mapped to the new model server-side.

## Security Logging Probe Configuration

Security logging endpoint detection (CRA Annex I §1(3)(j)) is configured via:

- `data/security_logging_paths.yaml`
- Optional env override: `CRA_SECURITY_LOG_PATHS_FILE` (absolute path to a YAML file with the same shape)

Default file format:

```yaml
log_paths:
	- /api/logs
	- /logs
	- /admin/logs
	- /syslog
	- /journal
	- /cgi-bin/log.cgi
```

## Additional API Endpoints

- `GET /api/network/default`
	- Returns detected subnet, e.g.:
		```json
		{"subnet":"192.168.1.0/24","source":"auto"}
		```
	- If detection fails, returns `404` with:
		```json
		{"subnet":null,"source":"fallback-required","message":"Unable to automatically detect local subnet"}
		```
- `GET /api/logs?limit=150`
	- Returns recent runtime logs for Expert console view:
		```json
		{"logs":["..."]}
		```

## Manual Probe Validation (Mock Device)

Run a local mock device that exposes:
- HTTP log endpoint at `/logs` (and `/api/logs`)
- Optional UDP syslog listener

```bash
python scripts/mock_security_logging_device.py --http-port 8080 --udp-port 514
```

If binding UDP/514 is restricted on your platform, disable UDP and validate via HTTP endpoint detection:

```bash
python scripts/mock_security_logging_device.py --http-port 8080 --disable-udp
```

## NVD Cache Policy

- Runtime state uses a persistent data directory when available (`/data` in Home Assistant add-ons).
- You can override runtime storage in local/dev runs with `CRA_DATA_DIR`.
- The NVD API cache file is runtime-generated at `<data_dir>/nvd_cache.json` and is intentionally not committed to Git.
- Scan history DB is stored at `<data_dir>/scans.db`.
- Cache entries are file-based with TTL invalidation (default: `86400` seconds / 24h in `NVDClient`).
- Refresh/invalidate cache manually by deleting `<data_dir>/nvd_cache.json`; it will be recreated on next NVD lookup.
- Tests do not require a committed cache fixture; `tests/test_vulnerability_data.py` uses temporary cache files.

## Permissions & Security
This add-on requires elevated permissions to function correctly:
- **`privileged`**: Configured as a list of Linux capabilities (e.g., `NET_ADMIN`, `NET_RAW`) in `config.yaml`. These are granted instead of full privileged mode to enable low-level network operations like ARP scanning and raw socket access.
- **`host_network: true`**: Required to share the host's network stack for accurate device discovery.

> [!WARNING]
> These settings grant the container significant access to the host network. Ensure you trust this add-on and the device running it. Restricting or removing these specific capabilities (not necessarily full privileged) may break scanning functionality.

## Installation
1. Add this repository to your Home Assistant Add-on Store.
2. Install the **CRA Compliance Auditor**.
3. Configure the `target_subnet` in the Configuration tab.
4. (Optional) Add your `gemini_api_key` for AI features.
5. (Optional, recommended) Add your `nvd_api_key` for faster and more reliable NVD vulnerability lookups.
6. Start the Add-on and open the Web UI.

## Development
To run locally for development:
```bash
npm install
npm run dev
```
