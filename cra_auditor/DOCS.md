# Home Assistant Add-on: CRA Compliance Auditor

## Description
The **CRA Compliance Auditor** is a powerful network security tool designed for Home Assistant. It scans your local network (LAN) to identify devices and evaluate their compliance with the EU Cyber Resilience Act (CRA) guidelines.

## Features
- **Network Scanning**: Discover devices on your subnet.
- **Port Analysis**: Detect open ports and potential vulnerabilities.
- **Compliance Status**: Categorize devices as Compliant, Warning, or Non-Compliant.
- **AI Insights**: (Optional) Integrate with Google Gemini for detailed security analysis.

## Configuration
To enable AI insights, you can provide a Gemini API Key in the configuration tab.

### Options
| Option | Type | Description |
| :--- | :--- | :--- |
| `target_subnet` | string | The CIDR range to scan (e.g., `192.168.1.0/24`). |
| `gemini_api_key` | string | (Optional) Your Google Gemini API Key for enhanced analysis. |
| `nvd_api_key` | string | (Optional, recommended) NVD API key for higher-rate CPE/CVE lookups. |

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
