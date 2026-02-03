# CRA Compliance Auditor Add-on for Home Assistant

<img src="media/cra-front.png" width="1200" height="475" alt="Logo">

A comprehensive Cyber Resilience Act (CRA) compliance scanner for your local network. This Home Assistant Add-on audits devices on your network, checks for common vulnerabilities, and provides security insights.

## Features
- **Network Discovery**: Automatically finds devices on your specified subnet.
- **Vulnerability Scanning**: Checks for open ports and known CVEs.
- **Compliance Reporting**: Categorizes devices based on EU Cyber Resilience Act standards.
- **AI Integration**: Optional integration with Gemini AI for enhanced security advice.

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
5. Start the Add-on and open the Web UI.

## Development
To run locally for development:
```bash
npm install
npm run dev
```
