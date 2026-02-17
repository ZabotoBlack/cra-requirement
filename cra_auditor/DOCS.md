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
