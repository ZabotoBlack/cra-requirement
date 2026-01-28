# CRA Compliance Auditor Add-on for Home Assistant

![Logo](logo.png)

A comprehensive Cyber Resilience Act (CRA) compliance scanner for your local network. This Home Assistant Add-on audits devices on your network, checks for common vulnerabilities, and provides security insights.

## Features
- **Network Discovery**: Automatically finds devices on your specified subnet.
- **Vulnerability Scanning**: Checks for open ports and known CVEs.
- **Compliance Reporting**: Categorizes devices based on EU Cyber Resilience Act standards.
- **AI Integration**: Optional integration with Gemini AI for enhanced security advice.

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
