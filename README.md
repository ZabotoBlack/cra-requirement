# CRA Compliance Auditor - Home Assistant Repository

> **Disclaimer:** This project and its contents were primarily coded with the assistance of AI. However, best efforts have been made to thoroughly check the code for security issues, implement strict application boundaries, and appropriately restrict permissions. Please review the configurations as you see fit and use at your own risk.

[![Open your Home Assistant instance and show the add-on store with this repository added.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FZabotoBlack%2Fcra-requirement)

This is a custom Home Assistant Add-on repository that hosts the **CRA Compliance Auditor**.

## About the CRA Compliance Auditor

A comprehensive Cyber Resilience Act (CRA) compliance scanner for your local network. This Home Assistant Add-on audits devices on your network, checks for common vulnerabilities, and provides security insights.

### Features
- **Network Discovery**: Automatically finds devices on your specified subnet.
- **Vulnerability Scanning**: Checks for open ports and known vulnerabilities.
- **Compliance Reporting**: Categorizes devices based on EU Cyber Resilience Act standards.
- **AI Integration**: Optional integration with Gemini AI for enhanced security advice.
- **3-Tier Dashboard Modes**: Switchable End User, Intermediate, and Expert views.

### Installation Requirements & Security Permissions
For the scanner to function optimally, this add-on requires specific capabilities (e.g., `NET_ADMIN`, `NET_RAW`) to run low-level network operations like ARP scanning and raw socket communication via Nmap. It runs with AppArmor profiles explicitly configured to restrict unauthorized filesystem or system interactions. 

For detailed developer documentation, component architecture, module responsibilities, and deeper configurations, please see the full [Add-on README](cra_auditor/README.md) and [Developer Docs](cra_auditor/DOCS.md) inside the `cra_auditor/` directory.

## How to Install

1. **Add the Repository:** Click the "Open in my Home Assistant" button above to add this repository to your instance automatically.
   *(Manual method: Go to Settings -> Add-ons -> Add-on Store -> 3 dots in the top right -> Repositories, and add `https://github.com/ZabotoBlack/cra-requirement`)*
2. **Install Add-on:** Locate **CRA Compliance Auditor** in your Add-on Store and click Install.
3. **Configure:** Open the add-on, navigate to the Configuration tab, and ensure your `target_subnet` and other settings (like an optional NVD API key) are configured.
4. **Start & Use:** Click Start, then use the "Open Web UI" button to view your network dashboard.
