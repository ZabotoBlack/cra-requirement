# Home Assistant Add-on: CRA Compliance Auditor - Documentation / Dokumentation

This document provides a comprehensive overview of the CRA Compliance Auditor Add-on in both English and German.
Dieses Dokument bietet eine umfassende Übersicht über das CRA Compliance Auditor Add-on in Englisch und Deutsch.

---

## 🇬🇧 English Documentation

### Summary
The **CRA Compliance Auditor** is a powerful Home Assistant Add-on that scans your local network to evaluate device compliance against the EU Cyber Resilience Act (CRA). It provides tiered dashboards (Basic to Expert), detects open ports and vulnerabilities, verifies built-in security mechanisms, and leverages AI for actionable remediation advice.

### Features
- **Network Discovery & Scanning**: Automatically detects your subnet or uses a designated CIDR range to find active network devices using ARP and Ping.
- **Advanced Hostname Resolution**: Improves device identification using Nmap NetBIOS, Reverse DNS (PTR), and mDNS (`zeroconf`).
- **Port & Service Analysis**: Scans open ports, detects operating systems, and identifies service versions running on local devices.
- **CRA Compliance Checks**: Evaluates devices against 8 key CRA requirements:
  - Minimal Attack Surface (Monitoring open ports)
  - Default Passwords (Checking for common default credentials)
  - Known Vulnerabilities (CVE lookups using the NVD API)
  - Security Logging (Probing for local logging endpoints)
  - HTTPS Only (Verifying secure communications)
  - Firmware Tracking (Detecting update endpoints)
  - Security.txt (Checking for proper disclosure channels)
  - Data Protection (Validating secure data handling, where applicable)
- **AI Security Insights**: Integrates Google Gemini to provide contextual, device-specific advice to mitigate risks and secure non-compliant endpoints.
- **Tiered 3-Level Dashboard**:
  - **End User (Basic)**: Locks advanced fields, uses auto-detected subnets, and focuses on simple health metrics.
  - **Intermediate**: Allows subnet selection, presenting a clear device list and compliance status.
  - **Expert**: Provides full technical access, raw data inspection, vulnerability details, JSON export, and a live runtime log console.
- **Historical Scans**: All reports are stored locally in an SQLite database (`scans.db`) so you can review previous audits.
- **Developer Tools**: Includes scripts for mocking security logging devices (`mock_security_logging_device.py`).

### Configuration (`config.yaml`)
| Option | Type | Description |
| :--- | :--- | :--- |
| `target_subnet` | string | The CIDR range to scan (e.g., `192.168.1.0/24`). |
| `gemini_api_key` | string | (Optional) Google Gemini API Key for enhanced AI analysis. |
| `nvd_api_key` | string | (Optional) Recommended to increase the rate limits for NVD CVE lookups. |
| `log_level` | string | Backend logging verbosity (`trace`, `debug`, `scan_info`, `info`, `warning`, `error`, `fatal`). Default: `info`. |
| `verify_ssl` | boolean | Toggle strict SSL verification. Default: `false`. |

### Scan Profiles
The Add-on UI and API (`POST /api/scan`) support modular profiles:
- **Discovery**: Fast network mapping. Finds IPs, MACs, and hostnames. *Skips all compliance checks.*
- **Standard**: Scans the top 100 ports + common vendor ports. Enables web-based checks (HTTPS, Security.txt) but disables aggressive authentication brute-forcing.
- **Deep**: Extensive port scanning, OS detection, service versioning, and aggressive compliance validation (including default credential checking).

### Developer Docs Map
- **`server.py`**: Flask API, scan state, UI asset serving, database persistence.
- **`scan_logic.py`**: The core Nmap scanning pipeline and individual compliance check routines.
- **`vulnerability_data/`**: NVD API client (`nvd.py`), rule lookups (`rules.py`), and CPE management (`cpe.py`).
- **`App.tsx` & `components/`**: React application shell, routing, 3-tier Dashboards, and Device List tables.

---

## 🇩🇪 Deutsche Dokumentation

### Zusammenfassung
Der **CRA Compliance Auditor** ist ein leistungsstarkes Home Assistant Add-on, das Ihr lokales Netzwerk scannt, um die Konformität von Geräten mit dem EU Cyber Resilience Act (CRA) zu bewerten. Es bietet mehrstufige Dashboards (Basic bis Expert), erkennt offene Ports und Schwachstellen, überprüft integrierte Sicherheitsmechanismen und nutzt KI für handlungsorientierte Behebungsvorschläge.

### Hauptfunktionen
- **Netzwerkerkennung & Scanning**: Erkennt automatisch Ihr Subnetz oder nutzt einen festgelegten CIDR-Bereich, um aktive Netzwerkgeräte über ARP und Ping zu finden.
- **Erweiterte Hostnamen-Auflösung**: Verbessert die Geräteidentifikation durch die Kombination von Nmap NetBIOS, Reverse DNS (PTR) und mDNS (`zeroconf`).
- **Port- & Service-Analyse**: Scannt offene Ports, erkennt Betriebssysteme und identifiziert Versionen laufender Dienste im lokalen Netzwerk.
- **CRA-Konformitätsprüfungen**: Bewertet Geräte anhand von 8 zentralen CRA-Anforderungen:
  - Minimale Angriffsfläche (Überwachung offener Ports)
  - Standardpasswörter (Überprüfung auf weit verbreitete Standard-Anmeldedaten)
  - Bekannte Schwachstellen (CVE-Abfragen über die NVD-API)
  - Security Logging (Prüfung auf lokale Endpunkte zur Sicherheitsprotokollierung)
  - Nur HTTPS (Sicherstellung verschlüsselter Kommunikation)
  - Firmware-Tracking (Erkennung von Update-Endpunkten)
  - Security.txt (Prüfung auf standardisierte Kanäle zur Schwachstellenmeldung)
  - Datenschutz (Überprüfung sicherer Datenhandhabung, sofern zutreffend)
- **KI-Sicherheitsanalysen**: Integriert Google Gemini, um kontextbezogene, gerätespezifische Ratschläge zur Risikominderung abzurufen.
- **Dreistufiges Dashboard**:
  - **End User (Basic)**: Sperrt erweiterte Felder, nutzt automatisch erkannte Subnetze und fokussiert sich auf einfache Gesundheitskennzahlen.
  - **Intermediate**: Erlaubt die Subnetzauswahl und bietet eine klare Geräte- und Konformitätsübersicht.
  - **Expert**: Bietet vollen technischen Zugriff, Rohdatenprüfung, Schwachstellendetails, JSON-Exporte und eine Live-Protokollkonsole.
- **Historische Scans**: Alle Berichte werden lokal in einer SQLite-Datenbank (`scans.db`) gespeichert, sodass frühere Audits jederzeit überprüfbar sind.
- **Entwickler-Tools**: Enthält Skripte zur Simulation von Geräten mit Sicherheitsprotokollierung (`mock_security_logging_device.py`).

### Konfiguration (`config.yaml`)
| Option | Typ | Beschreibung |
| :--- | :--- | :--- |
| `target_subnet` | string | Der zu scannende CIDR-Bereich (z.B. `192.168.1.0/24`). |
| `gemini_api_key` | string | (Optional) Google Gemini API-Schlüssel für erweiterte KI-Analysen. |
| `nvd_api_key` | string | (Optional) Empfohlen, um die Ratenlimits für NVD-CVE-Abfragen zu erhöhen. |
| `log_level` | string | Detailgrad der Backend-Protokolle (`trace`, `debug`, `scan_info`, `info`, `warning`, `error`, `fatal`). Standard: `info`. |
| `verify_ssl` | boolean | Aktiviert strikte SSL-Überprüfung. Standard: `false`. |

### Scan-Profile
Die Add-on-Benutzeroberfläche und die API (`POST /api/scan`) unterstützen modulare Profile:
- **Discovery (Entdeckung)**: Schnelles Netzwerk-Mapping. Findet IP- und MAC-Adressen sowie Hostnamen. *Überspringt alle Konformitätsprüfungen.*
- **Standard**: Scannt die Top-100-Ports sowie gängige Hersteller-Ports. Aktiviert webbasierte Prüfungen (HTTPS, Security.txt), verzichtet jedoch auf aggressives Authentication-Brute-Forcing.
- **Deep (Tiefenscan)**: Ausführlicher Port-Scan, Betriebssystemerkennung, Service-Versionierung und aggressive Konformitätsprüfungen (inkl. Tests auf Standardpasswörter).

### Entwickler-Dokumentation (Karte)
- **`server.py`**: Flask-API, Scan-Status, Auslieferung von UI-Assets, Datenbank-Persistenz.
- **`scan_logic.py`**: Die zentrale Nmap-Scanning-Pipeline und individuelle Konformitätsprüfroutinen.
- **`vulnerability_data/`**: NVD API Client (`nvd.py`), Regel-Lookups (`rules.py`) und CPE-Verwaltung (`cpe.py`).
- **`App.tsx` & `components/`**: React-Anwendungsstruktur, Routing, 3-stufige Dashboards und die Gerätelisten-Tabellen.
