# CRA Compliance Auditor Add-on for Home Assistant

![Logo](media/cra-front.png)

A comprehensive Cyber Resilience Act (CRA) compliance scanner for your local network. This Home Assistant Add-on audits devices on your network, checks for common vulnerabilities, and provides security insights.

Ein umfassender Cyber Resilience Act (CRA) Compliance-Scanner für Ihr lokales Netzwerk. Dieses Home Assistant Add-on prüft Geräte in Ihrem Netzwerk auf Schwachstellen und liefert Sicherheitseinblicke.

---

## Table of Contents / Inhaltsverzeichnis

- [English](#-english)
  - [Features](#features)
  - [Dashboard Modes](#dashboard-modes)
  - [CRA Compliance Checks](#cra-compliance-checks)
  - [Scan Profiles & Feature Flags](#scan-profiles--feature-flags)
  - [Configuration Reference](#configuration-reference)
  - [API Endpoint Reference](#api-endpoint-reference)
  - [Vendor Support](#vendor-support)
  - [Security & Permissions](#security--permissions)
  - [Installation](#installation)
- [Deutsch](#-deutsch)
  - [Funktionen](#funktionen)
  - [Dashboard-Modi](#dashboard-modi)
  - [CRA-Konformitätsprüfungen](#cra-konformitätsprüfungen)
  - [Scan-Profile & Feature-Flags](#scan-profile--feature-flags)
  - [Konfigurationsreferenz](#konfigurationsreferenz)
  - [API-Endpunkt-Referenz](#api-endpunkt-referenz)
  - [Herstellerunterstützung](#herstellerunterstützung)
  - [Sicherheit & Berechtigungen](#sicherheit--berechtigungen)
  - [Installation (DE)](#installation-1)

---

## English

### Features

- **Network Discovery & Scanning**: Automatically detects your subnet or uses a designated CIDR range to find active network devices using ARP, Ping, mDNS (`zeroconf`), and NetBIOS.
- **Advanced Hostname Resolution**: Combines Nmap NetBIOS, Reverse DNS (PTR), and mDNS for improved device identification.
- **Port & Service Analysis**: Scans open ports, detects operating systems, and identifies running service versions.
- **8 CRA Compliance Checks**: Evaluates devices against core EU Cyber Resilience Act requirements (see [CRA Compliance Checks](#cra-compliance-checks) below).
- **AI Security Insights**: Integrates Google Gemini to provide contextual, device-specific remediation advice.
- **3-Tier Dashboard**: End User (Basic), Intermediate, and Expert views — switchable via header toggle or Settings.
- **Scan History**: All reports stored locally in SQLite (`scans.db`) with search, sort, and per-report recall.
- **Bilingual UI**: Full English and German translation (150+ translation keys).
- **Dark / Light Theme**: User-selectable appearance toggle.
- **Guided Tour**: Interactive onboarding walkthrough for first-time users.
- **Scan Abort**: Cancel in-progress scans at any time.
- **JSON Export**: Export full scan reports in Expert mode.
- **Home Assistant Integration**: Merges scan results with the HA device registry for richer context.

### Dashboard Modes

The UI supports three switchable experience levels (toggle in the command header or Settings):

#### End User (Basic)
- Auto-detects subnet via backend (`/api/network/default`) and locks subnet input
- Simplified health summary cards and plain-language issue list
- Hides advanced tables and raw data views
- If automatic subnet detection is unavailable, prompts once for a CIDR subnet

#### Intermediate
- Editable subnet input
- Standard dashboard with device overview and optional expanded detail
- Compliance status per device

#### Expert
- Full dashboard plus complete device list with all check details
- In-app runtime log console via `/api/logs`
- JSON export button for full report payload
- Scan feature flag customization

### CRA Compliance Checks

Each device is evaluated against 8 checks derived from CRA Annex I requirements:

| # | Check | CRA Reference | What it does |
|:--|:------|:-------------|:-------------|
| 1 | **Minimal Attack Surface** | Annex I §1.3(e) | Analyzes open ports and calculates an attack surface score. Flags UPnP, SMBv1, or excessive port exposure. |
| 2 | **Default Passwords** | Annex I §1.3(c) | Probes for telnet access, default HTTP credentials, and vendor-specific weak authentication. |
| 3 | **Known Vulnerabilities** | Annex I §1.2(a) | Queries the NVD API for CVEs matching the device's CPE. Filters by CVSS severity. |
| 4 | **Security Logging** | Annex I §1.3(j) | Probes for HTTP log endpoints (configurable paths) and UDP syslog listeners (port 514). |
| 5 | **HTTPS Only** | Annex I §1.3(d) | Tests whether HTTP ports redirect to HTTPS. Flags unencrypted services (FTP, Telnet, plain HTTP). |
| 6 | **Firmware Tracking** | Annex I §1.4 | Detects firmware update endpoints and version strings using vendor-specific probe rules. |
| 7 | **Security.txt** | Annex I §1.2(b) | Checks for `/.well-known/security.txt` and parses contact, expires, encryption, and policy fields. |
| 8 | **SBOM Compliance** | Annex I §1.2(c) | Probes `/sbom` and `/.well-known/sbom` endpoints. Maps vendor SBOM availability status. Detects format (SPDX, CycloneDX). |

#### Compliance Status Values
- **Compliant** — All applicable checks passed
- **Warning** — Some checks raised concerns
- **Non-Compliant** — Critical failures detected
- **Discovered** — Device found but not yet evaluated

### Scan Profiles & Feature Flags

The backend supports modular scanning profiles and explicit feature flags via `POST /api/scan`.

#### Profile Defaults

| Profile | Port Scan | Port Range | OS Detection | Service Version | Compliance Checks | Auth Brute Force | Web Crawling |
|:--------|:----------|:-----------|:-------------|:----------------|:------------------|:-----------------|:-------------|
| **Discovery** | No | — | No | No | No | No | No |
| **Standard** | Yes | 1-100 + vendor ports | No | Yes | Yes | No | Yes |
| **Deep** | Yes | 1-1024 + vendor ports | Yes | Yes | Yes | Yes | Yes |

#### Supported Feature Flags
- `network_discovery`, `port_scan`, `os_detection`, `service_version`
- `netbios_info`, `compliance_checks`, `auth_brute_force`, `web_crawling`
- `port_range` (optional override, e.g. `"1-512"`)

#### Example Payload

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

Legacy `scan_type` and `auth_checks` fields are still accepted and mapped to the new model server-side.

### Configuration Reference

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `target_subnet` | string | — | CIDR range to scan (e.g. `192.168.1.0/24`) |
| `gemini_api_key` | password | — | (Optional) Google Gemini API key for AI remediation advice |
| `nvd_api_key` | password | — | (Optional, recommended) NVD API key for faster CVE lookups |
| `api_access_token` | password | — | (Optional) Token to protect sensitive API endpoints |
| `max_scan_hosts` | int | 65536 | Maximum number of hosts per scan |
| `min_ipv4_prefix` | int | 16 | Minimum allowed subnet prefix length (e.g. /16) |
| `log_level` | enum | `info` | Backend log verbosity: `trace`, `debug`, `scan_info`, `info`, `warning`, `error`, `fatal` |
| `verify_ssl` | bool | `false` | Strict SSL certificate verification for outbound probes |

#### Log Level Behavior
- `info` — High-level scan lifecycle and stage summaries
- `scan_info` — Detailed per-device scan progress and Nmap arguments
- `debug` — Internal diagnostics (lock/thread state, exception tracebacks)

> **Note:** Default output is intentionally less verbose than earlier versions. Set `log_level: scan_info` for detailed per-device progress.

### API Endpoint Reference

#### Scan Operations
| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/scan` | Start a scan (body: `{ subnet, options }`) |
| `GET` | `/api/status` | Poll scan progress and state |
| `POST` | `/api/scan/abort` | Cancel the active scan |

#### Data Retrieval
| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/report` | Latest scan results |
| `GET` | `/api/history` | List past scans (supports `search`, `sort`, `order` query params) |
| `GET` | `/api/history/<id>` | Full report for a specific scan |
| `DELETE` | `/api/history/<id>` | Remove a scan record |
| `GET` | `/api/config` | Feature flags: `gemini_enabled`, `nvd_enabled`, `version` |
| `GET` | `/api/logs?limit=150` | Runtime log buffer for Expert console |
| `GET` | `/api/network/default` | Auto-detected subnet (`{"subnet":"...","source":"auto"}`) |

#### AI & Analysis
| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/gemini/advice` | AI-generated remediation advice for a specific device |

### Vendor Support

The add-on includes vendor-specific detection and CRA mapping for 60+ IoT manufacturers, including:

**Active scanning support** (dedicated port probing): Tuya, Sonoff/ITEAD, TP-Link Kasa, Shelly, Philips Hue, IKEA Tradfri

**Vendor rules database** (`data/vendor_rules.yaml`):
- SBOM availability status per vendor
- Firmware update endpoint URLs
- Security.txt publication status
- Direct SBOM portal links (Siemens, Philips, Cisco, etc.)

### Security & Permissions

This add-on requires elevated permissions for network scanning:

| Setting | Value | Purpose |
|:--------|:------|:--------|
| `privileged` | `NET_ADMIN`, `NET_RAW` | Low-level network operations (ARP scanning, raw sockets) |
| `host_network` | `true` | Share host network stack for accurate device discovery |
| `apparmor` | Custom profile | Restricts filesystem access; R/W limited to `/data`, `/tmp` |

#### API Token Protection
Sensitive endpoints are protected by the `api_access_token` configuration option. When set, requests to protected endpoints must include the token. When not set, the system falls back to private-network IP verification.

#### Security Headers
The backend sets security headers on all responses:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options`

> **Warning:** These settings grant the container significant access to the host network. Ensure you trust this add-on and the device running it.

### Installation

1. Add this repository to your Home Assistant Add-on Store.
2. Install the **CRA Compliance Auditor**.
3. Configure `target_subnet` in the Configuration tab.
4. (Optional) Add your `gemini_api_key` for AI features.
5. (Optional, recommended) Add your `nvd_api_key` for faster NVD lookups.
6. (Optional) Set `api_access_token` for API endpoint protection.
7. Start the Add-on and open the Web UI.

### Security Logging Probe Configuration

Security logging endpoint detection (CRA Annex I §1(3)(j)) is configured via:

- `data/security_logging_paths.yaml`
- Optional env override: `CRA_SECURITY_LOG_PATHS_FILE`

Default probed paths:
```yaml
log_paths:
  - /api/logs
  - /logs
  - /admin/logs
  - /syslog
  - /journal
  - /cgi-bin/log.cgi
```

### NVD Cache Policy

- Cache stored at `<data_dir>/nvd_cache.json` (file-based, 24h TTL)
- Data directory: `/data` in HA add-on runtime, overridable via `CRA_DATA_DIR`
- Rate limiting: 6.2s between requests without API key, 0.8s with key
- Refresh cache by deleting `nvd_cache.json`; it regenerates on next lookup

---

## Deutsch

### Funktionen

- **Netzwerkerkennung & Scanning**: Erkennt automatisch Ihr Subnetz oder nutzt einen festgelegten CIDR-Bereich, um aktive Netzwerkgeräte über ARP, Ping, mDNS (`zeroconf`) und NetBIOS zu finden.
- **Erweiterte Hostnamen-Auflösung**: Kombiniert Nmap NetBIOS, Reverse DNS (PTR) und mDNS für verbesserte Geräteidentifikation.
- **Port- & Service-Analyse**: Scannt offene Ports, erkennt Betriebssysteme und identifiziert laufende Service-Versionen.
- **8 CRA-Konformitätsprüfungen**: Bewertet Geräte anhand zentraler EU Cyber Resilience Act Anforderungen (siehe [CRA-Konformitätsprüfungen](#cra-konformitätsprüfungen) unten).
- **KI-Sicherheitsanalysen**: Integriert Google Gemini für kontextbezogene, gerätespezifische Handlungsempfehlungen.
- **Dreistufiges Dashboard**: Endbenutzer (Basic), Fortgeschritten und Experte — umschaltbar über Header-Toggle oder Einstellungen.
- **Scan-Verlauf**: Alle Berichte lokal in SQLite (`scans.db`) gespeichert, mit Suche, Sortierung und Einzelberichtabruf.
- **Zweisprachige Oberfläche**: Vollständige Übersetzung Englisch und Deutsch (150+ Übersetzungsschlüssel).
- **Dark / Light Theme**: Wählbarer Darstellungsmodus.
- **Geführte Tour**: Interaktive Einführung für Erstbenutzer.
- **Scan-Abbruch**: Laufende Scans jederzeit abbrechen.
- **JSON-Export**: Vollständigen Scan-Bericht im Expertenmodus exportieren.
- **Home Assistant Integration**: Verknüpft Scan-Ergebnisse mit dem HA-Geräteregister für reichhaltigeren Kontext.

### Dashboard-Modi

Die Oberfläche unterstützt drei umschaltbare Erfahrungsstufen (Toggle im Header oder in den Einstellungen):

#### Endbenutzer (Basic)
- Automatische Subnetzerkennung über Backend (`/api/network/default`), Subnetzeingabe gesperrt
- Vereinfachte Gesundheitsübersicht und verständliche Problemliste
- Erweiterte Tabellen und Rohdaten ausgeblendet
- Falls automatische Erkennung nicht verfügbar: einmalige Abfrage des CIDR-Subnetzes

#### Fortgeschritten
- Editierbare Subnetzeingabe
- Standard-Dashboard mit Geräteübersicht und optionaler Detailansicht
- Compliance-Status pro Gerät

#### Experte
- Vollständiges Dashboard mit kompletter Geräteliste und allen Prüfdetails
- Laufzeit-Protokollkonsole über `/api/logs`
- JSON-Export-Button für den vollständigen Bericht
- Anpassung der Scan-Feature-Flags

### CRA-Konformitätsprüfungen

Jedes Gerät wird anhand von 8 Prüfungen bewertet, die aus den CRA Annex I Anforderungen abgeleitet sind:

| # | Prüfung | CRA-Referenz | Was wird geprüft |
|:--|:--------|:-------------|:-----------------|
| 1 | **Minimale Angriffsfläche** | Annex I §1.3(e) | Analysiert offene Ports und berechnet einen Angriffsflächenwert. Meldet UPnP, SMBv1 oder übermäßige Port-Exposition. |
| 2 | **Standardpasswörter** | Annex I §1.3(c) | Prüft auf Telnet-Zugang, Standard-HTTP-Anmeldedaten und herstellerspezifische schwache Authentifizierung. |
| 3 | **Bekannte Schwachstellen** | Annex I §1.2(a) | Fragt die NVD-API nach CVEs ab, die zum CPE des Geräts passen. Filtert nach CVSS-Schweregrad. |
| 4 | **Security Logging** | Annex I §1.3(j) | Prüft auf HTTP-Protokollierungsendpunkte (konfigurierbare Pfade) und UDP-Syslog-Listener (Port 514). |
| 5 | **Nur HTTPS** | Annex I §1.3(d) | Testet, ob HTTP-Ports auf HTTPS weiterleiten. Meldet unverschlüsselte Dienste (FTP, Telnet, HTTP). |
| 6 | **Firmware-Tracking** | Annex I §1.4 | Erkennt Firmware-Update-Endpunkte und Versionszeichenfolgen mittels herstellerspezifischer Probe-Regeln. |
| 7 | **Security.txt** | Annex I §1.2(b) | Prüft auf `/.well-known/security.txt` und parst Kontakt-, Ablauf-, Verschlüsselungs- und Richtlinienfelder. |
| 8 | **SBOM-Konformität** | Annex I §1.2(c) | Prüft `/sbom` und `/.well-known/sbom` Endpunkte. Kartiert Hersteller-SBOM-Verfügbarkeit. Erkennt Format (SPDX, CycloneDX). |

#### Konformitätsstatus-Werte
- **Konform (Compliant)** — Alle zutreffenden Prüfungen bestanden
- **Warnung (Warning)** — Einige Prüfungen zeigen Auffälligkeiten
- **Nicht konform (Non-Compliant)** — Kritische Fehler erkannt
- **Entdeckt (Discovered)** — Gerät gefunden, aber noch nicht bewertet

### Scan-Profile & Feature-Flags

Das Backend unterstützt modulare Scan-Profile und explizite Feature-Flags über `POST /api/scan`.

#### Profil-Standardwerte

| Profil | Port-Scan | Port-Bereich | OS-Erkennung | Service-Version | Konformitätsprüfungen | Auth-Brute-Force | Web-Crawling |
|:-------|:----------|:-------------|:-------------|:----------------|:----------------------|:-----------------|:-------------|
| **Discovery** | Nein | — | Nein | Nein | Nein | Nein | Nein |
| **Standard** | Ja | 1-100 + Hersteller-Ports | Nein | Ja | Ja | Nein | Ja |
| **Deep** | Ja | 1-1024 + Hersteller-Ports | Ja | Ja | Ja | Ja | Ja |

#### Unterstützte Feature-Flags
- `network_discovery`, `port_scan`, `os_detection`, `service_version`
- `netbios_info`, `compliance_checks`, `auth_brute_force`, `web_crawling`
- `port_range` (optionale Überschreibung, z.B. `"1-512"`)

#### Beispiel-Payload

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

Legacy-Felder `scan_type` und `auth_checks` werden weiterhin akzeptiert und serverseitig auf das neue Modell abgebildet.

### Konfigurationsreferenz

| Option | Typ | Standard | Beschreibung |
|:-------|:----|:---------|:-------------|
| `target_subnet` | string | — | Zu scannender CIDR-Bereich (z.B. `192.168.1.0/24`) |
| `gemini_api_key` | password | — | (Optional) Google Gemini API-Schlüssel für KI-Handlungsempfehlungen |
| `nvd_api_key` | password | — | (Optional, empfohlen) NVD API-Schlüssel für schnellere CVE-Abfragen |
| `api_access_token` | password | — | (Optional) Token zum Schutz sensibler API-Endpunkte |
| `max_scan_hosts` | int | 65536 | Maximale Anzahl Hosts pro Scan |
| `min_ipv4_prefix` | int | 16 | Minimale erlaubte Subnetz-Präfixlänge (z.B. /16) |
| `log_level` | enum | `info` | Backend-Protokollverbosität: `trace`, `debug`, `scan_info`, `info`, `warning`, `error`, `fatal` |
| `verify_ssl` | bool | `false` | Strikte SSL-Zertifikatsüberprüfung für ausgehende Probes |

#### Log-Level-Verhalten
- `info` — Übergeordneter Scan-Lebenszyklus und Stufenzusammenfassungen
- `scan_info` — Detaillierter Scan-Fortschritt pro Gerät und Nmap-Argumente
- `debug` — Interne Diagnose (Lock/Thread-Status, Exception-Tracebacks)

> **Hinweis:** Die Standardausgabe ist absichtlich weniger ausführlich als in früheren Versionen. Setzen Sie `log_level: scan_info` für detaillierten Geräte-Fortschritt.

### API-Endpunkt-Referenz

#### Scan-Operationen
| Methode | Endpunkt | Beschreibung |
|:--------|:---------|:-------------|
| `POST` | `/api/scan` | Scan starten (Body: `{ subnet, options }`) |
| `GET` | `/api/status` | Scan-Fortschritt und Status abfragen |
| `POST` | `/api/scan/abort` | Aktiven Scan abbrechen |

#### Datenabruf
| Methode | Endpunkt | Beschreibung |
|:--------|:---------|:-------------|
| `GET` | `/api/report` | Neueste Scan-Ergebnisse |
| `GET` | `/api/history` | Vergangene Scans auflisten (`search`, `sort`, `order` Query-Parameter) |
| `GET` | `/api/history/<id>` | Vollständiger Bericht eines bestimmten Scans |
| `DELETE` | `/api/history/<id>` | Scan-Eintrag löschen |
| `GET` | `/api/config` | Feature-Flags: `gemini_enabled`, `nvd_enabled`, `version` |
| `GET` | `/api/logs?limit=150` | Laufzeit-Logpuffer für Experten-Konsole |
| `GET` | `/api/network/default` | Automatisch erkanntes Subnetz (`{"subnet":"...","source":"auto"}`) |

#### KI & Analyse
| Methode | Endpunkt | Beschreibung |
|:--------|:---------|:-------------|
| `POST` | `/api/gemini/advice` | KI-generierte Handlungsempfehlung für ein bestimmtes Gerät |

### Herstellerunterstützung

Das Add-on enthält herstellerspezifische Erkennung und CRA-Zuordnung für 60+ IoT-Hersteller, darunter:

**Aktives Scanning** (dediziertes Port-Probing): Tuya, Sonoff/ITEAD, TP-Link Kasa, Shelly, Philips Hue, IKEA Tradfri

**Herstellerregeln-Datenbank** (`data/vendor_rules.yaml`):
- SBOM-Verfügbarkeitsstatus pro Hersteller
- Firmware-Update-Endpunkt-URLs
- Security.txt-Veröffentlichungsstatus
- Direkte SBOM-Portal-Links (Siemens, Philips, Cisco usw.)

### Sicherheit & Berechtigungen

Dieses Add-on benötigt erhöhte Berechtigungen für das Netzwerk-Scanning:

| Einstellung | Wert | Zweck |
|:------------|:-----|:------|
| `privileged` | `NET_ADMIN`, `NET_RAW` | Low-Level-Netzwerkoperationen (ARP-Scanning, Raw Sockets) |
| `host_network` | `true` | Gemeinsamer Host-Netzwerkstack für akkurate Geräteerkennung |
| `apparmor` | Eigenes Profil | Eingeschränkter Dateisystemzugriff; Schreibzugriff nur auf `/data`, `/tmp` |

#### API-Token-Schutz
Sensible Endpunkte werden durch die Konfigurationsoption `api_access_token` geschützt. Wenn gesetzt, müssen Anfragen an geschützte Endpunkte den Token enthalten. Ohne Token greift das System auf private Netzwerk-IP-Verifizierung zurück.

#### Sicherheitsheader
Das Backend setzt Sicherheitsheader bei allen Antworten:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options`

> **Warnung:** Diese Einstellungen gewähren dem Container erheblichen Zugriff auf das Host-Netzwerk. Stellen Sie sicher, dass Sie diesem Add-on und dem ausführenden Gerät vertrauen.

### Installation

1. Fügen Sie dieses Repository Ihrem Home Assistant Add-on Store hinzu.
2. Installieren Sie den **CRA Compliance Auditor**.
3. Konfigurieren Sie `target_subnet` im Reiter Konfiguration.
4. (Optional) Fügen Sie Ihren `gemini_api_key` für KI-Funktionen hinzu.
5. (Optional, empfohlen) Fügen Sie Ihren `nvd_api_key` für schnellere NVD-Abfragen hinzu.
6. (Optional) Setzen Sie `api_access_token` für API-Endpunktschutz.
7. Starten Sie das Add-on und öffnen Sie die Web-Oberfläche.

### Konfiguration der Security-Logging-Probe

Die Erkennung von Security-Logging-Endpunkten (CRA Annex I §1(3)(j)) wird konfiguriert über:

- `data/security_logging_paths.yaml`
- Optionale Umgebungsvariable: `CRA_SECURITY_LOG_PATHS_FILE`

Standard-Prüfpfade:
```yaml
log_paths:
  - /api/logs
  - /logs
  - /admin/logs
  - /syslog
  - /journal
  - /cgi-bin/log.cgi
```

### NVD-Cache-Richtlinie

- Cache gespeichert unter `<data_dir>/nvd_cache.json` (dateibasiert, 24h TTL)
- Datenverzeichnis: `/data` im HA-Add-on-Laufzeitbetrieb, überschreibbar via `CRA_DATA_DIR`
- Ratenlimitierung: 6,2s zwischen Anfragen ohne API-Schlüssel, 0,8s mit Schlüssel
- Cache aktualisieren durch Löschen von `nvd_cache.json`; wird bei nächster Abfrage neu erstellt
