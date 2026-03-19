# CRA Compliance Auditor — Home Assistant Add-on

> **Disclaimer:** This project and its contents were primarily coded with the assistance of AI. However, best efforts have been made to thoroughly check the code for security issues, implement strict application boundaries, and appropriately restrict permissions. Please review the configurations as you see fit and use at your own risk.
>
> **Haftungsausschluss:** Dieses Projekt und seine Inhalte wurden hauptsächlich mit Hilfe von KI erstellt. Es wurde jedoch sorgfältig auf Sicherheitsprobleme geprüft, strikte Anwendungsgrenzen implementiert und Berechtigungen entsprechend eingeschränkt. Bitte überprüfen Sie die Konfigurationen nach eigenem Ermessen und nutzen Sie das Projekt auf eigene Verantwortung.

[![Open your Home Assistant instance and show the add-on store with this repository added.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FZabotoBlack%2Fcra-requirement)

<!-- TODO: Add screenshot of the main dashboard here -->
<!-- ![Dashboard Screenshot](cra_auditor/media/cra-front.png) -->

---

## Table of Contents / Inhaltsverzeichnis

- [English](#-english)
  - [What is this?](#what-is-this)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Documentation](#documentation)
- [Deutsch](#-deutsch)
  - [Was ist das?](#was-ist-das)
  - [Hauptfunktionen](#hauptfunktionen)
  - [Installation (DE)](#installation-1)
  - [Schnellstart](#schnellstart)
  - [Dokumentation](#dokumentation)

---

## English

### What is this?

The **CRA Compliance Auditor** is a Home Assistant Add-on that scans your local network for IoT devices and evaluates their compliance with the **EU Cyber Resilience Act (CRA)**. It combines automated network scanning, vulnerability lookups, and optional AI-powered remediation advice into an interactive dashboard — accessible to beginners and experts alike.

The CRA (Regulation (EU) 2024/2847) requires manufacturers of products with digital elements to meet cybersecurity requirements throughout the product lifecycle. This tool helps you audit whether devices on your network meet key CRA Annex I requirements.

### Key Features

- **Network Discovery** — Automatically finds devices on your subnet using ARP, Ping, mDNS, and NetBIOS resolution
- **8 CRA Compliance Checks** — Evaluates each device against core CRA requirements:
  - Minimal Attack Surface (open port analysis)
  - Default Passwords (credential brute-force probing)
  - Known Vulnerabilities (CVE lookup via NVD API)
  - Security Logging (log endpoint detection)
  - HTTPS Only (encryption enforcement)
  - Firmware Tracking (update endpoint detection)
  - Security.txt (vulnerability disclosure policy)
  - SBOM Compliance (Software Bill of Materials availability)
- **3-Tier Dashboard** — Switchable End User / Intermediate / Expert views
- **AI Security Insights** — Optional Google Gemini integration for device-specific remediation advice
- **Scan Profiles** — Discovery (fast), Standard, and Deep scan modes
- **Scan History** — SQLite-backed history with search, sort, and individual report recall
- **60+ Vendor Mappings** — SBOM, firmware, and security.txt status for major IoT vendors
- **Bilingual UI** — English and German interface with full translation coverage
- **Dark / Light Theme** — User-selectable appearance
- **Guided Tour** — Interactive onboarding walkthrough for new users

### Installation

1. **Add the Repository**: Click the badge above, or manually go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories** and add:
   ```
   https://github.com/ZabotoBlack/cra-requirement
   ```
2. **Install**: Find **CRA Compliance Auditor** in the Add-on Store and click **Install**.
3. **Configure**: Open the add-on Configuration tab. Set your `target_subnet` (e.g. `192.168.1.0/24`). Optionally add your `gemini_api_key` and `nvd_api_key`.
4. **Start & Use**: Click **Start**, then open the **Web UI**.

### Quick Start

1. The dashboard auto-detects your subnet in Basic mode — just click **Start Scan**.
2. Switch to Intermediate or Expert mode for more control (subnet selection, scan depth, feature flags).
3. Review compliance results per device. Click a device for detailed check results.
4. (Optional) Enable Gemini AI for tailored remediation advice per device.

### Documentation

| Document | Description |
|:---|:---|
| [Add-on README](cra_auditor/README.md) | Full feature documentation, configuration reference, API endpoints, compliance checks |
| [Developer Docs](cra_auditor/DOCS.md) | Architecture, build instructions, testing, deployment, security profile |

---

## Deutsch

### Was ist das?

Der **CRA Compliance Auditor** ist ein Home Assistant Add-on, das Ihr lokales Netzwerk nach IoT-Geräten scannt und deren Konformität mit dem **EU Cyber Resilience Act (CRA)** bewertet. Es kombiniert automatisiertes Netzwerk-Scanning, Schwachstellenabfragen und optionale KI-gestützte Handlungsempfehlungen in einem interaktiven Dashboard — zugänglich für Einsteiger und Experten gleichermaßen.

Der CRA (Verordnung (EU) 2024/2847) verpflichtet Hersteller von Produkten mit digitalen Elementen, Cybersicherheitsanforderungen über den gesamten Produktlebenszyklus einzuhalten. Dieses Tool hilft Ihnen zu prüfen, ob Geräte in Ihrem Netzwerk die zentralen Anforderungen aus CRA Annex I erfüllen.

### Hauptfunktionen

- **Netzwerkerkennung** — Findet automatisch Geräte in Ihrem Subnetz mittels ARP, Ping, mDNS und NetBIOS-Auflösung
- **8 CRA-Konformitätsprüfungen** — Bewertet jedes Gerät anhand zentraler CRA-Anforderungen:
  - Minimale Angriffsfläche (Analyse offener Ports)
  - Standardpasswörter (Prüfung auf Standard-Anmeldedaten)
  - Bekannte Schwachstellen (CVE-Abfrage über NVD-API)
  - Security Logging (Erkennung von Protokollierungsendpunkten)
  - Nur HTTPS (Verschlüsselungsdurchsetzung)
  - Firmware-Tracking (Erkennung von Update-Endpunkten)
  - Security.txt (Richtlinie zur Schwachstellenmeldung)
  - SBOM-Konformität (Verfügbarkeit der Software-Stückliste)
- **Dreistufiges Dashboard** — Umschaltbar zwischen Endbenutzer / Fortgeschritten / Experte
- **KI-Sicherheitsanalysen** — Optionale Google Gemini-Integration für gerätespezifische Handlungsempfehlungen
- **Scan-Profile** — Discovery (schnell), Standard und Deep-Scan-Modi
- **Scan-Verlauf** — SQLite-gestützte Historie mit Suche, Sortierung und Einzelberichtabruf
- **60+ Herstellerzuordnungen** — SBOM-, Firmware- und Security.txt-Status für gängige IoT-Hersteller
- **Zweisprachige Oberfläche** — Englisch und Deutsch mit vollständiger Übersetzungsabdeckung
- **Dark / Light Theme** — Wählbare Darstellung
- **Geführte Tour** — Interaktive Einführung für neue Benutzer

### Installation

1. **Repository hinzufügen**: Klicken Sie auf das Badge oben, oder gehen Sie manuell zu **Einstellungen → Add-ons → Add-on Store → ⋮ → Repositories** und fügen Sie hinzu:
   ```
   https://github.com/ZabotoBlack/cra-requirement
   ```
2. **Installieren**: Finden Sie **CRA Compliance Auditor** im Add-on Store und klicken Sie auf **Installieren**.
3. **Konfigurieren**: Öffnen Sie den Reiter Konfiguration. Setzen Sie Ihr `target_subnet` (z.B. `192.168.1.0/24`). Optional: `gemini_api_key` und `nvd_api_key` hinzufügen.
4. **Starten & Nutzen**: Klicken Sie auf **Starten** und öffnen Sie die **Web-Oberfläche**.

### Schnellstart

1. Das Dashboard erkennt Ihr Subnetz im Basic-Modus automatisch — klicken Sie einfach auf **Scan starten**.
2. Wechseln Sie in den Fortgeschrittenen- oder Experten-Modus für mehr Kontrolle (Subnetzeingabe, Scantiefe, Feature-Flags).
3. Prüfen Sie die Compliance-Ergebnisse pro Gerät. Klicken Sie auf ein Gerät für detaillierte Prüfergebnisse.
4. (Optional) Aktivieren Sie Gemini-KI für maßgeschneiderte Handlungsempfehlungen pro Gerät.

### Dokumentation

| Dokument | Beschreibung |
|:---|:---|
| [Add-on README](cra_auditor/README.md) | Vollständige Funktionsdokumentation, Konfigurationsreferenz, API-Endpunkte, Konformitätsprüfungen |
| [Entwickler-Dokumentation](cra_auditor/DOCS.md) | Architektur, Build-Anleitung, Tests, Deployment, Sicherheitsprofil |
