import nmap
import re
import requests
import socket
import logging
import os
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pre-compiled regex for NetBIOS hostname extraction (performance)
_NBSTAT_RE = re.compile(r"NetBIOS name:\s+([\w-]+)")

# Pre-compiled regex for generic firmware version extraction from HTTP content
_FW_VERSION_RE = re.compile(
    r'(?:firmware|fw|version|ver|software|sw)[:\s_=-]*v?(\d+\.\d+[\w./-]*)',
    re.IGNORECASE,
)

# Known vendor SBOM availability status (best-effort lookup)
# Values: "available" = vendor publishes SBOMs, "unavailable" = known to NOT publish, "unknown" = no data
VENDOR_SBOM_STATUS = {
    "Philips": "available",
    "Signify": "available",        # Philips Hue parent company
    "Siemens": "available",
    "Bosch": "available",
    "Schneider Electric": "available",
    "ABB": "available",
    "Honeywell": "available",
    "Cisco": "available",
    "Intel": "available",
    "Microsoft": "available",
    "Google": "available",
    "Apple": "available",
    "Samsung": "available",
    "Tuya": "unavailable",
    "Sonoff": "unavailable",
    "ITEAD": "unavailable",        # Sonoff parent
    "Shelly": "unavailable",
    "Allterco": "unavailable",     # Shelly parent
    "TP-Link": "unavailable",
    "Kasa": "unavailable",
    "Tapo": "unavailable",
    "IKEA": "unknown",
    "AVM": "unknown",
    "Espressif": "unknown",
    "Xiaomi": "unavailable",
    "Aqara": "unavailable",
    "Meross": "unavailable",
    "Govee": "unavailable",
    "Wyze": "unavailable",
    "Ring": "unknown",
    "Amazon": "unknown",
    "Yamaha": "unknown",
    "Ubiquiti": "unknown",
    "Synology": "unknown",
    "QNAP": "unknown",
    "Netgear": "unavailable",
    "D-Link": "unavailable",
    "Reolink": "unavailable",
    "Hikvision": "unavailable",
    "Dahua": "unavailable",
    "ESPHome": "unavailable",
    "Tasmota": "unavailable",
    "Raspberry Pi": "unknown",
}

# Known vendor SBOM portal URLs (for direct linking in reports)
VENDOR_SBOM_URLS = {
    "Siemens": "https://sbom.siemens.com/",
    "Philips": "https://www.philips.com/a-w/security/coordinated-vulnerability-disclosure",
    "Signify": "https://www.signify.com/global/vulnerability-disclosure",
    "Bosch": "https://psirt.bosch.com/",
    "Cisco": "https://www.cisco.com/c/en/us/about/trust-center.html",
}

# Known vendor firmware update / changelog URLs
VENDOR_FIRMWARE_UPDATE_URLS = {
    "Shelly": "https://shelly-api-docs.shelly.cloud/gen2/changelog/",
    "Allterco": "https://shelly-api-docs.shelly.cloud/gen2/changelog/",
    "Philips": "https://www.philips-hue.com/en-us/support/release-notes",
    "Signify": "https://www.philips-hue.com/en-us/support/release-notes",
    "IKEA": "https://www.ikea.com/us/en/customer-service/product-support/smart-home/",
    "TP-Link": "https://www.tp-link.com/us/support/download/",
    "Kasa": "https://www.tp-link.com/us/support/download/",
    "Tapo": "https://www.tp-link.com/us/support/download/",
    "Tuya": "https://developer.tuya.com/en/docs/iot/firmware-update",
    "Sonoff": "https://sonoff.tech/product-review/product-tutorials/",
    "ITEAD": "https://sonoff.tech/product-review/product-tutorials/",
    "AVM": "https://en.avm.de/service/current-security-notifications/",
    "FRITZ": "https://en.avm.de/service/current-security-notifications/",
    "Cisco": "https://www.cisco.com/c/en/us/support/all-products.html",
    "Xiaomi": "https://home.mi.com/",
    "Aqara": "https://www.aqara.com/en/support",
    "Meross": "https://www.meross.com/support",
    "Ring": "https://support.ring.com/",
    "Yamaha": "https://download.yamaha.com/",
    "Ubiquiti": "https://www.ui.com/download/",
    "Synology": "https://www.synology.com/en-us/security/advisory",
    "QNAP": "https://www.qnap.com/en/security-advisory",
    "Netgear": "https://www.netgear.com/support/download/",
    "D-Link": "https://support.dlink.com/",
    "Reolink": "https://reolink.com/download-center/",
    "ESPHome": "https://esphome.io/changelog/",
    "Tasmota": "https://github.com/arendst/Tasmota/releases",
    "Hikvision": "https://www.hikvision.com/en/support/download/firmware/",
    "Dahua": "https://www.dahuasecurity.com/support/downloadCenter",
}

# Known vendor security.txt / vulnerability disclosure policy status
# Verified 2025-02 by probing /.well-known/security.txt on vendor websites
# Values: "available" = valid security.txt confirmed, "unavailable" = 404/403/no file, "unknown" = inconclusive
VENDOR_SECURITY_TXT_STATUS = {
    # === Verified AVAILABLE (valid security.txt confirmed) ===
    "Philips": "available",         # Contact: productsecurity@philips.com
    "Signify": "available",         # Contact: productsecurity@signify.com (Philips Hue parent)
    "Bosch": "available",           # PGP-signed, Contact: psirt.bosch.com
    "Schneider Electric": "available",  # Contact: cpcert@se.com, Expires: 2028
    "Cisco": "available",           # Contact: psirt@cisco.com, PGP-signed
    "Intel": "available",           # Contact: secure@intel.com
    "Microsoft": "available",       # Contact: msrc.microsoft.com, CSAF
    "Google": "available",          # Contact: security@google.com, Expires: 2030
    "Apple": "available",           # Contact: security.apple.com
    "Amazon": "available",          # Contact: hackerone.com/amazonvrp
    "Ring": "available",            # Contact: hackerone.com/ring (Amazon subsidiary)
    "Ubiquiti": "available",        # Contact: security@ui.com
    "Synology": "available",        # Contact: security@synology.com, bounty program
    "IKEA": "available",            # Contact: bugs.ikea.com, Expires: 2026
    "Huawei": "available",          # PGP-signed, Contact: psirt@huawei.com
    "Logitech": "available",        # Contact: logitech.com/security, HackerOne
    "HP": "available",              # Contact: hp-security-alert@hp.com
    "Dell": "available",            # Contact: bugcrowd.com/dell-com, Expires: 2026
    "Fortinet": "available",        # Contact: fortiguard.com/faq/psirt-contact
    "Honeywell": "unknown",          # Has PSIRT program but no RFC 9116 security.txt file
    # === Verified UNAVAILABLE (404/403/no valid security.txt) ===
    "Siemens": "unavailable",       # Returns 404 page (despite being security-mature)
    "ABB": "unavailable",           # Connection timeout / no response
    "Samsung": "unavailable",       # Returns 404
    "QNAP": "unavailable",         # Returns 403
    "AVM": "unavailable",          # Redirects to fritz.com → 404
    "FRITZ": "unavailable",        # AVM brand, same result
    "Tuya": "unavailable",         # Returns 404
    "Sonoff": "unavailable",       # Returns 404
    "ITEAD": "unavailable",        # Sonoff parent, returns 404
    "Shelly": "unavailable",       # Returns 404
    "Allterco": "unavailable",     # Shelly parent
    "TP-Link": "unavailable",      # Returns HTML redirect (not security.txt)
    "Kasa": "unavailable",         # TP-Link brand
    "Tapo": "unavailable",         # TP-Link brand
    "Xiaomi": "unavailable",       # Returns 403
    "Aqara": "unavailable",        # Returns 404
    "Meross": "unavailable",       # Returns 404
    "Govee": "unavailable",        # Returns 404
    "Wyze": "unavailable",         # Returns 404
    "Netgear": "unavailable",      # Returns 403
    "D-Link": "unavailable",       # Returns 404
    "Reolink": "unavailable",      # Returns 404
    "Hikvision": "unavailable",    # Returns 403
    "Dahua": "unavailable",        # Returns 503
    "ESPHome": "unavailable",      # Open-source project, no security.txt
    "Tasmota": "unavailable",      # Open-source project, no security.txt
    "LG": "unavailable",           # Returns 404
    "Sony": "unavailable",         # Returns 403
    "Linksys": "unavailable",      # Returns 404
    "Belkin": "unavailable",       # Returns 404
    "Yamaha": "unavailable",       # Returns 404
    "Nanoleaf": "unavailable",     # Returns 404
    "Eufy": "unavailable",         # Returns 404
    "Anker": "unavailable",        # Returns 404 (Eufy parent)
    "Juniper": "unavailable",      # Returns 404
    "Palo Alto": "unavailable",    # Returns 404
    "ZTE": "unavailable",          # Returns 403
    "Eero": "unavailable",         # Returns 404 (Amazon subsidiary)
    "Motorola": "unavailable",     # Returns 500
    # === UNKNOWN (inconclusive / not directly verified) ===
    "Espressif": "unknown",        # Returns 403, chip manufacturer
    "Raspberry Pi": "unknown",     # Not directly verified
    "Ecobee": "unknown",           # Has HackerOne program but no RFC 9116 file
    "Nest": "unknown",             # Google subsidiary, redirects to store page
    "Tenda": "unavailable",        # Returns HTML error page
}

# Known vendor security.txt / disclosure policy URLs (verified working)
VENDOR_SECURITY_TXT_URLS = {
    "Philips": "https://www.philips.com/.well-known/security.txt",
    "Signify": "https://www.signify.com/.well-known/security.txt",
    "Bosch": "https://www.bosch.com/.well-known/security.txt",
    "Schneider Electric": "https://www.se.com/.well-known/security.txt",
    "Cisco": "https://www.cisco.com/.well-known/security.txt",
    "Intel": "https://www.intel.com/.well-known/security.txt",
    "Microsoft": "https://www.microsoft.com/.well-known/security.txt",
    "Google": "https://www.google.com/.well-known/security.txt",
    "Apple": "https://www.apple.com/.well-known/security.txt",
    "Amazon": "https://www.amazon.com/.well-known/security.txt",
    "Ring": "https://ring.com/.well-known/security.txt",
    "Ubiquiti": "https://www.ui.com/.well-known/security.txt",
    "Synology": "https://www.synology.com/.well-known/security.txt",
    "IKEA": "https://www.ikea.com/.well-known/security.txt",
    "Huawei": "https://www.huawei.com/.well-known/security.txt",
    "Logitech": "https://www.logitech.com/.well-known/security.txt",
    "HP": "https://www.hp.com/.well-known/security.txt",
    "Dell": "https://www.dell.com/.well-known/security.txt",
    "Fortinet": "https://www.fortinet.com/.well-known/security.txt",
}

class CRAScanner:
    def __init__(self):
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap not found", exc_info=True)
        except Exception:
            logger.error("Unexpected error initializing nmap", exc_info=True)
            
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            logger.warning("Agent is NOT running as root. ARP scanning and MAC address detection will likely fail. Ensure 'privileged: true' is set in config.yaml.")
        else:
            logger.info("Agent is running as root/privileged. ARP scanning and MAC address detection enabled.")
            
        self.common_creds = [('admin', 'admin'), ('root', 'root'), ('user', '1234'), ('admin', '1234')]
        self.verify_ssl = False  # Configurable: set True to enforce SSL certificate verification during probes

        # Reuse a single requests.Session for connection pooling (performance)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    def scan_subnet(self, subnet, options=None):
        """
        Scans the given subnet for devices using a hybrid approach (Nmap + HA API).
        
        options: {
            "scan_type": "discovery" | "standard" | "deep",
            "auth_checks": bool,
            "vendors": ["tuya", "shelly", "hue", "kasa", "sonoff", "ikea"] | "all"
        }
        """
        if options is None: options = {}
        scan_type = options.get('scan_type', 'deep')
        auth_checks = options.get('auth_checks', True)
        selected_vendors = options.get('vendors', 'all') # 'all' or list of strings

        scan_start = time.time()
        total_stages = 4 if scan_type != 'discovery' else 3
        logger.info("[SCAN] " + "=" * 56)
        logger.info(f"[SCAN] Starting scan on {subnet} (type={scan_type}, auth_checks={auth_checks}, vendors={selected_vendors})")
        logger.info("[SCAN] " + "-" * 56)

        ha_devices = self._get_ha_devices() 
        
        if not self.nm:
            logger.error("[SCAN] Nmap not initialized. Relying solely on Home Assistant data.")
            return self._merge_devices([], ha_devices)

        # Scanned devices accumulator (IP -> Device Dict)
        scanned_devices = {}

        # Stage 1: Discovery Scan (Ping + ARP)
        logger.info(f"[SCAN] Stage 1/{total_stages}: Discovery scan (-sn -PR)...")
        stage_start = time.time()
        try:
            self.nm.scan(hosts=subnet, arguments='-sn -PR')
            self._update_scanned_devices(scanned_devices, discovery_phase=True)
        except Exception as e:
            logger.error(f"[SCAN] Nmap discovery scan failed: {e}")
            return self._merge_devices([], ha_devices)

        hosts_to_scan = list(scanned_devices.keys())
        stage_elapsed = time.time() - stage_start
        logger.info(f"[SCAN]   Found {len(hosts_to_scan)} live hosts in {stage_elapsed:.1f}s")
        for ip, dev in scanned_devices.items():
            logger.info(f"[SCAN]   -> {ip} (MAC: {dev.get('mac', 'Unknown')}, vendor: {dev.get('vendor', 'Unknown')})")

        nmap_devices = []
        
        # If discovery only, skip detailed scan
        current_stage = 2
        if hosts_to_scan and scan_type != 'discovery':
            # Stage 2: Detailed Scan
            logger.info(f"[SCAN] Stage {current_stage}/{total_stages}: Detailed port scan on {len(hosts_to_scan)} hosts...")
            stage_start = time.time()
            
            target_spec = " ".join(hosts_to_scan)
            
            # Build Nmap Arguments based on Options
            # Base arguments
            nmap_args = "-Pn" # Treat as online

            # Vendor Specific Ports (collected first to build unified port list)
            vendor_ports = []
            if selected_vendors == 'all' or 'tuya' in selected_vendors:
                vendor_ports.append('6668')
            if selected_vendors == 'all' or 'sonoff' in selected_vendors:
                vendor_ports.append('8081')
            if selected_vendors == 'all' or 'kasa' in selected_vendors:
                vendor_ports.append('9999')

            # Scan Type Depth
            # Note: --top-ports and -p conflict (nmap ignores --top-ports when -p is set).
            # So we build a single -p specification that covers both.
            if scan_type == 'deep':
                nmap_args += " -sV -O --script=nbstat"
                # Top 1000 ports + vendor ports
                port_spec = "1-1024"
                if vendor_ports:
                    port_spec += "," + ",".join(vendor_ports)
                nmap_args += f" -p {port_spec}"
            elif scan_type == 'standard':
                nmap_args += " -sV --script=nbstat"
                # Top 100 ports approximation + vendor ports
                port_spec = "1-100"
                if vendor_ports:
                    port_spec += "," + ",".join(vendor_ports)
                nmap_args += f" -p {port_spec}"
            else:
                nmap_args += " -F" # Fast scan (top 100 ports) if unnamed type
            
            try:
                logger.info(f"[SCAN]   Nmap args: {nmap_args}")
                self.nm.scan(hosts=target_spec, arguments=nmap_args)
                self._update_scanned_devices(scanned_devices, discovery_phase=False)
                stage_elapsed = time.time() - stage_start
                logger.info(f"[SCAN]   Completed in {stage_elapsed:.1f}s -- updated {len(scanned_devices)} devices")
            except Exception as e:
                logger.error(f"[SCAN] Nmap detail scan failed: {e}. Falling back to discovery results ({len(scanned_devices)} devices).")
            current_stage += 1
        
        nmap_devices = list(scanned_devices.values())

        # Stage: HA Merge
        logger.info(f"[SCAN] Stage {current_stage}/{total_stages}: Merging with Home Assistant devices...")
        merged_devices = self._merge_devices(nmap_devices, ha_devices)
        current_stage += 1
        
        # Stage: Compliance checks
        total_devices = len(merged_devices)
        logger.info(f"[SCAN] Stage {current_stage}/{total_stages}: Compliance checks on {total_devices} devices...")
        stage_start = time.time()
        final_results = []
        for idx, dev in enumerate(merged_devices, 1):
            check_vendor = dev.get('model') if dev.get('model') and dev.get('model') != "Unknown" else dev.get('vendor', 'Unknown')
            if dev.get('manufacturer') and dev.get('manufacturer') != "Unknown":
                 check_vendor = f"{dev['manufacturer']} {check_vendor}"
            if check_vendor == "Unknown " or check_vendor.strip() == "Unknown":
                 check_vendor = dev.get('vendor', 'Unknown')

            dev_label = dev.get('hostname') or dev.get('ip', 'Unknown')
            logger.info(f"[SCAN]   [{idx}/{total_devices}] {dev.get('ip', 'N/A')} ({check_vendor}) - {dev_label}")

            # Set resolved vendor for SBOM/firmware checks to use enriched data
            dev['resolved_vendor'] = check_vendor

            # ENHANCED CHECKS - Conditional
            sbd_result = {"passed": True, "details": "Skipped auth checks."}
            if auth_checks:
                sbd_result = self.check_secure_by_default(dev)
            
            conf_result = self.check_confidentiality(dev.get('openPorts', []))
            https_result = self.check_https_redirect(dev)
            vuln_result = self.check_vulnerabilities(check_vendor, dev.get('openPorts', []))
            sbom_result = self.check_sbom_compliance(dev)
            fw_result = self.check_firmware_tracking(dev)
            sec_txt_result = self.check_security_txt(dev)
            
            # Vendor Specific Checks - Conditional
            vendor_warnings = self._check_vendor_specifics(dev, selected_vendors)
            if vendor_warnings:
                if sbd_result['details'] == "Skipped auth checks.":
                     sbd_result['details'] = ""
                     
                sbd_result['details'] += " " + "; ".join(vendor_warnings)
                sbd_result['passed'] = False
                
            status = "Compliant"
            if not sbd_result['passed'] or not https_result['passed'] or not vuln_result['passed'] or (not fw_result['passed'] and fw_result.get('version_cves')):
                status = "Non-Compliant"
            elif not conf_result['passed'] or not sbom_result['passed'] or not fw_result['passed'] or not sec_txt_result['passed']:
                status = "Warning"

            # Log per-device check results with pass/fail symbols
            _p = lambda r: "pass" if r['passed'] else "FAIL"
            logger.info(
                f"[SCAN]     Secure={_p(sbd_result)}  Confid={_p(conf_result)}  "
                f"HTTPS={_p(https_result)}  CVE={_p(vuln_result)}  SBOM={_p(sbom_result)}  "
                f"FW={_p(fw_result)}  SecTxt={_p(sec_txt_result)}  => {status}"
            )

            dev.update({
                "status": status,
                "checks": {
                    "secureByDefault": sbd_result,
                    "dataConfidentiality": conf_result,
                    "httpsOnlyManagement": https_result,
                    "vulnerabilities": vuln_result,
                    "sbomCompliance": sbom_result,
                    "firmwareTracking": fw_result,
                    "securityTxt": sec_txt_result
                },
                "lastScanned": "Just now"
            })
            final_results.append(dev)

        stage_elapsed = time.time() - stage_start
        total_elapsed = time.time() - scan_start

        # Final summary
        compliant = sum(1 for d in final_results if d['status'] == 'Compliant')
        warning = sum(1 for d in final_results if d['status'] == 'Warning')
        non_compliant = sum(1 for d in final_results if d['status'] == 'Non-Compliant')
        logger.info("[SCAN] " + "=" * 56)
        logger.info(
            f"[SCAN] Scan complete: {len(final_results)} devices "
            f"({compliant} Compliant, {warning} Warning, {non_compliant} Non-Compliant) "
            f"in {total_elapsed:.1f}s"
        )
        return final_results

    def _update_scanned_devices(self, scanned_devices, discovery_phase=False):
        """Helper to parse nmap results and update the devices dict."""
        for host in self.nm.all_hosts():
            # Filter out if no addresses found (rare but possible)
            if 'addresses' not in self.nm[host]:
                continue
                
            nmap_host = self.nm[host]
            # Use bracket access as existing tests mock __getitem__ but not .get()
            addresses = nmap_host['addresses']
            
            mac = addresses.get('mac', 'Unknown')
            ip = host
            if 'ipv4' in addresses:
                ip = addresses.get('ipv4')
            
            # If this is the second pass (detailed), we might already have this device.
            existing = scanned_devices.get(ip)
            
            # Hostname Resolution
            hostname = nmap_host.hostname()
            if not hostname and 'script' in nmap_host:
                # Try to extract from nbstat
                if 'nbstat' in nmap_host['script']:
                    match = _NBSTAT_RE.search(nmap_host['script']['nbstat'])
                    if match:
                        hostname = match.group(1)
            
            if not hostname and discovery_phase:
                 # Try reverse DNS only in discovery or if missing
                 try:
                    hostname = socket.gethostbyaddr(ip)[0]
                 except Exception:
                    pass
            elif not hostname and existing and existing.get('hostname'):
                 # Keep existing hostname if new one is empty
                 hostname = existing.get('hostname')
            # Vendor
            vendor = "Unknown"
            if 'vendor' in nmap_host and mac != 'Unknown' and mac in nmap_host['vendor']:
                    vendor = nmap_host['vendor'][mac]
            
            os_name = self._get_os_match(host)
            open_ports = self._get_open_ports(host)
            
            # MERGE LOGIC: preserve existing data if new scan is incomplete
            if existing:
                if mac == 'Unknown' and existing.get('mac') != 'Unknown':
                    mac = existing.get('mac')
                
                if vendor == "Unknown" and existing.get('vendor') != "Unknown":
                    vendor = existing.get('vendor')
                
                if not hostname and existing.get('hostname'):
                    hostname = existing.get('hostname')
                
                if os_name == "Unknown" and existing.get('osMatch', "Unknown") != "Unknown":
                    os_name = existing.get('osMatch')
                
                # Ports: Detailed scan is usually authoritative.
                # But if detailed scan returned nothing (e.g. failed/filtered) AND we had ports (unlikely for discovery but consistent logic), we could keep.
                # For now, we assume detailed scan overwrite for ports is acceptable as discovery has none.

            device_data = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor, 
                "hostname": hostname,
                "openPorts": open_ports,
                "osMatch": os_name,
                "source": "nmap"
            }
            
            scanned_devices[ip] = device_data

    def _get_ha_devices(self):
        """Fetch devices from Home Assistant Supervisor API.
        
        Uses both the States API and the Device Registry API for richer data.
        The Device Registry provides sw_version, hw_version, manufacturer, and
        model which are often missing from entity states.
        """
        logger.info("[SCAN] Fetching Home Assistant devices...")
        supervisor_token = os.environ.get('SUPERVISOR_TOKEN')
        supervisor_url = "http://supervisor/core/api/states"
        
        if not supervisor_token:
            logger.warning("[SCAN]   SUPERVISOR_TOKEN not found. Using mock data for dev.")
            # MOCK DATA FOR LOCAL DEV / DEBUGGING
            mock_devices = [
                {"entity_id": "media_player.yamaha_yas_306", "attributes": {"friendly_name": "Living Room Soundbar", "ip_address": "192.168.1.55", "source": "ha", "manufacturer": "Yamaha", "model": "YAS-306", "sw_version": "2.51"}},
                {"entity_id": "light.zigbee_device_1", "attributes": {"friendly_name": "Kitchen Light", "source": "ha", "manufacturer": "Philips", "model": "LWB010", "sw_version": "1.50.2"}}, # Zigbee, no IP
                {"entity_id": "router.fritz_box_7590", "attributes": {"friendly_name": "FRITZ!Box 7590", "ip_address": "192.168.1.1", "source": "ha", "manufacturer": "AVM", "model": "FRITZ!Box 7590", "sw_version": "7.57"}}
            ]
            logger.info(f"[SCAN]   Loaded {len(mock_devices)} mock HA devices")
            return mock_devices
            
        headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        }
        
        # Fetch device registry for richer data (sw_version, manufacturer, model)
        device_registry = self._get_ha_device_registry(headers)
        logger.info(f"[SCAN]   Device Registry: {len(device_registry)} entries")
        
        devices = []
        try:
            response = self.session.get(supervisor_url, headers=headers, timeout=10)
            if response.status_code == 200:
                states = response.json()
                for state in states:
                    # Very simple heuristic to find "devices" with interesting attributes
                    attrs = state.get('attributes', {})
                    if 'ip_address' in attrs or 'manufacturer' in attrs or 'model' in attrs:
                        entity_id = state['entity_id']
                        # Enrich with device registry data
                        reg_info = device_registry.get(entity_id, {})
                        devices.append({
                            "entity_id": entity_id,
                            "attributes": attrs,
                            "ip": attrs.get('ip_address'),
                            "sw_version": reg_info.get('sw_version') or attrs.get('sw_version'),
                            "manufacturer": reg_info.get('manufacturer') or attrs.get('manufacturer'),
                            "model": reg_info.get('model') or attrs.get('model'),
                        })
            else:
                logger.error(f"[SCAN]   Failed to fetch HA states: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"[SCAN]   Error communicating with Supervisor: {e}")
        
        logger.info(f"[SCAN]   Found {len(devices)} HA devices")
        return devices

    def _get_ha_device_registry(self, headers):
        """Fetch the HA Device Registry for richer device metadata.
        
        Returns a dict mapping entity_id -> {sw_version, manufacturer, model, hw_version}.
        The Device Registry contains more reliable manufacturer/model data and
        software versions that the states API often lacks.
        """
        registry_url = "http://supervisor/core/api/config/device_registry"
        result = {}
        try:
            response = self.session.get(registry_url, headers=headers, timeout=10)
            if response.status_code == 200:
                devices = response.json()
                for device in devices:
                    # Map by identifiers — entities link to devices via device_id
                    # We store by device name as fallback key, and build entity mapping later
                    info = {
                        "sw_version": device.get('sw_version'),
                        "hw_version": device.get('hw_version'),
                        "manufacturer": device.get('manufacturer'),
                        "model": device.get('model'),
                        "name": device.get('name') or device.get('name_by_user'),
                    }
                    # Store by device ID for later entity matching
                    device_id = device.get('id')
                    if device_id:
                        result[device_id] = info
                
                # Also try to fetch entity registry to map entity_id -> device_id
                entity_map = self._map_entities_to_devices(headers, result)
                result.update(entity_map)
            else:
                logger.debug(f"Device Registry fetch returned {response.status_code} (may not be available)")
        except Exception as e:
            logger.debug(f"Device Registry fetch failed: {e}")
        
        return result

    def _map_entities_to_devices(self, headers, device_registry):
        """Map entity IDs to device registry entries via the Entity Registry API."""
        entity_url = "http://supervisor/core/api/config/entity_registry"
        entity_map = {}
        try:
            response = self.session.get(entity_url, headers=headers, timeout=10)
            if response.status_code == 200:
                entities = response.json()
                for entity in entities:
                    entity_id = entity.get('entity_id')
                    device_id = entity.get('device_id')
                    if entity_id and device_id and device_id in device_registry:
                        entity_map[entity_id] = device_registry[device_id]
        except Exception as e:
            logger.debug(f"Entity Registry fetch failed: {e}")
        return entity_map

    def _merge_devices(self, nmap_devices, ha_devices):
        """
        Merge separate lists of devices. 
        Priority: 
        - Match by IP (Nmap IP == HA IP)
        - Else append as new
        """
        merged = {d['ip']: d for d in nmap_devices if d.get('ip')}
        # Keep track of non-IP devices separately
        non_ip_devices = [d for d in nmap_devices if not d.get('ip')]

        ip_matched = 0
        ha_only_added = 0

        for ha_dev in ha_devices:
            attrs = ha_dev.get('attributes', {})
            ip = attrs.get('ip_address')
            
            # Use enriched data from Device Registry if available
            manufacturer = ha_dev.get('manufacturer') or attrs.get('manufacturer', 'Unknown')
            model = ha_dev.get('model') or attrs.get('model', 'Unknown')
            sw_version = ha_dev.get('sw_version') or attrs.get('sw_version')
            
            # Prepare HA device info
            new_dev_entry = {
                "ip": ip if ip else "N/A",
                "mac": "Unknown", # HA states rarely show MAC
                "vendor": manufacturer,
                "manufacturer": manufacturer,
                "model": model,
                "hostname": attrs.get('friendly_name', ha_dev['entity_id']),
                "openPorts": [],
                "osMatch": "Unknown",
                "source": "Home Assistant",
                "sw_version": sw_version,
            }

            if ip and ip in merged:
                # MERGE: We found this IP in Nmap results. Enrich it.
                ip_matched += 1
                existing = merged[ip]
                existing['source'] = 'Merged (Nmap + HA)'
                if existing['vendor'] == "Unknown" and new_dev_entry['vendor'] != "Unknown":
                    existing['vendor'] = new_dev_entry['vendor']
                # Always carry manufacturer from HA (more reliable than Nmap OUI)
                if manufacturer != 'Unknown':
                    existing['manufacturer'] = manufacturer
                if model != "Unknown":
                    existing['model'] = model
                # Carry sw_version from HA
                if sw_version:
                    existing['sw_version'] = sw_version
                # Prefer user-friendly hostname from HA
                existing['hostname'] = f"{existing['hostname']} ({new_dev_entry['hostname']})"
            else:
                # NEW FOUND: Either no IP (Zigbee?) or Nmap missed it
                ha_only_added += 1
                merged[ip if ip else f"no_ip_{ha_dev['entity_id']}"] = new_dev_entry

        result = list(merged.values()) + non_ip_devices
        logger.info(
            f"[SCAN]   Merged: {ip_matched} matched by IP, "
            f"{ha_only_added} HA-only added, {len(result)} total devices"
        )
        return result

    def _get_open_ports(self, host):
        ports = []
        for proto in self.nm[host].all_protocols():
            lport = self.nm[host][proto].keys()
            for port in lport:
                state = self.nm[host][proto][port]['state']
                if state == 'open':
                    port_info = self.nm[host][proto][port]
                    service = port_info['name']
                    entry = {"port": port, "protocol": proto, "service": service}
                    # Capture product/version from Nmap -sV (service version detection)
                    if port_info.get('product'):
                        entry['product'] = port_info['product']
                    if port_info.get('version'):
                        entry['version'] = port_info['version']
                    ports.append(entry)
        return ports

    def _get_os_match(self, host):
        if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
            return self.nm[host]['osmatch'][0]['name']
        return "Unknown"

    def check_secure_by_default(self, device):
        """Check for weak credentials and insecure defaults."""
        details = []
        passed = True
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        
        # 1. Telnet Check (Port 23) - Active Credential Test
        if any(p['port'] == 23 for p in open_ports):
            details.append("Telnet (port 23) is open.")
            if ip and ip != "N/A":
                creds_found = self._check_telnet_auth(ip)
                if creds_found:
                    passed = False
                    details.append(f"CRITICAL: Found weak Telnet credentials: {creds_found}")
                else:
                    passed = False # Open telnet is bad regardless
                    details.append("Telnet login accessible (Brute-force failed but service is insecure).")

        # 2. HTTP Check (Port 80/8080) - Unauth Checks
        http_ports = [p['port'] for p in open_ports if p['service'] == 'http' or p['port'] in [80, 8080]]
        for port in http_ports:
            if ip and ip != "N/A":
                unauth_info = self._check_http_auth(ip, port)
                if unauth_info:
                    passed = False
                    details.append(f"Insecure HTTP on port {port}: {unauth_info}")

        if not details:
            details.append("No obvious weak default access vectors found.")

        return {"passed": passed, "details": "; ".join(details)}

    def _check_telnet_auth(self, ip):
        """Try common credentials on Telnet."""
        # Simple socket-based brute force
        for user, password in self.common_creds:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((ip, 23))
                # Very basic Telnet negotiation skip (will fail on complex telnet servers, efficient for IoT)
                # Receive banner
                data = s.recv(1024) 
                
                # Send User
                s.sendall(user.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Send Pass
                s.sendall(password.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Check for success (prompt like #, $, >)
                # This is heuristic.
                resp = data.decode('utf-8', errors='ignore')
                if "#" in resp or "$" in resp or ">" in resp or "Success" in resp:
                    return f"{user}/{password}"
            except Exception:
                pass
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        return None

    def _check_http_auth(self, ip, port):
        """Check for unauthenticated access to standard endpoints."""
        endpoints = ['/', '/status', '/config', '/api', '/settings']
        for ep in endpoints:
            try:
                url = f"http://{ip}:{port}{ep}"
                r = self.session.get(url, timeout=2)
                if r.status_code == 200:
                    # Filter out simple login pages
                    if "login" not in r.text.lower() and "password" not in r.text.lower():
                        return f"Unauthenticated access to {ep}"
            except Exception:
                pass
        return None

    def _check_vendor_specifics(self, device, selected_vendors='all'):
        """Identify and check specific vendor vulnerabilities."""
        warnings = []
        ip = device.get('ip')
        ports = [int(p['port']) for p in device.get('openPorts', [])]
        
        if not ip or ip == "N/A": return []
        
        # Tuya
        if (selected_vendors == 'all' or 'tuya' in selected_vendors) and 6668 in ports:
            warnings.append("Possible Tuya Device (Port 6668 open). Ensure default keys are replaced.")

        # TP-Link Kasa
        if (selected_vendors == 'all' or 'kasa' in selected_vendors) and 9999 in ports:
             warnings.append("TP-Link Kasa Device (Port 9999). Old protocols may be vulnerable to local control injection.")

        # Sonoff LAN Mode
        if (selected_vendors == 'all' or 'sonoff' in selected_vendors) and 8081 in ports:
             warnings.append("Sonoff Device in LAN Mode (Port 8081). Ensure local network is trusted.")

        # Shelly
        if (selected_vendors == 'all' or 'shelly' in selected_vendors) and 80 in ports:
            try:
                r = self.session.get(f"http://{ip}/status", timeout=1)
                if r.status_code == 200 and "mac" in r.text: # Shelly JSON signature
                    if "auth" not in r.json() or not r.json().get("auth"):
                         warnings.append("Shelly Device: Authentication is NOT enabled for local web interface.")
            except Exception: pass

        # Philips Hue
        if (selected_vendors == 'all' or 'hue' in selected_vendors) and 80 in ports:
             try:
                r = self.session.get(f"http://{ip}/description.xml", timeout=1)
                if r.status_code == 200 and "Philips hue" in r.text:
                    warnings.append("Philips Hue Bridge detected. Ensure 'Link Button' authentication is strictly required.")
             except Exception: pass
        
        # Ikea
        if (selected_vendors == 'all' or 'ikea' in selected_vendors) and 80 in ports:
             # Basic header check for Ikea gateway signature (heuristic)
             try:
                 r = self.session.get(f"http://{ip}", timeout=1)
                 if "IKEA" in r.text or "Tradfri" in r.text:
                      warnings.append("IKEA Gateway detected. Ensure latest firmware to avoid known zigbee crash exploits.")
             except Exception: pass

        return warnings

    def check_confidentiality(self, open_ports):
        """Check for unencrypted services."""
        unencrypted_ports = [21, 23, 80] # FTP, Telnet, HTTP
        found_unencrypted = []
        
        for p in open_ports:
            if p['port'] in unencrypted_ports:
                found_unencrypted.append(f"{p['service']}/{p['port']}")
        
        if found_unencrypted:
            return {"passed": False, "details": f"Unencrypted ports found: {', '.join(found_unencrypted)}"}
        
        return {"passed": True, "details": "No common unencrypted management ports found."}

    def check_https_redirect(self, device):
        """Verify HTTP management interfaces redirect to HTTPS.

        CRA relevance: Annex I §1(3)(c), §1(3)(d).
        """
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])

        if not ip or ip == "N/A":
            return {
                "passed": True,
                "details": "Skipped HTTPS redirect check (no routable IP address).",
                "checked_ports": [],
                "failed_ports": [],
                "inconclusive_ports": []
            }

        http_ports = set()
        for port_info in open_ports:
            port = port_info.get('port')
            service = str(port_info.get('service', '')).lower()

            if port in (80, 8080):
                http_ports.add(int(port))
                continue

            if 'http' in service and 'https' not in service:
                try:
                    http_ports.add(int(port))
                except (TypeError, ValueError):
                    continue

        if not http_ports:
            return {
                "passed": True,
                "details": "No HTTP management ports detected for HTTPS redirect verification.",
                "checked_ports": [],
                "failed_ports": [],
                "inconclusive_ports": []
            }

        checked_ports = sorted(http_ports)
        failed_ports = []
        inconclusive_ports = []
        redirected_ports = []

        for port in checked_ports:
            url = f"http://{ip}:{port}/"
            try:
                response = self.session.get(url, timeout=2, allow_redirects=False)
                status_code = response.status_code
                location = (response.headers.get('Location') or '').strip()

                if 300 <= status_code < 400 and location.lower().startswith('https://'):
                    redirected_ports.append(port)
                elif status_code == 200:
                    failed_ports.append(port)
                elif 300 <= status_code < 400:
                    failed_ports.append(port)
                else:
                    inconclusive_ports.append(port)
            except requests.RequestException:
                inconclusive_ports.append(port)
            except Exception:
                inconclusive_ports.append(port)

        if failed_ports:
            details = (
                f"HTTP management exposed without HTTPS redirect on ports: {', '.join(str(p) for p in failed_ports)}."
            )
            if inconclusive_ports:
                details += f" Inconclusive probes on ports: {', '.join(str(p) for p in inconclusive_ports)}."
            return {
                "passed": False,
                "details": details,
                "checked_ports": checked_ports,
                "failed_ports": failed_ports,
                "inconclusive_ports": inconclusive_ports
            }

        details = "All detected HTTP management ports redirect to HTTPS."
        if inconclusive_ports:
            details = (
                f"No insecure HTTP responses detected. Inconclusive probes on ports: "
                f"{', '.join(str(p) for p in inconclusive_ports)}."
            )
        elif redirected_ports:
            details = f"HTTP management redirects to HTTPS on ports: {', '.join(str(p) for p in redirected_ports)}."

        return {
            "passed": True,
            "details": details,
            "checked_ports": checked_ports,
            "redirected_ports": redirected_ports,
            "failed_ports": [],
            "inconclusive_ports": inconclusive_ports
        }

    def check_vulnerabilities(self, vendor, open_ports):
        """Query external CVE API."""
        if not vendor or vendor == "Unknown":
             return {"passed": True, "details": "Vendor unknown, skipping CVE check.", "cves": []}

        # Clean vendor string for search
        search_term = vendor.split('(')[0].strip() # Remove extra info like (Running Linux...)
        
        cves = []
        try:
            # Using cve.circl.lu API
            url = f"https://cve.circl.lu/api/search/{search_term}"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', [])[:5]: # Check first 5 matches
                    if 'cvss' in item and item['cvss'] and float(item['cvss']) > 9.0:
                        cves.append({
                            "id": item.get('id', 'Unknown'),
                            "severity": "CRITICAL",
                            "description": item.get('summary', 'No description')[:100] + "..."
                        })
            
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
            return {"passed": True, "details": "CVE lookup failed (network error).", "cves": []}

        if cves:
             return {"passed": False, "details": f"Found {len(cves)} critical CVEs associated with '{search_term}'.", "cves": cves}

        return {"passed": True, "details": f"No critical CVEs found for '{search_term}'.", "cves": []}

    def check_sbom_compliance(self, device):
        """Check for SBOM availability per CRA Annex I §2(1).
        
        Two-layer approach:
        1. Device-level: probe well-known HTTP endpoints for SBOM files
        2. Vendor-level: lookup known vendor SBOM publication status
        """
        details = []
        sbom_found = False
        sbom_format = None
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        # Use resolved vendor (enriched from HA) if available, fallback to raw vendor
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')
        
        # Layer 1: Device-level SBOM endpoint probing
        http_ports = [p['port'] for p in open_ports 
                      if p.get('service') in ('http', 'https') or p['port'] in (80, 443, 8080, 8443)]
        
        if ip and ip != "N/A" and http_ports:
            sbom_found, sbom_format = self._probe_sbom_endpoints(ip, http_ports)
            if sbom_found:
                details.append(f"SBOM endpoint found on device (format: {sbom_format}).")
        
        # Layer 2: Vendor-level SBOM status lookup
        vendor_status = self._lookup_vendor_sbom_status(vendor)
        
        # Layer 3: Vendor SBOM portal URL lookup
        sbom_url = None
        for known_vendor, url in VENDOR_SBOM_URLS.items():
            if known_vendor.lower() in vendor.lower() or vendor.lower() in known_vendor.lower():
                sbom_url = url
                break
        
        if sbom_found:
            # Best case: device directly exposes SBOM
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": True,
                "sbom_format": sbom_format,
                "sbom_url": sbom_url
            }
        elif vendor_status == "available":
            details.append(f"Vendor '{vendor}' is known to publish SBOMs for their products.")
            if sbom_url:
                details.append(f"SBOM portal: {sbom_url}")
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": sbom_url
            }
        elif vendor_status == "unavailable":
            details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' does not publish SBOMs.")
            return {
                "passed": False,
                "details": "; ".join(details) if details else f"No SBOM found. Vendor '{vendor}' has no known SBOM publication.",
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": None
            }
        else:
            # Unknown vendor or vendor status
            if vendor == "Unknown":
                details.append("Vendor unknown — cannot determine SBOM availability.")
            else:
                details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' SBOM status is unknown.")
            return {
                "passed": False,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": None
            }

    def _probe_sbom_endpoints(self, ip, http_ports):
        """Probe well-known SBOM endpoints on a device.
        
        Returns (sbom_found: bool, sbom_format: str|None)
        """
        sbom_paths = [
            # IETF / CycloneDX well-known paths
            '/.well-known/sbom',
            '/sbom.json',
            '/sbom.xml',
            '/sbom',
            # Additional standard paths
            '/api/sbom',
            '/api/v1/sbom',
            '/device/sbom',
            '/bom.json',
            '/bom.xml',
            # CSAF (closely related to CRA)
            '/.well-known/csaf',
            # VEX (Vulnerability Exploitability eXchange)
            '/.well-known/vex',
        ]
        
        # CycloneDX and SPDX content-type indicators
        sbom_signatures = {
            'cyclonedx': 'CycloneDX',
            'spdx': 'SPDX',
            'bomFormat': 'CycloneDX',     # CycloneDX JSON key
            'specVersion': 'CycloneDX',   # CycloneDX JSON key (spec version field)
            'SPDXVersion': 'SPDX',        # SPDX JSON key
            'DocumentNamespace': 'SPDX',  # SPDX JSON key
            'spdxVersion': 'SPDX',        # SPDX JSON key (alt casing)
        }
        
        # Log SSL warning once per device check if disabled
        if not self.verify_ssl and http_ports:
             logger.warning(f"SBOM probe: SSL verification disabled for device {ip} (verify_ssl=False)")

        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            for path in sbom_paths:
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    r = self.session.get(url, timeout=2)
                    if r.status_code == 200 and len(r.text) > 50:
                        # Check content for known SBOM format signatures
                        content = r.text[:2000]  # Only check first 2KB
                        for signature, fmt in sbom_signatures.items():
                            if signature in content:
                                return True, fmt
                        
                        # Check Content-Type header
                        ct = r.headers.get('Content-Type', '').lower()
                        if 'cyclonedx' in ct:
                            return True, 'CycloneDX'
                        elif 'spdx' in ct:
                            return True, 'SPDX'
                        
                        # Generic: looks like a valid document but unknown format
                        if r.headers.get('Content-Type', '').startswith(('application/json', 'application/xml', 'text/xml')):
                            return True, 'Unknown Format'
                except Exception as e:
                    logger.debug(f"SBOM probe failed for {url}: {e}")
        
        return False, None

    def _lookup_vendor_sbom_status(self, vendor):
        """Check if vendor is known to publish SBOMs.
        
        Returns 'available', 'unavailable', or 'unknown'.
        """
        if not vendor or vendor == "Unknown":
            return "unknown"
        
        # Check exact match first
        if vendor in VENDOR_SBOM_STATUS:
            return VENDOR_SBOM_STATUS[vendor]
        
        # Check partial match (e.g. "Philips Lighting" matches "Philips")
        vendor_lower = vendor.lower()
        for known_vendor, status in VENDOR_SBOM_STATUS.items():
            if known_vendor.lower() in vendor_lower or vendor_lower in known_vendor.lower():
                return status
        
        return "unknown"

    def check_security_txt(self, device):
        """Check for security.txt disclosure policy per CRA §2(5) and §2(6).

        Two-layer approach:
        1. Device-level: probe /.well-known/security.txt on HTTP/HTTPS ports
        2. Vendor-level: lookup known vendor disclosure policy status
        """
        details = []
        security_txt_found = False
        parsed_fields = None
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')

        # Layer 1: Device-level security.txt probing
        http_ports = [p['port'] for p in open_ports
                      if p.get('service') in ('http', 'https') or p['port'] in (80, 443, 8080, 8443)]

        if ip and ip != "N/A" and http_ports:
            security_txt_found, parsed_fields = self._probe_security_txt(ip, http_ports)
            if security_txt_found:
                details.append("security.txt found on device.")
                if parsed_fields.get('contact'):
                    details.append(f"Contact: {parsed_fields['contact']}")
                if parsed_fields.get('expires'):
                    details.append(f"Expires: {parsed_fields['expires']}")
                    # Check if expired
                    try:
                        from datetime import datetime, timezone
                        exp_str = parsed_fields['expires'].strip()
                        # Try ISO 8601 format
                        exp_date = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                        if exp_date < datetime.now(timezone.utc):
                            details.append("WARNING: security.txt has expired!")
                    except Exception:
                        pass

        # Layer 2: Vendor-level disclosure status lookup
        vendor_status = self._lookup_vendor_security_txt_status(vendor)

        # Layer 3: Vendor disclosure URL lookup
        vendor_url = None
        for known_vendor, url in VENDOR_SECURITY_TXT_URLS.items():
            if known_vendor.lower() in vendor.lower() or vendor.lower() in known_vendor.lower():
                vendor_url = url
                break

        if security_txt_found:
            return {
                "passed": True,
                "details": "; ".join(details),
                "security_txt_found": True,
                "fields": parsed_fields,
                "vendor_url": vendor_url
            }
        elif vendor_status == "available":
            details.append(f"Vendor '{vendor}' is known to publish a security.txt disclosure policy.")
            if vendor_url:
                details.append(f"Disclosure policy: {vendor_url}")
            return {
                "passed": True,
                "details": "; ".join(details),
                "security_txt_found": False,
                "fields": None,
                "vendor_url": vendor_url
            }
        elif vendor_status == "unavailable":
            details.append(f"No security.txt found on device. Vendor '{vendor}' has no known disclosure policy.")
            return {
                "passed": False,
                "details": "; ".join(details) if details else f"No security.txt found. Vendor '{vendor}' has no known vulnerability disclosure policy.",
                "security_txt_found": False,
                "fields": None,
                "vendor_url": None
            }
        else:
            if vendor == "Unknown":
                details.append("Vendor unknown — cannot determine disclosure policy status.")
            else:
                details.append(f"No security.txt found on device. Vendor '{vendor}' disclosure status is unknown.")
            return {
                "passed": False,
                "details": "; ".join(details),
                "security_txt_found": False,
                "fields": None,
                "vendor_url": None
            }

    def _probe_security_txt(self, ip, http_ports):
        """Probe /.well-known/security.txt on a device.

        Returns (found: bool, fields: dict|None)
        Parses RFC 9116 fields: Contact, Expires, Encryption, Policy, Preferred-Languages, Canonical, Hiring
        """
        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            url = f"{scheme}://{ip}:{port}/.well-known/security.txt"
            try:
                r = self.session.get(url, timeout=2)
                if r.status_code == 200 and len(r.text) > 10:
                    content = r.text
                    # Validate it looks like a security.txt (must have Contact field per RFC 9116)
                    if 'contact:' not in content.lower():
                        continue

                    fields = {
                        "contact": None,
                        "expires": None,
                        "encryption": None,
                        "policy": None,
                        "preferred_languages": None,
                    }

                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith('#') or not line:
                            continue
                        # RFC 9116 format: "Field: Value" — use first colon+space as delimiter
                        match = re.match(r'^([A-Za-z-]+):\s*(.*)', line)
                        if match:
                            key_lower = match.group(1).lower()
                            val = match.group(2).strip()
                            if key_lower == 'contact':
                                fields['contact'] = val
                            elif key_lower == 'expires':
                                fields['expires'] = val
                            elif key_lower == 'encryption':
                                fields['encryption'] = val
                            elif key_lower == 'policy':
                                fields['policy'] = val
                            elif key_lower == 'preferred-languages':
                                fields['preferred_languages'] = val

                    # Must have Contact to be valid
                    if fields['contact']:
                        return True, fields
            except Exception as e:
                logger.debug(f"security.txt probe failed for {url}: {e}")

        return False, None

    def _lookup_vendor_security_txt_status(self, vendor):
        """Check if vendor is known to publish a security.txt disclosure policy.

        Returns 'available', 'unavailable', or 'unknown'.
        """
        if not vendor or vendor == "Unknown":
            return "unknown"

        if vendor in VENDOR_SECURITY_TXT_STATUS:
            return VENDOR_SECURITY_TXT_STATUS[vendor]

        vendor_lower = vendor.lower()
        for known_vendor, status in VENDOR_SECURITY_TXT_STATUS.items():
            if known_vendor.lower() in vendor_lower or vendor_lower in known_vendor.lower():
                return status

        return "unknown"

    def check_firmware_tracking(self, device):
        """Check firmware version tracking per CRA Annex I §2(2).
        
        Multi-source firmware version detection:
        1. Nmap -sV service version strings from open ports
        2. Vendor-specific firmware endpoints (Shelly, Hue, AVM, ESPHome, Tasmota, etc.)
        3. UPnP device description XML
        4. Generic HTTP content scraping (regex)
        5. Home Assistant sw_version attribute
        
        Then performs version-specific CVE lookup if version is found.
        """
        firmware_version = None
        firmware_source = None
        version_cves = []
        details = []
        ip = device.get('ip')
        # Use resolved vendor (enriched from HA) if available
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')
        open_ports = device.get('openPorts', [])

        # Layer 1: Extract version from Nmap -sV service probe results
        for port_info in open_ports:
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            if version:
                firmware_version = version
                firmware_source = f"Nmap service scan (port {port_info['port']}: {product} {version})".strip()
                details.append(f"Service version detected: {product} {version} on port {port_info['port']}.")
                break  # Use the first versioned service found

        # Layer 2: Vendor-specific firmware endpoint probing
        if not firmware_version and ip and ip != "N/A":
            http_ports = [p['port'] for p in open_ports
                          if p.get('service') in ('http', 'https') or p['port'] in (80, 443, 8080, 8443)]
            if http_ports:
                fw_ver, fw_src = self._probe_firmware_endpoints(ip, http_ports, vendor)
                if fw_ver:
                    firmware_version = fw_ver
                    firmware_source = fw_src
                    details.append(f"Firmware version detected via {fw_src}: {fw_ver}.")

        # Layer 3: Home Assistant sw_version
        if not firmware_version and device.get('sw_version'):
            firmware_version = device['sw_version']
            firmware_source = "Home Assistant"
            details.append(f"Firmware version from Home Assistant: {firmware_version}.")

        # Version-specific CVE lookup
        if firmware_version and vendor and vendor != "Unknown":
            search_term = f"{vendor.split('(')[0].strip()} {firmware_version}"
            try:
                url = f"https://cve.circl.lu/api/search/{search_term}"
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('data', [])[:5]:
                        if 'cvss' in item and item['cvss'] and float(item['cvss']) > 7.0:
                            severity = "CRITICAL" if float(item['cvss']) > 9.0 else "HIGH"
                            version_cves.append({
                                "id": item.get('id', 'Unknown'),
                                "severity": severity,
                                "description": item.get('summary', 'No description')[:100] + "..."
                            })
            except Exception as e:
                logger.error(f"Version-specific CVE lookup failed: {e}")
                details.append("Version-specific CVE lookup failed (network error).")

        if version_cves:
            details.append(f"Found {len(version_cves)} CVEs affecting firmware version '{firmware_version}'.")

        # Determine update URL
        update_url = None
        for known_vendor, url in VENDOR_FIRMWARE_UPDATE_URLS.items():
            if known_vendor.lower() in vendor.lower() or vendor.lower() in known_vendor.lower():
                update_url = url
                break

        # Determine pass/fail
        if firmware_version:
            if version_cves:
                passed = False
                details.append("Firmware has known vulnerabilities — update recommended.")
            else:
                passed = True
                if not details:
                    details.append(f"Firmware version '{firmware_version}' detected, no known CVEs.")
        else:
            passed = False
            details.append("Could not determine firmware version. CRA §2(2) requires version tracking.")

        return {
            "passed": passed,
            "details": "; ".join(details),
            "firmware_version": firmware_version,
            "firmware_source": firmware_source,
            "update_available": True if version_cves else None,
            "update_url": update_url,
            "version_cves": version_cves
        }

    def _probe_firmware_endpoints(self, ip, http_ports, vendor):
        """Probe vendor-specific firmware version endpoints.
        
        Supports: Shelly, Hue, AVM/FRITZ!, ESPHome, Tasmota, Sonoff,
                  IKEA Tradfri, UPnP XML descriptors, and generic HTTP scraping.
        
        Returns (version: str|None, source: str|None)
        """
        vendor_lower = vendor.lower() if vendor else ""
        
        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            base_url = f"{scheme}://{ip}:{port}"
            
            try:
                # Shelly devices expose firmware version at /settings or /shelly
                if 'shelly' in vendor_lower or 'allterco' in vendor_lower:
                    for path in ['/settings', '/shelly']:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200:
                            data = r.json()
                            fw = data.get('fw') or data.get('fw_version')
                            if fw:
                                return fw, f"Shelly API ({path})"
                
                # Philips Hue bridges expose version at /api/config
                if 'philips' in vendor_lower or 'signify' in vendor_lower or 'hue' in vendor_lower:
                    r = self.session.get(f"{base_url}/api/config", timeout=2)
                    if r.status_code == 200:
                        data = r.json()
                        sw = data.get('swversion') or data.get('apiversion')
                        if sw:
                            return sw, "Hue Bridge API (/api/config)"
                
                # AVM/FRITZ!Box firmware version endpoints
                if 'avm' in vendor_lower or 'fritz' in vendor_lower:
                    for path in ['/jason_boxinfo.xml', '/cgi-bin/system_status']:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200:
                            text = r.text
                            # Parse FRITZ!Box version from XML or HTML
                            fw_match = re.search(r'<(?:Version|firmware_version|Labor)>([^<]+)</', text)
                            if fw_match:
                                return fw_match.group(1).strip(), f"AVM API ({path})"
                            # Try to find version pattern in text
                            fw_match = re.search(r'FRITZ!OS[:\s]*(\d+\.\d+[\w.]*)', text, re.IGNORECASE)
                            if fw_match:
                                return fw_match.group(1), f"AVM API ({path})"
                
                # ESPHome devices expose version at /api or via headers
                if 'esp' in vendor_lower or 'esphome' in vendor_lower:
                    r = self.session.get(f"{base_url}/", timeout=2)
                    if r.status_code == 200:
                        # ESPHome sets X-Esphome-Version header
                        esphome_ver = r.headers.get('X-Esphome-Version')
                        if esphome_ver:
                            return esphome_ver, "ESPHome header (X-Esphome-Version)"
                        # Also check page content
                        ver_match = re.search(r'ESPHome[\s_-]*v?(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "ESPHome web interface"
                
                # Tasmota devices: /cm?cmnd=Status%202 returns firmware info
                if 'tasmota' in vendor_lower:
                    r = self.session.get(f"{base_url}/cm?cmnd=Status%202", timeout=2)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            fw = data.get('StatusFWR', {}).get('Version')
                            if fw:
                                return fw, "Tasmota API (Status 2)"
                        except (ValueError, AttributeError):
                            pass
                    # Fallback: root page often shows version
                    r = self.session.get(f"{base_url}/", timeout=2)
                    if r.status_code == 200:
                        ver_match = re.search(r'Tasmota[\s_-]*v?(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "Tasmota web interface"
                
                # Sonoff DIY Mode: /zeroconf/info
                if 'sonoff' in vendor_lower or 'itead' in vendor_lower:
                    try:
                        r = self.session.post(
                            f"{base_url}/zeroconf/info",
                            json={"deviceid": "", "data": {}},
                            timeout=2
                        )
                        if r.status_code == 200:
                            data = r.json()
                            fw = data.get('data', {}).get('fwVersion')
                            if fw:
                                return fw, "Sonoff DIY API (/zeroconf/info)"
                    except Exception:
                        pass
                
                # IKEA Tradfri Gateway
                if 'ikea' in vendor_lower or 'tradfri' in vendor_lower:
                    r = self.session.get(f"{base_url}/", timeout=2)
                    if r.status_code == 200:
                        ver_match = re.search(r'(?:firmware|version)[:\s]*(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "IKEA Gateway web interface"
                
                # UPnP device description XML (routers, NAS, media devices)
                for path in ['/description.xml', '/rootDesc.xml', '/gatedesc.xml',
                             '/DeviceDescription.xml', '/dmr/DeviceDescription.xml']:
                    try:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200 and '<root' in r.text[:500].lower():
                            text = r.text
                            # Extract firmware/software version from UPnP XML
                            for tag in ['firmwareVersion', 'softwareVersion', 'firmware_version']:
                                fw_match = re.search(rf'<{tag}>([^<]+)</', text, re.IGNORECASE)
                                if fw_match:
                                    return fw_match.group(1).strip(), f"UPnP XML ({path})"
                            # Try modelNumber as version indicator (some devices use this)
                            model_match = re.search(r'<modelNumber>([^<]+)</', text)
                            if model_match:
                                model_ver = model_match.group(1).strip()
                                # Only use if it looks like a version number
                                if re.match(r'\d+\.\d+', model_ver):
                                    return model_ver, f"UPnP XML modelNumber ({path})"
                    except Exception:
                        pass
                
                # Generic: try common firmware endpoints (JSON APIs)
                for path in ['/firmware', '/api/firmware', '/device/info',
                             '/system/info', '/api/system', '/api/device',
                             '/api/v1/device/info', '/status', '/api/status']:
                    r = self.session.get(f"{base_url}{path}", timeout=2)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            for key in ['fw_version', 'firmware_version', 'version',
                                        'fw', 'softwareVersion', 'sw_version',
                                        'firmwareVersion', 'sys_version', 'os_version']:
                                if key in data:
                                    return str(data[key]), f"Device API ({path})"
                            # Check nested structures
                            for outer in ['system', 'device', 'firmware', 'info']:
                                if isinstance(data.get(outer), dict):
                                    for key in ['version', 'fw_version', 'firmware_version', 'sw_version']:
                                        if key in data[outer]:
                                            return str(data[outer][key]), f"Device API ({path} → {outer}.{key})"
                        except (ValueError, AttributeError):
                            pass
                
                # Last resort: regex scan HTTP root page for version patterns
                try:
                    r = self.session.get(f"{base_url}/", timeout=2)
                    if r.status_code == 200 and len(r.text) > 20:
                        content = r.text[:5000]  # Only check first 5KB
                        match = _FW_VERSION_RE.search(content)
                        if match:
                            return match.group(1), "HTTP content scraping (regex)"
                except Exception:
                    pass
                
            except Exception as e:
                logger.debug(f"Firmware endpoint probe failed for {base_url}: {e}")
        
        return None, None

# For standalone testing
if __name__ == "__main__":
    scanner = CRAScanner()
    print(scanner.scan_subnet("192.168.1.0/24"))